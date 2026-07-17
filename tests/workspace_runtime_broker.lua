vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")
local workspace = require("nvim_remote_mirror.workspace")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function assert_error(value, err, code)
  assert_eq(value, nil, "operation unexpectedly succeeded")
  assert_eq(type(err), "table")
  assert_eq(err.code, code)
  assert_eq(tostring(err), err.message)
  return err
end

local function provider_error(code, message)
  return { code = code, message = message }
end

local remote_epoch = 4
local remote_state = "online"
local readiness_state = "ready"
local pending_prepare = nil
local pending_authorize = nil
local authorize_mode = "inline"
local trusted_state = true

local function descriptor(workspace_id, path_style, shell)
  return {
    api_version = 2,
    provider = "nrm",
    workspace_id = workspace_id or "remote-a",
    epoch = remote_epoch,
    state = remote_state,
    mode = "mirror",
    authority = {
      id = "authority-" .. (workspace_id or "remote-a"),
      kind = "ssh",
      label = "ssh://build.example.test",
      path_style = path_style or "posix",
      os = path_style == "windows" and "windows" or "linux",
      arch = "x86_64",
      shell = shell or "sh",
    },
    roots = {
      editor = "/tmp/nrm-broker-mirror",
      authority = path_style == "windows" and "B:/repos/demo" or "/srv/demo",
    },
    support = { process = true, terminal = true, watch = false },
  }
end

local provider = {
  resolve = function(query)
    if query.bufnr ~= nil then
      if vim.b[query.bufnr].broker_remote ~= true then
        return nil, provider_error("not_remote_buffer", "buffer is not associated with a remote workspace")
      end
      local result = descriptor(vim.b[query.bufnr].broker_workspace_id)
      result.relative_path = "src/main.lua"
      return result
    end
    if query.workspace_id then
      return descriptor(query.workspace_id)
    end
    return descriptor("global-active")
  end,
  current_epoch = function()
    return remote_epoch
  end,
  current_state = function()
    return remote_state
  end,
  is_trusted = function()
    return trusted_state
  end,
  authorize = function(_, _, callback)
    if authorize_mode == "inline" then
      callback(nil, true)
    else
      pending_authorize = callback
    end
    return true
  end,
  capability_status = function(_, capability)
    return {
      name = capability,
      state = readiness_state,
      supported = true,
      enabled = true,
      effective = readiness_state == "ready" and true or nil,
      revision = readiness_state == "ready" and 2 or 1,
    }
  end,
  prepare_capability = function(_, _, callback)
    pending_prepare = callback
    return true
  end,
  job_spec = function()
    return { argv = { "/usr/bin/nrm-sidecar", "runtime-proxy", "--ticket", "opaque" } }
  end,
  spawn = function()
    return nil, provider_error("unsupported", "not used by this test")
  end,
}

workspace._set_backend(provider)

local ok_runtime, runtime_or_err = pcall(require, "nvim_remote_mirror.workspace_runtime")
assert_eq(ok_runtime, true, "workspace runtime broker module is missing: " .. tostring(runtime_or_err))
local runtime = runtime_or_err
runtime._reset_for_test()

local plain = vim.api.nvim_create_buf(true, false)
vim.api.nvim_set_current_buf(plain)

-- A global NRM connection must not make an unrelated plain tab remote.
local local_context = assert(runtime.resolve())
assert_eq(local_context.provider, "local")
assert_eq(local_context.mode, "local")
assert_eq(local_context.state, "online")
assert_eq(local_context.authority.kind, "local")
assert_eq(local_context.roots.editor, vim.fs.normalize(vim.fn.getcwd()))
assert_eq(local_context.roots.authority, local_context.roots.editor)
local immutable_ok = pcall(function()
  local_context.provider = "nrm"
end)
assert_eq(immutable_ok, false, "broker contexts must be immutable")

local callbacks = 0
assert(local_context:prepare("terminal", function(err, prepared)
  callbacks = callbacks + 1
  assert_eq(err, nil)
  local bridge = assert(prepared:job_spec({
    command = { argv = { "sh" } },
    cwd = { space = "workspace", path = "" },
    stdio = "pty",
  }))
  assert_eq(bridge.argv[1], "sh")
  assert_eq(bridge.cwd, local_context.roots.authority)
  assert_eq(bridge.authority.kind, "local")
  assert_eq(bridge.input.newline, "\n")
end))
assert_eq(callbacks, 1, "local readiness must complete inline exactly once")

local env_bridge = assert(local_context:job_spec({
  command = { argv = { "env" } },
  env = {
    clear = true,
    set = { NRM_BROKER_TEST = "present" },
    unset = { "SHOULD_NOT_SURVIVE" },
  },
}))
assert_eq(env_bridge.clear_env, true)
assert_eq(env_bridge.env.NRM_BROKER_TEST, "present")
assert_eq(env_bridge.env.SHOULD_NOT_SURVIVE, nil)
local detached_bridge, detached_err = local_context:job_spec({
  command = { argv = { "sh" } },
  stdio = "pty",
  persistence = "detached",
})
assert_error(detached_bridge, detached_err, "persistence_unavailable")

if vim.fn.executable("sh") == 1 then
  local output = {}
  local exited = false
  local handle = assert(local_context:spawn({
    command = { argv = { "sh", "-c", 'printf %s "$NRM_BROKER_SPAWN"' } },
    env = { clear = true, set = { NRM_BROKER_SPAWN = "spawn-ok" } },
  }, {
    on_stdout = function(_, lines)
      vim.list_extend(output, lines)
    end,
    on_exit = function(_, code)
      assert_eq(code, 0)
      exited = true
    end,
  }))
  assert_eq(type(handle.kill), "function")
  assert(
    vim.wait(2000, function()
      return exited
    end, 10),
    "local managed process did not exit"
  )
  assert_eq(table.concat(output, ""), "spawn-ok")

  local timeout_result
  assert(local_context:spawn({
    command = { argv = { "sh", "-c", "sleep 2" } },
    timeout_ms = 20,
  }, {
    on_exit = function(_, _, _, result)
      timeout_result = result
    end,
  }))
  assert(
    vim.wait(2000, function()
      return timeout_result ~= nil
    end, 10),
    "local managed process ignored timeout_ms"
  )
  assert_eq(timeout_result.kind, "timed_out")
  assert_eq(timeout_result.error_code, "timeout")

  local limited_result
  local limited_output = {}
  assert(local_context:spawn({
    command = { argv = { "sh", "-c", "printf 123456789; sleep 2" } },
    max_output_bytes = 4,
  }, {
    on_stdout = function(_, lines)
      vim.list_extend(limited_output, lines)
    end,
    on_exit = function(_, _, _, result)
      limited_result = result
    end,
  }))
  assert(
    vim.wait(2000, function()
      return limited_result ~= nil
    end, 10),
    "local managed process ignored max_output_bytes"
  )
  assert_eq(limited_result.kind, "output_limit")
  assert_eq(limited_result.output_truncated, true)
  assert_eq(table.concat(limited_output, ""), "", "over-limit output leaked to the consumer")

  if vim.fn.executable("stty") == 1 then
    local pty_output = {}
    local pty_result
    assert(local_context:open_pty({
      command = { argv = { "sh", "-c", "stty size" } },
      initial_size = { cols = 91, rows = 37 },
    }, {
      on_stdout = function(_, lines)
        vim.list_extend(pty_output, lines)
      end,
      on_exit = function(_, _, _, result)
        pty_result = result
      end,
    }))
    assert(
      vim.wait(2000, function()
        return pty_result ~= nil
      end, 10),
      "local managed PTY did not exit"
    )
    assert_eq(pty_result.kind, "process_exit")
    assert(table.concat(pty_output, ""):find("37 91", 1, true), "local managed PTY ignored its initial size")
  end

  local pixel_handle, pixel_err = local_context:open_pty({
    command = { argv = { "sh" } },
    initial_size = { cols = 80, rows = 24, pixel_width = 800, pixel_height = 600 },
  })
  assert_error(pixel_handle, pixel_err, "unsupported")

  local resize_exited = false
  local resize_handle = assert(local_context:open_pty({
    command = { argv = { "sh", "-c", "sleep 2" } },
  }, {
    on_exit = function()
      resize_exited = true
    end,
  }))
  local resized, resize_err = resize_handle:resize(nil)
  assert_error(resized, resize_err, "invalid_argument")
  resized, resize_err = resize_handle:resize({ cols = 80.5, rows = 24 })
  assert_error(resized, resize_err, "invalid_argument")
  resized, resize_err = resize_handle:resize({ cols = 0, rows = 24 })
  assert_error(resized, resize_err, "invalid_argument")
  resized, resize_err = resize_handle:resize({ cols = 80, rows = 32768 })
  assert_error(resized, resize_err, "invalid_argument")
  assert(resize_handle:resize({ cols = 80, rows = 24 }))
  assert(resize_handle:kill())
  assert(
    vim.wait(2000, function()
      return resize_exited
    end, 10),
    "resized local PTY did not exit"
  )
end

-- Local cwd joining is lexical: environment and wildcard syntax are literal
-- filesystem bytes, not input to vim.fs.normalize()/expand().
local previous_literal_cwd = vim.fn.getcwd()
local literal_cwd_root = vim.fn.tempname()
local literal_cwd = vim.fs.joinpath(literal_cwd_root, "$HOME", "foo*", "literal workspace")
local wildcard_cwd = vim.fs.joinpath(literal_cwd_root, "$HOME", "fooX", "literal workspace")
assert_eq(vim.fn.mkdir(literal_cwd, "p"), 1)
assert_eq(vim.fn.mkdir(wildcard_cwd, "p"), 1)
vim.cmd("tcd " .. vim.fn.fnameescape(literal_cwd_root))
local literal_context = assert(runtime.resolve({ authority = "local" }))
local literal_bridge = assert(literal_context:job_spec({
  command = { argv = { "sh" } },
  cwd = { space = "workspace", path = "$HOME/foo*/literal workspace" },
  stdio = "pty",
}))
assert_eq(literal_bridge.cwd, literal_cwd)
local literal_query = assert(runtime.resolve({ authority = "local", path = literal_cwd }))
assert_eq(literal_query.workspace_id, literal_context.workspace_id)
vim.cmd("tcd " .. vim.fn.fnameescape(previous_literal_cwd))
assert_eq(vim.fn.delete(literal_cwd_root, "rf"), 0)

-- Windows UNC and root-relative paths are absolute-like inputs, never paths
-- relative to the workspace. Exercise the Windows resolver on every host by
-- temporarily replacing only the platform probes used by the local provider.
local saved_has = vim.fn.has
local saved_getcwd = vim.fn.getcwd
local saved_uname = vim.uv.os_uname
local saved_get_name = vim.api.nvim_buf_get_name
local windows_buffer = vim.api.nvim_create_buf(true, false)
local windows_buffer_name = [[\Windows\system32\cmd.exe]]
vim.fn.has = function(feature)
  if feature == "win32" then
    return 1
  end
  return saved_has(feature)
end
vim.fn.getcwd = function()
  return "B:/workspace"
end
vim.uv.os_uname = function()
  return { sysname = "Windows_NT", machine = "AMD64" }
end
vim.api.nvim_buf_get_name = function(bufnr)
  if bufnr == windows_buffer then
    return windows_buffer_name
  end
  return saved_get_name(bufnr)
end
local windows_probe_ok, windows_probe_err = pcall(function()
  for _, path in ipairs({ [[\Windows\system32]], [[\\server\share\project]] }) do
    local invalid_context, invalid_err = runtime.resolve({ authority = "local", path = path })
    assert_error(invalid_context, invalid_err, "workspace_not_found")
  end

  for _, name in ipairs({ [[\Windows\system32\cmd.exe]], [[\\server\share\project\file.txt]] }) do
    windows_buffer_name = name
    local invalid_buffer_context = assert(runtime.resolve({ authority = "local", bufnr = windows_buffer }))
    local invalid_bridge, invalid_bridge_err = invalid_buffer_context:job_spec({
      command = { argv = { "powershell.exe" } },
      cwd = { space = "buffer" },
    })
    assert_error(invalid_bridge, invalid_bridge_err, "invalid_process_spec")
  end
end)
vim.fn.has = saved_has
vim.fn.getcwd = saved_getcwd
vim.uv.os_uname = saved_uname
vim.api.nvim_buf_get_name = saved_get_name
assert(windows_probe_ok, windows_probe_err)

-- Global cwd changes in another tab monotonically stale every affected local
-- context, even if the global directory later returns to the same path.
local original_global_cwd = vim.fn.getcwd(-1, -1)
local global_cwd_a = vim.fn.tempname()
local global_cwd_b = vim.fn.tempname()
assert_eq(vim.fn.mkdir(global_cwd_a, "p"), 1)
assert_eq(vim.fn.mkdir(global_cwd_b, "p"), 1)
vim.cmd("cd " .. vim.fn.fnameescape(global_cwd_a))
local global_cwd_tab = vim.api.nvim_get_current_tabpage()
local global_cwd_context = assert(runtime.resolve({ authority = "local" }))
vim.cmd("tabnew")
local global_changer_tab = vim.api.nvim_get_current_tabpage()
vim.cmd("cd " .. vim.fn.fnameescape(global_cwd_b))
vim.cmd("cd " .. vim.fn.fnameescape(global_cwd_a))
vim.api.nvim_set_current_tabpage(global_cwd_tab)
local global_current, global_stale = global_cwd_context:is_current()
assert_eq(global_current, false, "local context revived after a global cwd excursion in another tab")
assert_eq(global_stale.code, "stale_context")
vim.api.nvim_set_current_tabpage(global_changer_tab)
vim.cmd("tabclose")
vim.api.nvim_set_current_tabpage(global_cwd_tab)
vim.cmd("cd " .. vim.fn.fnameescape(original_global_cwd))
assert_eq(vim.fn.delete(global_cwd_a, "d"), 0)
assert_eq(vim.fn.delete(global_cwd_b, "d"), 0)

-- Entering a tab with a different tab-local cwd emits DirChanged with
-- changed_window=true, but it does not mutate either tab's cwd. Switching
-- away and back must therefore preserve an explicit local context.
local tab_cwd_a = vim.fn.tempname()
local tab_cwd_b = vim.fn.tempname()
assert_eq(vim.fn.mkdir(tab_cwd_a, "p"), 1)
assert_eq(vim.fn.mkdir(tab_cwd_b, "p"), 1)
vim.cmd("tcd " .. vim.fn.fnameescape(tab_cwd_a))
local tab_cwd_origin = vim.api.nvim_get_current_tabpage()
local tab_cwd_context = assert(runtime.resolve({ authority = "local" }))
vim.cmd("tabnew")
local tab_cwd_other = vim.api.nvim_get_current_tabpage()
vim.cmd("tcd " .. vim.fn.fnameescape(tab_cwd_b))
vim.api.nvim_set_current_tabpage(tab_cwd_origin)
assert_eq(tab_cwd_context:is_current(), true, "tab switching falsely staled an unchanged local context")
vim.api.nvim_set_current_tabpage(tab_cwd_other)
vim.cmd("tabclose")
vim.api.nvim_set_current_tabpage(tab_cwd_origin)
vim.cmd("tcd " .. vim.fn.fnameescape(original_global_cwd))
assert_eq(vim.fn.delete(tab_cwd_a, "d"), 0)
assert_eq(vim.fn.delete(tab_cwd_b, "d"), 0)

-- Static support remains queryable after staleness, while a prepared facade
-- translates authority selection changes to stale_preparation on every
-- execution surface and can never revive after A -> B -> A.
local cwd_a = vim.fn.tempname()
local cwd_b = vim.fn.tempname()
assert_eq(vim.fn.mkdir(cwd_a, "p"), 1)
assert_eq(vim.fn.mkdir(cwd_b, "p"), 1)
vim.cmd("tcd " .. vim.fn.fnameescape(cwd_a))
local cwd_context = assert(runtime.resolve({ authority = "local" }))
local cwd_prepared
assert(cwd_context:prepare("terminal", function(err, prepared)
  assert_eq(err, nil)
  cwd_prepared = prepared
end))
assert_eq(cwd_context:supports("terminal"), true)
vim.cmd("tcd " .. vim.fn.fnameescape(cwd_b))
local cwd_current, cwd_stale = cwd_context:is_current()
assert_eq(cwd_current, false)
assert_eq(cwd_stale.code, "stale_context")
assert_eq(cwd_context:supports("terminal"), true, "static support changed with dynamic context state")
local stale_value, stale_err = cwd_prepared:job_spec({ command = { argv = { "sh" } }, stdio = "pty" })
assert_error(stale_value, stale_err, "stale_preparation")
stale_value, stale_err = cwd_prepared:spawn({ command = { argv = { "sh" } }, stdio = "pty" })
assert_error(stale_value, stale_err, "stale_preparation")
stale_value, stale_err = cwd_prepared:open_pty({ command = { argv = { "sh" } } })
assert_error(stale_value, stale_err, "stale_preparation")
vim.cmd("tcd " .. vim.fn.fnameescape(cwd_a))
assert_eq(cwd_context:is_current(), false, "local context revived after A -> B -> A")
vim.cmd("tcd " .. vim.fn.fnameescape(original_global_cwd))
assert_eq(vim.fn.delete(cwd_a, "d"), 0)
assert_eq(vim.fn.delete(cwd_b, "d"), 0)

-- Buffer-relative local contexts capture the buffer that supplied their cwd.
-- An implicit context must not keep launching in the old buffer directory
-- after the current buffer changes, and an explicit selection must stale when
-- the selected buffer is renamed. Explicit local still ignores NRM ownership;
-- this guard covers only the local path snapshot.
local buffer_root = vim.fn.tempname()
local implicit_first_dir = vim.fs.joinpath(buffer_root, "implicit-first")
local implicit_second_dir = vim.fs.joinpath(buffer_root, "implicit-second")
local explicit_first_dir = vim.fs.joinpath(buffer_root, "explicit-first")
local explicit_second_dir = vim.fs.joinpath(buffer_root, "explicit-second")
assert_eq(vim.fn.mkdir(implicit_first_dir, "p"), 1)
assert_eq(vim.fn.mkdir(implicit_second_dir, "p"), 1)
assert_eq(vim.fn.mkdir(explicit_first_dir, "p"), 1)
assert_eq(vim.fn.mkdir(explicit_second_dir, "p"), 1)
vim.cmd("tcd " .. vim.fn.fnameescape(buffer_root))

local implicit_first = vim.api.nvim_create_buf(true, false)
vim.api.nvim_buf_set_name(implicit_first, vim.fs.joinpath(implicit_first_dir, "file.txt"))
vim.api.nvim_set_current_buf(implicit_first)
local implicit_local = assert(runtime.resolve())
assert_eq(
  assert(implicit_local:job_spec({
    command = { argv = { "sh" } },
    cwd = { space = "buffer" },
  })).cwd,
  implicit_first_dir
)
local implicit_second = vim.api.nvim_create_buf(true, false)
vim.api.nvim_buf_set_name(implicit_second, vim.fs.joinpath(implicit_second_dir, "file.txt"))
vim.api.nvim_set_current_buf(implicit_second)
local implicit_current, implicit_stale = implicit_local:is_current()
assert_eq(implicit_current, false, "implicit local context followed a different current buffer")
assert_eq(implicit_stale.code, "stale_context")

local explicit_buffer = vim.api.nvim_create_buf(true, false)
vim.api.nvim_buf_set_name(explicit_buffer, vim.fs.joinpath(explicit_first_dir, "file.txt"))
local explicit_buffer_local = assert(runtime.resolve({ authority = "local", bufnr = explicit_buffer }))
assert_eq(
  assert(explicit_buffer_local:job_spec({
    command = { argv = { "sh" } },
    cwd = { space = "buffer" },
  })).cwd,
  explicit_first_dir
)
vim.api.nvim_buf_set_name(explicit_buffer, vim.fs.joinpath(explicit_second_dir, "file.txt"))
local explicit_buffer_current, explicit_buffer_stale = explicit_buffer_local:is_current()
assert_eq(explicit_buffer_current, false, "explicit local context survived a selected-buffer rename")
assert_eq(explicit_buffer_stale.code, "stale_context")

vim.cmd("tcd " .. vim.fn.fnameescape(original_global_cwd))
assert_eq(vim.fn.delete(buffer_root, "rf"), 0)
vim.api.nvim_set_current_buf(plain)

local remote_buf = vim.api.nvim_create_buf(true, false)
vim.b[remote_buf].broker_remote = true
vim.b[remote_buf].broker_workspace_id = "remote-buffer"
vim.api.nvim_set_current_buf(remote_buf)
local remote_context = assert(runtime.resolve())
assert_eq(remote_context.provider, "nrm")
assert_eq(remote_context.workspace_id, "remote-buffer")
vim.b[remote_buf].broker_remote = false
local buffer_current, buffer_stale = remote_context:is_current()
assert_eq(buffer_current, false)
assert_eq(buffer_stale.code, "stale_context")
vim.b[remote_buf].broker_remote = true

-- An explicit zero buffer handle is canonicalized at resolution time rather
-- than following whatever buffer becomes current later.
vim.api.nvim_set_current_buf(remote_buf)
local zero_context = assert(runtime.resolve({ bufnr = 0 }))
local other_remote_buf = vim.api.nvim_create_buf(true, false)
vim.b[other_remote_buf].broker_remote = true
vim.b[other_remote_buf].broker_workspace_id = "remote-other"
vim.api.nvim_set_current_buf(other_remote_buf)
assert_eq(zero_context:is_current(), true)
vim.api.nvim_set_current_buf(remote_buf)

-- Explicit local is the escape hatch even for an NRM-owned buffer.
local forced_local = assert(runtime.resolve({ authority = "local", bufnr = remote_buf }))
assert_eq(forced_local.provider, "local")

-- A tab binding applies to plain buffers, but a remote buffer still wins.
local tab = vim.api.nvim_get_current_tabpage()
assert(runtime._bind_tab_context(tab, assert(workspace.resolve({ workspace_id = "remote-tab" }))))
assert_eq(forced_local:is_current(), true, "explicit local context was invalidated by a tab binding")
vim.api.nvim_set_current_buf(plain)
assert_eq(assert(runtime.resolve()).workspace_id, "remote-tab")
vim.api.nvim_set_current_buf(remote_buf)
assert_eq(assert(runtime.resolve()).workspace_id, "remote-buffer")

-- Clearing a tab does not relabel an NRM buffer; plain buffers become local.
assert(runtime.use_local(tab))
assert_eq(assert(runtime.resolve()).workspace_id, "remote-buffer")
vim.api.nvim_set_current_buf(plain)
assert_eq(assert(runtime.resolve()).provider, "local")

-- Tab bindings do not leak to another tab.
assert(runtime._bind_tab_context(tab, assert(workspace.resolve({ workspace_id = "remote-tab" }))))
vim.cmd("tabnew")
local second_tab = vim.api.nvim_get_current_tabpage()
local second_plain = vim.api.nvim_create_buf(true, false)
vim.api.nvim_set_current_buf(second_plain)
assert_eq(assert(runtime.resolve()).provider, "local")
vim.api.nvim_set_current_tabpage(tab)
vim.api.nvim_set_current_buf(plain)
assert_eq(assert(runtime.resolve()).workspace_id, "remote-tab")

-- A late successful connect cannot undo an explicit local selection.
local pending_token = assert(runtime._capture_binding_token(tab))
assert(runtime.use_local(tab))
assert_eq(runtime._bind_connected(pending_token), false)
assert_eq(runtime._binding_for_test(tab), nil)

-- An offline remote binding must fail closed instead of falling back local.
assert(runtime._bind_tab_context(tab, assert(workspace.resolve({ workspace_id = "remote-tab" }))))
remote_state = "offline"
local offline = assert(runtime.resolve())
assert_eq(offline.provider, "nrm")
local offline_callback = 0
assert(offline:prepare("terminal", function(err)
  offline_callback = offline_callback + 1
  assert_eq(err.code, "workspace_offline")
end))
assert_eq(offline_callback, 1)
remote_state = "online"

-- A tab authority change invalidates an asynchronous remote preparation even
-- when the superseded provider finishes with its own error.
readiness_state = "unchecked"
pending_prepare = nil
local async_context = assert(runtime.resolve())
local async_callback = 0
assert(async_context:prepare("terminal", function(err, prepared)
  async_callback = async_callback + 1
  assert_eq(prepared, nil)
  assert_eq(err.code, "stale_context")
end))
assert_eq(type(pending_prepare), "function")
assert(runtime.use_local(tab))
readiness_state = "ready"
pending_prepare(provider_error("probe_failed", "superseded readiness probe failed"))
assert_eq(async_callback, 1)

-- Authorization callbacks obey the same selection guard. A late provider
-- denial/error must not mask that the caller changed authority meanwhile.
assert(runtime._bind_tab_context(tab, assert(workspace.resolve({ workspace_id = "remote-tab" }))))
authorize_mode = "delayed"
trusted_state = false
pending_authorize = nil
local authorize_context = assert(runtime.resolve())
local authorize_callback = 0
assert(authorize_context:authorize("terminal", function(authorize_err, granted)
  authorize_callback = authorize_callback + 1
  assert_eq(granted, false)
  assert_eq(authorize_err.code, "stale_context")
end))
assert_eq(type(pending_authorize), "function")
assert(runtime.use_local(tab))
pending_authorize(provider_error("authorization_failed", "superseded authorization failed"), false)
assert_eq(authorize_callback, 1)
authorize_mode = "inline"
trusted_state = true

-- An implicit tab binding must also stale when the current buffer changes to
-- a different remote authority while readiness is pending.
assert(runtime._bind_tab_context(tab, assert(workspace.resolve({ workspace_id = "remote-tab" }))))
vim.api.nvim_set_current_buf(plain)
readiness_state = "unchecked"
pending_prepare = nil
local buffer_race_context = assert(runtime.resolve())
local buffer_race_callback = 0
assert(buffer_race_context:prepare("terminal", function(buffer_race_err, prepared)
  buffer_race_callback = buffer_race_callback + 1
  assert_eq(prepared, nil)
  assert_eq(buffer_race_err.code, "stale_context")
end))
vim.api.nvim_set_current_buf(remote_buf)
readiness_state = "ready"
pending_prepare(nil)
assert_eq(buffer_race_callback, 1)
vim.api.nvim_set_current_buf(plain)

-- Broker-owned bridge metadata follows the authority shell, not local Neovim.
local windows_provider = vim.deepcopy(provider)
windows_provider.resolve = function()
  return descriptor("windows-remote", "windows", "powershell")
end
workspace._set_backend(windows_provider)
local windows_context = assert(runtime.resolve({ authority = "remote" }))
local windows_bridge = assert(windows_context:job_spec({
  command = { shell = "default" },
  stdio = "pty",
}))
assert_eq(windows_bridge.input.newline, "\r")
assert_eq(windows_bridge.authority.path_style, "windows")

local value, err = runtime.resolve({ authority = "somewhere" })
assert_error(value, err, "invalid_argument")
value, err = runtime.resolve({ authority = false })
assert_error(value, err, "invalid_argument")
value, err = runtime.resolve({ authority = 1 })
assert_error(value, err, "invalid_argument")

-- The compatibility wrapper remains remote-only and keeps its global fallback.
workspace._set_backend(provider)
assert_eq(assert(nrm.workspace()).provider, "nrm")

vim.cmd("runtime plugin/nvim_remote_mirror.lua")
assert_eq(vim.fn.exists(":RemoteUseLocal"), 2)
vim.cmd("RemoteUseLocal")
assert_eq(runtime._binding_for_test(tab), nil)

vim.api.nvim_set_current_tabpage(second_tab)
vim.cmd("tabclose")
runtime._prune_closed_tabs()
assert_eq(runtime._binding_for_test(second_tab), nil)

runtime._reset_for_test()
workspace._reset_for_test()

local saved_client = nrm.client
local saved_status = nrm.connection_status
local saved_generation = nrm.reconnect_generation
nrm.client = nil
nrm.connection_status = "disconnected"
nrm.reconnect_generation = 19

-- The legacy workspace API may associate path-only hydration metadata with
-- the active connection, but the authority broker must not treat that global
-- connection as stable ownership of the buffer. Broker selection fails closed
-- until the buffer carries its own workspace identity.
nrm.client = {
  target_arg = "ssh://active.example/srv/demo",
  hello = {
    workspace_key = "active-workspace",
    files_root = "/tmp/nrm-active/files",
    mirror_root = "/tmp/nrm-active",
    remote_root = "/srv/demo",
    remote_host = { os = "linux", arch = "x86_64", path_style = "posix", shell = "sh" },
  },
  runtime_readiness = {
    contract_version = 2,
    support = { process = true, terminal = true, watch = false },
  },
}
nrm.connection_status = "connected"

for _, case in ipairs({
  { marker = "nrm_remote_path", path = "src/path-only.lua" },
  { marker = "nrm_hydrate_path", path = "src/hydrate-only.lua" },
}) do
  local path_only = vim.api.nvim_create_buf(true, false)
  vim.b[path_only][case.marker] = case.path
  assert_eq(assert(workspace.resolve({ bufnr = path_only })).workspace_id, "active-workspace")
  local broker_value, broker_err = runtime.resolve({ bufnr = path_only })
  assert_error(broker_value, broker_err, "workspace_not_found")
end

nrm.client = nil
nrm.connection_status = "disconnected"

-- Reserved NRM ownership evidence is authoritative. Incomplete or malformed
-- metadata must never be suppressed into a local-provider fallback.
local incomplete = vim.api.nvim_create_buf(true, false)
vim.b[incomplete].nrm_remote_path = "src/incomplete.lua"
local incomplete_value, incomplete_err = workspace.resolve({ bufnr = incomplete })
assert_error(incomplete_value, incomplete_err, "workspace_not_found")
incomplete_value, incomplete_err = runtime.resolve({ bufnr = incomplete })
assert_error(incomplete_value, incomplete_err, "workspace_not_found")

local malformed_marker = vim.api.nvim_create_buf(true, false)
vim.b[malformed_marker].nrm_workspace_key = 42
local malformed_value, malformed_err = workspace.resolve({ bufnr = malformed_marker })
assert_error(malformed_value, malformed_err, "invalid_provider_state")
malformed_value, malformed_err = runtime.resolve({ bufnr = malformed_marker })
assert_error(malformed_value, malformed_err, "invalid_provider_state")

-- An explicitly selected plain buffer is part of auto/remote authority
-- selection even when the initial result is local. If it gains malformed NRM
-- ownership while work is pending, the retained context must fail closed.
local explicit_plain = vim.api.nvim_create_buf(true, false)
local explicit_plain_context = assert(runtime.resolve({ bufnr = explicit_plain }))
assert_eq(explicit_plain_context.provider, "local")
local explicit_local_context = assert(runtime.resolve({ authority = "local", bufnr = explicit_plain }))
vim.b[explicit_plain].nrm_workspace_key = 42
local explicit_plain_current, explicit_plain_stale = explicit_plain_context:is_current()
assert_eq(explicit_plain_current, false)
assert_eq(explicit_plain_stale.code, "stale_context")
assert_eq(explicit_local_context:is_current(), true, "explicit local override followed remote buffer ownership")

local mutable_authority = vim.api.nvim_create_buf(true, false)
vim.b[mutable_authority].nrm_remote_path = "src/main.lua"
vim.b[mutable_authority].nrm_workspace_key = "stable-workspace-key"
vim.b[mutable_authority].nrm_target_arg = "ssh://first.example/srv/demo"
vim.b[mutable_authority].nrm_files_root = "/tmp/nrm-authority-first/files"
local authority_context = assert(runtime.resolve({ bufnr = mutable_authority }))
vim.b[mutable_authority].nrm_target_arg = "ssh://second.example/srv/demo"
vim.b[mutable_authority].nrm_files_root = "/tmp/nrm-authority-second/files"
local authority_current, authority_stale = authority_context:is_current()
assert_eq(authority_current, false, "buffer context survived a same-workspace authority mutation")
assert_eq(authority_stale.code, "stale_context")

vim.b[mutable_authority].nrm_target_arg = "ssh://first.example/srv/demo"
vim.b[mutable_authority].nrm_files_root = "/tmp/nrm-authority-first/files"
vim.b[mutable_authority].nrm_remote_path = "src/first.lua"
local path_context = assert(runtime.resolve({ bufnr = mutable_authority }))
vim.b[mutable_authority].nrm_remote_path = "other/second.lua"
local path_current, path_stale = path_context:is_current()
assert_eq(path_current, false, "buffer context survived a same-workspace path mutation")
assert_eq(path_stale.code, "stale_context")

-- Production tab bindings retain identity across disconnect and re-resolve as
-- offline contexts at the current NRM epoch.
nrm.client = {
  target_arg = "ssh://host.example/srv/demo",
  hello = {
    workspace_key = "captured-remote",
    files_root = "/tmp/nrm-captured/files",
    mirror_root = "/tmp/nrm-captured",
    remote_root = "/srv/demo",
    remote_host = { os = "linux", arch = "x86_64", path_style = "posix", shell = "sh" },
  },
  runtime_readiness = {
    contract_version = 2,
    support = { process = true, terminal = true, watch = false },
  },
}
nrm.connection_status = "connected"
nrm.reconnect_generation = 20
local captured_identity = assert(workspace._capture_active_identity())
assert_eq(assert(workspace._resolve_captured_identity(captured_identity)).state, "online")
nrm.client = nil
nrm.connection_status = "disconnected"
nrm.reconnect_generation = 21
local captured_offline = assert(workspace._resolve_captured_identity(captured_identity))
assert_eq(captured_offline.state, "offline")
assert_eq(captured_offline.epoch, 21)
local captured_callback = 0
assert(captured_offline:prepare("terminal", function(captured_err)
  captured_callback = captured_callback + 1
  assert_eq(captured_err.code, "workspace_offline")
end))
assert_eq(captured_callback, 1)
nrm.client = saved_client
nrm.connection_status = saved_status
nrm.reconnect_generation = saved_generation

print("workspace runtime broker tests: ok")
