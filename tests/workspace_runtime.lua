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

local function assert_call_error(callback, code)
  local value, err = callback()
  return assert_error(value, err, code)
end

local function assert_throws(callback, needle)
  local ok, err = pcall(callback)
  assert_eq(ok, false, "operation unexpectedly succeeded")
  if not tostring(err):find(needle, 1, true) then
    error("expected " .. vim.inspect(err) .. " to contain " .. vim.inspect(needle))
  end
end

local function online_descriptor()
  return {
    provider = "nrm",
    workspace_id = "workspace-runtime",
    epoch = 4,
    state = "online",
    mode = "mirror",
    authority = {
      id = "authority-runtime",
      kind = "ssh",
      path_style = "windows",
      os = "windows",
      arch = "aarch64",
      shell = "powershell",
      target = "aarch64-pc-windows-msvc",
    },
    roots = {
      editor = "/mirror/runtime/files",
      authority = "B:/repos/runtime",
    },
    capabilities = {
      runtime_process_v1 = true,
      runtime_pty_v1 = true,
      workspace_watch_v1 = true,
    },
    relative_path = "src/module/main.lua",
  }
end

local function test_offline_resolution_and_paths()
  workspace._reset_for_test()
  assert_call_error(function()
    return workspace.resolve(false)
  end, "invalid_argument")
  local old_client = nrm.client
  local old_status = nrm.connection_status
  local old_generation = nrm.reconnect_generation
  nrm.client = nil
  nrm.connection_status = "disconnected"
  nrm.reconnect_generation = 11

  local bufnr = vim.api.nvim_create_buf(true, false)
  vim.b[bufnr].nrm_remote_path = "src/a b#c.lua"
  vim.b[bufnr].nrm_workspace_key = "workspace-offline"
  vim.b[bufnr].nrm_target_arg = "ssh://build.example.test/B:/repos/demo"
  vim.b[bufnr].nrm_files_root = "/mirror/demo/files"

  local context, err = workspace.resolve({ bufnr = bufnr })
  assert_eq(err, nil)
  assert_eq(context.api_version, 1)
  assert_eq(context.provider, "nrm")
  assert_eq(context.workspace_id, "workspace-offline")
  assert_eq(context.epoch, 11)
  assert_eq(context.state, "offline")
  assert_eq(context.mode, "mirror")
  assert_eq(context.authority.kind, "ssh")
  assert_eq(context.authority.path_style, "windows")
  assert_eq(context.roots.editor, "/mirror/demo/files")
  assert_eq(context.roots.authority, "B:/repos/demo")

  assert_throws(function()
    context.state = "online"
  end, "immutable")
  local authority = context.authority
  authority.kind = "local"
  assert_eq(context.authority.kind, "ssh", "nested context data leaked mutable state")

  assert_eq(
    context:map_path("/mirror/demo/files/src/a b#c.lua", { from = "editor", to = "authority" }),
    "B:/repos/demo/src/a b#c.lua"
  )
  assert_eq(
    context:map_path("/mirror/demo/files/src/a b#c.lua", { from = "editor", to = "authority_uri" }),
    "file:///B:/repos/demo/src/a%20b%23c.lua"
  )
  assert_eq(
    context:map_path("file:///B:/repos/demo/src/a%20b%23c.lua", { from = "authority_uri", to = "editor" }),
    "/mirror/demo/files/src/a b#c.lua"
  )
  assert_eq(
    context:map_path("B:\\repos\\demo\\src\\main.lua", { from = "authority", to = "editor_uri" }),
    "file:///mirror/demo/files/src/main.lua"
  )

  assert_call_error(function()
    return context:map_path("/mirror/other/main.lua", { from = "editor", to = "authority" })
  end, "invalid_path")
  assert_call_error(function()
    return context:map_path("file://server/share/a.lua", { from = "authority_uri", to = "editor" })
  end, "invalid_path")
  assert_call_error(function()
    return context:map_path("file:///B:/repos/demo/%GG", { from = "authority_uri", to = "editor" })
  end, "invalid_path")
  assert_call_error(function()
    return context:map_path("B:/repos/demo/../../../outside", { from = "authority", to = "editor" })
  end, "invalid_path")

  local callback_err
  local authorized, authorize_err = context:authorize("process", function(auth_err, granted)
    callback_err = auth_err
    assert_eq(granted, false)
  end)
  assert_error(authorized, authorize_err, "workspace_offline")
  assert_eq(callback_err.code, "workspace_offline")

  local plain = vim.api.nvim_create_buf(true, false)
  assert_call_error(function()
    return workspace.resolve({ bufnr = plain })
  end, "not_remote_buffer")
  assert_call_error(function()
    return workspace.resolve({ bufnr = -1 })
  end, "invalid_argument")
  assert_call_error(function()
    return workspace.resolve({ bufnr = bufnr, path = "/mirror/demo/files/src/a.lua" })
  end, "invalid_argument")
  local malformed = vim.api.nvim_create_buf(true, false)
  vim.b[malformed].nrm_remote_path = "src/main.lua"
  vim.b[malformed].nrm_target_arg = "ssh://-oProxyCommand=bad/repo"
  vim.b[malformed].nrm_files_root = "/mirror/demo/files"
  assert_call_error(function()
    return workspace.resolve({ bufnr = malformed })
  end, "invalid_provider_state")

  nrm.client = {
    job_id = 1,
    target_arg = "ssh://build.example.test/B:/repos/demo",
    hello = {
      workspace_key = "workspace-offline",
      remote_root = "B:/repos/demo",
      mirror_root = "/mirror/demo",
      files_root = "/mirror/demo/files",
      remote_host = {
        os = "windows",
        arch = "aarch64",
        shell = "powershell",
        path_style = "windows",
        target = "aarch64-pc-windows-msvc",
      },
      capabilities = { runtime_process_v1 = true },
    },
  }
  nrm.connection_status = "connected"
  local connected = assert(workspace.resolve({ path = "/mirror/demo/files/src/main.lua" }))
  assert_eq(connected.state, "online")
  assert_eq(connected.authority.os, "windows")
  assert_eq(connected.capabilities.runtime_process_v1, true)

  nrm.client = old_client
  nrm.connection_status = old_status
  nrm.reconnect_generation = old_generation
end

local function test_process_contract()
  workspace._reset_for_test()
  local epoch = 4
  local state = "online"
  local is_trusted = false
  local descriptor = online_descriptor()
  local captured_request
  local captured_spawn
  local handle_calls = {}
  local backend = {
    resolve = function()
      return descriptor
    end,
    current_epoch = function(snapshot)
      snapshot.roots.authority = "B:/mutated-by-current-epoch"
      return epoch
    end,
    current_state = function()
      return state
    end,
    is_trusted = function(_, capability)
      assert_eq(capability == "process" or capability == "terminal", true)
      return is_trusted
    end,
    authorize = function(_, capability, callback)
      assert_eq(capability, "process")
      is_trusted = true
      callback(nil, true)
    end,
    job_spec = function(_, request)
      captured_request = request
      local argv = { "/opt/NRM Sidecar/nrm-sidecar", "runtime-bridge", "--ticket", "/run/nrm/ticket-opaque" }
      return {
        argv = argv,
        command = "'/opt/NRM Sidecar/nrm-sidecar' 'runtime-bridge' '--ticket' '/run/nrm/ticket-opaque'",
        cwd = "/mirror/runtime/files",
      }
    end,
    spawn = function(snapshot, request, handlers)
      snapshot.roots.authority = "B:/mutated-by-provider"
      captured_spawn = { request = request, handlers = handlers }
      local handle = {
        attachment_token = "must-not-be-public",
        write = function(_, data)
          if data == "explode" then
            error("provider write exploded")
          end
          handle_calls.write = data
        end,
        close_stdin = function()
          handle_calls.close_stdin = true
        end,
        signal = function(_, signal)
          handle_calls.signal = signal
        end,
        kill = function()
          handle_calls.kill = true
        end,
        resize = function(_, size)
          handle_calls.resize = size
        end,
      }
      if request.persistence == "detached" then
        handle.session_id = "opaque-session"
        handle.detach = function()
          handle_calls.detach = true
        end
      end
      return handle
    end,
  }
  workspace._set_backend(backend)

  local context = assert(workspace.resolve({ workspace_id = "workspace-runtime" }))
  assert_eq(context.authority.target, "aarch64-pc-windows-msvc")

  local callback_called = false
  assert_eq(
    context:authorize("process", function(err, granted)
      assert_eq(err, nil)
      assert_eq(granted, true)
      callback_called = true
    end),
    true
  )
  assert_eq(callback_called, true)

  local bridge, err = context:job_spec({
    command = { argv = { "printf", "%s", "$(must-not-run)" } },
    cwd = { space = "buffer" },
    env = {
      set = { LANG = "C.UTF-8", NRM_SECRET = "do-not-leak;$(remote)" },
      unset = { "PAGER", "EDITOR" },
      clear = true,
    },
    stdio = "pty",
    persistence = "detached",
    timeout_ms = 3000,
    initial_size = {
      cols = 132,
      rows = 40,
      pixel_width = 1200,
      pixel_height = 800,
    },
  })
  assert_eq(err, nil)
  assert_eq(bridge.argv[4], "/run/nrm/ticket-opaque")
  assert_eq(bridge.command, "'/opt/NRM Sidecar/nrm-sidecar' 'runtime-bridge' '--ticket' '/run/nrm/ticket-opaque'")
  assert_eq(bridge.cwd, "/mirror/runtime/files")
  assert_eq(bridge.env, nil)
  assert_eq(bridge.command:find("$(must-not-run)", 1, true), nil)
  assert_eq(bridge.command:find("do-not-leak", 1, true), nil)
  assert_eq(captured_request.command.argv[3], "$(must-not-run)")
  assert_eq(captured_request.cwd.path, "src/module")
  assert_eq(captured_request.env.clear, true)
  assert_eq(captured_request.env.set.LANG, "C.UTF-8")
  assert_eq(captured_request.env.set.NRM_SECRET, "do-not-leak;$(remote)")
  assert_eq(captured_request.env.unset[1], "EDITOR")
  assert_eq(captured_request.env.unset[2], "PAGER")
  assert_eq(captured_request.stdio, "pty")
  assert_eq(captured_request.persistence, "detached")
  assert_eq(captured_request.initial_size.cols, 132)
  assert_eq(captured_request.max_output_bytes, nil)
  assert_eq(captured_request.timeout_ms, 3000)

  bridge = assert(context:job_spec({
    command = { shell = "default" },
    cwd = { space = "authority", path = "B:\\repos\\runtime\\tools" },
  }))
  assert_eq(captured_request.command.shell, "default")
  assert_eq(captured_request.cwd.path, "tools")
  assert_eq(captured_request.stdio, "pipe")
  assert_eq(captured_request.persistence, "attached")
  assert_eq(captured_request.initial_size, nil)
  assert_eq(bridge.argv[1], "/opt/NRM Sidecar/nrm-sidecar")

  local handle = assert(context:open_pty({
    command = { shell = "default" },
    cwd = { space = "workspace", path = "" },
  }, {
    on_exit = function() end,
  }))
  assert_eq(handle.session_id, nil)
  assert_eq(handle.attachment_token, nil)
  assert_eq(handle.detach, nil)
  assert_eq(captured_spawn.request.stdio, "pty")
  assert_eq(captured_spawn.request.initial_size.cols, 80)
  assert_eq(captured_spawn.request.initial_size.pixel_width, nil)
  assert_eq(type(captured_spawn.handlers.on_exit), "function")
  assert_eq(context.roots.authority, "B:/repos/runtime", "provider mutated its context snapshot")
  handle:write("input")
  handle:resize({ cols = 90, rows = 30 })
  assert_eq(handle_calls.write, "input")
  assert_eq(handle_calls.resize.cols, 90)
  assert_call_error(function()
    return handle:write("explode")
  end, "provider_error")
  assert_call_error(function()
    return context:open_pty({ command = { shell = "default" } }, { on_ouptut = function() end })
  end, "invalid_argument")

  local detached = assert(context:open_pty({
    command = { shell = "default" },
    persistence = "detached",
  }))
  assert_eq(detached.session_id, "opaque-session")
  assert_eq(type(detached.detach), "function")
  assert_eq(detached.attachment_token, nil)
  detached:detach()
  assert_eq(handle_calls.detach, true)

  descriptor.authority.kind = "mutated"
  descriptor.roots.authority = "B:/mutated-after-resolve"
  backend.current_epoch = function()
    return 999
  end
  backend.job_spec = function()
    error("mutated backend must not replace a bound context callback")
  end
  workspace._set_backend({
    current_epoch = function()
      return 999
    end,
  })
  assert(context:job_spec({ command = { argv = { "true" } } }))
  assert_eq(context.authority.kind, "ssh")
  assert_eq(context.roots.authority, "B:/repos/runtime")

  assert_call_error(function()
    return context:job_spec({ command = { shell = "echo unsafe" } })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "git" }, shell = "default" } })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({ command = { argv = {} } })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "git" } },
      cwd = { space = "workspace", path = "../../outside" },
    })
  end, "invalid_path")
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "cmd.exe" } },
      env = { set = { Path = "one" }, unset = { "PATH" } },
    })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "git" } }, initial_size = { cols = 80 } })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "git" } }, persistence = "detached" })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "git" } }, env = false })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "git" } }, persistence = false })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "git" } }, stdio = "pty", initial_size = false })
  end, "invalid_process_spec")
  for _, false_option in ipairs({
    { env = { set = false } },
    { env = { unset = false } },
    { stdio = false },
    { max_output_bytes = false },
    { stdio = "pty", initial_size = { cols = false } },
    { stdio = "pty", initial_size = { rows = false } },
  }) do
    false_option.command = { argv = { "git" } }
    assert_call_error(function()
      return context:job_spec(false_option)
    end, "invalid_process_spec")
  end
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "git" } },
      stdio = "pty",
      initial_size = { rows = 0 },
    })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "git" } }, unexpected = true })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({ command = { argv = { string.char(0xff) } } })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "git" } },
      cwd = { space = "workspace", path = "src/" .. string.char(0xc0, 0xaf) },
    })
  end, "invalid_path")
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "git" } },
      env = { set = { NRM_BAD_UTF8 = string.char(0xed, 0xa0, 0x80) } },
    })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "git" } },
      cwd = { space = "workspace", path = "src/stream:metadata" },
    })
  end, "invalid_path")
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "git" } },
      cwd = { space = "workspace", path = "src/CON.txt" },
    })
  end, "invalid_path")
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "git" } },
      cwd = { space = "workspace", path = "src/trailing." },
    })
  end, "invalid_path")
  for _, invalid_windows_cwd in ipairs({
    "C:relative",
    "C:/absolute",
    "//server/share",
    "\\\\server\\share",
    "src/name::$DATA",
    "src/trailing ",
    "src/CONIN$",
    "src/COM¹.txt",
  }) do
    assert_call_error(function()
      return context:job_spec({
        command = { argv = { "git" } },
        cwd = { space = "workspace", path = invalid_windows_cwd },
      })
    end, "invalid_path")
  end
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "git" } },
      cwd = { space = "authority", path = "B:drive-relative" },
    })
  end, "invalid_path")
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "git" } },
      cwd = { space = "workspace", path = string.rep("a", 16 * 1024 + 1) },
    })
  end, "invalid_path")
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "git" } },
      stdio = "pty",
      initial_size = { pixel_width = 800 },
    })
  end, "invalid_process_spec")
  local maximum_terminal = assert(context:job_spec({
    command = { argv = { "true" } },
    stdio = "pty",
    initial_size = {
      cols = 32767,
      rows = 32767,
      pixel_width = 65535,
      pixel_height = 65535,
    },
  }))
  assert_eq(maximum_terminal.argv[1], "/opt/NRM Sidecar/nrm-sidecar")
  assert_eq(captured_request.initial_size.cols, 32767)
  assert_eq(captured_request.initial_size.pixel_width, 65535)
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "true" } },
      stdio = "pty",
      initial_size = { cols = 32768, rows = 24 },
    })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "true" } },
      stdio = "pty",
      initial_size = { cols = 80, rows = 24, pixel_width = 65536, pixel_height = 1 },
    })
  end, "invalid_process_spec")
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "true" } },
      stdio = "pty",
      max_output_bytes = 1024,
    })
  end, "invalid_process_spec")
  for _, argument in ipairs({ "line\nfeed", "tab\tvalue", "c1\194\133value" }) do
    assert_call_error(function()
      return context:job_spec({ command = { argv = { "printf", argument } } })
    end, "invalid_process_spec")
  end

  local maximum_argv = {}
  for index = 1, 1024 do
    maximum_argv[index] = index == 1 and "true" or "x"
  end
  assert(context:job_spec({ command = { argv = maximum_argv } }))
  maximum_argv[1025] = "x"
  assert_call_error(function()
    return context:job_spec({ command = { argv = maximum_argv } })
  end, "invalid_process_spec")

  assert(context:job_spec({ command = { argv = { "true" } }, max_output_bytes = 128 * 1024 * 1024 }))
  assert_call_error(function()
    return context:job_spec({
      command = { argv = { "true" } },
      max_output_bytes = 128 * 1024 * 1024 + 1,
    })
  end, "invalid_process_spec")

  local maximum_env = {}
  for index = 1, 2048 do
    maximum_env["NRM_LIMIT_" .. index] = "x"
  end
  assert(context:job_spec({ command = { argv = { "true" } }, env = { set = maximum_env } }))
  maximum_env.NRM_LIMIT_OVERFLOW = "x"
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "true" } }, env = { set = maximum_env } })
  end, "invalid_process_spec")

  is_trusted = false
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "git" } } })
  end, "workspace_untrusted")
  is_trusted = true
  state = "offline"
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "git" } } })
  end, "workspace_offline")
  state = "online"
  epoch = 5
  local current, stale_err = context:is_current()
  assert_eq(current, false)
  assert_eq(stale_err.code, "stale_context")
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "git" } } })
  end, "stale_context")

  workspace._reset_for_test()
end

local function test_capabilities_and_provider_failures()
  workspace._reset_for_test()
  local descriptor = online_descriptor()
  descriptor.capabilities.runtime_pty_v1 = false
  local provider = {
    resolve = function()
      return descriptor
    end,
    current_epoch = function()
      return 4
    end,
    current_state = function()
      return "online"
    end,
    is_trusted = function()
      return true
    end,
    job_spec = function()
      return { argv = { "" } }
    end,
  }
  local function resolve_provider()
    workspace._set_backend(provider)
    return assert(workspace.resolve())
  end

  local context = resolve_provider()
  assert_call_error(function()
    return context:job_spec({ command = { shell = "default" }, stdio = "pty" })
  end, "unsupported")
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "true" } } })
  end, "provider_error")

  provider.job_spec = function()
    return nil, "raw provider failure"
  end
  context = resolve_provider()
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "true" } } })
  end, "provider_error")
  provider.job_spec = function()
    return nil, { code = "ticket_expired", message = "runtime ticket expired" }
  end
  context = resolve_provider()
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "true" } } })
  end, "ticket_expired")
  provider.job_spec = function()
    return { argv = { "nrm-sidecar" }, command = "bad\ncommand" }
  end
  context = resolve_provider()
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "true" } } })
  end, "provider_error")
  provider.job_spec = function()
    return { argv = { "nrm-sidecar", string.char(0xff) } }
  end
  context = resolve_provider()
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "true" } } })
  end, "provider_error")
  provider.job_spec = function()
    return { argv = { "nrm-sidecar" }, env = { NRM_REMOTE_TOKEN = "must-not-leak" } }
  end
  context = resolve_provider()
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "true" } } })
  end, "provider_error")

  local metachar_argv = {
    "/opt/Sidecar Builds/nrm-sidecar",
    "runtime-proxy",
    "--ticket",
    "/tmp/opaque '$(ticket); never execute",
  }
  local metachar_command = table.concat(
    vim.tbl_map(function(argument)
      return vim.fn.shellescape(argument, 1)
    end, metachar_argv),
    " "
  )
  provider.job_spec = function(_, request)
    assert_eq(request.command.argv[2], "$(remote-command)")
    return { argv = metachar_argv, command = metachar_command, env = {} }
  end
  context = resolve_provider()
  local metachar_bridge = assert(context:job_spec({
    command = { argv = { "printf", "$(remote-command)" } },
    env = { set = { NRM_SECRET = "remote-secret" } },
  }))
  assert_eq(metachar_bridge.command, metachar_command)
  assert_eq(metachar_bridge.command:find("remote-command", 1, true), nil)
  assert_eq(metachar_bridge.command:find("remote-secret", 1, true), nil)
  metachar_argv[1] = "mutated-after-return"
  assert_eq(metachar_bridge.argv[1], "/opt/Sidecar Builds/nrm-sidecar")

  provider.job_spec = function()
    return nil, setmetatable({}, {
      __tostring = function()
        error("hostile tostring")
      end,
    })
  end
  context = resolve_provider()
  assert_call_error(function()
    return context:job_spec({ command = { argv = { "true" } } })
  end, "provider_error")

  provider.spawn = function()
    return { write = function() end }
  end
  context = resolve_provider()
  assert_call_error(function()
    return context:spawn({ command = { argv = { "true" } } })
  end, "provider_error")
  provider.spawn = function()
    return {
      session_id = "session-on-attached-process",
      write = function() end,
      close_stdin = function() end,
      signal = function() end,
      kill = function() end,
    }
  end
  context = resolve_provider()
  assert_call_error(function()
    return context:spawn({ command = { argv = { "true" } } })
  end, "provider_error")
  assert_call_error(function()
    return context:spawn({ command = { argv = { "true" } } }, { on_exit = "not-a-function" })
  end, "invalid_argument")
  assert_call_error(function()
    return context:spawn({ command = { argv = { "true" } } }, { on_typo = function() end })
  end, "invalid_argument")

  provider.is_trusted = function()
    return false
  end
  provider.authorize = function(_, _, callback)
    callback("raw authorization failure", false)
  end
  context = resolve_provider()
  local authorization_error
  context:authorize("process", function(auth_err, granted)
    authorization_error = auth_err
    assert_eq(granted, false)
  end)
  assert_eq(authorization_error.code, "provider_error")
  local authorized, err = context:authorize("unknown", function() end)
  assert_error(authorized, err, "invalid_argument")

  workspace._set_backend({
    resolve = function()
      return online_descriptor()
    end,
    job_spec = "not-a-function",
  })
  assert_call_error(function()
    return workspace.resolve()
  end, "provider_error")

  workspace._set_backend({
    resolve = function()
      local invalid_descriptor = online_descriptor()
      invalid_descriptor.capabilities = false
      return invalid_descriptor
    end,
  })
  assert_call_error(function()
    return workspace.resolve()
  end, "invalid_provider_state")
  workspace._reset_for_test()
end

local function main()
  test_offline_resolution_and_paths()
  test_process_contract()
  test_capabilities_and_provider_failures()
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
