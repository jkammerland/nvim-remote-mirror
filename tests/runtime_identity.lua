vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")
local runtime = require("nvim_remote_mirror.runtime")
local workspace = require("nvim_remote_mirror.workspace")

local function assert_eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function assert_error(value, err, code)
  assert_eq(value, nil, "operation unexpectedly succeeded")
  assert_eq(type(err), "table")
  assert_eq(err.code, code)
  return err
end

local function helper_value(argv, name)
  for index = 1, #argv - 1 do
    if argv[index] == name then
      return argv[index + 1]
    end
  end
  return nil
end

local function snapshot(runtime_config)
  return {
    authority = {
      id = "captured-authority",
      kind = "ssh",
      path_style = "posix",
      shell = "/bin/sh",
    },
    roots = { authority = "/srv/captured-workspace" },
    _runtime_config = runtime_config,
  }
end

local function main()
  runtime._reset_for_test()

  local captured_sidecar = vim.fn.fnamemodify(vim.fn.tempname() .. " Captured Sidecar", ":p")
  local captured_state = vim.fn.tempname() .. "-captured-state"
  local live_sidecar = vim.fn.fnamemodify(vim.fn.tempname() .. " Live Sidecar", ":p")
  local live_state = vim.fn.tempname() .. "-live-state"
  local captured = snapshot({
    sidecar = captured_sidecar,
    agent = "nrm-agent-a",
    remote_agent = "nrm-agent-a",
    state_dir = captured_state,
    request_timeout_ms = 30000,
    ssh_connect_timeout_seconds = 10,
  })

  nrm.setup({
    sidecar = live_sidecar,
    state_dir = live_state,
    remote_runtime = {
      enabled = true,
      trust = "prompt",
      detached_ttl_ms = 86400000,
      ticket_create_timeout_ms = 3456,
    },
  })

  local calls = {}
  runtime._set_command_runner(function(argv, stdin, timeout_ms)
    table.insert(calls, { argv = vim.deepcopy(argv), stdin = stdin, timeout_ms = timeout_ms })
    if argv[2] == "runtime-state-prepare" then
      return { code = 0, stdout = "", stderr = "" }
    end
    if argv[2] == "runtime-trust-check" then
      return { code = 0, stdout = "untrusted\n", stderr = "" }
    end
    return { code = 0, stdout = "", stderr = "" }
  end)

  assert_eq(runtime.is_trusted(captured), false)
  assert_eq(#calls, 2)
  for _, call in ipairs(calls) do
    assert_eq(call.argv[1], captured_sidecar, "trust helper ignored the connection's captured sidecar")
    assert_eq(
      helper_value(call.argv, "--state-dir"),
      captured_state,
      "trust helper ignored the connection's captured state directory"
    )
  end

  calls = {}
  assert(runtime.trust_workspace({ context = captured, force = true }))
  assert_eq(#calls, 2)
  assert_eq(calls[1].argv[1], captured_sidecar)
  assert_eq(calls[2].argv[1], captured_sidecar)
  assert_eq(calls[2].argv[2], "runtime-trust-add")
  assert_eq(helper_value(calls[2].argv, "--state-dir"), captured_state)

  nrm.connection_status = "connected"
  nrm.reconnect_generation = 17
  nrm.connection_target = "ssh://captured.example.test/srv/captured-workspace"
  nrm.client = {
    target_arg = nrm.connection_target,
    runtime_config = vim.deepcopy(captured._runtime_config),
    hello = {
      workspace_key = "captured-workspace",
      files_root = vim.fn.fnamemodify(vim.fn.tempname() .. "-mirror", ":p"),
      mirror_root = vim.fn.fnamemodify(vim.fn.tempname() .. "-mirror-root", ":p"),
      remote_root = "/srv/captured-workspace",
      remote_host = { path_style = "posix" },
      capabilities = {},
    },
  }
  local context = assert(workspace.resolve())
  nrm.setup({
    sidecar = live_sidecar,
    state_dir = live_state,
    remote_runtime = { enabled = true, trust = "prompt" },
  })
  calls = {}
  assert_eq(runtime.is_trusted(context), false)
  assert_eq(calls[1].argv[1], captured_sidecar, "direct trust check lost its captured sidecar identity")
  assert_eq(helper_value(calls[2].argv, "--state-dir"), captured_state)
  calls = {}
  local original_confirm = vim.fn.confirm
  vim.fn.confirm = function()
    return 1
  end
  local authorization_error
  local authorization_granted
  runtime.authorize(context, "terminal", function(authorize_err, granted)
    authorization_error = authorize_err
    authorization_granted = granted
  end)
  vim.fn.confirm = original_confirm
  assert_eq(authorization_error, nil)
  assert_eq(authorization_granted, true)
  assert_eq(#calls, 4)
  for _, call in ipairs(calls) do
    assert_eq(call.argv[1], captured_sidecar, "direct authorization lost its captured sidecar identity")
    assert_eq(helper_value(call.argv, "--state-dir"), captured_state)
  end
  calls = {}
  assert(runtime.trust_workspace({ context = context, force = true }))
  assert_eq(calls[1].argv[1], captured_sidecar, "public context lost its captured sidecar identity")
  assert_eq(helper_value(calls[1].argv, "--state-dir"), captured_state)
  assert_eq(calls[2].argv[1], captured_sidecar)
  assert_eq(helper_value(calls[2].argv, "--state-dir"), captured_state)
  calls = {}
  assert(runtime.untrust_workspace({ context = context }))
  assert_eq(calls[1].argv[1], captured_sidecar, "untrust used a later live sidecar")
  assert_eq(helper_value(calls[2].argv, "--state-dir"), captured_state)

  local captured_default_state = snapshot({
    sidecar = captured_sidecar,
    agent = "nrm-agent-a",
    remote_agent = "nrm-agent-a",
    request_timeout_ms = 30000,
    ssh_connect_timeout_seconds = 10,
  })
  calls = {}
  assert_eq(runtime.is_trusted(captured_default_state), false)
  assert_eq(
    helper_value(calls[1].argv, "--state-dir"),
    vim.fs.joinpath(vim.fn.stdpath("state"), "nvim-remote-mirror"),
    "captured default state directory fell back to a later live state directory"
  )

  local value, err = runtime.trust_workspace(false)
  assert_error(value, err, "invalid_argument")
  value, err = runtime.untrust_workspace(false)
  assert_error(value, err, "invalid_argument")
  value, err = runtime.trust_workspace({ query = false, force = true })
  assert_error(value, err, "invalid_argument")

  calls = {}
  local offline = snapshot(nil)
  assert_eq(runtime.is_trusted(offline), false)
  assert_eq(#calls, 2)
  for _, call in ipairs(calls) do
    assert_eq(call.argv[1], live_sidecar, "offline trust helper did not use live configuration")
    assert_eq(helper_value(call.argv, "--state-dir"), live_state)
  end

  local bare = vim.fn.fnamemodify(vim.v.progpath, ":t")
  local resolved = vim.fn.exepath(bare)
  assert(resolved ~= "", "test requires Neovim to be discoverable on PATH")
  nrm.setup({
    sidecar = bare,
    state_dir = live_state,
    remote_runtime = { enabled = true, trust = "prompt" },
  })
  calls = {}
  assert_eq(runtime.is_trusted(offline), false)
  assert_eq(calls[1].argv[1], resolved, "bare sidecar name was not pinned to its resolved executable")
  assert_eq(calls[2].argv[1], resolved, "trust check used a different sidecar identity than state preparation")

  local false_sidecar = snapshot(vim.tbl_extend("force", vim.deepcopy(captured._runtime_config), { sidecar = false }))
  calls = {}
  value, err = runtime.is_trusted(false_sidecar)
  err = assert_error(value, err, "trust_store_error")
  assert_eq(err.details.reason, "invalid_executable")
  assert_eq(#calls, 0, "false captured sidecar fell back to live configuration")

  for _, invalid_config in ipairs({ false, "corrupt" }) do
    local invalid_runtime_config = snapshot(nil)
    invalid_runtime_config._runtime_config = invalid_config
    calls = {}
    value, err = runtime.is_trusted(invalid_runtime_config)
    assert_error(value, err, "trust_store_error")
    assert_eq(#calls, 0, "invalid captured runtime config fell back to live configuration")
  end

  local false_state = snapshot(vim.tbl_extend("force", vim.deepcopy(captured._runtime_config), { state_dir = false }))
  value, err = runtime.is_trusted(false_state)
  err = assert_error(value, err, "trust_store_error")
  assert_eq(err.details.reason, "invalid_state_directory")
  assert_eq(#calls, 0, "false captured state directory fell back to live configuration")

  nrm.setup({
    sidecar = "./nrm-sidecar",
    state_dir = live_state,
    remote_runtime = { enabled = true, trust = "prompt" },
  })
  calls = {}
  value, err = runtime.is_trusted(offline)
  err = assert_error(value, err, "trust_store_error")
  assert_eq(err.details.reason, "invalid_executable")
  assert_eq(#calls, 0, "unsafe relative sidecar was invoked before trust authorization")

  runtime._reset_for_test()
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(tostring(err))
  vim.cmd("cquit")
end
vim.cmd("qa")
