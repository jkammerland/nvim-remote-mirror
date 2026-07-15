vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")

local KEY = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
local SOCKET_DIRECTORY = "/tmp/nrm-reconnect-transport"
local SOCKET_PATH = SOCKET_DIRECTORY .. "/sidecar.sock"
local SKIP_REASON = "automatic agent bootstrap is disabled for an explicit socket_path; use a derived socket path"

local function assert_eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local original_sockconnect = vim.fn.sockconnect
local original_jobstart = vim.fn.jobstart
local original_chansend = vim.fn.chansend
local original_chanclose = vim.fn.chanclose
local original_notify = vim.notify
local original_defer_fn = vim.defer_fn
local uv = vim.uv or vim.loop
local original_fs_lstat = uv.fs_lstat
local original_fs_realpath = uv.fs_realpath
local original_os_getuid = uv.os_getuid
local original_os_get_passwd = uv.os_get_passwd

local function main()
  nrm.setup({
    connection = "stdio",
    socket_path = SOCKET_PATH,
    auto_reconnect = true,
    reconnect_delay_ms = 1,
    reconnect_max_attempts = 3,
    reconnect_stable_ms = 1,
    background_mirror = false,
    recover_local_edits_on_connect = false,
    flush_queue_on_connect = false,
    remote_agent_auto_install = true,
    remote_agent_install_path = "/opt/nrm/bin/nrm-agent",
    remote_agent_registry_url = "file:///tmp/releases/v{version}/nrm-agent-manifest-v1.json",
    remote_agent_registry_public_keys = { ["release-a"] = KEY },
    remote_agent_registry_signature_threshold = 1,
  })

  local next_channel = 80
  local socket_options = {}
  local sent_methods = {}
  local closed_channels = {}
  local jobstart_calls = 0

  vim.notify = function() end
  vim.defer_fn = function(callback)
    callback()
  end
  uv.os_getuid = function()
    return 1000
  end
  uv.os_get_passwd = function()
    return { uid = 1000 }
  end
  uv.fs_lstat = function(path)
    if path == SOCKET_DIRECTORY then
      return { type = "directory", uid = 1000, mode = 448 }
    end
    if path == SOCKET_PATH then
      return { type = "socket", uid = 1000, mode = 384 }
    end
    return original_fs_lstat(path)
  end
  uv.fs_realpath = function(path)
    if path == SOCKET_DIRECTORY then
      return path
    end
    return original_fs_realpath(path)
  end
  vim.fn.sockconnect = function(mode, path, opts)
    assert_eq(mode, "pipe")
    assert_eq(path, SOCKET_PATH)
    next_channel = next_channel + 1
    socket_options[next_channel] = opts
    return next_channel
  end
  vim.fn.jobstart = function()
    jobstart_calls = jobstart_calls + 1
    error("per-call socket transport changed to stdio or tried to start a socket daemon")
  end
  vim.fn.chansend = function(channel, payload)
    local request = vim.json.decode(payload)
    table.insert(sent_methods, request.method)
    if request.method == "workspace_info" then
      socket_options[channel].on_data(nil, {
        vim.json.encode({
          id = request.id,
          ok = true,
          result = {
            sidecar_version = "0.1.0",
            protocol_version = 7,
            registry_policy_fingerprint = nrm._test_registry_policy_fingerprint(nrm.config),
            workspace_key = "workspace",
            remote_root = "/repo",
            mirror_root = "/mirror/workspace",
            files_root = "/mirror/workspace/files",
            remote_status = "unchecked",
            remote_checked = false,
            remote_available = false,
            commands = { "workspace_info", "remote_agent_update", "disconnect" },
            capabilities = {
              remote_agent_bootstrap = true,
              remote_agent_automatic_bootstrap_v1 = true,
            },
          },
        }),
        "",
      })
    elseif request.method == "disconnect" then
      socket_options[channel].on_data(nil, {
        vim.json.encode({
          id = request.id,
          ok = true,
          result = { shutdown = true },
        }),
        "",
      })
    else
      error("unexpected request method " .. tostring(request.method))
    end
    return #payload
  end
  vim.fn.chanclose = function(channel)
    table.insert(closed_channels, channel)
    return 0
  end

  local function assert_socket_connection(expected_channel, label)
    assert_eq(nrm.config.connection, "stdio", label .. " changed the configured default transport")
    assert_eq(nrm.connection_status, "connected", label .. " did not connect")
    assert_eq(nrm.client.transport, "socket", label .. " changed transport")
    assert_eq(nrm.client.connection, "socket", label .. " lost the per-call connection override")
    assert_eq(nrm.client.job_id, expected_channel, label .. " retained the wrong channel")
    assert_eq(nrm.last_connection, "socket", label .. " did not preserve the reconnect transport")
    assert_eq(nrm.connection_state().agent_bootstrap_state, "skipped", label .. " attempted automatic bootstrap")
    assert_eq(nrm.connection_state().agent_bootstrap_reason, SKIP_REASON, label .. " lost the fixed-socket guard")
  end

  nrm.connect("ssh://host/repo", { connection = "socket" })
  assert_socket_connection(81, "initial connect")
  assert_eq(sent_methods, { "workspace_info" })

  nrm.reconnect()
  assert_socket_connection(82, "manual reconnect")
  assert_eq(sent_methods, { "workspace_info", "disconnect", "workspace_info" })
  assert_eq(closed_channels, { 81 })

  socket_options[82].on_data(nil, { "" })
  assert_socket_connection(83, "EOF reconnect")
  assert_eq(sent_methods, { "workspace_info", "disconnect", "workspace_info", "workspace_info" })
  assert_eq(jobstart_calls, 0, "socket reconnect unexpectedly started a process")

  for _, method in ipairs(sent_methods) do
    if method == "remote_agent_update" or method == "remote_agent_install" then
      error("fixed socket reconnect attempted installer mutation")
    end
  end
end

local ok, err = xpcall(main, debug.traceback)
vim.fn.sockconnect = original_sockconnect
vim.fn.jobstart = original_jobstart
vim.fn.chansend = original_chansend
vim.fn.chanclose = original_chanclose
vim.notify = original_notify
vim.defer_fn = original_defer_fn
uv.fs_lstat = original_fs_lstat
uv.fs_realpath = original_fs_realpath
uv.os_getuid = original_os_getuid
uv.os_get_passwd = original_os_get_passwd
nrm.client = nil
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
