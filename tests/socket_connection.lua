vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error(
      (message or "assertion failed")
        .. ": expected "
        .. vim.inspect(expected)
        .. ", got "
        .. vim.inspect(actual)
    )
  end
end

local function arg_after(args, name)
  for index = 1, #args - 1 do
    if args[index] == name then
      return args[index + 1]
    end
  end
  return nil
end

local original_sockconnect = vim.fn.sockconnect
local original_jobstart = vim.fn.jobstart
local original_chansend = vim.fn.chansend
local original_chanclose = vim.fn.chanclose
local original_jobstop = vim.fn.jobstop
local original_mkdir = vim.fn.mkdir
local original_notify = vim.notify

local function main()
  nrm.setup({
    connection = "socket",
    socket_path = "/tmp/nrm-test-sidecar.sock",
    agent = "/local/build/nrm-agent",
    remote_agent = "nrm-agent",
    auto_reconnect = false,
    background_mirror = false,
    recover_local_edits_on_connect = false,
    flush_queue_on_connect = false,
    daemon_start_timeout_ms = 200,
  })

  local daemon_started = false
  local daemon_command = nil
  local socket_opts = nil
  local sent_methods = {}
  local closed_channel = nil
  local stopped_job = nil
  local mkdir_path = nil
  local mkdir_mode = nil
  local mkdir_perm = nil

  vim.notify = function() end
  vim.fn.sockconnect = function(mode, path, opts)
    assert_eq(mode, "pipe")
    assert_eq(path, "/tmp/nrm-test-sidecar.sock")
    if not daemon_started then
      error("socket is not listening yet")
    end
    socket_opts = opts
    return 55
  end
  vim.fn.mkdir = function(path, mode, perm)
    mkdir_path = path
    mkdir_mode = mode
    mkdir_perm = perm
    return 1
  end
  vim.fn.jobstart = function(command, opts)
    daemon_started = true
    daemon_command = command
    assert_eq(opts.detach, true)
    assert_eq(opts.on_exit, nil)
    return 77
  end
  vim.fn.chansend = function(channel, payload)
    assert_eq(channel, 55)
    local decoded = vim.json.decode(payload)
    table.insert(sent_methods, decoded.method)
    socket_opts.on_data(nil, {
      vim.json.encode({
        id = decoded.id,
        ok = true,
        result = {
          sidecar_version = "0.1.0",
          protocol_version = 5,
          workspace_key = "workspace",
          remote_root = "/repo",
          mirror_root = "/mirror/workspace",
          files_root = "/mirror/workspace/files",
          remote_status = "unchecked",
          remote_checked = false,
          remote_available = false,
          commands = { "workspace_info", "disconnect" },
          notifications = { "workspace/remote_health" },
        },
      }),
      "",
    })
    return #payload
  end
  vim.fn.chanclose = function(channel)
    closed_channel = channel
    return 0
  end
  vim.fn.jobstop = function(job)
    stopped_job = job
    return 0
  end

  nrm.connect("ssh://host/repo")

  assert_eq(nrm.connection_status, "connected")
  assert_eq(nrm.client.transport, "socket")
  assert_eq(nrm.client.job_id, 55)
  assert_eq(nrm.client.daemon_job_id, 77)
  assert_eq(sent_methods[1], "workspace_info")
  assert_eq(mkdir_path, "/tmp")
  assert_eq(mkdir_mode, "p")
  assert_eq(mkdir_perm, 448)
  assert_eq(daemon_command[2], "listen")
  assert_eq(arg_after(daemon_command, "--socket"), "/tmp/nrm-test-sidecar.sock")
  assert_eq(arg_after(daemon_command, "--remote-root"), "/repo")
  assert_eq(arg_after(daemon_command, "--ssh"), "host")
  assert_eq(arg_after(daemon_command, "--agent"), "nrm-agent")

  nrm.disconnect()
  local closed = vim.wait(500, function()
    return closed_channel ~= nil
  end)
  if not closed then
    error("timed out waiting for socket channel close")
  end
  assert_eq(sent_methods[2], "disconnect")
  assert_eq(closed_channel, 55)
  assert_eq(stopped_job, nil)
  assert_eq(nrm.connection_status, "disconnected")
  assert_eq(nrm.connection_reason, "explicit disconnect")

  nrm.config.socket_path = nil
  nrm.config.socket_dir = "/tmp/nrm-test-sockets"
  nrm.config.state_dir = "/tmp/nrm-state-a"
  nrm.config.remote_agent = "nrm-agent"
  local path_a = nrm._test_socket_path_for("ssh://host/repo", { ssh = "host", remote_root = "/repo" })
  nrm.config.state_dir = "/tmp/nrm-state-b"
  local path_b = nrm._test_socket_path_for("ssh://host/repo", { ssh = "host", remote_root = "/repo" })
  nrm.config.remote_agent = "other-agent"
  local path_c = nrm._test_socket_path_for("ssh://host/repo", { ssh = "host", remote_root = "/repo" })
  if path_a == path_b or path_b == path_c then
    error("socket path did not change with daemon-affecting config")
  end
end

local ok, err = xpcall(main, debug.traceback)
vim.fn.sockconnect = original_sockconnect
vim.fn.jobstart = original_jobstart
vim.fn.chansend = original_chansend
vim.fn.chanclose = original_chanclose
vim.fn.jobstop = original_jobstop
vim.fn.mkdir = original_mkdir
vim.notify = original_notify
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
