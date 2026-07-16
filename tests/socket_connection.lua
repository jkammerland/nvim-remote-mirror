vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")

local KEY = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
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

local function agent_capabilities()
  return {
    scan = true,
    read = true,
    write_cas = true,
    checksum = true,
    grep = true,
    lsp_proxy = false,
    batch_read = true,
    batch_validate = true,
    chunked_write = true,
    request_ids = true,
    cancellation = false,
    streaming = false,
    multiplexing = false,
    git = true,
    runtime_process_v1 = true,
    runtime_pty_v1 = true,
    workspace_watch_v1 = false,
  }
end

local original_sockconnect = vim.fn.sockconnect
local original_jobstart = vim.fn.jobstart
local original_chansend = vim.fn.chansend
local original_chanclose = vim.fn.chanclose
local original_jobstop = vim.fn.jobstop
local original_notify = vim.notify
local uv = vim.uv or vim.loop
local original_fs_lstat = uv.fs_lstat
local original_fs_mkdir = uv.fs_mkdir
local original_fs_chmod = uv.fs_chmod
local original_fs_realpath = uv.fs_realpath
local original_os_getuid = uv.os_getuid
local original_os_get_passwd = uv.os_get_passwd

local function main()
  nrm.setup({
    connection = "socket",
    socket_path = "/tmp/nrm-test-sidecar/socket.sock",
    agent = "/local/build/nrm-agent",
    remote_agent = "nrm-agent",
    auto_reconnect = false,
    background_mirror = false,
    recover_local_edits_on_connect = false,
    flush_queue_on_connect = false,
    daemon_start_timeout_ms = 200,
    remote_agent_auto_install = true,
    remote_agent_registry_url = "file:///tmp/releases/v{version}/nrm-agent-manifest-v1.json",
    remote_agent_registry_public_keys = { ["release-a"] = KEY },
    remote_agent_registry_signature_threshold = 1,
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
  local expected_socket_path = "/tmp/nrm-test-sidecar/socket.sock"
  local fake_directories = {}
  local delay_agent_update = false
  local delayed_agent_update = nil
  local delayed_disconnect = nil

  local function reply(decoded, result)
    socket_opts.on_data(nil, {
      vim.json.encode({
        id = decoded.id,
        ok = true,
        result = result,
      }),
      "",
    })
  end

  vim.notify = function() end
  uv.os_getuid = function()
    return 1000
  end
  uv.os_get_passwd = function()
    return { uid = 1000 }
  end
  uv.fs_lstat = function(path)
    if path == expected_socket_path and daemon_started then
      return { type = "socket", uid = 1000, mode = 384 }
    end
    if fake_directories[path] then
      return { type = "directory", uid = 1000, mode = 448 }
    end
    if path == "/tmp/nrm-test-sidecar" or path == "/tmp/nrm-test-sockets" then
      return nil, "ENOENT: no such file or directory: " .. path, "ENOENT"
    end
    return original_fs_lstat(path)
  end
  uv.fs_realpath = function(path)
    if fake_directories[path] then
      return path
    end
    return original_fs_realpath(path)
  end
  vim.fn.sockconnect = function(mode, path, opts)
    assert_eq(mode, "pipe")
    assert_eq(path, expected_socket_path)
    if not daemon_started then
      error("socket is not listening yet")
    end
    socket_opts = opts
    return 55
  end
  uv.fs_mkdir = function(path, mode)
    mkdir_path = path
    mkdir_mode = mode
    fake_directories[path] = true
    return true
  end
  uv.fs_chmod = function(path, mode)
    if not fake_directories[path] then
      return nil, "ENOENT: no such file or directory: " .. path, "ENOENT"
    end
    mkdir_perm = mode
    return true
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
    local result
    if decoded.method == "workspace_info" then
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
        notifications = { "workspace/remote_health" },
        capabilities = {
          remote_agent_bootstrap = true,
          remote_agent_automatic_bootstrap_v1 = true,
        },
        runtime = {
          contract_version = 2,
          support = { process = true, terminal = true, watch = false },
          authority = { state = "unchecked", revision = 0 },
        },
      }
    elseif decoded.method == "remote_agent_update" then
      assert_eq(decoded.params.automatic, true)
      if delay_agent_update then
        delayed_agent_update = decoded
        return #payload
      end
      result = {
        status = "updated",
        automatic = true,
        remote_health = {
          remote_status = "connected",
          remote_checked = true,
          remote_available = true,
          agent_status = "ok",
          agent_version = "0.1.0",
          expected_agent_version = "0.1.0",
          protocol_version = 7,
          expected_protocol_version = 7,
          runtime = {
            contract_version = 2,
            support = { process = true, terminal = true, watch = false },
            authority = {
              state = "ready",
              revision = 1,
              agent_version = "0.1.0",
              protocol_version = 7,
              capabilities = agent_capabilities(),
              effective = { process = true, terminal = true, watch = false },
            },
          },
        },
      }
    else
      assert_eq(decoded.method, "disconnect")
      if delay_agent_update and delayed_agent_update then
        delayed_disconnect = decoded
        return #payload
      end
      result = { shutdown = true }
    end
    reply(decoded, result)
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
  assert_eq(nrm.connection_state().agent_bootstrap_state, "skipped")
  assert_eq(
    nrm.connection_state().agent_bootstrap_reason,
    "automatic agent bootstrap is disabled for an explicit socket_path; use a derived socket path"
  )
  assert_eq(mkdir_path, "/tmp/nrm-test-sidecar")
  assert_eq(mkdir_mode, 448)
  assert_eq(mkdir_perm, 448)
  assert_eq(daemon_command[2], "listen")
  assert_eq(arg_after(daemon_command, "--socket"), "/tmp/nrm-test-sidecar/socket.sock")
  assert_eq(arg_after(daemon_command, "--remote-root"), "/repo")
  assert_eq(arg_after(daemon_command, "--ssh"), "host")
  assert_eq(arg_after(daemon_command, "--agent"), "nrm-agent")
  assert_eq(arg_after(daemon_command, "--local-agent"), "/local/build/nrm-agent")

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
  expected_socket_path = nrm._test_socket_path_for("ssh://host/repo", { ssh = "host", remote_root = "/repo" })
  closed_channel = nil
  nrm.connect("ssh://host/repo")
  assert_eq(sent_methods[3], "workspace_info")
  assert_eq(sent_methods[4], "remote_agent_update")
  assert_eq(nrm.connection_state().agent_bootstrap_state, "ready")
  assert_eq(nrm.connection_state().agent_bootstrap_result, "updated")
  nrm.disconnect()
  assert(
    vim.wait(500, function()
      return closed_channel ~= nil
    end),
    "timed out waiting for derived socket channel close"
  )
  assert_eq(sent_methods[5], "disconnect")

  delay_agent_update = true
  delayed_agent_update = nil
  delayed_disconnect = nil
  closed_channel = nil
  stopped_job = nil
  nrm.connect("ssh://host/repo")
  assert_eq(sent_methods[6], "workspace_info")
  assert_eq(sent_methods[7], "remote_agent_update")
  assert_eq(nrm.connection_status, "bootstrapping_agent")
  assert_eq(delayed_agent_update.method, "remote_agent_update")

  nrm.disconnect()
  assert_eq(sent_methods[8], "disconnect")
  assert_eq(delayed_disconnect.method, "disconnect")
  assert_eq(nrm.connection_status, "disconnected")
  assert(
    vim.wait(500, function()
      return closed_channel ~= nil
    end),
    "derived socket did not detach while automatic update was still in flight"
  )
  assert_eq(closed_channel, 55)
  assert_eq(stopped_job, nil, "derived socket disconnect must not stop the detached daemon")

  reply(delayed_agent_update, {
    status = "updated",
    automatic = true,
    remote_health = {
      remote_status = "connected",
      remote_checked = true,
      remote_available = true,
      agent_status = "ok",
      agent_version = "0.1.0",
      expected_agent_version = "0.1.0",
      protocol_version = 7,
      expected_protocol_version = 7,
      runtime = {
        contract_version = 2,
        support = { process = true, terminal = true, watch = false },
        authority = {
          state = "ready",
          revision = 1,
          agent_version = "0.1.0",
          protocol_version = 7,
          capabilities = agent_capabilities(),
          effective = { process = true, terminal = true, watch = false },
        },
      },
    },
  })
  assert_eq(nrm.client, nil)
  assert_eq(nrm.connection_status, "disconnected", "late automatic update reply reconnected a detached socket")
  assert_eq(stopped_job, nil, "late automatic update reply stopped the detached daemon")
  delay_agent_update = false

  nrm.config.state_dir = "/tmp/nrm-state-a"
  nrm.config.remote_agent = "nrm-agent"
  local path_a = nrm._test_socket_path_for("ssh://host/repo", { ssh = "host", remote_root = "/repo" })
  nrm.config.state_dir = "/tmp/nrm-state-b"
  local path_b = nrm._test_socket_path_for("ssh://host/repo", { ssh = "host", remote_root = "/repo" })
  nrm.config.remote_agent = "other-agent"
  local path_c = nrm._test_socket_path_for("ssh://host/repo", { ssh = "host", remote_root = "/repo" })
  nrm.config.agent = "/local/build/other-nrm-agent"
  local path_d = nrm._test_socket_path_for("ssh://host/repo", { ssh = "host", remote_root = "/repo" })
  if path_a == path_b or path_b == path_c or path_c == path_d then
    error("socket path did not change with daemon-affecting config")
  end

  if vim.fn.has("win32") ~= 1 then
    local sidecar = vim.fn.tempname()
    vim.fn.writefile({ "aaaa" }, sidecar, "b")
    vim.fn.setfperm(sidecar, "rwx------")
    nrm.config.sidecar = sidecar
    local before_stat = assert(uv.fs_stat(sidecar), "failed to stat temporary sidecar")
    local before = nrm._test_socket_path_for("ssh://host/repo", { ssh = "host", remote_root = "/repo" })
    vim.wait(1100, function()
      return false
    end)
    vim.fn.writefile({ "bbbb" }, sidecar, "b")
    local atime = before_stat.atime.sec + (before_stat.atime.nsec or 0) / 1000000000
    local mtime = before_stat.mtime.sec + (before_stat.mtime.nsec or 0) / 1000000000
    assert(uv.fs_utime(sidecar, atime, mtime), "failed to restore temporary sidecar timestamps")
    local after = nrm._test_socket_path_for("ssh://host/repo", { ssh = "host", remote_root = "/repo" })
    assert_eq(assert(uv.fs_stat(sidecar), "failed to restat temporary sidecar").size, before_stat.size)
    if before == after then
      error("socket path did not change after an in-place same-size sidecar replacement")
    end
    assert(vim.fn.delete(sidecar) == 0, "failed to remove temporary sidecar")
  end
end

local ok, err = xpcall(main, debug.traceback)
vim.fn.sockconnect = original_sockconnect
vim.fn.jobstart = original_jobstart
vim.fn.chansend = original_chansend
vim.fn.chanclose = original_chanclose
vim.fn.jobstop = original_jobstop
vim.notify = original_notify
uv.fs_lstat = original_fs_lstat
uv.fs_mkdir = original_fs_mkdir
uv.fs_chmod = original_fs_chmod
uv.fs_realpath = original_fs_realpath
uv.os_getuid = original_os_getuid
uv.os_get_passwd = original_os_get_passwd
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
