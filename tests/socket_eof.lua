vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local original_sockconnect = vim.fn.sockconnect
local original_jobstart = vim.fn.jobstart
local original_chansend = vim.fn.chansend
local original_notify = vim.notify

local function main()
  nrm.setup({
    connection = "socket",
    socket_path = "/tmp/nrm-test-sidecar-eof.sock",
    auto_reconnect = false,
    background_mirror = false,
    recover_local_edits_on_connect = false,
    flush_queue_on_connect = false,
  })

  local socket_opts = nil
  local hold_status = false
  vim.notify = function() end
  vim.fn.sockconnect = function(_, _, opts)
    socket_opts = opts
    return 55
  end
  vim.fn.jobstart = function()
    error("socket should already be available")
  end
  vim.fn.chansend = function(_, payload)
    local decoded = vim.json.decode(payload)
    if decoded.method == "workspace_info" then
      socket_opts.on_data(nil, {
        vim.json.encode({
          id = decoded.id,
          ok = true,
          result = {
            sidecar_version = "0.1.0",
            protocol_version = 5,
            registry_policy_fingerprint = "disabled",
            workspace_key = "workspace",
            remote_root = "/repo",
            mirror_root = "/mirror/workspace",
            files_root = "/mirror/workspace/files",
            remote_status = "unchecked",
            remote_checked = false,
            remote_available = false,
            commands = { "workspace_info", "status" },
            notifications = { "workspace/remote_health" },
          },
        }),
        "",
      })
    elseif decoded.method == "status" then
      hold_status = true
    else
      error("unexpected request method " .. tostring(decoded.method))
    end
    return #payload
  end

  nrm.connect("/repo")
  assert_eq(nrm.connection_status, "connected")

  local status_error = nil
  nrm.request("status", {}, function(err)
    status_error = err
  end)
  assert_eq(hold_status, true)
  socket_opts.on_data(nil, { "" })

  assert_eq(status_error, "sidecar socket closed")
  assert_eq(nrm.client, nil)
  assert_eq(nrm.connection_status, "disconnected")
  assert_eq(nrm.connection_error, "sidecar socket closed")
  vim.wait(20, function()
    return false
  end)
end

local ok, err = xpcall(main, debug.traceback)
vim.fn.sockconnect = original_sockconnect
vim.fn.jobstart = original_jobstart
vim.fn.chansend = original_chansend
vim.notify = original_notify
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
