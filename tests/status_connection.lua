vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")

local function assert_contains(text, needle, message)
  if not tostring(text):find(needle, 1, true) then
    error((message or "missing text") .. ": expected " .. vim.inspect(text) .. " to contain " .. vim.inspect(needle))
  end
end

local notifications = {}
vim.notify = function(message)
  table.insert(notifications, tostring(message))
end

local function next_notification()
  local start = #notifications
  local ok = vim.wait(200, function()
    return #notifications > start
  end)
  if not ok then
    error("timed out waiting for notification")
  end
  return notifications[#notifications]
end

local function fake_client()
  return {
    job_id = 1,
    closing = false,
    target_arg = "ssh://host/repo",
    hello = {
      workspace_key = "workspace",
      files_root = "/mirror/workspace/files",
    },
  }
end

local function status_result()
  return {
    known_files = 10,
    cached_files = 3,
    indexed_files = 2,
    dirty_files = 1,
    pending_saves = 1,
    failed_saves = 0,
    conflicted_saves = 0,
    stale_files = 1,
    deleted_files = 0,
    remote_status = "unavailable",
    remote_checked = true,
    remote_available = false,
    remote_error = "ssh connect failed",
    retry_after_ms = 1500,
  }
end

local function main()
  nrm.client = nil
  nrm.connection_status = "disconnected"
  nrm.connection_target = nil
  nrm.connection_reason = "explicit disconnect"
  nrm.connection_error = nil
  nrm.reconnect_pending = false
  nrm.status()
  local message = next_notification()
  assert_contains(message, "connection=disconnected")
  assert_contains(message, "reason=explicit disconnect")

  nrm.connection_status = "reconnect_pending"
  nrm.connection_target = "ssh://host/repo"
  nrm.connection_reason = nil
  nrm.connection_error = "sidecar exited"
  nrm.reconnect_pending = true
  nrm.reconnect_attempts = 1
  nrm.config.reconnect_max_attempts = 3
  nrm.status()
  message = next_notification()
  assert_contains(message, "connection=reconnect_pending")
  assert_contains(message, "reconnect=pending")
  assert_contains(message, "attempts=1/3")
  assert_contains(message, "target=ssh://host/repo")

  nrm.client = fake_client()
  nrm.connection_status = "connected"
  nrm.connection_target = "ssh://host/repo"
  nrm.connection_reason = nil
  nrm.connection_error = nil
  nrm.reconnect_pending = false
  nrm.request = function(method, _, callback)
    if method ~= "status" then
      error("unexpected request method " .. tostring(method))
    end
    callback(nil, status_result())
  end
  nrm.status()
  message = next_notification()
  assert_contains(message, "known=10 cached=3")
  assert_contains(message, "connection=connected")
  assert_contains(message, "remote=unavailable")
  assert_contains(message, "retry_after_ms=1500")
  assert_contains(message, "error=ssh connect failed")
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
