vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local original_jobstart = vim.fn.jobstart
local original_chansend = vim.fn.chansend
local original_jobstop = vim.fn.jobstop
local original_notify = vim.notify
local original_defer_fn = vim.defer_fn

local job_opts = nil
local next_job_id = 70
local stopped_jobs = {}
local workspace_error = "workspace_info failed"

local function main()
  vim.notify = function() end
  vim.fn.jobstart = function(_, opts)
    next_job_id = next_job_id + 1
    job_opts = opts
    return next_job_id
  end
  vim.fn.jobstop = function(job)
    table.insert(stopped_jobs, job)
    return 1
  end
  vim.fn.chansend = function(_, payload)
    local request = vim.json.decode(payload)
    assert_eq(request.method, "workspace_info")
    job_opts.on_stdout(nil, {
      vim.json.encode({
        id = request.id,
        ok = false,
        error = workspace_error,
      }),
      "",
    })
    return #payload
  end

  nrm.setup({
    auto_reconnect = false,
    background_mirror = false,
    recover_local_edits_on_connect = false,
    flush_queue_on_connect = false,
  })
  nrm.connect("ssh://host/repo")
  assert_eq(nrm.client, nil, "failed workspace_info retained a client")
  assert_eq(nrm.connection_status, "disconnected")
  assert_eq(nrm.connection_target, "ssh://host/repo")
  assert_eq(nrm.connection_error, workspace_error)
  assert_eq(nrm.reconnect_pending, false)
  assert_eq(stopped_jobs, { 71 })

  local deferred = {}
  vim.defer_fn = function(callback, delay)
    table.insert(deferred, { callback = callback, delay = delay })
  end
  workspace_error = "workspace_info timed out"
  nrm.setup({
    auto_reconnect = true,
    reconnect_delay_ms = 7,
    reconnect_max_attempts = 3,
  })
  nrm.connect("ssh://host/repo")
  assert_eq(nrm.client, nil, "failed workspace_info retained a reconnect client")
  assert_eq(nrm.connection_status, "reconnect_pending")
  assert_eq(nrm.connection_error, workspace_error)
  assert_eq(nrm.reconnect_pending, true)
  assert_eq(nrm.reconnect_attempts, 1)
  assert_eq(stopped_jobs, { 71, 72 })
  assert_eq(#deferred, 1, "failed workspace_info did not schedule one reconnect")
  assert_eq(deferred[1].delay, 7)

  vim.wait(10, function()
    return false
  end)
end

local ok, err = xpcall(main, debug.traceback)
vim.fn.jobstart = original_jobstart
vim.fn.chansend = original_chansend
vim.fn.jobstop = original_jobstop
vim.notify = original_notify
vim.defer_fn = original_defer_fn
nrm.client = nil
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
