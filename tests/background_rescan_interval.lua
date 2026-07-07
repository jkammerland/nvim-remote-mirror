vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local requests = {}

local function main()
  nrm.client = {
    job_id = 1,
    closing = false,
    hello = {
      workspace_key = "workspace",
      files_root = "/mirror/workspace/files",
    },
  }
  nrm.config.background_mirror_interval_ms = 1000000
  nrm.config.background_mirror_scan_limit = 12
  nrm.config.background_mirror_rescan_interval_ms = 34567
  nrm.config.background_mirror_prefetch_limit = 0
  nrm.config.background_mirror_refresh_limit = 0

  nrm.request = function(method, params, callback)
    table.insert(requests, {
      method = method,
      params = params,
    })
    if method == "remote_probe" then
      callback(nil, {
        remote_available = true,
        remote_status = "connected",
        remote_checked = true,
      })
    elseif method == "scan" then
      callback(nil, {
        entries = {},
        truncated = false,
        skipped = true,
      })
    else
      error("unexpected method " .. tostring(method))
    end
  end

  nrm.start_background_mirror()
  local ok = vim.wait(200, function()
    return #requests >= 2
  end)
  assert_eq(ok, true, "background mirror should issue probe and scan")
  nrm.stop_background_mirror()

  assert_eq(requests[1].method, "remote_probe")
  assert_eq(requests[2].method, "scan")
  assert_eq(requests[2].params.limit, 12)
  assert_eq(requests[2].params.resume, true)
  assert_eq(requests[2].params.rescan_after_ms, 34567)
end

local ok, err = xpcall(main, debug.traceback)
nrm.stop_background_mirror()
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
