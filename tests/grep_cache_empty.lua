vim.opt.runtimepath:prepend(vim.fn.getcwd())

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

local function main()
  vim.fn.setqflist({}, " ", {
    title = "stale",
    items = {
      {
        filename = "stale.txt",
        lnum = 1,
        col = 1,
        text = "stale hit",
      },
    },
  })

  vim.notify = function() end
  nrm.request = function(method, _, callback)
    if method == "grep" then
      callback("ssh unavailable", nil)
    elseif method == "grep_cache" then
      callback(nil, { hits = {}, truncated = false })
    else
      error("unexpected request method " .. tostring(method))
    end
  end

  nrm.grep("missing")

  local ok = vim.wait(200, function()
    return vim.fn.getqflist({ title = true }).title == "RemoteGrep cache missing"
  end)
  if not ok then
    error("timed out waiting for cache quickfix update")
  end

  assert_eq(#vim.fn.getqflist(), 0)
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
