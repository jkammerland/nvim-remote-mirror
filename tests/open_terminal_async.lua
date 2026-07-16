vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function main()
  local original_workspace = nrm.workspace
  local pending
  local context = {
    workspace_id = "terminal-async",
    prepare = function(_, capability, callback)
      assert_eq(capability, "terminal")
      pending = callback
      return true
    end,
  }
  nrm.workspace = function()
    return context
  end

  local win_new_events = 0
  vim.api.nvim_create_autocmd("WinNew", {
    callback = function()
      win_new_events = win_new_events + 1
    end,
  })

  local windows_before = #vim.api.nvim_list_wins()
  local callback_calls = 0
  local callback_err
  assert_eq(
    nrm.open_terminal({}, function(err)
      callback_calls = callback_calls + 1
      callback_err = err
    end),
    true
  )
  assert_eq(callback_calls, 0)
  assert_eq(#vim.api.nvim_list_wins(), windows_before, "terminal split opened before readiness completed")
  assert_eq(win_new_events, 0, "terminal readiness caused a transient split before completion")
  pending({ code = "capability_not_ready", message = "agent unavailable" })
  pending(nil, {})
  assert_eq(callback_calls, 1, "terminal callback was not exactly-once")
  assert_eq(callback_err.code, "capability_not_ready")
  assert_eq(#vim.api.nvim_list_wins(), windows_before, "failed readiness left an empty terminal split")
  assert_eq(win_new_events, 0, "failed readiness opened and then hid a transient split")

  local handle = { kill = function() end }
  local prepared = {
    open_pty = function(_, process)
      assert_eq(process.command, { shell = "default" })
      return handle
    end,
  }
  local success
  assert(nrm.open_terminal({}, function(err, result)
    assert_eq(err, nil)
    success = result
  end))
  assert_eq(success, nil)
  assert_eq(#vim.api.nvim_list_wins(), windows_before)
  pending(nil, prepared)
  assert_eq(success, handle)
  assert_eq(#vim.api.nvim_list_wins(), windows_before + 1, "successful readiness did not create a terminal split")
  assert_eq(win_new_events, 1, "successful readiness created an unexpected number of splits")
  vim.cmd("close!")

  local value, err = nrm.open_terminal({}, false)
  assert_eq(value, nil)
  assert_eq(err.code, "invalid_argument")
  assert(tostring(err):find("requires a callback", 1, true))
  nrm.workspace = original_workspace
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
