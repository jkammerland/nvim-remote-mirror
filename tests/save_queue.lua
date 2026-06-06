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

local function assert_contains(text, needle, message)
  if not tostring(text):find(needle, 1, true) then
    error((message or "missing text") .. ": expected " .. vim.inspect(text) .. " to contain " .. vim.inspect(needle))
  end
end

local notifications = {}
vim.notify = function(message, level)
  table.insert(notifications, { message = tostring(message), level = level })
end

local function wait_for_notification_count(count)
  local ok = vim.wait(300, function()
    return #notifications >= count
  end)
  if not ok then
    error("timed out waiting for notification " .. tostring(count))
  end
end

local function wait_for_quickfix_count(count)
  local ok = vim.wait(300, function()
    return #vim.fn.getqflist() == count
  end)
  if not ok then
    error("timed out waiting for quickfix count " .. tostring(count))
  end
end

local function qf_title()
  return vim.fn.getqflist({ title = 1 }).title
end

local function qf_first_text()
  local items = vim.fn.getqflist({ items = 1 }).items
  return items[1] and items[1].text or nil
end

local function main()
  local calls = {}
  local tmp = vim.fn.tempname()
  vim.fn.mkdir(tmp, "p")
  vim.fn.mkdir(tmp .. "/src", "p")
  vim.fn.mkdir(tmp .. "/conflicts", "p")
  local local_a = tmp .. "/src/a.rs"
  local local_b = tmp .. "/src/b.rs"
  local remote_conflict = tmp .. "/conflicts/c.remote.full"
  vim.fn.writefile({ "local a" }, local_a)
  vim.fn.writefile({ "local b" }, local_b)
  vim.fn.writefile({ "remote c" }, remote_conflict)
  nrm.request = function(method, params, callback)
    table.insert(calls, { method = method, params = params })
    assert_eq(method, "save_queue")
    assert_eq(params.limit, 3)
    callback(nil, {
      total = 4,
      limit = 3,
      truncated = true,
      counts = {
        pending = 1,
        failed = 1,
        conflict = 1,
      },
      entries = {
        {
          queue_id = 7,
          path = "src/a.rs",
          state = "pending",
          attempts = 0,
          local_path = local_a,
          snapshot_path = tmp .. "/save-a.snapshot",
        },
        {
          queue_id = 8,
          path = "src/b.rs",
          state = "failed",
          attempts = 2,
          local_path = local_b,
          last_error = "ssh connect failed",
        },
        {
          queue_id = 9,
          path = "src/c.rs",
          state = "conflict",
          attempts = 1,
          local_path = tmp .. "/src/c.rs",
          remote_conflict_path = remote_conflict,
          last_error = "remote changed",
        },
      },
    })
  end

  nrm.save_queue({ limit = 3 })
  wait_for_quickfix_count(3)
  wait_for_notification_count(1)

  local info = vim.fn.getqflist({ title = 1 })
  local items = vim.fn.getqflist()
  assert_eq(info.title, "RemoteSaveQueue")
  assert_contains(items[1].text, "[pending] #7 src/a.rs")
  assert_contains(items[2].text, "[failed] #8 src/b.rs attempts=2")
  assert_contains(items[2].text, "ssh connect failed")
  assert_contains(items[3].text, "[conflict] #9 src/c.rs attempts=1")
  assert_contains(items[3].text, "remote=" .. remote_conflict)
  assert_eq(vim.fn.bufname(items[3].bufnr), remote_conflict)
  assert_contains(notifications[1].message, "showing=3 total=4")
  assert_contains(notifications[1].message, "truncated_at=3")
  assert_eq(notifications[1].level, vim.log.levels.ERROR)

  nrm.request = function(method, params, callback)
    table.insert(calls, { method = method, params = params })
    assert_eq(method, "save_queue")
    assert_eq(next(params), nil)
    callback(nil, {
      total = 0,
      counts = {
        pending = 0,
        failed = 0,
        conflict = 0,
      },
      entries = {},
    })
  end

  nrm.save_queue()
  wait_for_notification_count(2)
  assert_eq(notifications[2].message, "save queue is empty")
  assert_eq(#calls, 2)

  local pending = {}
  nrm.client = { job_id = 1, hello = { workspace_key = "workspace-a" } }
  nrm.request = function(_, params, callback)
    table.insert(pending, { params = params, callback = callback })
  end
  nrm.save_queue({ limit = 1 })
  nrm.save_queue({ limit = 1 })
  assert_eq(#pending, 2)

  pending[2].callback(nil, {
    total = 1,
    limit = 1,
    truncated = false,
    counts = { pending = 1, failed = 0, conflict = 0 },
    entries = {
      {
        queue_id = 11,
        path = "new.rs",
        state = "pending",
        local_path = tmp .. "/new.rs",
      },
    },
  })
  wait_for_quickfix_count(1)
  assert_eq(qf_title(), "RemoteSaveQueue")
  assert_eq(qf_first_text(), "[pending] #11 new.rs")

  pending[1].callback(nil, {
    total = 1,
    limit = 1,
    truncated = false,
    counts = { pending = 1, failed = 0, conflict = 0 },
    entries = {
      {
        queue_id = 10,
        path = "old.rs",
        state = "pending",
        local_path = tmp .. "/old.rs",
      },
    },
  })
  vim.wait(50, function()
    return false
  end)
  assert_eq(qf_first_text(), "[pending] #11 new.rs", "stale queue result must not replace quickfix")

  local old_client_request = pending[#pending]
  nrm.client = { job_id = 2, hello = { workspace_key = "workspace-b" } }
  old_client_request.callback(nil, {
    total = 1,
    limit = 1,
    truncated = false,
    counts = { pending = 1, failed = 0, conflict = 0 },
    entries = {
      {
        queue_id = 12,
        path = "client-a.rs",
        state = "pending",
        local_path = tmp .. "/client-a.rs",
      },
    },
  })
  vim.wait(50, function()
    return false
  end)
  assert_eq(qf_first_text(), "[pending] #11 new.rs", "old client result must not replace quickfix")
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
