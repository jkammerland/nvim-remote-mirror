vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")
local ui = require("nvim_remote_mirror.ui")

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

local function assert_line_contains(lines, needle)
  for _, line in ipairs(lines) do
    if line:find(needle, 1, true) then
      return
    end
  end
  error("expected dashboard lines to contain " .. vim.inspect(needle) .. ":\n" .. table.concat(lines, "\n"))
end

local function assert_dashboard_visible(message)
  vim.wait(100, function()
    return vim.bo.filetype == "nrm-dashboard"
  end)
  assert_eq(vim.bo.filetype, "nrm-dashboard", message)
end

local function assert_dashboard_closed(message)
  vim.wait(100, function()
    return vim.bo.filetype ~= "nrm-dashboard"
  end)
  assert_eq(vim.bo.filetype == "nrm-dashboard", false, message)
end

local function fake_client()
  return {
    job_id = 1,
    transport = "socket",
    hello = {
      workspace_key = "workspace",
      remote_root = "/remote/repo",
      mirror_root = "/mirror/workspace",
      files_root = "/mirror/workspace/files",
      remote_status = "unchecked",
    },
  }
end

local function main()
  nrm.client = nil
  nrm.connection_status = "disconnected"
  nrm.connection_target = nil
  nrm.connection_reason = "explicit disconnect"
  nrm.connection_error = nil
  nrm.reconnect_pending = false

  local disconnected_status = nil
  nrm.status_async(function(err, result)
    assert_eq(err, nil)
    disconnected_status = result
  end)
  assert_eq(disconnected_status.connected, false)
  assert_eq(disconnected_status.connection.status, "disconnected")
  assert_eq(disconnected_status.connection.reason, "explicit disconnect")

  nrm.client = fake_client()
  nrm.connection_status = "connected"
  nrm.connection_target = "ssh://host/repo"
  nrm.request = function(method, params, callback)
    if method == "status" then
      assert_eq(next(params), nil)
      callback(nil, {
        known_files = 12,
        cached_files = 7,
        indexed_files = 5,
        dirty_files = 1,
        stale_files = 2,
        deleted_files = 0,
        pending_saves = 1,
        failed_saves = 0,
        conflicted_saves = 1,
        remote_status = "available",
        remote_checked = true,
        remote_available = true,
        background_scan_state = "in_progress",
        background_scan_cursor = "src/main.rs",
      })
      return
    end
    if method == "find_paths" then
      assert_eq(params.query, "readme")
      assert_eq(params.limit, 5)
      callback(nil, {
        hits = {
          {
            path = "README.md",
            local_path = "/mirror/workspace/files/README.md",
            cached = true,
          },
        },
      })
      return
    end
    if method == "save_queue" then
      assert_eq(params.limit, 2)
      callback(nil, {
        total = 3,
        limit = 2,
        truncated = true,
        counts = {
          pending = 1,
          failed = 0,
          conflict = 1,
        },
        entries = {
          {
            queue_id = 9,
            path = "src/lib.rs",
            state = "conflict",
            attempts = 1,
            local_path = "/mirror/workspace/files/src/lib.rs",
            remote_conflict_path = "/mirror/workspace/conflicts/src-lib.remote",
          },
        },
      })
      return
    end
    error("unexpected method " .. tostring(method))
  end

  local status = nil
  nrm.status_async(function(err, result)
    assert_eq(err, nil)
    status = result
  end)
  assert_eq(status.connected, true)
  assert_eq(status.connection.transport, "socket")
  assert_eq(status.connection.remote_root, "/remote/repo")
  assert_eq(status.remote_summary, "remote=available")

  local lines = ui._format_dashboard_lines(status)
  assert_line_contains(lines, "Connection")
  assert_line_contains(lines, "Mirror")
  assert_line_contains(lines, "Mirror Root")
  assert_line_contains(lines, "/mirror/workspace")
  assert_line_contains(lines, "Save Queue")
  assert_line_contains(lines, "z cwd")
  assert_line_contains(lines, "src/main.rs")

  local find_result = nil
  nrm.find_paths_async("readme", { limit = 5 }, function(err, result)
    assert_eq(err, nil)
    find_result = result
  end)
  assert_eq(find_result.hits[1].path, "README.md")
  assert_contains(nrm.format_find_hit(find_result.hits[1]), "README.md [cached]")

  local queue_result = nil
  nrm.save_queue_async({ limit = 2 }, function(err, result)
    assert_eq(err, nil)
    queue_result = result
  end)
  assert_contains(nrm.format_save_queue_entry(queue_result.entries[1]), "[conflict] #9 src/lib.rs")
  local queue_prompt = ui._queue_prompt({}, queue_result, #queue_result.entries)
  assert_contains(queue_prompt, "showing=1")
  assert_contains(queue_prompt, "total=3")
  assert_contains(queue_prompt, "conflicts=1")
  assert_contains(queue_prompt, "truncated_at=2")

  local actions = ui._queue_actions(queue_result.entries[1])
  assert_eq(#actions >= 4, true)

  local conflict_select_prompt = nil
  vim.ui.select = function(items, opts)
    assert_eq(#items, 1)
    conflict_select_prompt = opts.prompt
  end
  nrm.request = function(method, params, callback)
    assert_eq(method, "save_queue")
    assert_eq(params.limit, 100)
    assert_eq(params.state, "conflict")
    callback(nil, {
      total = 1,
      limit = 100,
      truncated = false,
      counts = { pending = 0, failed = 0, conflict = 1 },
      entries = {
        {
          queue_id = 10,
          path = "src/conflict.rs",
          state = "conflict",
          remote_conflict_path = "/mirror/workspace/conflicts/src-conflict.remote",
        },
      },
    })
  end
  ui.conflicts()
  assert_contains(conflict_select_prompt, "Remote conflicts")

  local original_input = vim.ui.input
  local original_open = nrm.open
  local original_grep = nrm.grep
  nrm.client = nil
  nrm.connection_status = "disconnected"

  vim.ui.input = function(_, callback)
    callback("README.md")
  end
  nrm.open = function()
    error("not connected; run :RemoteConnect first")
  end
  ui.workspace()
  assert_dashboard_visible("workspace dashboard should open before failed open")
  ui.open()
  assert_dashboard_visible("failed open should keep dashboard visible")

  local opened_path = nil
  nrm.open = function(path)
    opened_path = path
  end
  ui.open()
  assert_eq(opened_path, "README.md")
  assert_dashboard_closed("successful open should close dashboard")

  vim.ui.input = function(_, callback)
    callback("needle")
  end
  nrm.grep = function()
    error("not connected; run :RemoteConnect first")
  end
  ui.workspace()
  assert_dashboard_visible("workspace dashboard should open before failed grep")
  ui.grep()
  assert_dashboard_visible("failed grep should keep dashboard visible")

  local grep_query = nil
  nrm.grep = function(query)
    grep_query = query
  end
  ui.grep()
  assert_eq(grep_query, "needle")
  assert_dashboard_closed("successful grep should close dashboard")

  vim.ui.input = original_input
  nrm.open = original_open
  nrm.grep = original_grep
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
