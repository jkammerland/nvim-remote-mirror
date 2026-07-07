vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")
local pickers = require("nvim_remote_mirror.pickers")
local adapters = require("nvim_remote_mirror.adapters")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function assert_contains(text, needle, message)
  if not tostring(text):find(needle, 1, true) then
    error((message or "missing text") .. ": expected " .. vim.inspect(text) .. " to contain " .. vim.inspect(needle))
  end
end

local function main()
  assert_eq(adapters.files, pickers.files)
  assert_eq(adapters.grep, pickers.grep)

  local original_find_paths_async = nrm.find_paths_async
  local original_grep_async = nrm.grep_async
  local original_request = nrm.request
  local original_open = nrm.open
  local original_select = vim.ui.select
  local original_notify = vim.notify
  local original_win_set_cursor = vim.api.nvim_win_set_cursor

  local opened_path = nil
  nrm.open = function(path)
    opened_path = path
  end

  local selected_prompt = nil
  vim.ui.select = function(items, opts, callback)
    selected_prompt = opts.prompt
    assert_eq(#items, 1)
    callback(items[1])
  end

  local find_query = nil
  local find_limit = nil
  nrm.find_paths_async = function(query, opts, callback)
    find_query = query
    find_limit = opts.limit
    callback(nil, {
      hits = {
        {
          path = "src/lib.rs",
          local_path = "/mirror/src/lib.rs",
          cached = true,
        },
      },
    })
  end
  pickers.files({ query = "lib", limit = 7 })
  assert_eq(find_query, "lib")
  assert_eq(find_limit, 7)
  assert_eq(selected_prompt, "Remote files")
  assert_eq(opened_path, "src/lib.rs")

  local notices = {}
  vim.notify = function(message, level)
    table.insert(notices, { message = message, level = level })
  end
  opened_path = nil
  pickers.files({ query = "lib", provider = "telescope" })
  assert_eq(opened_path, "src/lib.rs")
  assert_contains(notices[#notices].message, "picker provider telescope is not available")
  assert_eq(notices[#notices].level, vim.log.levels.WARN)

  opened_path = nil
  nrm.find_paths_async = function(_, _, callback)
    callback(nil, {
      hits = {
        {
          local_path = "/mirror/missing-path.rs",
          cached = true,
        },
      },
    })
  end
  pickers.files({ query = "missing-path" })
  assert_eq(opened_path, nil)
  assert_contains(notices[#notices].message, "selected remote file has no workspace path")
  assert_eq(notices[#notices].level, vim.log.levels.ERROR)

  local grep_query = nil
  local grep_limit = nil
  local grep_selected = nil
  local grep_is_current = nil
  nrm.grep_async = function(query, opts, callback)
    grep_query = query
    grep_limit = opts.limit
    grep_is_current = opts.is_current
    callback(nil, {
      source = "remote",
      hits = {
        {
          path = "src/lib.rs",
          local_path = "/mirror/src/lib.rs",
          line = 12,
          column = 5,
          text = "needle here",
        },
      },
    })
  end
  pickers.grep({
    query = "needle",
    limit = 3,
    on_select = function(item)
      grep_selected = item
    end,
  })
  assert_eq(grep_query, "needle")
  assert_eq(grep_limit, 3)
  assert_eq(selected_prompt, "Remote grep")
  assert_eq(grep_selected.path, "src/lib.rs")
  assert_eq(type(grep_is_current), "function")
  assert_eq(grep_is_current(), true)
  assert_contains(pickers._grep_label(grep_selected), "src/lib.rs:12:5:needle here")

  local cursor_position = nil
  opened_path = nil
  nrm.open = function(path, opts)
    opened_path = path
    assert_eq(type(opts.on_open), "function")
    opts.on_open({ path = path })
  end
  vim.api.nvim_win_set_cursor = function(win, position)
    assert_eq(win, 0)
    cursor_position = position
  end
  nrm.grep_async = function(_, _, callback)
    callback(nil, {
      source = "remote",
      hits = {
        {
          path = "src/main.rs",
          local_path = "/mirror/src/main.rs",
          line = 8,
          column = 4,
          text = "needle main",
        },
      },
    })
  end
  pickers.grep({ query = "needle" })
  assert_eq(opened_path, "src/main.rs")
  assert_eq(cursor_position[1], 8)
  assert_eq(cursor_position[2], 3)

  local picker_grep_callbacks = {}
  nrm.grep_async = function(query, opts)
    picker_grep_callbacks[query] = opts.is_current
  end
  pickers.grep({ query = "old" })
  pickers.grep({ query = "new" })
  assert_eq(picker_grep_callbacks.old(), false)
  assert_eq(picker_grep_callbacks.new(), true)

  nrm.open = original_open
  local original_client = nrm.client
  local opened_temp_path = vim.fn.tempname()
  vim.fn.writefile({ "open callback" }, opened_temp_path)
  local test_client = {
    target_arg = "local",
    hello = {
      workspace_key = "test-workspace",
      files_root = "/mirror",
    },
  }
  local open_events = {}
  nrm.client = test_client
  nrm.request = function(method, params, callback)
    assert_eq(method, "open")
    table.insert(open_events, "request")
    callback(nil, {
      path = params.path,
      local_path = opened_temp_path,
      hash = "hash-open",
    })
  end
  nrm.open("src/open.rs", {
    on_open = function(result)
      table.insert(open_events, "on_open")
      assert_eq(result.path, "src/open.rs")
      assert_eq(vim.api.nvim_buf_get_name(0), opened_temp_path)
      assert_eq(vim.b.nrm_remote_path, "src/open.rs")
      assert_eq(vim.b.nrm_remote_hash, "hash-open")
    end,
  })
  assert_eq(
    vim.wait(1000, function()
      return #open_events == 2
    end),
    true
  )
  assert_eq(table.concat(open_events, ","), "request,on_open")

  local stale_open_called = false
  local stale_client = {
    target_arg = "local",
    hello = {
      workspace_key = "stale-workspace",
      files_root = "/mirror",
    },
  }
  nrm.client = stale_client
  nrm.request = function(_, params, callback)
    callback(nil, {
      path = params.path,
      local_path = opened_temp_path,
      hash = "hash-stale",
    })
  end
  nrm.open("src/stale.rs", {
    on_open = function()
      stale_open_called = true
    end,
  })
  nrm.client = test_client
  vim.wait(50, function()
    return stale_open_called
  end)
  assert_eq(stale_open_called, false)
  nrm.client = original_client

  nrm.grep_async = original_grep_async
  local grep_async_result = nil
  local grep_pages = 0
  local cache_requests = 0
  nrm.request = function(method, params, callback)
    if method == "grep" then
      grep_pages = grep_pages + 1
      assert_eq(params.query, "needle")
      assert_eq(params.max_files, 1)
      if grep_pages == 1 then
        callback(nil, {
          hits = {
            { path = "a.rs", local_path = "/mirror/a.rs", line = 1, column = 1, text = "needle a" },
          },
          truncated = true,
          next_after = "a.rs",
          scanned_files = 1,
        })
      else
        assert_eq(params.after, "a.rs")
        callback(nil, {
          hits = {
            { path = "b.rs", local_path = "/mirror/b.rs", line = 2, column = 1, text = "needle b" },
          },
          truncated = false,
          scanned_files = 1,
        })
      end
      return
    end
    if method == "grep_cache" then
      cache_requests = cache_requests + 1
      callback(nil, { hits = {} })
      return
    end
    error("unexpected method " .. tostring(method))
  end
  nrm.grep_async("needle", { limit = 2, remote_page_files = 1 }, function(err, result)
    assert_eq(err, nil)
    grep_async_result = result
  end)
  assert_eq(grep_pages, 2)
  assert_eq(cache_requests, 1)
  assert_eq(grep_async_result.source, "remote")
  assert_eq(#grep_async_result.hits, 2)
  assert_eq(grep_async_result.scanned_files, 2)

  local merged_result = nil
  nrm.request = function(method, _, callback)
    if method == "grep" then
      callback(nil, {
        hits = {
          { path = "remote.rs", local_path = "/mirror/remote.rs", line = 1, column = 1, text = "needle remote" },
        },
        truncated = false,
      })
      return
    end
    if method == "grep_cache" then
      callback(nil, {
        hits = {
          {
            path = "dirty.rs",
            local_path = "/mirror/dirty.rs",
            line = 2,
            column = 1,
            text = "needle dirty",
            dirty = true,
          },
          {
            path = "clean.rs",
            local_path = "/mirror/clean.rs",
            line = 3,
            column = 1,
            text = "needle clean",
          },
        },
      })
      return
    end
    error("unexpected method " .. tostring(method))
  end
  nrm.grep_async("needle", { limit = 5 }, function(err, result)
    assert_eq(err, nil)
    merged_result = result
  end)
  assert_eq(merged_result.source, "remote")
  assert_eq(#merged_result.hits, 2)
  assert_eq(merged_result.hits[1].path, "remote.rs")
  assert_eq(merged_result.hits[2].path, "dirty.rs")

  local partial_result = nil
  local partial_page = 0
  nrm.request = function(method, _, callback)
    if method == "grep" then
      partial_page = partial_page + 1
      if partial_page == 1 then
        callback(nil, {
          hits = {
            { path = "partial.rs", local_path = "/mirror/partial.rs", line = 1, column = 1, text = "needle partial" },
          },
          truncated = true,
          next_after = "partial.rs",
        })
      else
        callback("remote page failed", nil)
      end
      return
    end
    if method == "grep_cache" then
      callback(nil, {
        hits = {
          {
            path = "dirty.rs",
            local_path = "/mirror/dirty.rs",
            line = 2,
            column = 1,
            text = "needle dirty",
            dirty = true,
          },
        },
      })
      return
    end
    error("unexpected method " .. tostring(method))
  end
  nrm.grep_async("needle", { limit = 5, remote_page_files = 1 }, function(err, result)
    assert_eq(err, nil)
    partial_result = result
  end)
  assert_eq(partial_result.source, "remote")
  assert_eq(partial_result.remote_error, "remote page failed")
  assert_eq(partial_result.truncated, true)
  assert_eq(#partial_result.hits, 2)
  assert_eq(partial_result.hits[1].path, "partial.rs")
  assert_eq(partial_result.hits[2].path, "dirty.rs")

  local fallback_result = nil
  nrm.request = function(method, _, callback)
    if method == "grep" then
      callback("remote unavailable", nil)
      return
    end
    if method == "grep_cache" then
      callback(nil, {
        hits = {
          { path = "cached.rs", local_path = "/mirror/cached.rs", line = 3, column = 2, text = "needle cache" },
        },
      })
      return
    end
    error("unexpected method " .. tostring(method))
  end
  nrm.grep_async("needle", { limit = 5 }, function(err, result)
    assert_eq(err, nil)
    fallback_result = result
  end)
  assert_eq(fallback_result.source, "cache")
  assert_eq(fallback_result.remote_error, "remote unavailable")
  assert_eq(fallback_result.hits[1].path, "cached.rs")

  local no_cache_error = nil
  nrm.request = function(method, _, callback)
    if method == "grep" then
      callback("remote unavailable", nil)
      return
    end
    error("unexpected method " .. tostring(method))
  end
  nrm.grep_async("needle", { limit = 5, cache = false }, function(err)
    no_cache_error = err
  end)
  assert_eq(no_cache_error, "remote unavailable")

  local preempted_cache_result = nil
  nrm.request = function(method, _, callback)
    if method == "grep" then
      callback(nil, {
        preempted = true,
      })
      return
    end
    if method == "grep_cache" then
      callback(nil, {
        hits = {
          { path = "cached.rs", local_path = "/mirror/cached.rs", line = 3, column = 2, text = "needle cache" },
        },
      })
      return
    end
    error("unexpected method " .. tostring(method))
  end
  nrm.grep_async("needle", { limit = 5 }, function(err, result)
    assert_eq(err, nil)
    preempted_cache_result = result
  end)
  assert_eq(preempted_cache_result.source, "cache")
  assert_eq(preempted_cache_result.remote_preempted, true)
  assert_eq(preempted_cache_result.hits[1].path, "cached.rs")

  local stale_grep_callback = nil
  local stale_cache_callback = nil
  local stale_grep_requests = 0
  local stale_result_called = false
  local current_grep = true
  nrm.request = function(method, _, callback)
    if method == "grep" then
      stale_grep_requests = stale_grep_requests + 1
      stale_grep_callback = callback
      return
    end
    if method == "grep_cache" then
      stale_cache_callback = callback
      return
    end
    error("unexpected method " .. tostring(method))
  end
  nrm.grep_async("needle", {
    limit = 3,
    remote_page_files = 1,
    is_current = function()
      return current_grep
    end,
  }, function()
    stale_result_called = true
  end)
  current_grep = false
  stale_cache_callback(nil, {
    hits = {
      { path = "dirty.rs", local_path = "/mirror/dirty.rs", line = 1, column = 1, text = "needle", dirty = true },
    },
  })
  stale_grep_callback(nil, {
    hits = {
      { path = "first.rs", local_path = "/mirror/first.rs", line = 1, column = 1, text = "needle" },
    },
    truncated = true,
    next_after = "first.rs",
  })
  assert_eq(stale_grep_requests, 1)
  assert_eq(stale_result_called, false)

  local stale_callbacks = {}
  local selected = {}
  nrm.find_paths_async = function(query, _, callback)
    stale_callbacks[query] = callback
  end
  vim.ui.select = function(items, _, callback)
    table.insert(selected, items[1].path)
    callback(items[1])
  end
  pickers.files({
    query = "old",
    on_select = function(item)
      table.insert(selected, "open:" .. item.path)
    end,
  })
  pickers.files({
    query = "new",
    on_select = function(item)
      table.insert(selected, "open:" .. item.path)
    end,
  })
  stale_callbacks.new(nil, { hits = { { path = "new.rs", local_path = "/mirror/new.rs" } } })
  stale_callbacks.old(nil, { hits = { { path = "old.rs", local_path = "/mirror/old.rs" } } })
  assert_eq(table.concat(selected, ","), "new.rs,open:new.rs")

  nrm.find_paths_async = original_find_paths_async
  nrm.grep_async = original_grep_async
  nrm.request = original_request
  nrm.open = original_open
  vim.ui.select = original_select
  vim.notify = original_notify
  vim.api.nvim_win_set_cursor = original_win_set_cursor
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
