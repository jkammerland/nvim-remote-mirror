local nrm = require("nvim_remote_mirror")

local M = {}

local state = {
  buf = nil,
  win = nil,
}

local function notify(message, level)
  vim.notify(message, level or vim.log.levels.INFO, { title = "nvim-remote-mirror" })
end

local function value(text, fallback)
  if text == nil or text == "" then
    return fallback or "-"
  end
  return tostring(text)
end

local function number_value(text)
  return tostring(tonumber(text) or 0)
end

local function add_line(lines, label, text)
  table.insert(lines, string.format("  %-16s %s", label, value(text)))
end

local function add_section(lines, title)
  if #lines > 0 then
    table.insert(lines, "")
  end
  table.insert(lines, title)
  table.insert(lines, string.rep("-", #title))
end

local function scan_text(status)
  local scan = value(status.background_scan_state, "not_started")
  if scan == "completed" and status.background_scan_summary then
    return status.background_scan_summary
  end
  if scan == "in_progress" and status.background_scan_cursor then
    return scan .. " after " .. tostring(status.background_scan_cursor)
  end
  return scan
end

local function format_dashboard_lines(status, err)
  status = status or {}
  local connection = status.connection or nrm.connection_state()
  local lines = {
    "nvim-remote-mirror",
  }

  if err then
    table.insert(lines, "")
    table.insert(lines, "Status request failed: " .. tostring(err))
  end

  add_section(lines, "Actions")
  table.insert(lines, "  c connect    o open       f files      g grep")
  table.insert(lines, "  z cwd        s saves      C conflicts  r refresh")
  table.insert(lines, "  d disconnect R reconnect  q close      x close")

  add_section(lines, "Connection")
  add_line(lines, "State", connection.status)
  add_line(lines, "Target", connection.target or connection.last_target)
  add_line(lines, "Transport", connection.transport)
  add_line(lines, "Remote", status.remote_status or connection.remote_status or "unchecked")
  if status.retry_after_ms or connection.retry_after_ms then
    add_line(lines, "Retry After", tostring(math.floor(tonumber(status.retry_after_ms or connection.retry_after_ms) or 0)) .. " ms")
  end
  add_line(lines, "Error", status.remote_error or connection.remote_error or connection.error or connection.reason)

  add_section(lines, "Mirror")
  add_line(lines, "Mirror Root", connection.mirror_root)
  add_line(lines, "Files Root", connection.files_root)
  add_line(lines, "Known", number_value(status.known_files))
  add_line(lines, "Cached", number_value(status.cached_files))
  add_line(lines, "Indexed", number_value(status.indexed_files))
  add_line(lines, "Dirty", number_value(status.dirty_files))
  add_line(lines, "Stale", number_value(status.stale_files))
  add_line(lines, "Deleted", number_value(status.deleted_files))
  add_line(lines, "Scan", scan_text(status))

  add_section(lines, "Save Queue")
  add_line(lines, "Pending", number_value(status.pending_saves))
  add_line(lines, "Failed", number_value(status.failed_saves))
  add_line(lines, "Unreplayable", number_value(status.unreplayable_saves))
  add_line(lines, "Conflicts", number_value(status.conflicted_saves))

  return lines
end

local function set_lines(lines)
  if not state.buf or not vim.api.nvim_buf_is_valid(state.buf) then
    state.buf = vim.api.nvim_create_buf(false, true)
  end
  vim.bo[state.buf].buftype = "nofile"
  vim.bo[state.buf].bufhidden = "wipe"
  vim.bo[state.buf].swapfile = false
  vim.bo[state.buf].filetype = "nrm-dashboard"
  vim.bo[state.buf].modifiable = true
  vim.api.nvim_buf_set_lines(state.buf, 0, -1, false, lines)
  vim.bo[state.buf].modifiable = false
end

local function close()
  if state.win and vim.api.nvim_win_is_valid(state.win) then
    vim.api.nvim_win_close(state.win, true)
  end
  state.win = nil
end

local function map(buf, lhs, rhs, desc)
  vim.keymap.set("n", lhs, rhs, { buffer = buf, nowait = true, silent = true, desc = desc })
end

local function ensure_window()
  if state.win and vim.api.nvim_win_is_valid(state.win) then
    return
  end

  if not state.buf or not vim.api.nvim_buf_is_valid(state.buf) then
    state.buf = vim.api.nvim_create_buf(false, true)
  end

  local width = math.min(math.max(vim.o.columns - 4, 40), 90)
  local height = math.min(math.max(vim.o.lines - 6, 18), 34)
  state.win = vim.api.nvim_open_win(state.buf, true, {
    relative = "editor",
    width = width,
    height = height,
    row = math.max(math.floor((vim.o.lines - height) / 2) - 1, 0),
    col = math.max(math.floor((vim.o.columns - width) / 2), 0),
    border = "single",
    title = " Remote Workspace ",
    title_pos = "center",
  })
  vim.wo[state.win].wrap = false
  vim.wo[state.win].cursorline = true

  map(state.buf, "q", close, "Remote mirror: close")
  map(state.buf, "x", close, "Remote mirror: close")
  map(state.buf, "s", M.queue, "Remote mirror: queue")
  map(state.buf, "C", M.conflicts, "Remote mirror: conflicts")
  map(state.buf, "r", M.refresh_workspace, "Remote mirror: refresh")
  map(state.buf, "c", M.connect, "Remote mirror: connect")
  map(state.buf, "o", M.open, "Remote mirror: open")
  map(state.buf, "f", M.files, "Remote mirror: files")
  map(state.buf, "g", M.grep, "Remote mirror: grep")
  map(state.buf, "z", function()
    local ok, err = pcall(nrm.cd)
    if not ok then
      notify(tostring(err), vim.log.levels.ERROR)
      return
    end
    M.refresh_workspace()
  end, "Remote mirror: cwd")
  map(state.buf, "d", function()
    nrm.disconnect()
    M.refresh_workspace()
  end, "Remote mirror: disconnect")
  map(state.buf, "R", function()
    local ok, err = pcall(nrm.reconnect)
    if not ok then
      notify(tostring(err), vim.log.levels.ERROR)
    end
    vim.defer_fn(M.refresh_workspace, 100)
  end, "Remote mirror: reconnect")
end

function M.refresh_workspace()
  ensure_window()
  set_lines({ "nvim-remote-mirror", "", "Loading workspace status..." })
  nrm.status_async(function(err, status)
    vim.schedule(function()
      if not state.buf or not vim.api.nvim_buf_is_valid(state.buf) then
        return
      end
      set_lines(format_dashboard_lines(status, err))
    end)
  end)
end

function M.workspace()
  M.refresh_workspace()
end

local function prompt(prompt_text, default, callback)
  vim.ui.input({ prompt = prompt_text, default = default or "" }, function(value_text)
    if value_text == nil then
      return
    end
    callback(value_text)
  end)
end

function M.connect()
  prompt("Remote target: ", nrm.connection_state().last_target or "", function(target)
    local ok, err = pcall(nrm.connect, target)
    if not ok then
      notify(tostring(err), vim.log.levels.ERROR)
    end
    vim.defer_fn(M.refresh_workspace, 150)
  end)
end

function M.open()
  local default = vim.bo.filetype == "nrm-dashboard" and "" or vim.fn.expand("<cfile>")
  prompt("Remote path: ", default, function(path)
    if path == "" then
      return
    end
    local ok, err = pcall(nrm.open, path)
    if not ok then
      notify(tostring(err), vim.log.levels.ERROR)
      return
    end
    close()
  end)
end

local function select_find_hit(query, result)
  local hits = result and result.hits or {}
  if #hits == 0 then
    notify("no remote mirror paths matched " .. vim.inspect(query), vim.log.levels.WARN)
    return
  end
  if result.truncated then
    notify("showing first " .. tostring(result.limit or #hits) .. " paths", vim.log.levels.WARN)
  end
  vim.ui.select(hits, {
    prompt = "Remote files",
    format_item = function(hit)
      return nrm.format_find_hit(hit)
    end,
  }, function(hit)
    if not hit then
      return
    end
    local ok, err = pcall(nrm.open, hit.path)
    if not ok then
      notify(tostring(err), vim.log.levels.ERROR)
      return
    end
    close()
  end)
end

function M.files()
  prompt("Find remote file: ", "", function(query)
    nrm.find_paths_async(query, function(err, result)
      if err then
        notify(err, vim.log.levels.ERROR)
        return
      end
      select_find_hit(query, result)
    end)
  end)
end

function M.grep()
  local default = vim.bo.filetype == "nrm-dashboard" and "" or vim.fn.expand("<cword>")
  prompt("Remote grep: ", default, function(query)
    if query == "" then
      return
    end
    local ok, err = pcall(nrm.grep, query)
    if not ok then
      notify(tostring(err), vim.log.levels.ERROR)
      return
    end
    close()
  end)
end

local function path_exists(path)
  return type(path) == "string" and path ~= "" and (vim.uv or vim.loop).fs_stat(path) ~= nil
end

local function edit_path(path)
  if not path_exists(path) then
    notify("path is not available: " .. tostring(path), vim.log.levels.WARN)
    return
  end
  close()
  vim.cmd.edit(vim.fn.fnameescape(path))
end

local function diff_paths(left, right)
  if not path_exists(left) or not path_exists(right) then
    notify("both files must exist to open a diff", vim.log.levels.WARN)
    return
  end
  close()
  vim.cmd("tabnew " .. vim.fn.fnameescape(left))
  vim.cmd("vertical diffsplit " .. vim.fn.fnameescape(right))
end

local function queue_actions(entry, opts)
  opts = opts or {}
  local actions = {}
  if entry.local_path then
    table.insert(actions, {
      label = "Open local mirror file",
      run = function()
        edit_path(entry.local_path)
      end,
    })
  end
  if entry.snapshot_path then
    table.insert(actions, {
      label = "Open saved snapshot",
      run = function()
        edit_path(entry.snapshot_path)
      end,
    })
  end
  if entry.remote_conflict_path then
    table.insert(actions, {
      label = "Open remote conflict copy",
      run = function()
        edit_path(entry.remote_conflict_path)
      end,
    })
  end
  if entry.local_path and entry.remote_conflict_path then
    table.insert(actions, {
      label = "Diff local vs remote conflict",
      run = function()
        diff_paths(entry.local_path, entry.remote_conflict_path)
      end,
    })
  end
  table.insert(actions, {
    label = "Retry queued saves",
    run = function()
      nrm.flush_queue()
    end,
  })
  table.insert(actions, {
    label = "Refresh queue",
    run = function()
      M.queue(opts)
    end,
  })
  return actions
end

local function select_queue_action(entry, opts)
  vim.ui.select(queue_actions(entry, opts), {
    prompt = nrm.format_save_queue_entry(entry),
    format_item = function(action)
      return action.label
    end,
  }, function(action)
    if action then
      action.run()
    end
  end)
end

local function queue_prompt(opts, result, shown_count)
  opts = opts or {}
  result = result or {}
  local counts = result.counts or {}
  local total = tonumber(result.total) or shown_count or #(result.entries or {})
  local parts = {
    opts.conflicts_only and "Remote conflicts" or "Remote save queue",
    "showing=" .. tostring(shown_count or #(result.entries or {})),
    "total=" .. tostring(total),
    "pending=" .. tostring(tonumber(counts.pending) or 0),
    "failed=" .. tostring(tonumber(counts.failed) or 0),
    "conflicts=" .. tostring(tonumber(counts.conflict) or 0),
  }
  if (tonumber(counts.unreplayable) or 0) > 0 then
    table.insert(parts, "unreplayable=" .. tostring(tonumber(counts.unreplayable) or 0))
  end
  if result.truncated then
    table.insert(parts, "truncated_at=" .. tostring(result.limit or shown_count or #(result.entries or {})))
  end
  return table.concat(parts, " ")
end

function M.queue(opts)
  opts = opts or {}
  nrm.save_queue_async({
    limit = opts.limit or 100,
    state = opts.conflicts_only and "conflict" or nil,
  }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    local entries = result and result.entries or {}
    if #entries == 0 then
      local message = opts.conflicts_only and "save queue has no conflicts" or "save queue is empty"
      notify(message)
      return
    end
    if result and result.truncated then
      notify(
        "save queue truncated at " .. tostring(result.limit or #entries) .. " of " .. tostring(result.total or #entries),
        vim.log.levels.WARN
      )
    end
    vim.ui.select(entries, {
      prompt = queue_prompt(opts, result, #entries),
      format_item = function(entry)
        return nrm.format_save_queue_entry(entry)
      end,
    }, function(entry)
      if entry then
        select_queue_action(entry, opts)
      end
    end)
  end)
end

function M.conflicts()
  M.queue({ conflicts_only = true })
end

M._format_dashboard_lines = format_dashboard_lines
M._queue_actions = queue_actions
M._queue_prompt = queue_prompt

return M
