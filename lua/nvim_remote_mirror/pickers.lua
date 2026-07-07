local nrm = require("nvim_remote_mirror")

local M = {}

local state = {
  files_generation = 0,
  grep_generation = 0,
}

local function notify(message, level)
  vim.notify(message, level or vim.log.levels.INFO, { title = "nvim-remote-mirror" })
end

local function picker_provider(opts)
  opts = opts or {}
  local configured = nrm.config.picker and nrm.config.picker.provider or "auto"
  local provider = opts.provider or configured or "auto"
  if provider == "auto" or provider == "builtin" then
    return "builtin"
  end
  notify("picker provider " .. tostring(provider) .. " is not available; using builtin", vim.log.levels.WARN)
  return "builtin"
end

local function select_builtin(items, opts, on_select)
  vim.ui.select(items, {
    prompt = opts.prompt,
    format_item = opts.format_item,
  }, on_select)
end

local function select_items(items, opts, on_select)
  picker_provider(opts)
  select_builtin(items, opts, on_select)
end

local function default_file_select(item)
  if not item.path or item.path == "" then
    notify("selected remote file has no workspace path", vim.log.levels.ERROR)
    return
  end
  nrm.open(item.path)
end

local function grep_label(hit)
  local path = hit.path or hit.local_path or "<unknown>"
  local line = tonumber(hit.line) or 1
  local column = tonumber(hit.column) or 1
  local text = hit.text or ""
  return string.format("%s:%d:%d:%s", path, line, column, text)
end

local function default_grep_select(hit)
  if not hit.path or hit.path == "" then
    notify("selected grep hit has no workspace path", vim.log.levels.ERROR)
    return
  end
  nrm.open(hit.path, {
    on_open = function()
      if hit.line then
        pcall(vim.api.nvim_win_set_cursor, 0, { tonumber(hit.line) or 1, math.max((tonumber(hit.column) or 1) - 1, 0) })
      end
    end,
  })
end

function M.files(opts)
  opts = opts or {}
  state.files_generation = state.files_generation + 1
  local generation = state.files_generation
  local query = opts.query or ""
  nrm.find_paths_async(query, { limit = opts.limit }, function(err, result)
    if generation ~= state.files_generation then
      return
    end
    if err then
      notify(err, vim.log.levels.ERROR)
      if opts.on_error then
        opts.on_error(err)
      end
      return
    end
    local hits = result and result.hits or {}
    if opts.on_results then
      opts.on_results(result or { hits = {} })
    end
    if #hits == 0 then
      notify("no remote mirror paths matched " .. vim.inspect(query), vim.log.levels.WARN)
      return
    end
    select_items(hits, {
      provider = opts.provider,
      prompt = opts.prompt or "Remote files",
      format_item = opts.format_item or nrm.format_find_hit,
    }, function(item)
      if item and generation == state.files_generation then
        (opts.on_select or default_file_select)(item)
      end
    end)
  end)
end

function M.grep(opts)
  opts = opts or {}
  state.grep_generation = state.grep_generation + 1
  local generation = state.grep_generation
  local query = opts.query or ""
  local user_is_current = opts.is_current
  local grep_opts = vim.tbl_extend("force", opts, {
    is_current = function()
      return generation == state.grep_generation and (type(user_is_current) ~= "function" or user_is_current())
    end,
  })
  if query == "" then
    notify("grep query is empty", vim.log.levels.WARN)
    return
  end
  nrm.grep_async(query, grep_opts, function(err, result)
    if generation ~= state.grep_generation then
      return
    end
    if err then
      notify(err, vim.log.levels.ERROR)
      if opts.on_error then
        opts.on_error(err)
      end
      return
    end
    local hits = result and result.hits or {}
    if opts.on_results then
      opts.on_results(result or { hits = {} })
    end
    if #hits == 0 then
      notify("no remote grep matches for " .. vim.inspect(query), vim.log.levels.WARN)
      return
    end
    select_items(hits, {
      provider = opts.provider,
      prompt = opts.prompt or "Remote grep",
      format_item = opts.format_item or grep_label,
    }, function(item)
      if item and generation == state.grep_generation then
        (opts.on_select or default_grep_select)(item)
      end
    end)
  end)
end

M._grep_label = grep_label

return M
