local M = {}

local ERROR_MT = {
  __tostring = function(err)
    return err.message
  end,
}

local function integration_error(code, message, details)
  return setmetatable({
    code = code,
    message = message,
    details = details,
  }, ERROR_MT)
end

local function valid_key(key)
  return type(key) == "string" and key ~= "" and #key <= 256 and key:find("[%z\1-\31\127]") == nil
end

local function hash(value)
  if vim.fn.exists("*sha256") == 1 then
    return vim.fn.sha256(value)
  end
  local result = 2166136261
  for index = 1, #value do
    result = (result * 16777619 + value:byte(index)) % 4294967296
  end
  return string.format("%08x", result)
end

function M.scope_id(context)
  if
    type(context) ~= "table"
    or type(context.provider) ~= "string"
    or type(context.workspace_id) ~= "string"
    or type(context.authority) ~= "table"
    or type(context.authority.id) ~= "string"
  then
    return nil, integration_error("invalid_context", "workspace runtime context has no stable authority identity")
  end
  return "runtime-" .. hash(table.concat({ context.provider, context.authority.id, context.workspace_id }, "\30"))
end

local function default_resolve(query)
  return require("nvim_remote_mirror.workspace_runtime").resolve(query)
end

local function default_terminal_new(opts)
  local ok, terminal = pcall(require, "toggleterm.terminal")
  if not ok then
    error("ToggleTerm is not available: " .. tostring(terminal))
  end
  return terminal.Terminal:new(opts)
end

-- Neovim Ex counts cannot address IDs at or above 2^31, while ToggleTerm's
-- ordinary allocator continues to fill the low positive range when these
-- reserved IDs are present in its sorted registry.
local next_managed_terminal_id = 2147483647

local function default_managed_terminal_id()
  local terminals = require("toggleterm.terminal")
  repeat
    next_managed_terminal_id = next_managed_terminal_id + 1
    if next_managed_terminal_id > 9007199254740991 then
      error("nrm ToggleTerm managed terminal ID space is exhausted")
    end
  until terminals.get(next_managed_terminal_id, true) == nil
  return next_managed_terminal_id
end

local function default_is_alive(term)
  if
    type(term) ~= "table"
    or type(term.job_id) ~= "number"
    or term.job_id <= 0
    or type(term.bufnr) ~= "number"
    or not vim.api.nvim_buf_is_valid(term.bufnr)
  then
    return false
  end
  local ok, status = pcall(vim.fn.jobwait, { term.job_id }, 0)
  return ok and type(status) == "table" and status[1] == -1
end

local function default_open_terminal(term, size, direction, authoritative_cwd)
  if type(authoritative_cwd) == "string" and authoritative_cwd ~= "" then
    -- ToggleTerm applies expand() on every open. fnameescape() makes literal
    -- '$', wildcard, backslash, and whitespace path bytes survive that step;
    -- first spawn expands twice and reopen expands once. Reset every time
    -- because ToggleTerm stores the fully expanded form after spawning.
    local escaped_cwd = vim.fn.fnameescape(authoritative_cwd)
    if type(term.bufnr) ~= "number" or not vim.api.nvim_buf_is_valid(term.bufnr) then
      escaped_cwd = vim.fn.fnameescape(escaped_cwd)
    end
    term.dir = escaped_cwd
  end
  local ok_config, config = pcall(require, "toggleterm.config")
  local settings = ok_config and type(config.get) == "function" and config.get() or nil
  if type(settings) ~= "table" or settings.autochdir ~= true then
    return term:open(size, direction)
  end

  local original_on_create = term.on_create
  local original_on_open = term.on_open
  local restored = false
  local function restore()
    if restored then
      return
    end
    restored = true
    settings.autochdir = true
    term.on_create = original_on_create
    term.on_open = original_on_open
  end

  -- ToggleTerm's global autochdir otherwise replaces a validated local
  -- provider cwd on both first open and reopen. Restore before invoking the
  -- user's on_open callback so the temporary override is not observable there.
  local function restore_then(callback, self, ...)
    restore()
    if type(callback) == "function" then
      return callback(self, ...)
    end
  end
  term.on_create = function(self, ...)
    return restore_then(original_on_create, self, ...)
  end
  term.on_open = function(self, ...)
    return restore_then(original_on_open, self, ...)
  end
  settings.autochdir = false
  local ok_open, result = pcall(term.open, term, size, direction)
  restore()
  if not ok_open then
    error(result, 0)
  end
  return result
end

local function default_stamp(term, scope_id, key)
  term.__nrm_workspace_runtime = {
    scope_id = scope_id,
    key = key,
  }
  if type(term.bufnr) == "number" and vim.api.nvim_buf_is_valid(term.bufnr) then
    vim.b[term.bufnr].nrm_workspace_runtime_scope = scope_id
    vim.b[term.bufnr].nrm_workspace_runtime_key = key
  end
end

local function default_notify(message, level)
  vim.notify(message, level or vim.log.levels.ERROR, { title = "nrm ToggleTerm" })
end

local function new_local_command_guard(deps)
  deps = deps or {}
  local guard = {
    installed = false,
    deps = {
      command_exists = deps.command_exists or function()
        return vim.fn.exists(":ToggleTerm") == 2
      end,
      is_initialized = deps.is_initialized or function()
        return type(package.loaded["toggleterm"]) == "table"
      end,
      create_command = deps.create_command or function(callback, complete)
        vim.api.nvim_create_user_command("ToggleTerm", callback, {
          count = true,
          complete = complete,
          force = true,
          nargs = "*",
        })
      end,
      parse = deps.parse or function(args)
        return require("toggleterm.commandline").parse(args)
      end,
      complete = deps.complete or function(...)
        return require("toggleterm.commandline").toggle_term_complete(...)
      end,
      toggle_counted = deps.toggle_counted or function(count, size, dir, direction, name)
        return require("toggleterm").toggle(count, size, dir, direction, name)
      end,
      find_open_windows = deps.find_open_windows or function(is_managed)
        return require("toggleterm.ui").find_open_windows(function(bufnr)
          if is_managed(bufnr) then
            return false
          end
          return vim.bo[bufnr].filetype == "toggleterm" or vim.b[bufnr].toggle_number ~= nil
        end)
      end,
      close_terminal_view = deps.close_terminal_view or function(windows)
        return require("toggleterm.ui").close_and_save_terminal_view(windows)
      end,
      open_terminal_view = deps.open_terminal_view or function(size, direction)
        return require("toggleterm.ui").open_terminal_view(size, direction)
      end,
      get_toggled_id = deps.get_toggled_id or function()
        return require("toggleterm.terminal").get_toggled_id()
      end,
      get_or_create = deps.get_or_create or function(id, dir, direction, name)
        return require("toggleterm.terminal").get_or_create_term(id, dir, direction, name)
      end,
      is_managed = deps.is_managed or function()
        return false
      end,
    },
  }

  function guard:toggle_command(args, count)
    local parsed = self.deps.parse(args)
    vim.validate({
      size = { parsed.size, "number", true },
      dir = { parsed.dir, "string", true },
      direction = { parsed.direction, "string", true },
      name = { parsed.name, "string", true },
    })
    local size = parsed.size and tonumber(parsed.size) or nil
    count = tonumber(count) or 0
    if count >= 1 then
      self.deps.toggle_counted(count, size, parsed.dir, parsed.direction, parsed.name)
      return
    end
    local has_open, windows = self.deps.find_open_windows(self.deps.is_managed)
    if has_open then
      self.deps.close_terminal_view(windows)
      return
    end
    if self.deps.open_terminal_view(size, parsed.direction) then
      return
    end
    local term = self.deps.get_or_create(self.deps.get_toggled_id(), parsed.dir, parsed.direction, parsed.name)
    if type(term) ~= "table" or type(term.open) ~= "function" then
      error("ToggleTerm did not create a local terminal", 0)
    end
    term:open(size, parsed.direction)
  end

  function guard:install()
    if self.installed then
      return true
    end
    if not self.deps.command_exists() or not self.deps.is_initialized() then
      return nil,
        integration_error(
          "toggleterm_not_initialized",
          "ToggleTerm must be initialized before the workspace adapter is used"
        )
    end
    local ok, err = pcall(self.deps.create_command, function(opts)
      self:toggle_command(opts.args, opts.count)
    end, self.deps.complete)
    if not ok then
      return nil,
        integration_error("toggleterm_command_guard_failed", "failed to protect the local ToggleTerm command", {
          cause = tostring(err),
        })
    end
    self.installed = true
    return true
  end

  return guard
end

local Controller = {}
Controller.__index = Controller

local function new_controller(deps)
  deps = deps or {}
  local managed_terminal_id = deps.managed_terminal_id
  if managed_terminal_id == nil then
    -- Injected factories in unit tests need no upstream registry allocation.
    managed_terminal_id = deps.terminal_new and function()
      return nil
    end or default_managed_terminal_id
  end
  return setmetatable({
    deps = {
      resolve = deps.resolve or default_resolve,
      terminal_new = deps.terminal_new or default_terminal_new,
      managed_terminal_id = managed_terminal_id,
      is_alive = deps.is_alive or default_is_alive,
      open_terminal = deps.open_terminal or default_open_terminal,
      current_tab = deps.current_tab or vim.api.nvim_get_current_tabpage,
      current_buf = deps.current_buf or vim.api.nvim_get_current_buf,
      notify = deps.notify or default_notify,
      stamp = deps.stamp or default_stamp,
      jobstop = deps.jobstop or vim.fn.jobstop,
    },
    records = {},
    next_generation = 0,
  }, Controller)
end

local function safe_callback(callback, err, term)
  if type(callback) ~= "function" then
    return
  end
  local ok, callback_err = pcall(callback, err, term)
  if not ok then
    vim.schedule(function()
      vim.notify("nrm ToggleTerm callback failed: " .. tostring(callback_err), vim.log.levels.ERROR)
    end)
  end
end

function Controller:_notify_error(err)
  local message = type(err) == "table" and err.message or tostring(err)
  if type(err) == "table" and type(err.details) == "table" and type(err.details.cause) == "string" then
    message = message .. ": " .. err.details.cause
  end
  self.deps.notify(message, vim.log.levels.ERROR)
end

function Controller:_scope(scope_id, create)
  local scope = self.records[scope_id]
  if not scope and create then
    scope = {}
    self.records[scope_id] = scope
  end
  return scope
end

function Controller:_remove(record)
  local scope = self.records[record.binding.scope_id]
  if scope and scope[record.key] == record then
    scope[record.key] = nil
    if next(scope) == nil then
      self.records[record.binding.scope_id] = nil
    end
  end
end

function Controller:_binding(query)
  local context, context_err = self.deps.resolve(query)
  if not context then
    return nil, context_err
  end
  local scope_id, scope_err = M.scope_id(context)
  if not scope_id then
    return nil, scope_err
  end
  return {
    context = context,
    scope_id = scope_id,
    provider = context.provider,
    workspace_id = context.workspace_id,
    authority_id = context.authority.id,
  }
end

function Controller:resolve(query)
  return self:_binding(query)
end

local function stamped_identity(value)
  if type(value) == "table" and type(value.__nrm_workspace_runtime) == "table" then
    return value.__nrm_workspace_runtime.scope_id, value.__nrm_workspace_runtime.key
  end
  if type(value) == "number" and vim.api.nvim_buf_is_valid(value) then
    return vim.b[value].nrm_workspace_runtime_scope, vim.b[value].nrm_workspace_runtime_key
  end
  return nil, nil
end

function Controller:lookup(value)
  local scope_id
  local key
  if type(value) == "table" and type(value.scope_id) == "string" and type(value.key) == "string" then
    scope_id = value.scope_id
    key = value.key
  else
    scope_id, key = stamped_identity(value)
  end
  local scope = scope_id and self.records[scope_id] or nil
  return scope and scope[key] or nil
end

function Controller:is_managed(value)
  return self:lookup(value) ~= nil
end

function Controller:_finish_callbacks(record, err, term)
  local callbacks = record.callbacks
  record.callbacks = {}
  for _, callback in ipairs(callbacks) do
    safe_callback(callback, err, term)
  end
end

function Controller:_dispose_terminal(term)
  if type(term) ~= "table" then
    return true
  end
  local shutdown_cause
  if type(term.shutdown) == "function" then
    local ok, err = pcall(term.shutdown, term)
    if ok then
      return true
    end
    shutdown_cause = tostring(err)
  end
  if type(term.job_id) == "number" and term.job_id > 0 then
    local ok, stopped = pcall(self.deps.jobstop, term.job_id)
    if ok and (stopped == 1 or stopped == true) then
      return true
    end
    return nil,
      integration_error("terminal_cleanup_failed", "failed to stop the ToggleTerm bridge", {
        shutdown_cause = shutdown_cause,
        jobstop_cause = ok and ("jobstop returned " .. tostring(stopped)) or tostring(stopped),
      })
  end
  if shutdown_cause then
    return nil,
      integration_error("terminal_cleanup_failed", "failed to shut down the ToggleTerm bridge", {
        shutdown_cause = shutdown_cause,
      })
  end
  return true
end

function Controller:_fail(record, err)
  local reported_err = err
  if record.term then
    local disposed, cleanup_err = self:_dispose_terminal(record.term)
    if disposed then
      self:_remove(record)
      record.term = nil
    else
      record.state = "cleanup_failed"
      record.cleanup_error = cleanup_err
      local details = type(err) == "table" and vim.deepcopy(err.details or {}) or {}
      details.cleanup_error = {
        code = cleanup_err.code,
        message = cleanup_err.message,
        details = cleanup_err.details,
      }
      reported_err = integration_error(
        type(err) == "table" and err.code or "terminal_cleanup_failed",
        (type(err) == "table" and err.message or tostring(err)) .. "; cleanup also failed",
        details
      )
      record.failure = reported_err
    end
  else
    self:_remove(record)
  end
  self:_notify_error(reported_err)
  self:_finish_callbacks(record, reported_err)
  return reported_err
end

function Controller:_on_exit(record, generation, ...)
  if record.generation ~= generation then
    return
  end
  self:_remove(record)
  local chained = record.chained_on_exit
  if type(chained) == "function" then
    local ok, err = pcall(chained, ...)
    if not ok then
      vim.schedule(function()
        vim.notify("ToggleTerm on_exit callback failed: " .. tostring(err), vim.log.levels.ERROR)
      end)
    end
  end
end

function Controller:_start(record, prepared)
  if self.deps.current_tab() ~= record.origin_tab then
    self:_fail(record, integration_error("stale_context", "terminal preparation completed in a different tab"))
    return
  end
  local context_current, current_err = record.binding.context:is_current()
  if not context_current then
    self:_fail(record, current_err or integration_error("stale_context", "workspace authority changed"))
    return
  end

  local bridge, bridge_err = prepared:job_spec({
    command = record.opts.command or { shell = "default" },
    cwd = record.opts.cwd or { space = "workspace", path = "" },
    env = record.opts.env,
    stdio = "pty",
    persistence = "attached",
    initial_size = record.opts.initial_size,
  })
  if not bridge then
    self:_fail(record, bridge_err)
    return
  end
  if type(bridge.command) ~= "string" or type(bridge.input) ~= "table" or type(bridge.input.newline) ~= "string" then
    self:_fail(record, integration_error("invalid_bridge", "workspace runtime returned an incomplete terminal bridge"))
    return
  end

  local terminal_env = bridge.env
  if terminal_env == nil or next(terminal_env) == nil then
    terminal_env = vim.empty_dict()
  end
  local terminal_opts = {
    -- IDs above the Ex count range keep raw ToggleTerm/TermExec counts from
    -- colliding without disturbing ToggleTerm's ordinary low-ID allocator.
    id = self.deps.managed_terminal_id(),
    cmd = bridge.command,
    dir = bridge.cwd,
    -- Override ToggleTerm-wide job settings so the validated bridge remains
    -- authoritative. An empty map with clear_env=false means ordinary
    -- inheritance, without injecting plugin-global additions.
    env = terminal_env,
    clear_env = bridge.clear_env == true,
    newline_chr = bridge.input.newline,
    direction = record.opts.direction,
    display_name = record.opts.display_name,
    -- Keep broker-owned terminals out of ordinary upstream listings. The
    -- reserved ID range and command guard isolate raw command behavior.
    hidden = true,
    close_on_exit = true,
  }
  local ok_new, term = pcall(self.deps.terminal_new, terminal_opts)
  if not ok_new or type(term) ~= "table" then
    self:_fail(
      record,
      integration_error("terminal_create_failed", "failed to create ToggleTerm terminal", {
        cause = tostring(term),
      })
    )
    return
  end

  record.term = term
  record.bridge_cwd = bridge.cwd
  record.state = "running"
  record.chained_on_exit = term.on_exit
  local generation = record.generation
  local controller = self
  term.on_exit = function(...)
    controller:_on_exit(record, generation, ...)
  end
  terminal_opts.on_exit = term.on_exit
  self.deps.stamp(term, record.binding.scope_id, record.key)
  local ok_open, open_err = pcall(self.deps.open_terminal, term, nil, record.opts.direction, record.bridge_cwd)
  if not ok_open then
    self:_fail(
      record,
      integration_error("terminal_open_failed", "failed to open ToggleTerm terminal", {
        cause = tostring(open_err),
      })
    )
    return
  end
  local ok_is_open, is_open = pcall(term.is_open, term)
  if not self.deps.is_alive(term) or not ok_is_open or is_open ~= true then
    self:_fail(record, integration_error("terminal_open_failed", "ToggleTerm terminal did not start"))
    return
  end
  self.deps.stamp(term, record.binding.scope_id, record.key)
  self:_finish_callbacks(record, nil, term)
end

function Controller:_begin(binding, opts, callback)
  self.next_generation = self.next_generation + 1
  local record = {
    state = "pending",
    binding = binding,
    key = opts.key,
    opts = vim.deepcopy(opts),
    callbacks = {},
    origin_tab = self.deps.current_tab(),
    generation = self.next_generation,
  }
  if callback then
    table.insert(record.callbacks, callback)
  end
  self:_scope(binding.scope_id, true)[opts.key] = record

  local accepted, prepare_err = binding.context:prepare("terminal", function(err, prepared)
    local scope = self.records[binding.scope_id]
    if not scope or scope[record.key] ~= record or record.state ~= "pending" then
      return
    end
    if err then
      self:_fail(record, err)
      return
    end
    self:_start(record, prepared)
  end)
  if accepted ~= true then
    self:_fail(
      record,
      prepare_err or integration_error("prepare_rejected", "workspace runtime rejected terminal preparation")
    )
    return nil, prepare_err
  end
  return true
end

function Controller:_operate_running(record, action, direction, callback)
  if not self.deps.is_alive(record.term) then
    self:_remove(record)
    return false
  end
  local is_open = record.term:is_open()
  if not (action == "toggle" and is_open) then
    local current, current_err = record.binding.context:is_current()
    if not current then
      local stale_err = self:_fail(
        record,
        current_err or integration_error("stale_context", "workspace authority changed; resolve it again")
      )
      safe_callback(callback, stale_err)
      return true
    end
  end
  if action == "toggle" and is_open then
    local ok, err = pcall(record.term.close, record.term)
    if not ok then
      local close_err = integration_error("terminal_close_failed", "failed to hide ToggleTerm terminal", {
        cause = tostring(err),
      })
      self:_notify_error(close_err)
      safe_callback(callback, close_err)
      return true
    end
  elseif is_open then
    local ok, err = pcall(record.term.focus, record.term)
    if not ok then
      local focus_err = integration_error("terminal_focus_failed", "failed to focus ToggleTerm terminal", {
        cause = tostring(err),
      })
      self:_notify_error(focus_err)
      safe_callback(callback, focus_err)
      return true
    end
  else
    local ok, err = pcall(self.deps.open_terminal, record.term, nil, direction, record.bridge_cwd)
    if not ok then
      local open_err = integration_error("terminal_open_failed", "failed to reopen ToggleTerm terminal", {
        cause = tostring(err),
      })
      open_err = self:_fail(record, open_err)
      safe_callback(callback, open_err)
      return true
    end
    local ok_is_open, reopened = pcall(record.term.is_open, record.term)
    if not self.deps.is_alive(record.term) or not ok_is_open or reopened ~= true then
      local open_err = integration_error("terminal_open_failed", "ToggleTerm terminal did not reopen")
      open_err = self:_fail(record, open_err)
      safe_callback(callback, open_err)
      return true
    end
  end
  safe_callback(callback, nil, record.term)
  return true
end

function Controller:_reject_cleanup_failed(record, callback)
  if record.state ~= "cleanup_failed" then
    return nil
  end
  local cleanup_err = record.cleanup_error
    or integration_error("terminal_cleanup_failed", "ToggleTerm bridge cleanup must be retried")
  self:_notify_error(cleanup_err)
  safe_callback(callback, cleanup_err)
  return cleanup_err
end

function Controller:_perform(action, opts, callback)
  if opts == nil then
    opts = {}
  end
  if type(opts) ~= "table" then
    return nil, integration_error("invalid_argument", "ToggleTerm integration options must be a table")
  end
  if callback ~= nil and type(callback) ~= "function" then
    return nil, integration_error("invalid_argument", "ToggleTerm integration callback must be a function")
  end
  local allowed = {
    key = true,
    direction = true,
    binding = true,
    query = true,
    cwd = true,
    command = true,
    env = true,
    initial_size = true,
    display_name = true,
    hidden = true,
  }
  for field in next, opts do
    if not allowed[field] then
      return nil, integration_error("invalid_argument", "unknown ToggleTerm integration option: " .. tostring(field))
    end
  end
  local key = opts.key
  if key == nil then
    key = "shell"
  end
  if not valid_key(key) then
    return nil, integration_error("invalid_argument", "ToggleTerm integration key must be control-free text")
  end
  local direction = opts.direction
  if
    direction ~= nil
    and direction ~= "float"
    and direction ~= "horizontal"
    and direction ~= "vertical"
    and direction ~= "tab"
  then
    return nil, integration_error("invalid_argument", "ToggleTerm direction is invalid")
  end
  if opts.hidden ~= nil and opts.hidden ~= true then
    return nil,
      integration_error("invalid_argument", "managed ToggleTerm terminals must remain hidden from upstream commands")
  end
  if
    opts.display_name ~= nil
    and (
      type(opts.display_name) ~= "string"
      or opts.display_name == ""
      or #opts.display_name > 1024
      or opts.display_name:find("[%z\1-\31\127]") ~= nil
    )
  then
    return nil, integration_error("invalid_argument", "ToggleTerm display_name must be control-free text")
  end
  local provided_binding = opts.binding
  local provided_query = opts.query
  opts = {
    key = key,
    direction = direction,
    cwd = vim.deepcopy(opts.cwd),
    command = vim.deepcopy(opts.command),
    env = vim.deepcopy(opts.env),
    initial_size = vim.deepcopy(opts.initial_size),
    display_name = opts.display_name,
    hidden = opts.hidden,
  }

  local managed = self:lookup(self.deps.current_buf())
  if managed and managed.key == key and provided_binding == nil and provided_query == nil then
    local cleanup_err = self:_reject_cleanup_failed(managed, callback)
    if cleanup_err then
      return nil, cleanup_err
    end
    if managed.state == "pending" then
      managed.opts.direction = opts.direction or managed.opts.direction
      if callback then
        table.insert(managed.callbacks, callback)
      end
      return true
    end
    if self:_operate_running(managed, action, opts.direction, callback) then
      return true
    end
  end

  local binding = provided_binding
  if binding == nil then
    local binding_err
    binding, binding_err = self:_binding(provided_query)
    if not binding then
      self:_notify_error(binding_err)
      safe_callback(callback, binding_err)
      return nil, binding_err
    end
  end
  if type(binding) ~= "table" or type(binding.scope_id) ~= "string" or type(binding.context) ~= "table" then
    return nil, integration_error("invalid_argument", "ToggleTerm integration binding is invalid")
  end
  local expected_scope, scope_err = M.scope_id(binding.context)
  if not expected_scope then
    return nil, scope_err
  end
  if binding.scope_id ~= expected_scope then
    return nil,
      integration_error("invalid_argument", "ToggleTerm integration binding authority does not match its scope")
  end

  local scope = self:_scope(binding.scope_id, false)
  local record = scope and scope[key] or nil
  if record then
    local cleanup_err = self:_reject_cleanup_failed(record, callback)
    if cleanup_err then
      return nil, cleanup_err
    end
    if record.state == "pending" then
      record.opts.direction = opts.direction or record.opts.direction
      if callback then
        table.insert(record.callbacks, callback)
      end
      return true
    end
    if self:_operate_running(record, action, opts.direction, callback) then
      return true
    end
  end
  return self:_begin(binding, opts, callback)
end

function Controller:toggle(opts, callback)
  return self:_perform("toggle", opts, callback)
end

function Controller:open(opts, callback)
  return self:_perform("open", opts, callback)
end

function Controller:shutdown(opts)
  opts = opts or {}
  if type(opts) ~= "table" or not valid_key(opts.key) then
    return nil, integration_error("invalid_argument", "shutdown requires a valid logical terminal key")
  end
  local scope_id = opts.scope_id or (opts.binding and opts.binding.scope_id)
  if type(scope_id) ~= "string" then
    return nil, integration_error("invalid_argument", "shutdown requires a binding or scope_id")
  end
  local record = self:lookup({ scope_id = scope_id, key = opts.key })
  if not record then
    return true
  end
  if record.state == "pending" then
    self:_remove(record)
    local err = integration_error("cancelled", "pending terminal launch was cancelled")
    self:_finish_callbacks(record, err)
    return true
  end
  local disposed, dispose_err = self:_dispose_terminal(record.term)
  if not disposed then
    return nil,
      integration_error("terminal_shutdown_failed", "failed to shut down ToggleTerm terminal", {
        cause = dispose_err.message,
        cleanup_error = dispose_err,
      })
  end
  self:_remove(record)
  record.term = nil
  return true
end

local controller = new_controller()
local local_command_guard = new_local_command_guard({
  is_managed = function(term)
    return controller:is_managed(term)
  end,
})

local function ensure_local_command_guard()
  local ok, err = local_command_guard:install()
  if not ok then
    controller:_notify_error(err)
    return nil, err
  end
  return true
end

function M.resolve(query)
  return controller:resolve(query)
end

function M.toggle(opts, callback)
  local ok, err = ensure_local_command_guard()
  if not ok then
    safe_callback(callback, err)
    return nil, err
  end
  return controller:toggle(opts, callback)
end

function M.open(opts, callback)
  local ok, err = ensure_local_command_guard()
  if not ok then
    safe_callback(callback, err)
    return nil, err
  end
  return controller:open(opts, callback)
end

function M.shutdown(opts)
  return controller:shutdown(opts)
end

function M.lookup(value)
  return controller:lookup(value)
end

function M.is_managed(value)
  return controller:is_managed(value)
end

M._test = {
  new_controller = new_controller,
  new_local_command_guard = new_local_command_guard,
  default_managed_terminal_id = default_managed_terminal_id,
  default_open_terminal = default_open_terminal,
}

return M
