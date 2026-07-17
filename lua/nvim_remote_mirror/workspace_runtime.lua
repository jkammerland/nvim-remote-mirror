local workspace = require("nvim_remote_mirror.workspace")

local M = {}

local ERROR_MT = {
  __tostring = function(err)
    return err.message
  end,
}

local tab_bindings = {}
local tab_binding_revisions = {}
local tab_optout_revisions = {}
local local_cwd_revisions = {}
local next_local_cwd_revision = 0
local context_records = setmetatable({}, { __mode = "k" })
local prepared_records = setmetatable({}, { __mode = "k" })

local function runtime_error(code, message, details)
  return setmetatable({
    code = code,
    message = message,
    details = details,
  }, ERROR_MT)
end

local function copy(value)
  return vim.deepcopy(value)
end

local function is_integer(value)
  return type(value) == "number" and value == math.floor(value)
end

local function current_tabpage()
  return vim.api.nvim_get_current_tabpage()
end

local function valid_tabpage(tabpage)
  return type(tabpage) == "number" and vim.api.nvim_tabpage_is_valid(tabpage)
end

local function binding_revision(tabpage)
  return tab_binding_revisions[tabpage] or 0
end

local function optout_revision(tabpage)
  return tab_optout_revisions[tabpage] or 0
end

local function local_cwd_revision(tabpage)
  return local_cwd_revisions[tabpage] or 0
end

local function advance_local_cwd_revision(tabpage)
  next_local_cwd_revision = next_local_cwd_revision + 1
  local_cwd_revisions[tabpage] = next_local_cwd_revision
  return next_local_cwd_revision
end

local function advance_binding_revision(tabpage)
  tab_binding_revisions[tabpage] = binding_revision(tabpage) + 1
end

local function tabpage_cwd(tabpage)
  if not valid_tabpage(tabpage) then
    return nil
  end
  local tabnr = vim.api.nvim_tabpage_get_number(tabpage)
  local ok, cwd = pcall(vim.fn.getcwd, -1, tabnr)
  if not ok or type(cwd) ~= "string" or cwd == "" then
    return nil
  end
  local style = vim.fn.has("win32") == 1 and "windows" or "posix"
  return workspace._normalize_absolute(cwd, style)
end

local function host_metadata()
  local uname = vim.uv.os_uname()
  local sysname = tostring(uname.sysname or ""):lower()
  local windows = sysname:find("windows", 1, true) ~= nil
  local os_name
  if windows then
    os_name = "windows"
  elseif sysname:find("darwin", 1, true) then
    os_name = "macos"
  elseif sysname:find("linux", 1, true) then
    os_name = "linux"
  else
    os_name = sysname ~= "" and sysname or nil
  end
  return {
    os = os_name,
    arch = tostring(uname.machine or "") ~= "" and tostring(uname.machine) or nil,
    path_style = windows and "windows" or "posix",
    shell = vim.o.shell,
  }
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

local function path_equal(left, right, path_style)
  if path_style == "windows" then
    return left:lower() == right:lower()
  end
  return left == right
end

local function relative_within(root, path, path_style)
  return workspace._relative_within(root, path, path_style)
end

local function absolute_local_path(root, path, path_style)
  local normalized_separators = path_style == "windows" and path:gsub("\\", "/") or path
  local absolute_like = normalized_separators:sub(1, 1) == "/"
    or (path_style == "windows" and normalized_separators:match("^%a:") ~= nil)
  if absolute_like then
    return workspace._normalize_absolute(path, path_style)
  end
  return workspace._join_absolute(root, path, path_style)
end

local function local_descriptor(tabpage, query)
  local root = tabpage_cwd(tabpage)
  if not root then
    return nil, runtime_error("workspace_not_found", "local tab working directory is unavailable")
  end
  local host = host_metadata()
  local identity_root = host.path_style == "windows" and root:lower() or root
  local workspace_id = "local-" .. hash(host.path_style .. "\30" .. identity_root)
  if query.workspace_id ~= nil or query.workspace_key ~= nil then
    local requested = query.workspace_id or query.workspace_key
    if requested ~= workspace_id then
      return nil, runtime_error("workspace_not_found", "local workspace is not known")
    end
  end

  local relative_path
  if query.bufnr ~= nil then
    if type(query.bufnr) ~= "number" or not vim.api.nvim_buf_is_valid(query.bufnr) then
      return nil, runtime_error("invalid_argument", "bufnr must identify a valid buffer")
    end
    local name = vim.api.nvim_buf_get_name(query.bufnr)
    if name ~= "" then
      local absolute_name = absolute_local_path(root, name, host.path_style)
      if absolute_name then
        relative_path = relative_within(root, absolute_name, host.path_style)
      end
    end
  elseif query.path ~= nil then
    if type(query.path) ~= "string" or query.path == "" then
      return nil, runtime_error("invalid_argument", "path must be a non-empty string")
    end
    local absolute_path = absolute_local_path(root, query.path, host.path_style)
    relative_path = absolute_path and relative_within(root, absolute_path, host.path_style) or nil
    if relative_path == nil then
      return nil, runtime_error("workspace_not_found", "path is outside the local tab workspace")
    end
  end

  return {
    api_version = workspace.API_VERSION,
    provider = "local",
    workspace_id = workspace_id,
    epoch = local_cwd_revision(tabpage),
    state = "online",
    mode = "local",
    authority = {
      id = workspace_id,
      kind = "local",
      label = "local",
      path_style = host.path_style,
      os = host.os,
      arch = host.arch,
      shell = host.shell,
    },
    roots = {
      editor = root,
      authority = root,
    },
    support = { process = true, terminal = true, watch = false },
    relative_path = relative_path,
    _tabpage = tabpage,
    _cwd = root,
  }
end

local function local_error(code, message, details)
  return { code = code, message = message, details = details }
end

local function local_environment(request, windows)
  local changes = request.env
  local has_changes = changes.clear == true or next(changes.set) ~= nil or #changes.unset > 0
  if not has_changes then
    return nil, nil
  end
  local env = changes.clear and vim.empty_dict() or vim.fn.environ()
  local function remove(name)
    if windows then
      for key in next, env do
        if key:lower() == name:lower() then
          env[key] = nil
        end
      end
    else
      env[name] = nil
    end
  end
  for _, name in ipairs(changes.unset) do
    remove(name)
  end
  for name, value in next, changes.set do
    remove(name)
    env[name] = value
  end
  return env, true
end

local function local_argv(snapshot, request)
  if request.command.argv then
    return copy(request.command.argv)
  end
  return { snapshot.authority.shell }
end

local function join_local_cwd(snapshot, relative)
  return workspace._join_absolute(snapshot.roots.authority, relative, snapshot.authority.path_style)
end

local function local_job_spec(snapshot, request)
  if request.persistence == "detached" then
    return nil,
      local_error(
        "persistence_unavailable",
        "detachable local terminals are unavailable until the persistent runtime broker is implemented"
      )
  end
  local windows = snapshot.authority.path_style == "windows"
  local env, clear_env = local_environment(request, windows)
  local cwd, cwd_err = join_local_cwd(snapshot, request.cwd.path)
  if not cwd then
    return nil, local_error("invalid_path", "failed to resolve the local runtime cwd", {
      cause = cwd_err,
    })
  end
  return {
    argv = local_argv(snapshot, request),
    cwd = cwd,
    env = env,
    clear_env = clear_env,
  }
end

local function deliver_handler(handlers, name, ...)
  local handler = handlers[name]
  if type(handler) ~= "function" then
    return
  end
  local ok, err = pcall(handler, ...)
  if not ok then
    vim.schedule(function()
      vim.notify("local workspace runtime callback failed: " .. tostring(err), vim.log.levels.ERROR)
    end)
  end
end

local function start_local_process(snapshot, request, handlers)
  if request.persistence == "detached" then
    return nil,
      local_error(
        "persistence_unavailable",
        "detachable local terminals are unavailable until the persistent runtime broker is implemented"
      )
  end
  if
    request.stdio == "pty"
    and request.initial_size
    and (request.initial_size.pixel_width ~= nil or request.initial_size.pixel_height ~= nil)
  then
    return nil, local_error("unsupported", "local managed PTYs do not support pixel dimensions")
  end
  local spec, spec_err = local_job_spec(snapshot, request)
  if not spec then
    return nil, spec_err
  end
  local exited = false
  local closed_stdin = false
  local job_id
  local output_bytes = 0
  local termination_result = nil
  local timeout_timer = nil

  local function close_timeout_timer()
    if timeout_timer and not timeout_timer:is_closing() then
      timeout_timer:stop()
      timeout_timer:close()
    end
    timeout_timer = nil
  end

  local function stop_with_result(kind, error_code, message, output_truncated)
    if exited or termination_result then
      return
    end
    termination_result = {
      schema_version = 1,
      kind = kind,
      error_code = error_code,
      message = message,
      output_truncated = output_truncated == true,
    }
    if job_id then
      pcall(vim.fn.jobstop, job_id)
    end
  end

  local function line_list_bytes(data)
    if type(data) ~= "table" then
      return 0
    end
    local bytes = math.max(#data - 1, 0)
    for _, line in ipairs(data) do
      if type(line) == "string" then
        bytes = bytes + #line
      end
    end
    return bytes
  end

  local function deliver_output(name, id, data, event)
    if request.stdio == "pipe" then
      output_bytes = output_bytes + line_list_bytes(data)
      if output_bytes > request.max_output_bytes then
        stop_with_result("output_limit", "output_limit", "local workspace process exceeded its output limit", true)
        return
      end
    end
    if not termination_result then
      deliver_handler(handlers, name, id, data, event)
    end
  end

  local options = {
    cwd = spec.cwd,
    env = spec.env,
    clear_env = spec.clear_env,
    stdout_buffered = false,
    stderr_buffered = false,
    on_stdout = function(id, data, event)
      deliver_output("on_stdout", id, data, event)
    end,
    on_stderr = function(id, data, event)
      deliver_output("on_stderr", id, data, event)
    end,
    on_exit = function(id, code, event)
      exited = true
      close_timeout_timer()
      local result = termination_result
        or {
          schema_version = 1,
          kind = "process_exit",
          exit_code = code,
          output_truncated = false,
        }
      result.exit_code = code
      deliver_handler(handlers, "on_exit", id, code, event, result)
    end,
  }
  if request.stdio == "pty" then
    options.pty = true
    options.width = request.initial_size.cols
    options.height = request.initial_size.rows
  end
  local ok, started = pcall(vim.fn.jobstart, spec.argv, options)
  if not ok then
    return nil, local_error("spawn_failed", "failed to start local workspace process", { cause = tostring(started) })
  end
  job_id = tonumber(started)
  if not job_id or job_id <= 0 then
    return nil, local_error("spawn_failed", "failed to start local workspace process", { job_id = started })
  end
  if request.timeout_ms then
    timeout_timer = vim.uv.new_timer()
    timeout_timer:start(request.timeout_ms, 0, function()
      vim.schedule(function()
        stop_with_result("timed_out", "timeout", "local workspace process timed out", false)
      end)
    end)
  end

  local function running()
    if exited then
      return nil, local_error("process_exited", "local workspace process has already exited")
    end
    return true
  end

  local handle = {}
  function handle:write(data)
    local active, active_err = running()
    if not active then
      return nil, active_err
    end
    if type(data) ~= "string" then
      return nil, local_error("invalid_argument", "runtime input must be a string")
    end
    if closed_stdin then
      return nil, local_error("input_closed", "local runtime input is closed")
    end
    local sent = vim.fn.chansend(job_id, data)
    if tonumber(sent) == nil or sent <= 0 then
      return nil, local_error("input_failed", "failed to write local runtime input")
    end
    return sent
  end
  function handle:close_stdin()
    if closed_stdin then
      return true
    end
    closed_stdin = true
    local ok_close, close_err = pcall(vim.fn.chanclose, job_id, "stdin")
    if not ok_close then
      return nil, local_error("input_failed", "failed to close local runtime input", { cause = tostring(close_err) })
    end
    return true
  end
  function handle:signal(signal)
    local active, active_err = running()
    if not active then
      return nil, active_err
    end
    local signals = { interrupt = 2, terminate = 15, kill = 9, hangup = 1 }
    local number = signals[signal]
    if not number then
      return nil, local_error("invalid_argument", "unknown runtime signal")
    end
    local pid = tonumber(vim.fn.jobpid(job_id))
    local ok_kill, killed = false, nil
    if pid then
      ok_kill, killed = pcall(vim.uv.kill, pid, number)
    end
    if not ok_kill or killed == nil then
      local ok_stop, stopped = pcall(vim.fn.jobstop, job_id)
      if not ok_stop or stopped ~= 1 then
        return nil, local_error("signal_failed", "failed to signal local runtime process")
      end
    end
    return true
  end
  function handle:kill()
    if exited then
      return true
    end
    local ok_stop, stopped = pcall(vim.fn.jobstop, job_id)
    if not ok_stop or stopped ~= 1 then
      return nil, local_error("signal_failed", "failed to stop local runtime process")
    end
    return true
  end
  function handle:resize(size)
    local active, active_err = running()
    if not active then
      return nil, active_err
    end
    if
      type(size) ~= "table"
      or not is_integer(size.cols)
      or not is_integer(size.rows)
      or size.cols < 1
      or size.rows < 1
      or size.cols > 32767
      or size.rows > 32767
    then
      return nil, local_error("invalid_argument", "terminal size is invalid")
    end
    local ok_resize, resized = pcall(vim.fn.jobresize, job_id, size.cols, size.rows)
    if not ok_resize or resized ~= 1 then
      return nil, local_error("resize_failed", "failed to resize local runtime terminal")
    end
    return true
  end
  return handle
end

local function local_provider(tabpage)
  return {
    resolve = function(query)
      return local_descriptor(tabpage, query)
    end,
    current_epoch = function(snapshot)
      local cwd = tabpage_cwd(snapshot._tabpage)
      local revision = local_cwd_revision(snapshot._tabpage)
      if not cwd or not path_equal(cwd, snapshot._cwd, snapshot.authority.path_style) then
        -- DirChanged normally advances the generation. Keep this check as a
        -- fail-closed backstop for cwd changes made without that event.
        if revision == snapshot.epoch then
          revision = advance_local_cwd_revision(snapshot._tabpage)
        end
      end
      return revision
    end,
    current_state = function(snapshot)
      return valid_tabpage(snapshot._tabpage) and "online" or "offline"
    end,
    is_trusted = function()
      return true
    end,
    authorize = function(_, _, callback)
      callback(nil, true)
      return true
    end,
    capability_status = function(snapshot, capability)
      local supported = snapshot.support[capability] == true
      return {
        name = capability,
        state = supported and "ready" or "unsupported",
        supported = supported,
        enabled = true,
        effective = supported,
        revision = 0,
      }
    end,
    prepare_capability = function(_, _, callback)
      callback(nil)
      return true
    end,
    job_spec = local_job_spec,
    spawn = start_local_process,
  }
end

local function prune_closed_tabs()
  local tabpages = {}
  for tabpage in next, tab_bindings do
    tabpages[tabpage] = true
  end
  for tabpage in next, tab_binding_revisions do
    tabpages[tabpage] = true
  end
  for tabpage in next, tab_optout_revisions do
    tabpages[tabpage] = true
  end
  for tabpage in next, local_cwd_revisions do
    tabpages[tabpage] = true
  end
  for tabpage in next, tabpages do
    if not valid_tabpage(tabpage) then
      tab_bindings[tabpage] = nil
      tab_binding_revisions[tabpage] = nil
      tab_optout_revisions[tabpage] = nil
      local_cwd_revisions[tabpage] = nil
    end
  end
end

function M._prune_closed_tabs()
  prune_closed_tabs()
end

function M._capture_binding_token(tabpage)
  tabpage = tabpage or current_tabpage()
  if not valid_tabpage(tabpage) then
    return nil, runtime_error("invalid_argument", "tabpage must identify a valid tab")
  end
  return {
    tabpage = tabpage,
    revision = optout_revision(tabpage),
  }
end

function M._bind_connected(token)
  if type(token) ~= "table" or not valid_tabpage(token.tabpage) then
    return false
  end
  if token.revision ~= optout_revision(token.tabpage) then
    return false
  end
  local identity = workspace._capture_active_identity()
  if not identity then
    return nil, runtime_error("workspace_not_found", "connected remote workspace identity is unavailable")
  end
  tab_bindings[token.tabpage] = { identity = identity }
  advance_binding_revision(token.tabpage)
  return true
end

function M._bind_tab_context(tabpage, context)
  if not valid_tabpage(tabpage) then
    return nil, runtime_error("invalid_argument", "tabpage must identify a valid tab")
  end
  if type(context) ~= "table" or context.provider ~= "nrm" then
    return nil, runtime_error("invalid_argument", "tab binding requires an NRM workspace context")
  end
  tab_bindings[tabpage] = { context = context }
  advance_binding_revision(tabpage)
  return true
end

function M.use_local(tabpage)
  tabpage = tabpage or current_tabpage()
  if not valid_tabpage(tabpage) then
    return nil, runtime_error("invalid_argument", "tabpage must identify a valid tab")
  end
  tab_bindings[tabpage] = nil
  tab_optout_revisions[tabpage] = optout_revision(tabpage) + 1
  advance_binding_revision(tabpage)
  return true
end

function M._binding_for_test(tabpage)
  return tab_bindings[tabpage]
end

local function resolve_binding(tabpage)
  local binding = tab_bindings[tabpage]
  if not binding then
    return nil, runtime_error("workspace_not_found", "tab has no remote workspace binding")
  end
  if binding.identity then
    return workspace._resolve_captured_identity(binding.identity)
  end
  return binding.context
end

local function strip_authority(query)
  local result = copy(query)
  result.authority = nil
  return result
end

local function validate_broker_query(query)
  if query == nil then
    query = {}
  end
  if type(query) ~= "table" then
    return nil, runtime_error("invalid_argument", "workspace runtime query must be a table")
  end
  local allowed = { authority = true, bufnr = true, path = true, workspace_id = true, workspace_key = true }
  for key in next, query do
    if not allowed[key] then
      return nil, runtime_error("invalid_argument", "unknown workspace runtime query field: " .. tostring(key))
    end
  end
  local authority = query.authority
  if authority == nil then
    authority = "auto"
  end
  if authority ~= "auto" and authority ~= "local" and authority ~= "remote" then
    return nil, runtime_error("invalid_argument", "authority must be auto, local, or remote")
  end
  local selectors = 0
  for _, field in ipairs({ "bufnr", "path", "workspace_id", "workspace_key" }) do
    if query[field] ~= nil then
      selectors = selectors + 1
    end
  end
  if selectors > 1 then
    return nil, runtime_error("invalid_argument", "workspace runtime query accepts at most one selector")
  end
  local result = copy(query)
  result.authority = authority
  return result
end

local function is_absence_error(err)
  return type(err) == "table" and (err.code == "not_remote_buffer" or err.code == "workspace_not_found")
end

local function remote_buffer_context(bufnr)
  local context, err = workspace._resolve_owned_buffer(bufnr)
  if context then
    return context
  end
  -- Once a buffer carries NRM ownership evidence, an incomplete or stale
  -- identity must fail closed. Only a definitive non-remote result permits
  -- the broker to continue to a tab binding or local authority.
  if type(err) == "table" and err.code == "not_remote_buffer" then
    return nil, nil
  end
  return nil, err
end

local function select_context(query, tabpage)
  local authority = query.authority
  local provider_query = strip_authority(query)
  if provider_query.bufnr == 0 then
    provider_query.bufnr = vim.api.nvim_get_current_buf()
  end
  if authority == "local" then
    if provider_query.workspace_id ~= nil or provider_query.workspace_key ~= nil then
      return nil, runtime_error("invalid_argument", "local authority does not accept a remote workspace identity")
    end
    local context, err = workspace._resolve_with_provider(local_provider(tabpage), provider_query)
    return context, "explicit_local", err
  end

  if provider_query.workspace_id ~= nil or provider_query.workspace_key ~= nil then
    local context, err = workspace.resolve(provider_query)
    return context, "explicit", err
  end

  if provider_query.path ~= nil then
    local context, err = workspace.resolve(provider_query)
    if context then
      return context, "explicit"
    end
    if not is_absence_error(err) then
      return nil, "explicit", err
    end
    if tab_bindings[tabpage] then
      local bound, bound_err = resolve_binding(tabpage)
      return bound, "tab", bound_err
    end
    if authority == "remote" then
      local active, active_err = workspace.resolve({})
      return active, "explicit", active_err
    end
    local local_context, local_err = workspace._resolve_with_provider(local_provider(tabpage), provider_query)
    return local_context, "local", local_err
  end

  local bufnr = provider_query.bufnr
  local implicit_buffer = bufnr == nil
  if bufnr == nil then
    bufnr = vim.api.nvim_get_current_buf()
  end
  local from_buffer, buffer_err = remote_buffer_context(bufnr)
  if from_buffer then
    return from_buffer, "buffer", nil, implicit_buffer and bufnr or nil, bufnr
  end
  if buffer_err then
    return nil, "buffer", buffer_err
  end
  if tab_bindings[tabpage] then
    local bound, bound_err = resolve_binding(tabpage)
    return bound, "tab", bound_err, nil, implicit_buffer and nil or bufnr, implicit_buffer
  end
  if authority == "remote" then
    local active, active_err = workspace.resolve({})
    return active, "explicit", active_err, nil, implicit_buffer and nil or bufnr
  end
  provider_query.bufnr = bufnr
  local local_context, local_err = workspace._resolve_with_provider(local_provider(tabpage), provider_query)
  return local_context, "local", local_err, nil, implicit_buffer and nil or bufnr, implicit_buffer
end

local function newline_for(context)
  local shell = tostring(context.authority.shell or ""):lower()
  if context.authority.path_style == "windows" then
    if shell:find("pwsh", 1, true) or shell:find("powershell", 1, true) then
      return "\r"
    end
    return "\r\n"
  end
  local shell_name = shell:match("[^/\\]+$") or shell
  if shell_name == "nu" or shell_name == "nushell" or shell_name:match("^nu[.]exe$") then
    return "\r"
  end
  return "\n"
end

local function enrich_bridge(context, bridge)
  local result = copy(bridge)
  local authority = context.authority
  result.authority = {
    id = authority.id,
    kind = authority.kind,
    label = authority.label,
    path_style = authority.path_style,
    os = authority.os,
    arch = authority.arch,
    shell = authority.shell,
    target = authority.target,
    workspace_id = context.workspace_id,
    epoch = context.epoch,
  }
  result.input = { newline = newline_for(context) }
  return result
end

local BrokerContext = {}
local BrokerPrepared = {}

local function context_record(context)
  local record = context_records[context]
  if not record then
    error("invalid workspace runtime broker context", 2)
  end
  return record
end

local function same_selected_authority(left, right)
  local left_fingerprint = workspace._selection_fingerprint(left)
  local right_fingerprint = workspace._selection_fingerprint(right)
  return left_fingerprint ~= nil and right_fingerprint ~= nil and vim.deep_equal(left_fingerprint, right_fingerprint)
end

local function selection_current(record)
  local selection = record.selection
  if not valid_tabpage(selection.tabpage) then
    return nil, runtime_error("stale_context", "workspace authority selection belongs to a closed tab")
  end
  if selection.source == "tab" or selection.source == "local" then
    if binding_revision(selection.tabpage) ~= selection.binding_revision then
      return nil, runtime_error("stale_context", "workspace authority selection changed; resolve it again")
    end
  end
  if selection.implicit_bufnr ~= nil then
    if current_tabpage() ~= selection.tabpage or vim.api.nvim_get_current_buf() ~= selection.implicit_bufnr then
      return nil, runtime_error("stale_context", "current buffer authority changed; resolve it again")
    end
  end
  if selection.implicit_selection then
    if current_tabpage() ~= selection.tabpage then
      return nil, runtime_error("stale_context", "implicit workspace authority selection moved to another tab")
    end
    local selected, selected_err = remote_buffer_context(vim.api.nvim_get_current_buf())
    if selected_err then
      return nil,
        runtime_error("stale_context", "current buffer has invalid remote authority state", {
          cause = selected_err,
        })
    end
    if selection.source == "tab" and selected and not same_selected_authority(selected, record.context) then
      return nil, runtime_error("stale_context", "current buffer changed the selected remote authority")
    end
    if selection.source == "local" and selected then
      return nil, runtime_error("stale_context", "current buffer became remote-owned; resolve it again")
    end
  end
  if selection.local_bufnr ~= nil then
    if not vim.api.nvim_buf_is_valid(selection.local_bufnr) then
      return nil, runtime_error("stale_context", "selected local buffer is no longer available")
    end
    if
      selection.local_implicit
      and (current_tabpage() ~= selection.tabpage or vim.api.nvim_get_current_buf() ~= selection.local_bufnr)
    then
      return nil, runtime_error("stale_context", "current local buffer changed; resolve it again")
    end
    local current_local, local_err = local_descriptor(selection.tabpage, { bufnr = selection.local_bufnr })
    if not current_local or current_local.relative_path ~= selection.local_relative_path then
      return nil,
        runtime_error("stale_context", "selected local buffer path changed; resolve it again", {
          cause = local_err,
        })
    end
  end
  if selection.selected_bufnr ~= nil then
    if not vim.api.nvim_buf_is_valid(selection.selected_bufnr) then
      return nil, runtime_error("stale_context", "selected buffer authority is no longer available")
    end
    local selected, selected_err = remote_buffer_context(selection.selected_bufnr)
    if selected_err then
      return nil,
        runtime_error("stale_context", "selected buffer has invalid remote authority state", {
          cause = selected_err,
        })
    end
    if selection.source == "buffer" and (not selected or not same_selected_authority(selected, record.context)) then
      return nil, runtime_error("stale_context", "remote buffer authority changed; resolve it again")
    end
    if selection.source ~= "buffer" and selected then
      if selection.source == "local" then
        return nil, runtime_error("stale_context", "selected buffer became remote-owned; resolve it again")
      end
      if not same_selected_authority(selected, record.context) then
        return nil, runtime_error("stale_context", "selected buffer changed the workspace authority")
      end
    end
  end
  local current, current_err = record.context:is_current()
  if not current then
    return nil, current_err
  end
  return true
end

local function guarded_context(context)
  local record = context_record(context)
  local current, current_err = selection_current(record)
  if not current then
    return nil, current_err
  end
  return record
end

function BrokerContext:supports(capability)
  return context_record(self).context:supports(capability)
end

function BrokerContext:capability_status(capability)
  local record, current_err = guarded_context(self)
  if not record then
    return nil, current_err
  end
  return record.context:capability_status(capability)
end

function BrokerContext:is_current()
  local current, current_err = selection_current(context_record(self))
  return current == true, current_err
end

function BrokerContext:authorize(capability, callback)
  if type(callback) ~= "function" then
    return nil, runtime_error("invalid_argument", "authorize requires a callback")
  end
  local record, current_err = guarded_context(self)
  if not record then
    return nil, current_err
  end
  return record.context:authorize(capability, function(err, granted)
    local still_current, stale_err = selection_current(record)
    if not still_current then
      callback(stale_err, false)
      return
    end
    callback(err, granted == true)
  end)
end

local function prepared_record(prepared)
  local record = prepared_records[prepared]
  if not record then
    error("invalid prepared workspace runtime broker", 2)
  end
  return record
end

local function guarded_prepared(prepared)
  local record = prepared_record(prepared)
  local context, current_err = guarded_context(record.context)
  if context then
    return record
  end
  if type(current_err) == "table" and current_err.code == "stale_context" then
    return nil,
      runtime_error("stale_preparation", "prepared workspace runtime selection is stale", {
        cause = current_err,
      })
  end
  return nil, current_err
end

local PREPARED_MT

local function wrap_prepared(context, prepared)
  local wrapper = setmetatable({}, PREPARED_MT)
  prepared_records[wrapper] = {
    context = context,
    prepared = prepared,
  }
  return wrapper
end

function BrokerContext:prepare(capability, callback)
  if type(callback) ~= "function" then
    return nil, runtime_error("invalid_argument", "prepare requires a callback")
  end
  local record, current_err = guarded_context(self)
  if not record then
    return nil, current_err
  end
  return record.context:prepare(capability, function(err, prepared)
    local still_current, stale_err = selection_current(record)
    if not still_current then
      callback(stale_err)
      return
    end
    if err then
      callback(err)
      return
    end
    callback(nil, wrap_prepared(self, prepared))
  end)
end

function BrokerContext:map_path(path, opts)
  local record, current_err = guarded_context(self)
  if not record then
    return nil, current_err
  end
  return record.context:map_path(path, opts)
end

function BrokerContext:job_spec(opts)
  local record, current_err = guarded_context(self)
  if not record then
    return nil, current_err
  end
  local bridge, bridge_err = record.context:job_spec(opts)
  if not bridge then
    return nil, bridge_err
  end
  return enrich_bridge(self, bridge)
end

function BrokerContext:spawn(opts, handlers)
  local record, current_err = guarded_context(self)
  if not record then
    return nil, current_err
  end
  return record.context:spawn(opts, handlers)
end

function BrokerContext:open_pty(opts, handlers)
  local record, current_err = guarded_context(self)
  if not record then
    return nil, current_err
  end
  return record.context:open_pty(opts, handlers)
end

function BrokerPrepared:job_spec(opts)
  local record, current_err = guarded_prepared(self)
  if not record then
    return nil, current_err
  end
  local bridge, bridge_err = record.prepared:job_spec(opts)
  if not bridge then
    return nil, bridge_err
  end
  return enrich_bridge(record.context, bridge)
end

function BrokerPrepared:spawn(opts, handlers)
  local record, current_err = guarded_prepared(self)
  if not record then
    return nil, current_err
  end
  return record.prepared:spawn(opts, handlers)
end

function BrokerPrepared:open_pty(opts, handlers)
  local record, current_err = guarded_prepared(self)
  if not record then
    return nil, current_err
  end
  return record.prepared:open_pty(opts, handlers)
end

PREPARED_MT = {
  __index = function(prepared, key)
    local method = BrokerPrepared[key]
    if method then
      return method
    end
    local record = prepared_records[prepared]
    if not record then
      return nil
    end
    if key == "workspace" then
      return record.context
    end
    return record.prepared[key]
  end,
  __newindex = function()
    error("prepared workspace runtime brokers are immutable", 2)
  end,
  __metatable = "nrm prepared workspace runtime broker",
}

local CONTEXT_MT = {
  __index = function(context, key)
    local method = BrokerContext[key]
    if method then
      return method
    end
    local record = context_records[context]
    local value = record and record.context[key]
    if type(value) == "table" then
      return copy(value)
    end
    return value
  end,
  __newindex = function()
    error("workspace runtime broker contexts are immutable", 2)
  end,
  __metatable = "nrm workspace runtime broker context",
}

local function wrap_context(context, selection)
  local wrapper = setmetatable({}, CONTEXT_MT)
  context_records[wrapper] = {
    context = context,
    selection = selection,
  }
  return wrapper
end

function M.resolve(query)
  local normalized, query_err = validate_broker_query(query)
  if not normalized then
    return nil, query_err
  end
  prune_closed_tabs()
  local tabpage = current_tabpage()
  local context, source, resolve_err, implicit_bufnr, selected_bufnr, implicit_selection =
    select_context(normalized, tabpage)
  if not context then
    return nil, resolve_err or runtime_error("workspace_not_found", "workspace authority is unavailable")
  end
  local local_bufnr
  local local_implicit = false
  local fingerprint = context.provider == "local" and workspace._selection_fingerprint(context) or nil
  local local_relative_path = fingerprint and fingerprint.relative_path or nil
  if type(local_relative_path) == "string" then
    if normalized.bufnr ~= nil then
      local_bufnr = normalized.bufnr == 0 and vim.api.nvim_get_current_buf() or normalized.bufnr
    elseif source == "local" and normalized.path == nil then
      local_bufnr = vim.api.nvim_get_current_buf()
      local_implicit = true
    end
  end
  return wrap_context(context, {
    tabpage = tabpage,
    source = source,
    binding_revision = binding_revision(tabpage),
    implicit_bufnr = implicit_bufnr,
    selected_bufnr = selected_bufnr,
    implicit_selection = implicit_selection == true,
    local_bufnr = local_bufnr,
    local_implicit = local_implicit,
    local_relative_path = local_bufnr and local_relative_path or nil,
  })
end

function M._reset_for_test()
  tab_bindings = {}
  tab_binding_revisions = {}
  tab_optout_revisions = {}
  local_cwd_revisions = {}
  next_local_cwd_revision = 0
  context_records = setmetatable({}, { __mode = "k" })
  prepared_records = setmetatable({}, { __mode = "k" })
end

local group = vim.api.nvim_create_augroup("NrmWorkspaceRuntimeBroker", { clear = true })
vim.api.nvim_create_autocmd("TabClosed", {
  group = group,
  callback = function()
    vim.schedule(prune_closed_tabs)
  end,
})
vim.api.nvim_create_autocmd("DirChanged", {
  group = group,
  callback = function()
    -- Entering a window or tab with its own cwd reports a directory change to
    -- observers, but does not mutate that scope. The provider's current_epoch
    -- path comparison remains the fail-closed backstop for missed mutations.
    if vim.v.event.changed_window == true then
      return
    end
    local scope = vim.v.event.scope
    if scope == "window" then
      return
    end
    if scope == "global" then
      for _, tabpage in ipairs(vim.api.nvim_list_tabpages()) do
        local tabnr = vim.api.nvim_tabpage_get_number(tabpage)
        local ok, has_tab_cwd = pcall(vim.fn.haslocaldir, -1, tabnr)
        if ok and has_tab_cwd == 0 then
          advance_local_cwd_revision(tabpage)
        end
      end
      return
    end
    advance_local_cwd_revision(current_tabpage())
  end,
})

return M
