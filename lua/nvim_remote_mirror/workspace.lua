local M = {}

M.API_VERSION = 1

local MAX_OUTPUT_BYTES = 128 * 1024 * 1024
local MAX_TIMEOUT_MS = 24 * 60 * 60 * 1000
local MAX_ARGV = 1024
local MAX_ENV_CHANGES = 2048
local MAX_PATH_BYTES = 16 * 1024
local MAX_PROCESS_TEXT_BYTES = 192 * 1024
local MAX_ERROR_MESSAGE_BYTES = 8 * 1024
local MAX_TERMINAL_CELLS = 32767
local MAX_TERMINAL_PIXELS = 65535

local backend_override = nil
local context_records = setmetatable({}, { __mode = "k" })

local ERROR_MT = {
  __tostring = function(err)
    return err.message
  end,
}

local function workspace_error(code, message, details)
  return setmetatable({
    code = code,
    message = message,
    details = details,
  }, ERROR_MT)
end

local function copy(value, seen)
  if type(value) ~= "table" then
    return value
  end
  seen = seen or {}
  if seen[value] then
    return seen[value]
  end
  local result = {}
  seen[value] = result
  for key, child in next, value do
    result[copy(key, seen)] = copy(child, seen)
  end
  return result
end

local function optional_string(value)
  if type(value) == "string" and value ~= "" then
    return value
  end
  return nil
end

local function contains_control(value)
  return type(value) ~= "string" or value:find("[%z\1-\31\127]") ~= nil or value:find("\194[\128-\159]") ~= nil
end

local valid_utf8

local function safe_tostring(value)
  local ok, rendered = pcall(tostring, value)
  if not ok or type(rendered) ~= "string" then
    return nil
  end
  return rendered
end

local function normalize_provider_error(value, fallback_message)
  if
    type(value) == "table"
    and type(value.code) == "string"
    and #value.code <= 64
    and value.code:match("^[a-z][a-z0-9_]*$")
    and type(value.message) == "string"
    and value.message ~= ""
    and #value.message <= MAX_ERROR_MESSAGE_BYTES
    and valid_utf8(value.code)
    and valid_utf8(value.message)
    and not contains_control(value.code)
    and not contains_control(value.message)
  then
    return workspace_error(value.code, value.message, copy(value.details))
  end
  local cause = value == nil and nil or safe_tostring(value)
  if cause and (#cause > MAX_ERROR_MESSAGE_BYTES or not valid_utf8(cause) or contains_control(cause)) then
    cause = nil
  end
  return workspace_error("provider_error", fallback_message, {
    cause = cause,
  })
end

valid_utf8 = function(value)
  if type(value) ~= "string" then
    return false
  end
  local index = 1
  while index <= #value do
    local first = value:byte(index)
    if first <= 0x7f then
      index = index + 1
    else
      local length
      local second_min = 0x80
      local second_max = 0xbf
      if first >= 0xc2 and first <= 0xdf then
        length = 2
      elseif first >= 0xe0 and first <= 0xef then
        length = 3
        if first == 0xe0 then
          second_min = 0xa0
        elseif first == 0xed then
          second_max = 0x9f
        end
      elseif first >= 0xf0 and first <= 0xf4 then
        length = 4
        if first == 0xf0 then
          second_min = 0x90
        elseif first == 0xf4 then
          second_max = 0x8f
        end
      else
        return false
      end
      if index + length - 1 > #value then
        return false
      end
      local second = value:byte(index + 1)
      if second < second_min or second > second_max then
        return false
      end
      for offset = 2, length - 1 do
        local continuation = value:byte(index + offset)
        if continuation < 0x80 or continuation > 0xbf then
          return false
        end
      end
      index = index + length
    end
  end
  return true
end

local function valid_windows_segment(segment)
  if segment:find('[<>:"|?*]') or segment:match("[ .]$") then
    return false
  end
  local stem = (segment:match("^([^.]*)") or segment):upper()
  if stem == "CON" or stem == "PRN" or stem == "AUX" or stem == "NUL" or stem == "CONIN$" or stem == "CONOUT$" then
    return false
  end
  if
    stem:match("^COM[1-9]$")
    or stem:match("^LPT[1-9]$")
    or stem == "COM¹"
    or stem == "COM²"
    or stem == "COM³"
    or stem == "LPT¹"
    or stem == "LPT²"
    or stem == "LPT³"
  then
    return false
  end
  return true
end

local function has_only_fields(value, allowed)
  for key in next, value do
    if not allowed[key] then
      return false, tostring(key)
    end
  end
  return true
end

local function is_integer(value)
  return type(value) == "number" and value == math.floor(value)
end

local function validate_array(value, name, allow_empty)
  if type(value) ~= "table" then
    return nil, workspace_error("invalid_process_spec", name .. " must be a list")
  end
  local size = #value
  if not allow_empty and size == 0 then
    return nil, workspace_error("invalid_process_spec", name .. " must not be empty")
  end
  local count = 0
  for key in next, value do
    if not is_integer(key) or key < 1 or key > size then
      return nil, workspace_error("invalid_process_spec", name .. " must be a dense list")
    end
    count = count + 1
  end
  if count ~= size then
    return nil, workspace_error("invalid_process_spec", name .. " must be a dense list")
  end
  return size
end

local function percent_decode(value)
  local output = {}
  local index = 1
  while index <= #value do
    local char = value:sub(index, index)
    if char == "%" then
      local digits = value:sub(index + 1, index + 2)
      if #digits ~= 2 or not digits:match("^%x%x$") then
        return nil, workspace_error("invalid_path", "path contains malformed percent encoding")
      end
      table.insert(output, string.char(tonumber(digits, 16)))
      index = index + 3
    else
      table.insert(output, char)
      index = index + 1
    end
  end
  local decoded = table.concat(output)
  if contains_control(decoded) or not valid_utf8(decoded) then
    return nil, workspace_error("invalid_path", "path must be control-free UTF-8")
  end
  return decoded
end

local function percent_encode(value)
  local output = {}
  for index = 1, #value do
    local byte = value:byte(index)
    local unreserved = (byte >= 65 and byte <= 90)
      or (byte >= 97 and byte <= 122)
      or (byte >= 48 and byte <= 57)
      or byte == 45
      or byte == 46
      or byte == 95
      or byte == 126
    if unreserved or byte == 47 or byte == 58 then
      table.insert(output, string.char(byte))
    else
      table.insert(output, string.format("%%%02X", byte))
    end
  end
  return table.concat(output)
end

local function path_style_for(path, fallback)
  if type(path) == "string" and path:match("^%a:[/\\]") then
    return "windows"
  end
  return fallback or "posix"
end

local function normalize_absolute(path, style)
  if type(path) ~= "string" or path == "" then
    return nil, workspace_error("invalid_path", "path must be a non-empty string")
  end
  if contains_control(path) or not valid_utf8(path) or #path > MAX_PATH_BYTES then
    return nil, workspace_error("invalid_path", "path must be control-free UTF-8 within the protocol limit")
  end

  if style == "windows" then
    path = path:gsub("\\", "/")
    if path:sub(1, 2) == "//" then
      return nil, workspace_error("invalid_path", "UNC paths are not supported")
    end
    if not path:match("^%a:/") then
      return nil, workspace_error("invalid_path", "Windows paths must use an absolute drive root")
    end
    path = path:sub(1, 1):upper() .. path:sub(2)
  else
    if path:sub(1, 1) ~= "/" then
      return nil, workspace_error("invalid_path", "POSIX paths must be absolute")
    end
    if path:find("\\", 1, true) then
      return nil, workspace_error("invalid_path", "POSIX paths must use forward slashes")
    end
  end

  local prefix
  local remainder
  if style == "windows" then
    prefix = path:sub(1, 3)
    remainder = path:sub(4)
  else
    prefix = "/"
    remainder = path:sub(2)
  end

  local segments = {}
  for segment in remainder:gmatch("[^/]+") do
    if segment ~= "." then
      if segment == ".." then
        if #segments == 0 then
          return nil, workspace_error("invalid_path", "path escapes its filesystem root")
        end
        table.remove(segments)
      else
        if style == "windows" then
          if not valid_windows_segment(segment) then
            return nil, workspace_error("invalid_path", "Windows path contains an invalid or reserved segment")
          end
        end
        table.insert(segments, segment)
      end
    end
  end

  if #segments == 0 then
    return prefix
  end
  return prefix .. table.concat(segments, "/")
end

local function relative_within(root, path, style)
  local normalized_root, root_err = normalize_absolute(root, style)
  if not normalized_root then
    return nil, root_err
  end
  local normalized_path, path_err = normalize_absolute(path, style)
  if not normalized_path then
    return nil, path_err
  end
  local compared_root = style == "windows" and normalized_root:lower() or normalized_root
  local compared_path = style == "windows" and normalized_path:lower() or normalized_path
  if compared_path == compared_root then
    return "", normalized_root
  end
  local prefix = compared_root
  if prefix:sub(-1) ~= "/" then
    prefix = prefix .. "/"
  end
  if compared_path:sub(1, #prefix) ~= prefix then
    return nil, workspace_error("invalid_path", "path is outside the workspace root")
  end
  return normalized_path:sub(#prefix + 1), normalized_root
end

local function join_absolute(root, relative, style)
  local separator = root:sub(-1) == "/" and "" or "/"
  if relative == "" then
    return normalize_absolute(root, style)
  end
  return normalize_absolute(root .. separator .. relative, style)
end

local function parse_file_uri(uri, style)
  if type(uri) ~= "string" or uri:sub(1, 8) ~= "file:///" then
    return nil, workspace_error("invalid_path", "only absolute local file:/// URIs are supported")
  end
  if uri:find("?", 1, true) or uri:find("#", 1, true) then
    return nil, workspace_error("invalid_path", "file URI queries and fragments are not supported")
  end
  local path, decode_err = percent_decode(uri:sub(8))
  if not path then
    return nil, decode_err
  end
  if path:sub(1, 2) == "//" then
    return nil, workspace_error("invalid_path", "UNC and double-root file URIs are not supported")
  end
  if style == "windows" and path:match("^/%a:/") then
    path = path:sub(2)
  end
  return normalize_absolute(path, style)
end

local function file_uri(path, style)
  if style == "windows" then
    return "file:///" .. percent_encode(path)
  end
  return "file://" .. percent_encode(path)
end

local function normalize_relative_path(path, style)
  if path == nil or path == "" or path == "." then
    return ""
  end
  if type(path) ~= "string" or contains_control(path) or not valid_utf8(path) or #path > MAX_PATH_BYTES then
    return nil, workspace_error("invalid_path", "workspace-relative path is invalid")
  end
  if path:sub(1, 1) == "/" or path:sub(1, 1) == "\\" or path:match("^%a:") then
    return nil, workspace_error("invalid_path", "workspace-relative path must not be absolute")
  end
  if path:find("\\", 1, true) then
    return nil, workspace_error("invalid_path", "workspace-relative paths must use forward slashes")
  end
  local segments = {}
  for segment in path:gmatch("[^/]+") do
    if segment ~= "." then
      if segment == ".." then
        if #segments == 0 then
          return nil, workspace_error("invalid_path", "workspace-relative path escapes the workspace")
        end
        table.remove(segments)
      else
        if style == "windows" and not valid_windows_segment(segment) then
          return nil, workspace_error("invalid_path", "Windows cwd contains an invalid or reserved segment")
        end
        table.insert(segments, segment)
      end
    end
  end
  return table.concat(segments, "/")
end

local function parse_target(target)
  target = optional_string(target)
  if not target then
    return nil
  end
  if target:sub(1, 6) ~= "ssh://" then
    return {
      kind = "local",
      remote_root = target,
      target = target,
    }
  end
  local destination, encoded_path = target:sub(7):match("^([^/]+)(/.*)$")
  if
    not destination
    or destination == ""
    or #destination > 1024
    or destination:sub(1, 1) == "-"
    or destination:find("%s")
    or contains_control(destination)
  then
    return nil
  end
  local remote_root = percent_decode(encoded_path)
  if not remote_root then
    return nil
  end
  if remote_root:match("^/%a:/") then
    remote_root = remote_root:sub(2)
  end
  return {
    kind = "ssh",
    destination = destination,
    remote_root = remote_root,
    target = target,
  }
end

local function workspace_hash(parts)
  local joined = table.concat(parts, "\30")
  if vim.fn.exists("*sha256") == 1 then
    return vim.fn.sha256(joined)
  end
  local left = 5381
  local right = 2166136261
  for index = 1, #joined do
    local byte = joined:byte(index)
    left = (left * 33 + byte) % 4294967296
    right = (right * 65599 + byte) % 4294967296
  end
  return string.format("%08x%08x", left, right)
end

local function identity_matches(identity, active)
  if identity.workspace_key and active.workspace_key and identity.workspace_key ~= active.workspace_key then
    return false
  end
  if identity.target_arg and active.target_arg and identity.target_arg ~= active.target_arg then
    return false
  end
  if identity.files_root and active.files_root then
    local identity_root = identity.files_root:gsub("\\", "/"):gsub("/+$", "")
    local active_root = active.files_root:gsub("\\", "/"):gsub("/+$", "")
    if identity_root ~= active_root then
      return false
    end
  end
  return identity.workspace_key ~= nil or identity.target_arg ~= nil or identity.files_root ~= nil
end

local function active_identity(nrm)
  local client = nrm.client
  local hello = client and client.hello
  if not client or not hello then
    return nil
  end
  return {
    workspace_key = optional_string(hello.workspace_key),
    target_arg = optional_string(client.target_arg) or optional_string(nrm.connection_target),
    files_root = optional_string(hello.files_root),
    remote_root = optional_string(hello.remote_root),
    mirror_root = optional_string(hello.mirror_root),
    remote_host = type(hello.remote_host) == "table" and copy(hello.remote_host) or nil,
    capabilities = type(hello.capabilities) == "table" and copy(hello.capabilities) or {},
    runtime_config = type(client.runtime_config) == "table" and copy(client.runtime_config) or nil,
  }
end

local function buffer_identity(bufnr)
  if not vim.api.nvim_buf_is_valid(bufnr) then
    return nil
  end
  local path = optional_string(vim.b[bufnr].nrm_remote_path) or optional_string(vim.b[bufnr].nrm_hydrate_path)
  local identity = {
    workspace_key = optional_string(vim.b[bufnr].nrm_workspace_key),
    target_arg = optional_string(vim.b[bufnr].nrm_target_arg),
    files_root = optional_string(vim.b[bufnr].nrm_files_root),
    relative_path = path,
  }
  local has_scope = identity.workspace_key ~= nil or identity.target_arg ~= nil or identity.files_root ~= nil
  if not has_scope and not path then
    return nil
  end
  return identity
end

local function state_for_status(status)
  if status == "connected" then
    return "online"
  end
  if status == "reconnect_pending" or status == "reconnecting" then
    return "reconnecting"
  end
  if status == "connecting" or status == "bootstrapping_agent" then
    return "connecting"
  end
  return "offline"
end

local function descriptor_for_identity(nrm, identity)
  local active = active_identity(nrm)
  local matches_active = active and identity_matches(identity, active) or false
  local source = matches_active and active or identity
  local target = parse_target(source.target_arg)
  if source.target_arg and not target then
    return nil, workspace_error("invalid_provider_state", "remote buffer contains an invalid target identity")
  end
  local remote_root = source.remote_root or (target and target.remote_root)
  local remote_host = source.remote_host or {}
  local path_style = remote_host.path_style or path_style_for(remote_root)
  if remote_root then
    local normalized_root, root_err = normalize_absolute(remote_root, path_style)
    if not normalized_root then
      return nil,
        workspace_error("invalid_provider_state", "remote buffer contains an invalid authority root", {
          cause = root_err.message,
        })
    end
    remote_root = normalized_root
  end
  local workspace_id = source.workspace_key
    or workspace_hash({ source.target_arg or "", source.files_root or "", remote_root or "" })
  local authority_kind = target and target.kind or (source.target_arg and "remote" or "unknown")
  local authority_id = workspace_hash({ authority_kind, source.target_arg or "", remote_root or "" })
  return {
    api_version = M.API_VERSION,
    provider = "nrm",
    workspace_id = workspace_id,
    epoch = tonumber(nrm.reconnect_generation) or 0,
    state = matches_active and state_for_status(nrm.connection_status) or "offline",
    mode = "mirror",
    authority = {
      id = authority_id,
      kind = authority_kind,
      label = target and (target.kind == "ssh" and "ssh://" .. target.destination or "local") or authority_kind,
      path_style = path_style,
      os = optional_string(remote_host.os),
      arch = optional_string(remote_host.arch),
      shell = optional_string(remote_host.shell),
      target = optional_string(remote_host.target),
    },
    roots = {
      editor = source.files_root,
      authority = remote_root,
    },
    capabilities = source.capabilities or {},
    relative_path = identity.relative_path,
    _target_arg = source.target_arg,
    _workspace_key = source.workspace_key,
    _ssh = target and target.destination or nil,
    _remote_host = type(source.remote_host) == "table" and copy(source.remote_host) or nil,
    _runtime_config = copy(source.runtime_config),
  }
end

local function default_resolve(query)
  local nrm = package.loaded["nvim_remote_mirror"] or require("nvim_remote_mirror")
  local identity
  if query.bufnr ~= nil then
    if not is_integer(query.bufnr) or not vim.api.nvim_buf_is_valid(query.bufnr) then
      return nil, workspace_error("invalid_argument", "bufnr must identify a valid buffer")
    end
    identity = buffer_identity(query.bufnr)
    if not identity then
      return nil, workspace_error("not_remote_buffer", "buffer is not associated with a remote workspace")
    end
    if not identity.workspace_key and not identity.target_arg and not identity.files_root then
      local active = active_identity(nrm)
      if not active then
        return nil, workspace_error("workspace_not_found", "remote buffer has no recoverable workspace identity")
      end
      active.relative_path = identity.relative_path
      identity = active
    end
  elseif query.path ~= nil then
    if type(query.path) ~= "string" or query.path == "" then
      return nil, workspace_error("invalid_argument", "path must be a non-empty string")
    end
    local active = active_identity(nrm)
    if active and active.files_root then
      local style = path_style_for(active.files_root)
      local relative = relative_within(active.files_root, query.path, style)
      if relative then
        identity = copy(active)
        identity.relative_path = relative
      end
    end
    if not identity then
      for _, bufnr in ipairs(vim.api.nvim_list_bufs()) do
        local candidate = buffer_identity(bufnr)
        if candidate and vim.api.nvim_buf_get_name(bufnr) == query.path then
          identity = candidate
          break
        end
      end
    end
    if not identity then
      return nil, workspace_error("workspace_not_found", "path is not inside a known remote workspace")
    end
  else
    local active = active_identity(nrm)
    if query.workspace_id ~= nil or query.workspace_key ~= nil then
      local wanted = query.workspace_id or query.workspace_key
      if type(wanted) ~= "string" or wanted == "" then
        return nil, workspace_error("invalid_argument", "workspace identity must be a non-empty string")
      end
      if active then
        local active_descriptor = descriptor_for_identity(nrm, active)
        if active_descriptor and (active.workspace_key == wanted or active_descriptor.workspace_id == wanted) then
          identity = active
        end
      end
      if not identity then
        for _, bufnr in ipairs(vim.api.nvim_list_bufs()) do
          local candidate = buffer_identity(bufnr)
          if candidate then
            local descriptor = descriptor_for_identity(nrm, candidate)
            if descriptor and (candidate.workspace_key == wanted or descriptor.workspace_id == wanted) then
              identity = candidate
              break
            end
          end
        end
      end
      if not identity then
        return nil, workspace_error("workspace_not_found", "remote workspace is not known")
      end
    else
      local bufnr = vim.api.nvim_get_current_buf()
      identity = buffer_identity(bufnr) or active
      if not identity then
        return nil, workspace_error("workspace_not_found", "no remote workspace is active")
      end
    end
  end
  return descriptor_for_identity(nrm, identity)
end

local default_backend = {}

function default_backend.resolve(query)
  return default_resolve(query)
end

function default_backend.current_epoch()
  local nrm = package.loaded["nvim_remote_mirror"] or require("nvim_remote_mirror")
  return tonumber(nrm.reconnect_generation) or 0
end

function default_backend.current_state(snapshot)
  local nrm = package.loaded["nvim_remote_mirror"] or require("nvim_remote_mirror")
  local active = active_identity(nrm)
  if not active then
    return "offline"
  end
  local active_descriptor = descriptor_for_identity(nrm, active)
  if not active_descriptor or active_descriptor.workspace_id ~= snapshot.workspace_id then
    return "offline"
  end
  return state_for_status(nrm.connection_status)
end

function default_backend.is_trusted(snapshot, capability)
  return require("nvim_remote_mirror.runtime").is_trusted(snapshot, capability)
end

function default_backend.authorize(snapshot, capability, callback)
  return require("nvim_remote_mirror.runtime").authorize(snapshot, capability, callback)
end

function default_backend.job_spec(snapshot, request)
  return require("nvim_remote_mirror.runtime").job_spec(snapshot, request)
end

function default_backend.spawn(snapshot, request, handlers)
  return require("nvim_remote_mirror.runtime").spawn(snapshot, request, handlers)
end

local function backend()
  return backend_override or default_backend
end

local PROVIDER_METHODS = {
  "resolve",
  "current_epoch",
  "current_state",
  "is_trusted",
  "authorize",
  "job_spec",
  "spawn",
}

-- A resolved context is tied to the provider implementation that created it.
-- Capturing the callbacks also prevents later setup calls (or mutations of a
-- provider table) from changing the authority behind an existing context.
local function bind_provider(provider)
  local bound = {}
  for _, name in ipairs(PROVIDER_METHODS) do
    local callback = provider[name]
    if callback ~= nil then
      if type(callback) ~= "function" then
        return nil,
          workspace_error("provider_error", "workspace provider field must be a function: " .. name, {
            field = name,
          })
      end
      bound[name] = callback
    end
  end
  return bound
end

local function validate_descriptor(descriptor)
  if type(descriptor) ~= "table" then
    return nil, workspace_error("invalid_provider_state", "workspace provider returned no descriptor")
  end
  local workspace_id = optional_string(descriptor.workspace_id)
  if not workspace_id then
    return nil, workspace_error("invalid_provider_state", "workspace provider returned no workspace_id")
  end
  local epoch = descriptor.epoch
  if not is_integer(epoch) or epoch < 0 then
    return nil, workspace_error("invalid_provider_state", "workspace provider returned an invalid epoch")
  end
  local states = { online = true, offline = true, connecting = true, reconnecting = true, error = true }
  if not states[descriptor.state] then
    return nil, workspace_error("invalid_provider_state", "workspace provider returned an invalid state")
  end
  local modes = { mirror = true, remote_nvim = true }
  if not modes[descriptor.mode] then
    return nil, workspace_error("invalid_provider_state", "workspace provider returned an invalid mode")
  end
  if type(descriptor.authority) ~= "table" or type(descriptor.roots) ~= "table" then
    return nil, workspace_error("invalid_provider_state", "workspace provider returned incomplete authority metadata")
  end
  for _, field in ipairs({ "id", "kind" }) do
    local value = descriptor.authority[field]
    if not optional_string(value) or #value > 1024 or contains_control(value) or not valid_utf8(value) then
      return nil,
        workspace_error("invalid_provider_state", "workspace provider returned an invalid authority " .. field)
    end
  end
  local authority_label = descriptor.authority.label
  if
    authority_label ~= nil
    and (
      not optional_string(authority_label)
      or #authority_label > 1024
      or contains_control(authority_label)
      or not valid_utf8(authority_label)
    )
  then
    return nil, workspace_error("invalid_provider_state", "workspace provider returned an invalid authority label")
  end
  local path_style = descriptor.authority.path_style
  if path_style ~= "posix" and path_style ~= "windows" then
    return nil, workspace_error("invalid_provider_state", "workspace provider returned an invalid path style")
  end
  descriptor = copy(descriptor)
  descriptor.authority.label = authority_label or descriptor.authority.id
  descriptor.api_version = M.API_VERSION
  descriptor.provider = optional_string(descriptor.provider) or "nrm"
  descriptor.capabilities = type(descriptor.capabilities) == "table" and descriptor.capabilities or {}
  return descriptor
end

local Context = {}

local function record_for(context)
  local record = context_records[context]
  if not record then
    error("invalid workspace context", 2)
  end
  return record
end

local function current_epoch(record)
  local provider = record.provider
  if type(provider.current_epoch) ~= "function" then
    return record.snapshot.epoch
  end
  local ok, epoch = pcall(provider.current_epoch, copy(record.snapshot))
  if not ok then
    return nil, normalize_provider_error(epoch, "workspace provider failed to report its current epoch")
  end
  if not is_integer(epoch) or epoch < 0 then
    return nil, workspace_error("provider_error", "workspace provider returned an invalid current epoch")
  end
  return epoch
end

local function ensure_current(record)
  local epoch, epoch_err = current_epoch(record)
  if epoch == nil then
    return nil, epoch_err
  end
  if epoch ~= record.snapshot.epoch then
    return nil,
      workspace_error("stale_context", "workspace context is stale; resolve it again", {
        expected_epoch = epoch,
        context_epoch = record.snapshot.epoch,
      })
  end
  return true
end

local function current_state(record)
  local provider = record.provider
  if type(provider.current_state) == "function" then
    local ok, state = pcall(provider.current_state, copy(record.snapshot))
    if not ok then
      return nil, normalize_provider_error(state, "workspace provider failed to report its state")
    end
    local states = { online = true, offline = true, connecting = true, reconnecting = true, error = true }
    if not states[state] then
      return nil, workspace_error("provider_error", "workspace provider returned an invalid current state")
    end
    return state
  end
  return record.snapshot.state
end

local function ensure_online(record)
  local ok, err = ensure_current(record)
  if not ok then
    return nil, err
  end
  local state, state_err = current_state(record)
  if state == nil then
    return nil, state_err
  end
  if state ~= "online" then
    return nil, workspace_error("workspace_offline", "remote workspace runtime is not online", { state = state })
  end
  return true
end

local function trusted(record, capability)
  local provider = record.provider
  if type(provider.is_trusted) == "function" then
    local ok, result, provider_err = pcall(provider.is_trusted, copy(record.snapshot), capability)
    if not ok then
      return nil, normalize_provider_error(result, "workspace trust provider failed")
    end
    if result == nil and provider_err ~= nil then
      return nil, normalize_provider_error(provider_err, "workspace trust provider failed")
    end
    return result == true
  end
  return false
end

local capability_keys = {
  process = "runtime_process_v1",
  terminal = "runtime_pty_v1",
  watch = "workspace_watch_v1",
}

local function validate_capability(record, capability)
  local key = capability_keys[capability]
  if not key then
    return nil, workspace_error("invalid_argument", "unknown workspace capability: " .. tostring(capability))
  end
  if record.snapshot.capabilities[key] ~= true then
    return nil,
      workspace_error("unsupported", "workspace provider does not support " .. capability, {
        capability = key,
      })
  end
  return true
end

function Context:is_current()
  local ok, err = ensure_current(record_for(self))
  return ok == true, err
end

function Context:authorize(capability, callback)
  local record = record_for(self)
  if type(callback) ~= "function" then
    return nil, workspace_error("invalid_argument", "authorize requires a callback")
  end
  local function deliver(callback_err, granted)
    local callback_ok, callback_failure = pcall(callback, callback_err, granted)
    if not callback_ok then
      vim.schedule(function()
        vim.notify("workspace authorization callback failed: " .. tostring(callback_failure), vim.log.levels.ERROR)
      end)
    end
  end
  local ok, err = ensure_online(record)
  if not ok then
    deliver(err, false)
    return nil, err
  end
  ok, err = validate_capability(record, capability)
  if not ok then
    deliver(err, false)
    return nil, err
  end
  local is_trusted, trust_err = trusted(record, capability)
  if trust_err then
    deliver(trust_err, false)
    return nil, trust_err
  end
  if is_trusted then
    deliver(nil, true)
    return true
  end
  local provider = record.provider
  if type(provider.authorize) ~= "function" then
    err = workspace_error("workspace_untrusted", "remote workspace is not trusted for process execution")
    deliver(err, false)
    return nil, err
  end
  local called = false
  local function finish(auth_err, granted)
    if called then
      return
    end
    called = true
    local still_current, stale_err = ensure_current(record)
    if not still_current then
      deliver(stale_err, false)
      return
    end
    if auth_err then
      deliver(normalize_provider_error(auth_err, "workspace authorization provider failed"), false)
      return
    end
    if granted ~= true then
      deliver(workspace_error("workspace_untrusted", "remote workspace authorization was denied"), false)
      return
    end
    deliver(nil, true)
  end
  local invoke_ok, invoke_err = pcall(provider.authorize, copy(record.snapshot), capability, finish)
  if not invoke_ok then
    finish(normalize_provider_error(invoke_err, "workspace authorization provider failed"))
  end
  return true
end

function Context:map_path(path, opts)
  local record = record_for(self)
  opts = opts or {}
  if type(opts) ~= "table" then
    return nil, workspace_error("invalid_argument", "map_path options must be a table")
  end
  local fields_ok, unknown = has_only_fields(opts, { from = true, to = true })
  if not fields_ok then
    return nil, workspace_error("invalid_argument", "unknown map_path option: " .. unknown)
  end
  local from = opts.from
  local to = opts.to
  local spaces = { editor = true, authority = true, editor_uri = true, authority_uri = true }
  if not spaces[from] or not spaces[to] or from == to then
    return nil, workspace_error("invalid_argument", "map_path requires distinct editor/authority path or URI spaces")
  end
  local source_space = from:gsub("_uri$", "")
  local target_space = to:gsub("_uri$", "")
  if source_space == target_space then
    return nil, workspace_error("invalid_argument", "map_path must cross editor and authority spaces")
  end
  local source_root = record.snapshot.roots[source_space]
  local target_root = record.snapshot.roots[target_space]
  if not optional_string(source_root) or not optional_string(target_root) then
    return nil, workspace_error("unsupported", "workspace path roots are incomplete")
  end
  local source_style = source_space == "authority" and record.snapshot.authority.path_style
    or path_style_for(source_root)
  local target_style = target_space == "authority" and record.snapshot.authority.path_style
    or path_style_for(target_root)
  local source_path = path
  if from:sub(-4) == "_uri" then
    local uri_err
    source_path, uri_err = parse_file_uri(path, source_style)
    if not source_path then
      return nil, uri_err
    end
  end
  local relative, relative_err = relative_within(source_root, source_path, source_style)
  if relative == nil then
    return nil, relative_err
  end
  local mapped, mapped_err = join_absolute(target_root, relative, target_style)
  if not mapped then
    return nil, mapped_err
  end
  if to:sub(-4) == "_uri" then
    return file_uri(mapped, target_style)
  end
  return mapped
end

local function normalize_command(command)
  if type(command) ~= "table" then
    return nil, workspace_error("invalid_process_spec", "command must be a table")
  end
  local fields_ok, unknown = has_only_fields(command, { argv = true, shell = true })
  if not fields_ok then
    return nil, workspace_error("invalid_process_spec", "unknown command field: " .. unknown)
  end
  if (command.argv == nil) == (command.shell == nil) then
    return nil, workspace_error("invalid_process_spec", "command must contain exactly one of argv or shell")
  end
  if command.argv ~= nil then
    local size, list_err = validate_array(command.argv, "command.argv", false)
    if not size then
      return nil, list_err
    end
    if size > MAX_ARGV then
      return nil, workspace_error("invalid_process_spec", "command.argv exceeds the protocol argument limit")
    end
    local argv = {}
    for index = 1, size do
      local argument = command.argv[index]
      if type(argument) ~= "string" or contains_control(argument) or not valid_utf8(argument) then
        return nil, workspace_error("invalid_process_spec", "command arguments must be control-free UTF-8 strings")
      end
      if index == 1 and argument == "" then
        return nil, workspace_error("invalid_process_spec", "command executable must not be empty")
      end
      argv[index] = argument
    end
    return { argv = argv }
  end
  if command.shell ~= "default" then
    return nil,
      workspace_error(
        "invalid_process_spec",
        "command.shell must be 'default'; use an explicit argv shell invocation for shell programs"
      )
  end
  return { shell = "default" }
end

local function normalize_cwd(record, cwd)
  if cwd == nil then
    return { space = "workspace", path = "" }
  end
  if type(cwd) ~= "table" then
    return nil, workspace_error("invalid_process_spec", "cwd must be a table")
  end
  local fields_ok, unknown = has_only_fields(cwd, { space = true, path = true })
  if not fields_ok then
    return nil, workspace_error("invalid_process_spec", "unknown cwd field: " .. unknown)
  end
  if cwd.space == "buffer" then
    if cwd.path ~= nil then
      return nil, workspace_error("invalid_process_spec", "buffer cwd does not accept a path")
    end
    local relative_path = record.snapshot.relative_path
    if not optional_string(relative_path) then
      return nil, workspace_error("invalid_process_spec", "buffer cwd requires a buffer-backed context")
    end
    local normalized, path_err = normalize_relative_path(relative_path, record.snapshot.authority.path_style)
    if normalized == nil then
      return nil, path_err
    end
    local directory = normalized:match("^(.*)/[^/]+$") or ""
    return { space = "workspace", path = directory }
  end
  if cwd.space == "workspace" then
    local normalized, path_err = normalize_relative_path(cwd.path, record.snapshot.authority.path_style)
    if normalized == nil then
      return nil, path_err
    end
    return { space = "workspace", path = normalized }
  end
  if cwd.space ~= "editor" and cwd.space ~= "authority" then
    return nil, workspace_error("invalid_process_spec", "cwd.space must be workspace, buffer, editor, or authority")
  end
  if type(cwd.path) ~= "string" or cwd.path == "" then
    return nil, workspace_error("invalid_process_spec", "absolute cwd spaces require a path")
  end
  local root = record.snapshot.roots[cwd.space]
  if not optional_string(root) then
    return nil, workspace_error("unsupported", "workspace cwd root is unavailable")
  end
  local style = cwd.space == "authority" and record.snapshot.authority.path_style or path_style_for(root)
  local relative, path_err = relative_within(root, cwd.path, style)
  if relative == nil then
    return nil, path_err
  end
  return { space = "workspace", path = relative }
end

local function normalize_env(record, env)
  env = env or {}
  if type(env) ~= "table" then
    return nil, workspace_error("invalid_process_spec", "env must be a table")
  end
  local fields_ok, unknown = has_only_fields(env, { clear = true, set = true, unset = true })
  if not fields_ok then
    return nil, workspace_error("invalid_process_spec", "unknown env field: " .. unknown)
  end
  if env.clear ~= nil and type(env.clear) ~= "boolean" then
    return nil, workspace_error("invalid_process_spec", "env.clear must be a boolean")
  end
  local set = env.set or {}
  if type(set) ~= "table" then
    return nil, workspace_error("invalid_process_spec", "env.set must be a table")
  end
  local normalized_set = {}
  local seen = {}
  local windows = record.snapshot.authority.path_style == "windows"
  for key, value in next, set do
    if
      type(key) ~= "string"
      or key == ""
      or contains_control(key)
      or key:find("=", 1, true)
      or not valid_utf8(key)
      or type(value) ~= "string"
      or value:find("%z")
      or not valid_utf8(value)
    then
      return nil, workspace_error("invalid_process_spec", "environment entries must be valid NUL-free strings")
    end
    local compared = windows and key:lower() or key
    if seen[compared] then
      return nil, workspace_error("invalid_process_spec", "environment contains duplicate variable names")
    end
    seen[compared] = "set"
    normalized_set[key] = value
  end
  local unset = env.unset or {}
  local size, list_err = validate_array(unset, "env.unset", true)
  if not size then
    return nil, list_err
  end
  local normalized_unset = {}
  local change_count = 0
  for _ in next, normalized_set do
    change_count = change_count + 1
  end
  if change_count + size > MAX_ENV_CHANGES then
    return nil, workspace_error("invalid_process_spec", "environment changes exceed the protocol limit")
  end
  for index = 1, size do
    local key = unset[index]
    if type(key) ~= "string" or key == "" or contains_control(key) or key:find("=", 1, true) or not valid_utf8(key) then
      return nil, workspace_error("invalid_process_spec", "env.unset names must be valid strings")
    end
    local compared = windows and key:lower() or key
    if seen[compared] then
      return nil, workspace_error("invalid_process_spec", "environment variable is both set and unset")
    end
    seen[compared] = "unset"
    table.insert(normalized_unset, key)
  end
  table.sort(normalized_unset, function(left, right)
    local compared_left = windows and left:lower() or left
    local compared_right = windows and right:lower() or right
    return compared_left < compared_right
  end)
  return {
    clear = env.clear == true,
    set = normalized_set,
    unset = normalized_unset,
  }
end

local function bounded_integer(value, name, maximum)
  if value == nil then
    return nil
  end
  if not is_integer(value) or value < 1 or value > maximum then
    return nil, workspace_error("invalid_process_spec", name .. " must be an integer from 1 to " .. maximum)
  end
  return value
end

local function normalize_initial_size(initial_size)
  initial_size = initial_size or {}
  if type(initial_size) ~= "table" then
    return nil, workspace_error("invalid_process_spec", "initial_size must be a table")
  end
  local fields_ok, unknown = has_only_fields(initial_size, {
    cols = true,
    rows = true,
    pixel_width = true,
    pixel_height = true,
  })
  if not fields_ok then
    return nil, workspace_error("invalid_process_spec", "unknown initial_size field: " .. unknown)
  end
  local cols, cols_err = bounded_integer(initial_size.cols or 80, "initial_size.cols", MAX_TERMINAL_CELLS)
  if not cols then
    return nil, cols_err
  end
  local rows, rows_err = bounded_integer(initial_size.rows or 24, "initial_size.rows", MAX_TERMINAL_CELLS)
  if not rows then
    return nil, rows_err
  end
  local function pixel(value, name)
    if not is_integer(value) or value < 0 or value > MAX_TERMINAL_PIXELS then
      return nil,
        workspace_error("invalid_process_spec", name .. " must be an integer from 0 to " .. MAX_TERMINAL_PIXELS)
    end
    return value
  end
  if (initial_size.pixel_width == nil) ~= (initial_size.pixel_height == nil) then
    return nil, workspace_error("invalid_process_spec", "initial_size pixel width and height must be provided together")
  end
  local pixel_width
  local pixel_height
  if initial_size.pixel_width ~= nil then
    local width_err
    pixel_width, width_err = pixel(initial_size.pixel_width, "initial_size.pixel_width")
    if pixel_width == nil then
      return nil, width_err
    end
    local height_err
    pixel_height, height_err = pixel(initial_size.pixel_height, "initial_size.pixel_height")
    if pixel_height == nil then
      return nil, height_err
    end
  end
  return {
    cols = cols,
    rows = rows,
    pixel_width = pixel_width,
    pixel_height = pixel_height,
  }
end

local function normalize_process_spec(record, opts)
  if type(opts) ~= "table" then
    return nil, workspace_error("invalid_process_spec", "process options must be a table")
  end
  local fields_ok, unknown = has_only_fields(opts, {
    command = true,
    cwd = true,
    env = true,
    stdio = true,
    persistence = true,
    max_output_bytes = true,
    timeout_ms = true,
    initial_size = true,
  })
  if not fields_ok then
    return nil, workspace_error("invalid_process_spec", "unknown process option: " .. unknown)
  end
  local command, command_err = normalize_command(opts.command)
  if not command then
    return nil, command_err
  end
  local cwd, cwd_err = normalize_cwd(record, opts.cwd)
  if not cwd then
    return nil, cwd_err
  end
  local env, env_err = normalize_env(record, opts.env)
  if not env then
    return nil, env_err
  end
  local stdio = opts.stdio or "pipe"
  if stdio ~= "pipe" and stdio ~= "pty" then
    return nil, workspace_error("invalid_process_spec", "stdio must be pipe or pty")
  end
  local persistence = opts.persistence or "attached"
  if persistence ~= "attached" and persistence ~= "detached" then
    return nil, workspace_error("invalid_process_spec", "persistence must be attached or detached")
  end
  if persistence == "detached" and stdio ~= "pty" then
    return nil, workspace_error("invalid_process_spec", "detached persistence requires stdio = 'pty'")
  end
  if opts.initial_size ~= nil and stdio ~= "pty" then
    return nil, workspace_error("invalid_process_spec", "initial_size requires stdio = 'pty'")
  end
  local max_output_bytes
  local output_err
  if stdio == "pty" then
    if opts.max_output_bytes ~= nil then
      return nil, workspace_error("invalid_process_spec", "max_output_bytes applies only to pipe processes")
    end
  else
    max_output_bytes, output_err =
      bounded_integer(opts.max_output_bytes or (4 * 1024 * 1024), "max_output_bytes", MAX_OUTPUT_BYTES)
    if not max_output_bytes then
      return nil, output_err
    end
  end
  local timeout_ms, timeout_err = bounded_integer(opts.timeout_ms, "timeout_ms", MAX_TIMEOUT_MS)
  if opts.timeout_ms ~= nil and not timeout_ms then
    return nil, timeout_err
  end
  local initial_size
  if stdio == "pty" then
    initial_size, output_err = normalize_initial_size(opts.initial_size)
    if not initial_size then
      return nil, output_err
    end
  end
  local text_bytes = #cwd.path
  if command.argv then
    for _, argument in ipairs(command.argv) do
      text_bytes = text_bytes + #argument
    end
  else
    text_bytes = text_bytes + #command.shell
  end
  for key, value in next, env.set do
    text_bytes = text_bytes + #key + #value
  end
  for _, key in ipairs(env.unset) do
    text_bytes = text_bytes + #key
  end
  if text_bytes > MAX_PROCESS_TEXT_BYTES then
    return nil, workspace_error("invalid_process_spec", "process text exceeds the runtime frame budget")
  end
  return {
    command = command,
    cwd = cwd,
    env = env,
    stdio = stdio,
    persistence = persistence,
    max_output_bytes = max_output_bytes,
    timeout_ms = timeout_ms,
    initial_size = initial_size,
  }
end

local function prepare_process(record, opts)
  local ok, err = ensure_online(record)
  if not ok then
    return nil, err
  end
  local request, request_err = normalize_process_spec(record, opts)
  if not request then
    return nil, request_err
  end
  local capability = request.stdio == "pty" and "terminal" or "process"
  ok, err = validate_capability(record, capability)
  if not ok then
    return nil, err
  end
  local is_trusted, trust_err = trusted(record, capability)
  if trust_err then
    return nil, trust_err
  end
  if not is_trusted then
    return nil, workspace_error("workspace_untrusted", "remote workspace is not trusted for process execution")
  end
  return request
end

local function canonical_bridge_command(argv)
  local command = {}
  for _, argument in ipairs(argv) do
    local ok, escaped = pcall(vim.fn.shellescape, argument, 1)
    if not ok or type(escaped) ~= "string" or escaped == "" or contains_control(escaped) or not valid_utf8(escaped) then
      return nil, workspace_error("provider_error", "failed to quote the local bridge command")
    end
    table.insert(command, escaped)
  end
  return table.concat(command, " ")
end

local function validate_bridge_spec(spec)
  if type(spec) ~= "table" then
    return nil, workspace_error("provider_error", "workspace provider returned an invalid job specification")
  end
  local fields_ok, unknown = has_only_fields(spec, { argv = true, command = true, cwd = true, env = true })
  if not fields_ok then
    return nil, workspace_error("provider_error", "workspace provider returned an unknown bridge field: " .. unknown)
  end
  local size, list_err = validate_array(spec.argv, "bridge argv", false)
  if not size then
    return nil, workspace_error("provider_error", list_err.message)
  end
  if size > MAX_ARGV then
    return nil, workspace_error("provider_error", "workspace provider returned too many bridge arguments")
  end
  local text_bytes = 0
  for index = 1, size do
    if
      type(spec.argv[index]) ~= "string"
      or contains_control(spec.argv[index])
      or not valid_utf8(spec.argv[index])
      or (index == 1 and spec.argv[index] == "")
    then
      return nil, workspace_error("provider_error", "workspace provider returned invalid bridge arguments")
    end
    text_bytes = text_bytes + #spec.argv[index]
  end
  if text_bytes > MAX_PROCESS_TEXT_BYTES then
    return nil, workspace_error("provider_error", "workspace provider returned an oversized bridge command")
  end
  if spec.cwd ~= nil then
    if
      type(spec.cwd) ~= "string"
      or spec.cwd == ""
      or contains_control(spec.cwd)
      or not valid_utf8(spec.cwd)
      or #spec.cwd > MAX_PATH_BYTES
    then
      return nil, workspace_error("provider_error", "workspace provider returned an invalid bridge cwd")
    end
    local normalized_cwd = normalize_absolute(spec.cwd, path_style_for(spec.cwd))
    if not normalized_cwd then
      return nil, workspace_error("provider_error", "workspace provider returned a non-absolute bridge cwd")
    end
  end
  if spec.env ~= nil then
    if type(spec.env) ~= "table" or next(spec.env) ~= nil then
      return nil,
        workspace_error(
          "provider_error",
          "local bridge environment must be empty; remote values belong in the private runtime ticket"
        )
    end
  end
  local result = copy(spec)
  local command, command_err = canonical_bridge_command(result.argv)
  if not command then
    return nil, command_err
  end
  if spec.command ~= nil and spec.command ~= command then
    return nil,
      workspace_error("provider_error", "workspace provider command does not match its authoritative bridge argv")
  end
  -- String-only plugin APIs receive a canonical rendering of the validated
  -- local bridge argv. The backend must put the remote spec in its private,
  -- single-use ticket; no remote environment is accepted here.
  result.command = command
  return result
end

function Context:job_spec(opts)
  local record = record_for(self)
  local request, request_err = prepare_process(record, opts)
  if not request then
    return nil, request_err
  end
  local provider = record.provider
  if type(provider.job_spec) ~= "function" then
    return nil, workspace_error("unsupported", "workspace provider has no local process bridge")
  end
  local invoke_ok, spec, spec_err = pcall(provider.job_spec, copy(record.snapshot), copy(request))
  if not invoke_ok then
    return nil, normalize_provider_error(spec, "workspace process provider failed")
  end
  if not spec then
    return nil, normalize_provider_error(spec_err, "workspace process provider returned no job specification")
  end
  return validate_bridge_spec(spec)
end

local function validate_process_handle(handle, request)
  if type(handle) ~= "table" then
    return nil, workspace_error("provider_error", "workspace process provider returned an invalid handle")
  end
  local required = { "write", "close_stdin", "signal", "kill" }
  if request.stdio == "pty" then
    table.insert(required, "resize")
  end
  if request.persistence == "detached" then
    table.insert(required, "detach")
  end
  local surface = {}
  for _, method in ipairs(required) do
    if type(handle[method]) ~= "function" then
      return nil,
        workspace_error("provider_error", "workspace process handle is missing method: " .. method, {
          method = method,
        })
    end
    local callback = handle[method]
    surface[method] = function(_, ...)
      local ok, value, method_err = pcall(callback, handle, ...)
      if not ok then
        return nil, normalize_provider_error(value, "workspace process handle method failed: " .. method)
      end
      if value == nil and method_err ~= nil then
        return nil, normalize_provider_error(method_err, "workspace process handle method failed: " .. method)
      end
      return value, method_err
    end
  end
  if request.persistence == "detached" then
    if
      type(handle.session_id) ~= "string"
      or handle.session_id == ""
      or #handle.session_id > 256
      or contains_control(handle.session_id)
      or not valid_utf8(handle.session_id)
    then
      return nil, workspace_error("provider_error", "detached workspace process handle has no valid opaque session ID")
    end
    surface.session_id = handle.session_id
  elseif handle.session_id ~= nil then
    return nil,
      workspace_error("provider_error", "attached workspace process handle unexpectedly returned a session ID")
  end
  return surface
end

local function normalize_handlers(handlers)
  if handlers == nil then
    return {}
  end
  if type(handlers) ~= "table" then
    return nil, workspace_error("invalid_argument", "spawn handlers must be a table")
  end
  local result = {}
  local count = 0
  local supported = { on_stdout = true, on_stderr = true, on_exit = true }
  for name, callback in next, handlers do
    if
      type(name) ~= "string"
      or name == ""
      or contains_control(name)
      or not valid_utf8(name)
      or type(callback) ~= "function"
    then
      return nil, workspace_error("invalid_argument", "spawn handlers must map valid names to functions")
    end
    if not supported[name] then
      return nil, workspace_error("invalid_argument", "unknown spawn handler: " .. name)
    end
    count = count + 1
    if count > 32 then
      return nil, workspace_error("invalid_argument", "spawn handler count exceeds the API limit")
    end
    result[name] = callback
  end
  return result
end

function Context:spawn(opts, handlers)
  local record = record_for(self)
  local normalized_handlers, handlers_err = normalize_handlers(handlers)
  if not normalized_handlers then
    return nil, handlers_err
  end
  local request, request_err = prepare_process(record, opts)
  if not request then
    return nil, request_err
  end
  local provider = record.provider
  if type(provider.spawn) ~= "function" then
    return nil, workspace_error("unsupported", "workspace provider has no managed process runtime")
  end
  local invoke_ok, handle, spawn_err = pcall(provider.spawn, copy(record.snapshot), copy(request), normalized_handlers)
  if not invoke_ok then
    return nil, normalize_provider_error(handle, "workspace process provider failed")
  end
  if not handle then
    return nil, normalize_provider_error(spawn_err, "workspace process provider returned no handle")
  end
  return validate_process_handle(handle, request)
end

function Context:open_pty(opts, handlers)
  opts = copy(opts or {})
  opts.stdio = "pty"
  return self:spawn(opts, handlers)
end

local CONTEXT_MT = {
  __index = function(context, key)
    local method = Context[key]
    if method then
      return method
    end
    local record = context_records[context]
    local value = record and record.public[key]
    if type(value) == "table" then
      return copy(value)
    end
    return value
  end,
  __newindex = function()
    error("workspace contexts are immutable", 2)
  end,
  __metatable = "nrm workspace context",
}

function M.resolve(query)
  query = query or {}
  if type(query) ~= "table" then
    return nil, workspace_error("invalid_argument", "workspace query must be a table")
  end
  local fields_ok, unknown = has_only_fields(query, {
    bufnr = true,
    path = true,
    workspace_id = true,
    workspace_key = true,
  })
  if not fields_ok then
    return nil, workspace_error("invalid_argument", "unknown workspace query field: " .. unknown)
  end
  local selectors = 0
  for _, field in ipairs({ "bufnr", "path", "workspace_id", "workspace_key" }) do
    if query[field] ~= nil then
      selectors = selectors + 1
    end
  end
  if selectors > 1 then
    return nil, workspace_error("invalid_argument", "workspace query accepts at most one selector")
  end
  local provider, bind_err = bind_provider(backend())
  if not provider then
    return nil, bind_err
  end
  if type(provider.resolve) ~= "function" then
    return nil, workspace_error("unsupported", "workspace provider cannot resolve contexts")
  end
  local invoke_ok, descriptor, resolve_err = pcall(provider.resolve, copy(query))
  if not invoke_ok then
    return nil, normalize_provider_error(descriptor, "workspace provider failed to resolve context")
  end
  if not descriptor then
    if resolve_err == nil then
      return nil, workspace_error("workspace_not_found", "remote workspace is not known")
    end
    return nil, normalize_provider_error(resolve_err, "workspace provider failed to resolve context")
  end
  descriptor, resolve_err = validate_descriptor(descriptor)
  if not descriptor then
    return nil, resolve_err
  end
  local context = setmetatable({}, CONTEXT_MT)
  context_records[context] = {
    provider = provider,
    snapshot = descriptor,
    public = {
      api_version = descriptor.api_version,
      provider = descriptor.provider,
      workspace_id = descriptor.workspace_id,
      epoch = descriptor.epoch,
      state = descriptor.state,
      mode = descriptor.mode,
      authority = copy(descriptor.authority),
      roots = copy(descriptor.roots),
      capabilities = copy(descriptor.capabilities),
    },
  }
  return context
end

-- Internal integration hooks. The main plugin owns persistence, prompts, and the
-- sidecar process bridge; this module owns validation and fail-closed semantics.
function M._set_backend(provider)
  if provider ~= nil and type(provider) ~= "table" then
    error("workspace backend must be a table or nil")
  end
  backend_override = provider
end

function M._reset_for_test()
  backend_override = nil
end

function M._normalize_process_spec(context, opts)
  return normalize_process_spec(record_for(context), opts)
end

return M
