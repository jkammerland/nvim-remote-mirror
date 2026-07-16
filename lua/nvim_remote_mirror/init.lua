local M = {}

local uv = vim.uv or vim.loop

local function plugin_root()
  local source = debug.getinfo(1, "S").source
  if source:sub(1, 1) == "@" then
    source = source:sub(2)
  end
  return source:gsub("/lua/nvim_remote_mirror/init%.lua$", "")
end

local function executable_or_default(name)
  local candidate = plugin_root() .. "/target/debug/" .. name
  if uv.fs_stat(candidate) then
    return candidate
  end
  return name
end

local DEFAULT_CONFIG = {
  sidecar = executable_or_default("nrm-sidecar"),
  agent = executable_or_default("nrm-agent"),
  remote_agent = "nrm-agent",
  remote_agent_install_path = nil,
  remote_agent_auto_install = true,
  remote_agent_registry_url = nil,
  remote_agent_registry_public_keys = {},
  remote_agent_registry_signature_threshold = 1,
  remote_agent_registry_cache_dir = nil,
  remote_agent_registry_cache_max_bytes = 512 * 1024 * 1024,
  remote_agent_registry_timeout_ms = 120000,
  connection = "stdio",
  socket_path = nil,
  socket_dir = nil,
  daemon_start_timeout_ms = 1000,
  state_dir = nil,
  find_limit = 200,
  grep_limit = 200,
  grep_remote_page_files = 512,
  grep_remote_max_file_bytes = 512 * 1024,
  grep_remote_max_total_bytes = 8 * 1024 * 1024,
  grep_cache_max_files = 2000,
  grep_cache_max_file_bytes = 512 * 1024,
  grep_cache_max_total_bytes = 8 * 1024 * 1024,
  git_output_max_bytes = 1024 * 1024,
  request_timeout_ms = 30000,
  ssh_connect_timeout_seconds = 10,
  open_batch_max_file_bytes = 4 * 1024 * 1024,
  prefetch_max_file_bytes = 4 * 1024 * 1024,
  prefetch_max_total_bytes = 16 * 1024 * 1024,
  open_prefetch_related = false,
  open_prefetch_related_limit = 16,
  auto_hydrate_mirror_buffers = true,
  adoption_policy = "tracked_or_explicit",
  auto_reconnect = true,
  reconnect_delay_ms = 1000,
  reconnect_max_attempts = 3,
  reconnect_stable_ms = 10000,
  recover_local_edits_on_connect = true,
  recover_local_edits_limit = 256,
  flush_queue_on_connect = true,
  flush_queue_on_connect_delay_ms = 500,
  flush_queue_on_connect_limit = 1,
  background_mirror = true,
  background_mirror_interval_ms = 5000,
  background_mirror_rescan_interval_ms = 300000,
  background_mirror_scan_limit = 256,
  background_mirror_prefetch_limit = 4,
  background_mirror_refresh_limit = 32,
  background_mirror_max_file_bytes = 128 * 1024,
  background_mirror_max_total_bytes = 512 * 1024,
  picker = {
    provider = "auto",
  },
  remote_runtime = {
    enabled = true,
    trust = "prompt",
    detached_ttl_ms = 86400000,
    ticket_create_timeout_ms = 5000,
  },
}

M.config = vim.deepcopy(DEFAULT_CONFIG)

M.client = nil
M.last_target = nil
M.last_connection = nil
M.last_workspace_identity = nil
M.reconnect_attempts = 0
M.reconnect_generation = 0
M.grep_generation = 0
M.find_generation = 0
M.git_status_generation = 0
M.git_diff_generation = 0
M.git_blame_generation = 0
M.save_queue_generation = 0
M.connection_status = "disconnected"
M.connection_target = nil
M.connection_reason = nil
M.connection_error = nil
M.reconnect_pending = false
M.deferred_flushes = {}
M.background_mirror_running = false
M.background_mirror_generation = 0
M.background_scan_after = nil
M.mirror_autocmd_group = nil
M.lsp_clients = {}
M.lsp_last = nil
M.lsp_last_error = nil
M.lsp_generation = 0

local setup_mirror_autohydrate
local update_remote_state
local stop_lsp_for_client
local lsp_status_result
local remote_agent_bootstrap_params
local request_timeout_ms

local function notify(message, level)
  vim.schedule(function()
    vim.notify(message, level or vim.log.levels.INFO, { title = "nvim-remote-mirror" })
  end)
end

local function emit_workspace_event(pattern, client, extra)
  local hello = client and client.hello or {}
  local data = {
    epoch = M.reconnect_generation,
    workspace_key = type(hello.workspace_key) == "string" and hello.workspace_key ~= "" and hello.workspace_key or nil,
    target = client and client.target_arg or M.connection_target,
    state = M.connection_status,
  }
  if type(extra) == "table" then
    for key, value in pairs(extra) do
      data[key] = value
    end
  end
  pcall(vim.api.nvim_exec_autocmds, "User", {
    pattern = pattern,
    modeline = false,
    data = data,
  })
end

local function bump_reconnect_generation(reason, client)
  M.reconnect_generation = M.reconnect_generation + 1
  emit_workspace_event("NrmWorkspaceEpochChanged", client, { reason = reason })
  return M.reconnect_generation
end

local function optional_string(value)
  if type(value) == "string" and value ~= "" then
    return value
  end
  return nil
end

local function decode_standard_base64(value)
  if type(value) ~= "string" or #value == 0 or #value % 4 ~= 0 then
    return nil
  end
  local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local decoded = {}
  for offset = 1, #value, 4 do
    local chars = {
      value:sub(offset, offset),
      value:sub(offset + 1, offset + 1),
      value:sub(offset + 2, offset + 2),
      value:sub(offset + 3, offset + 3),
    }
    local numbers = {}
    local padding = 0
    for index, char in ipairs(chars) do
      if char == "=" then
        if offset + 3 ~= #value or index < 3 then
          return nil
        end
        padding = padding + 1
        numbers[index] = 0
      else
        if padding > 0 then
          return nil
        end
        local position = alphabet:find(char, 1, true)
        if not position then
          return nil
        end
        numbers[index] = position - 1
      end
    end
    if padding > 2 then
      return nil
    end
    if padding == 1 and numbers[3] % 4 ~= 0 then
      return nil
    end
    if padding == 2 and numbers[2] % 16 ~= 0 then
      return nil
    end
    local packed = numbers[1] * 262144 + numbers[2] * 4096 + numbers[3] * 64 + numbers[4]
    table.insert(decoded, string.char(math.floor(packed / 65536) % 256))
    if padding < 2 then
      table.insert(decoded, string.char(math.floor(packed / 256) % 256))
    end
    if padding == 0 then
      table.insert(decoded, string.char(packed % 256))
    end
  end
  return table.concat(decoded)
end

local REGISTRY_MAX_TRUSTED_KEYS = 32
local LUA_MAX_SAFE_INTEGER = 9007199254740991

-- Canonical compressed encodings of the eight small-order Edwards points.
-- Rust remains authoritative for complete Ed25519 point validation.
local WEAK_ED25519_PUBLIC_KEYS = {
  ["AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="] = true,
  ["xxdqcD1N2E+6PAt2DRBnDyogU/osOczGTsf9d5KsA3o="] = true,
  ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA="] = true,
  ["JuiVj8KyJ7BFw/SJ8u+Y8NXfrAXTxjM5sTgCiG1T/AU="] = true,
  ["7P///////////////////////////////////////38="] = true,
  ["JuiVj8KyJ7BFw/SJ8u+Y8NXfrAXTxjM5sTgCiG1T/IU="] = true,
  ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="] = true,
  ["xxdqcD1N2E+6PAt2DRBnDyogU/osOczGTsf9d5KsA/o="] = true,
}

local function parse_ipv4_literal(host)
  local parts = {}
  for part in host:gmatch("[^.]+") do
    table.insert(parts, part)
  end
  local numeric = #parts > 0 and table.concat(parts, ".") == host
  for _, part in ipairs(parts) do
    numeric = numeric and (part:match("^[0-9]+$") ~= nil or part:match("^0[xX][0-9A-Fa-f]+$") ~= nil)
  end
  if not numeric then
    return nil
  end
  if #parts ~= 4 then
    return false
  end

  local octets = {}
  for _, part in ipairs(parts) do
    if (#part > 1 and part:sub(1, 1) == "0") or not part:match("^[0-9]+$") then
      return false
    end
    local octet = tonumber(part)
    if not octet or octet > 255 then
      return false
    end
    table.insert(octets, octet)
  end
  if table.concat(octets, ".") ~= host then
    return false
  end
  return octets
end

local function ipv4_is_globally_routable(octets)
  local a, b, c = octets[1], octets[2], octets[3]
  return not (
    a == 0
    or a == 10
    or (a == 100 and b >= 64 and b <= 127)
    or a == 127
    or (a == 169 and b == 254)
    or (a == 172 and b >= 16 and b <= 31)
    or (a == 192 and b == 0 and c == 0)
    or (a == 192 and b == 0 and c == 2)
    or (a == 192 and b == 88 and c == 99)
    or (a == 192 and b == 168)
    or (a == 198 and b >= 18 and b <= 19)
    or (a == 198 and b == 51 and c == 100)
    or (a == 203 and b == 0 and c == 113)
    or a >= 224
  )
end

local function ipv6_tokens(part)
  if part == "" then
    return {}
  end
  if part:sub(1, 1) == ":" or part:sub(-1) == ":" then
    return nil
  end
  local tokens = {}
  for token in part:gmatch("[^:]+") do
    table.insert(tokens, token)
  end
  return tokens
end

local function parse_ipv6_literal(host)
  local compression = host:find("::", 1, true)
  if compression and host:find("::", compression + 2, true) then
    return nil
  end
  local left_text = compression and host:sub(1, compression - 1) or host
  local right_text = compression and host:sub(compression + 2) or ""
  local left = ipv6_tokens(left_text)
  local right = ipv6_tokens(right_text)
  if not left or not right then
    return nil
  end

  local tokens = {}
  vim.list_extend(tokens, left)
  vim.list_extend(tokens, right)
  local segments = {}
  for index, token in ipairs(tokens) do
    if token:find(".", 1, true) then
      if index ~= #tokens or (compression and index <= #left) then
        return nil
      end
      local octets = parse_ipv4_literal(token)
      if type(octets) ~= "table" then
        return nil
      end
      table.insert(segments, octets[1] * 256 + octets[2])
      table.insert(segments, octets[3] * 256 + octets[4])
    else
      if #token == 0 or #token > 4 or not token:match("^[0-9A-Fa-f]+$") then
        return nil
      end
      table.insert(segments, tonumber(token, 16))
    end
  end

  local missing = 8 - #segments
  if (compression and missing < 1) or (not compression and missing ~= 0) then
    return nil
  end
  if compression then
    local insertion = #left + 1
    if #left > 0 and left[#left]:find(".", 1, true) then
      insertion = insertion + 1
    end
    for _ = 1, missing do
      table.insert(segments, insertion, 0)
    end
  end
  return #segments == 8 and segments or nil
end

local function ipv6_is_globally_routable(segments)
  local embeds_ipv4 = true
  for index = 1, 6 do
    embeds_ipv4 = embeds_ipv4 and segments[index] == 0
  end
  local mapped_ipv4 = true
  for index = 1, 5 do
    mapped_ipv4 = mapped_ipv4 and segments[index] == 0
  end
  mapped_ipv4 = mapped_ipv4 and segments[6] == 0xFFFF

  local first, second = segments[1], segments[2]
  local global_unicast = first >= 0x2000 and first <= 0x3FFF
  local special_purpose = (
    first == 0x2001 and (second == 0 or second == 2 or (second >= 0x10 and second <= 0x2F) or second == 0x0DB8)
  )
    or first == 0x2002
    or (first == 0x3FFF and second <= 0x0FFF)
  return global_unicast and not special_purpose and not embeds_ipv4 and not mapped_ipv4
end

local function validate_https_registry_host(authority)
  local function valid_port_suffix(suffix)
    if suffix == "" then
      return true
    end
    local digits = suffix:match("^:([0-9]+)$")
    local port = digits and tonumber(digits) or nil
    return port ~= nil and port <= 65535
  end

  local host
  if authority:find("\\", 1, true) or authority:find("%", 1, true) then
    error("remote_agent_registry_url must contain a valid HTTPS host")
  end
  if authority:sub(1, 1) == "[" then
    local close = authority:find("]", 2, true)
    if not close then
      error("remote_agent_registry_url must contain a valid HTTPS host")
    end
    local suffix = authority:sub(close + 1)
    if not valid_port_suffix(suffix) then
      error("remote_agent_registry_url must contain a valid HTTPS host")
    end
    host = authority:sub(2, close - 1)
    local segments = parse_ipv6_literal(host)
    if not segments then
      error("remote_agent_registry_url must contain a valid IPv6 host")
    end
    if not ipv6_is_globally_routable(segments) then
      error("remote_agent_registry_url must not use localhost or a non-global literal host")
    end
    return
  end

  local colon = authority:find(":", 1, true)
  host = colon and authority:sub(1, colon - 1) or authority
  if host == "" or (colon and not valid_port_suffix(authority:sub(colon))) then
    error("remote_agent_registry_url must contain a valid HTTPS host")
  end
  if host:find("[", 1, true) or host:find("]", 1, true) then
    error("remote_agent_registry_url must contain a valid HTTPS host")
  end
  host = host:lower():gsub("%.+$", "")
  if host == "" or host:sub(1, 1) == "." or host:find("..", 1, true) then
    error("remote_agent_registry_url must contain a valid HTTPS host")
  end
  if host == "localhost" or host:sub(-10) == ".localhost" then
    error("remote_agent_registry_url must not use localhost or a non-global literal host")
  end
  local octets = parse_ipv4_literal(host)
  if octets == false then
    error("remote_agent_registry_url must contain a canonical IPv4 host")
  end
  if octets and not ipv4_is_globally_routable(octets) then
    error("remote_agent_registry_url must not use localhost or a non-global literal host")
  end
end

local function validate_registry_config(config)
  if type(config.remote_agent_auto_install) ~= "boolean" then
    error("remote_agent_auto_install must be a boolean")
  end
  local url = config.remote_agent_registry_url
  if url ~= nil then
    if type(url) ~= "string" or url == "" then
      error("remote_agent_registry_url must be nil or a non-empty string")
    end
    local without_version, placeholders = url:gsub("{version}", "")
    if placeholders ~= 1 then
      error("remote_agent_registry_url must contain exactly one {version} placeholder")
    end
    if without_version:find("[{}]") then
      error("remote_agent_registry_url contains an unsupported placeholder or unmatched brace")
    end
    if not url:match("^https://") and not url:match("^file:///") then
      error("remote_agent_registry_url must use https:// or an absolute file:// URL")
    end
    if url:find("[?#]") or url:find("%s") then
      error("remote_agent_registry_url must not contain queries, fragments, or whitespace")
    end
    if url:sub(-1) == "/" then
      error("remote_agent_registry_url must name a manifest file")
    end
    local authority = url:match("^https://([^/]+)")
    if url:match("^https://") and not authority then
      error("remote_agent_registry_url must contain an HTTPS host")
    end
    if authority and authority:find("@", 1, true) then
      error("remote_agent_registry_url must not contain credentials")
    end
    if authority then
      validate_https_registry_host(authority)
    end
    if url:match("^file:////") then
      error("remote_agent_registry_url file paths must be local absolute paths")
    end
  end

  local keys = config.remote_agent_registry_public_keys
  if type(keys) ~= "table" then
    error("remote_agent_registry_public_keys must be a key-id table")
  end
  local configured_key_count = 0
  for _ in pairs(keys) do
    configured_key_count = configured_key_count + 1
  end
  if configured_key_count > REGISTRY_MAX_TRUSTED_KEYS then
    error("remote agent registry public keys must contain at most 32 keys")
  end
  local key_count = 0
  local key_material = {}
  for key_id, encoded in pairs(keys) do
    if type(key_id) ~= "string" or #key_id == 0 or #key_id > 128 or not key_id:match("^[A-Za-z0-9._-]+$") then
      error("remote agent registry key IDs must use 1-128 ASCII letters, digits, '.', '_', or '-'")
    end
    local decoded = decode_standard_base64(encoded)
    if not decoded or #decoded ~= 32 then
      error("remote agent registry public keys must be canonical standard-base64 32-byte keys")
    end
    if key_material[decoded] then
      error("remote agent registry public keys must contain distinct key material")
    end
    if WEAK_ED25519_PUBLIC_KEYS[encoded] then
      error("remote agent registry public keys must not use weak Ed25519 points")
    end
    key_material[decoded] = key_id
    key_count = key_count + 1
  end
  local threshold = config.remote_agent_registry_signature_threshold
  if type(threshold) ~= "number" or threshold % 1 ~= 0 or threshold < 1 then
    error("remote_agent_registry_signature_threshold must be a positive integer")
  end
  if url and (key_count == 0 or threshold > key_count) then
    error("registry signature threshold must not exceed the configured trusted key count")
  end
  local cache_dir = config.remote_agent_registry_cache_dir
  if cache_dir ~= nil and (type(cache_dir) ~= "string" or cache_dir == "") then
    error("remote_agent_registry_cache_dir must be nil or a non-empty string")
  end
  for _, field in ipairs({ "remote_agent_registry_cache_max_bytes", "remote_agent_registry_timeout_ms" }) do
    local value = config[field]
    if type(value) ~= "number" or value % 1 ~= 0 or value < 1 then
      error(field .. " must be a positive integer")
    end
    if value > LUA_MAX_SAFE_INTEGER then
      error(field .. " must not exceed Lua's maximum safe integer")
    end
  end
  if
    not url
    and (
      key_count > 0
      or threshold ~= 1
      or cache_dir ~= nil
      or config.remote_agent_registry_cache_max_bytes ~= 512 * 1024 * 1024
      or config.remote_agent_registry_timeout_ms ~= 120000
    )
  then
    error("remote agent registry options require remote_agent_registry_url")
  end
end

local function validate_remote_runtime_config(config)
  local runtime = config.remote_runtime
  if type(runtime) ~= "table" then
    error("remote_runtime must be a table")
  end
  local allowed = {
    enabled = true,
    trust = true,
    detached_ttl_ms = true,
    ticket_create_timeout_ms = true,
  }
  for key in pairs(runtime) do
    if not allowed[key] then
      error("remote_runtime contains an unknown option: " .. tostring(key))
    end
  end
  if type(runtime.enabled) ~= "boolean" then
    error("remote_runtime.enabled must be a boolean")
  end
  if runtime.trust ~= "prompt" and runtime.trust ~= "always" and runtime.trust ~= "never" then
    error("remote_runtime.trust must be 'prompt', 'always', or 'never'")
  end
  if
    type(runtime.detached_ttl_ms) ~= "number"
    or runtime.detached_ttl_ms ~= math.floor(runtime.detached_ttl_ms)
    or runtime.detached_ttl_ms < 1
    or runtime.detached_ttl_ms > 30 * 24 * 60 * 60 * 1000
  then
    error("remote_runtime.detached_ttl_ms must be an integer from 1 to 2592000000")
  end
  if
    type(runtime.ticket_create_timeout_ms) ~= "number"
    or runtime.ticket_create_timeout_ms ~= math.floor(runtime.ticket_create_timeout_ms)
    or runtime.ticket_create_timeout_ms < 1
    or runtime.ticket_create_timeout_ms > 120000
  then
    error("remote_runtime.ticket_create_timeout_ms must be an integer from 1 to 120000")
  end
end

local function sorted_registry_keys(config)
  local entries = {}
  for key_id, key in pairs(config.remote_agent_registry_public_keys or {}) do
    table.insert(entries, { id = key_id, key = key })
  end
  table.sort(entries, function(left, right)
    return left.id < right.id
  end)
  return entries
end

local function registry_integer_string(value)
  return string.format("%.0f", value)
end

local function registry_policy_fingerprint(config)
  if not config.remote_agent_registry_url then
    return "disabled"
  end
  local parts = {
    "nrm-registry-policy-v1",
    config.remote_agent_registry_url,
    registry_integer_string(config.remote_agent_registry_signature_threshold),
    config.remote_agent_registry_cache_dir or "",
    registry_integer_string(config.remote_agent_registry_cache_max_bytes),
    registry_integer_string(config.remote_agent_registry_timeout_ms),
  }
  for _, entry in ipairs(sorted_registry_keys(config)) do
    table.insert(parts, entry.id .. "=" .. vim.fn.sha256(entry.key))
  end
  return vim.fn.sha256(table.concat(parts, "\31"))
end

local function registry_policy_matches(result, expected)
  return type(result) == "table" and optional_string(result.registry_policy_fingerprint) == expected
end

local function auto_adoption_enabled()
  return M.config.adoption_policy == "auto"
end

local function normalize_local_root(path)
  path = vim.fn.fnamemodify(path, ":p")
  local stripped = path:gsub("[/\\]+$", "")
  if stripped == "" or stripped:match("^%a:$") then
    return path
  end
  return stripped
end

local function normalize_local_path(path)
  return vim.fn.fnamemodify(path, ":p"):gsub("\\", "/")
end

local function validate_ssh_destination(destination)
  if destination == "" then
    error("ssh destination must not be empty")
  end
  if destination:sub(1, 1) == "-" then
    error("ssh destination must not begin with '-'")
  end
  if destination:find("[/\\]") then
    error("ssh destination must not contain path separators")
  end
  for index = 1, #destination do
    local byte = destination:byte(index)
    if byte <= 32 or byte == 127 then
      error("ssh destination must not contain whitespace or control characters")
    end
  end

  local at_start, at_end = destination:find("@", 1, true)
  local user = nil
  local host = destination
  if at_start then
    if destination:find("@", at_end + 1, true) then
      error("ssh destination must contain at most one '@'")
    end
    user = destination:sub(1, at_start - 1)
    host = destination:sub(at_end + 1)
    if user == "" or not user:match("^[%a%d._-]+$") then
      error("ssh destination contains an invalid user name")
    end
  end
  if host == "" or host:sub(1, 1) == "-" then
    error("ssh destination contains an invalid host name")
  end

  if host:sub(1, 1) == "[" or host:sub(-1) == "]" then
    if host:sub(1, 1) ~= "[" or host:sub(-1) ~= "]" or #host <= 2 then
      error("ssh destination contains an invalid bracketed host")
    end
    local address = host:sub(2, -2)
    if not address:match("^[%a%d:.%%_-]+$") then
      error("ssh destination contains an invalid bracketed host")
    end
  elseif not host:match("^[%a%d._-]+$") then
    error("ssh destination contains an invalid host name")
  end
end

local function percent_decode_ssh_path(path)
  local decoded = {}
  local index = 1
  while index <= #path do
    local byte = path:byte(index)
    if byte == string.byte("%") then
      local escape = path:sub(index + 1, index + 2)
      if #escape ~= 2 or not escape:match("^%x%x$") then
        error("ssh target path contains a malformed percent escape")
      end
      table.insert(decoded, string.char(tonumber(escape, 16)))
      index = index + 3
    else
      table.insert(decoded, string.char(byte))
      index = index + 1
    end
  end
  return table.concat(decoded)
end

local function validate_ssh_path(path)
  local index = 1
  while index <= #path do
    local byte = path:byte(index)
    local codepoint = nil
    local length = 1
    if byte < 0x80 then
      codepoint = byte
    elseif byte >= 0xC2 and byte <= 0xDF then
      length = 2
      local second = path:byte(index + 1)
      if not second or second < 0x80 or second > 0xBF then
        error("ssh target path must be valid UTF-8")
      end
      codepoint = (byte - 0xC0) * 0x40 + (second - 0x80)
    elseif byte >= 0xE0 and byte <= 0xEF then
      length = 3
      local second = path:byte(index + 1)
      local third = path:byte(index + 2)
      local second_min = byte == 0xE0 and 0xA0 or 0x80
      local second_max = byte == 0xED and 0x9F or 0xBF
      if not second or not third or second < second_min or second > second_max or third < 0x80 or third > 0xBF then
        error("ssh target path must be valid UTF-8")
      end
      codepoint = (byte - 0xE0) * 0x1000 + (second - 0x80) * 0x40 + (third - 0x80)
    elseif byte >= 0xF0 and byte <= 0xF4 then
      length = 4
      local second = path:byte(index + 1)
      local third = path:byte(index + 2)
      local fourth = path:byte(index + 3)
      local second_min = byte == 0xF0 and 0x90 or 0x80
      local second_max = byte == 0xF4 and 0x8F or 0xBF
      if
        not second
        or not third
        or not fourth
        or second < second_min
        or second > second_max
        or third < 0x80
        or third > 0xBF
        or fourth < 0x80
        or fourth > 0xBF
      then
        error("ssh target path must be valid UTF-8")
      end
      codepoint = (byte - 0xF0) * 0x40000 + (second - 0x80) * 0x1000 + (third - 0x80) * 0x40 + (fourth - 0x80)
    else
      error("ssh target path must be valid UTF-8")
    end
    if codepoint < 32 or (codepoint >= 0x7F and codepoint <= 0x9F) then
      error("ssh target path must not contain control characters")
    end
    index = index + length
  end

  if path:sub(1, 1) ~= "/" then
    error("expected ssh://host/absolute/path")
  end
  if path:sub(2, 2) == "/" or path:sub(2, 2) == "\\" then
    error("ssh target path must not use a UNC root")
  end

  local first_segment = path:match("^/([^/]*)") or ""
  if first_segment:match("^%a:") then
    if not path:match("^/%a:/") then
      error("ssh target path must use an absolute drive root")
    end
    local windows_path = first_segment:sub(1, 1):upper() .. path:sub(3)
    if windows_path:find("\\", 1, true) then
      error("ssh target drive paths must use forward slashes")
    end
    if windows_path:find("//", 1, true) then
      error("ssh target drive paths must not contain empty segments")
    end
    local remainder = windows_path:sub(4)
    for segment in remainder:gmatch("[^/]+") do
      if segment == "." or segment == ".." then
        error("ssh target drive paths must not contain dot segments")
      end
      if segment:find(":", 1, true) then
        error("ssh target drive paths must not contain alternate data streams")
      end
      if segment:match("[ .]$") then
        error("ssh target drive path segments must not end in a dot or space")
      end
    end
    return windows_path
  end
  if first_segment:sub(-1) == ":" then
    error("ssh target path contains an invalid drive root")
  end

  if path:find("//", 2, true) then
    error("ssh target paths must not contain empty segments")
  end
  for segment in path:gmatch("[^/]+") do
    if segment == "." or segment == ".." then
      error("ssh target paths must not contain dot segments")
    end
  end

  return path
end

local function percent_encode_ssh_path(path)
  local encoded = {}
  for index = 1, #path do
    local byte = path:byte(index)
    local unreserved = (byte >= string.byte("A") and byte <= string.byte("Z"))
      or (byte >= string.byte("a") and byte <= string.byte("z"))
      or (byte >= string.byte("0") and byte <= string.byte("9"))
      or byte == string.byte("-")
      or byte == string.byte(".")
      or byte == string.byte("_")
      or byte == string.byte("~")
    if unreserved or byte == string.byte("/") or byte == string.byte(":") then
      table.insert(encoded, string.char(byte))
    else
      table.insert(encoded, string.format("%%%02X", byte))
    end
  end
  return table.concat(encoded)
end

local function parse_target(target)
  if target == nil or target == "" then
    return { remote_root = normalize_local_root(uv.cwd()) }
  end

  if target:sub(1, 6) == "ssh://" then
    local ssh_body = target:sub(7)
    local host, path = ssh_body:match("^([^/]+)(/.*)$")
    if not host or not path then
      error("expected ssh://host/absolute/path")
    end
    validate_ssh_destination(host)
    path = validate_ssh_path(percent_decode_ssh_path(path))
    return { ssh = host, remote_root = path }
  end

  return { remote_root = normalize_local_root(target) }
end

local function reconnect_arg(target)
  if target.ssh then
    local path = target.remote_root
    if path:match("^%a:/") then
      path = "/" .. path
    end
    return "ssh://" .. target.ssh .. percent_encode_ssh_path(path)
  end
  return target.remote_root
end

local function files_root_relative_path(files_root, local_path)
  local_path = optional_string(local_path)
  if not local_path then
    return nil
  end
  if not files_root or files_root == "" then
    return nil
  end
  local root = normalize_local_path(files_root):gsub("/+$", "")
  local path = normalize_local_path(local_path)
  local prefix = root .. "/"
  if path:sub(1, #prefix) ~= prefix then
    return nil
  end
  local relative = path:sub(#prefix + 1)
  if relative == "" or relative:sub(1, 1) == "/" then
    return nil
  end
  return relative
end

local function mirror_relative_path(client, local_path)
  local hello = client and client.hello
  return files_root_relative_path(hello and hello.files_root, local_path)
end

local function files_root_local_path(files_root, relative_path)
  relative_path = optional_string(relative_path)
  files_root = optional_string(files_root)
  if not relative_path or not files_root then
    return nil
  end
  if relative_path:sub(1, 1) == "/" or relative_path:find("^%a:[/\\]") then
    return nil
  end
  local normalized_relative = relative_path:gsub("\\", "/")
  if normalized_relative:sub(1, 1) == "/" or normalized_relative:find("^%a:/") then
    return nil
  end
  if normalized_relative == "." then
    return nil
  end
  for segment in normalized_relative:gmatch("[^/]+") do
    if segment == ".." then
      return nil
    end
  end
  local root = normalize_local_path(files_root):gsub("/+$", "")
  local path = normalize_local_path(vim.fs.joinpath(root, normalized_relative))
  local prefix = root .. "/"
  if path ~= root and path:sub(1, #prefix) ~= prefix then
    return nil
  end
  return path
end

local function close_timer(timer)
  if timer and not timer:is_closing() then
    timer:stop()
    timer:close()
  end
end

local function clear_mirror_autohydrate()
  if M.mirror_autocmd_group then
    pcall(vim.api.nvim_del_augroup_by_id, M.mirror_autocmd_group)
    M.mirror_autocmd_group = nil
  end
end

local function clear_pending(client, id)
  local pending = client.pending[id]
  if not pending then
    return nil
  end
  client.pending[id] = nil
  if type(pending) == "table" then
    close_timer(pending.timer)
    return pending.callback
  end
  return pending
end

local function handle_response(client, line)
  local ok, decoded = pcall(vim.json.decode, line)
  if not ok then
    notify("invalid sidecar response: " .. line, vim.log.levels.ERROR)
    return
  end

  if decoded.id == nil and decoded.method then
    if decoded.method == "workspace/remote_health" then
      update_remote_state(client, decoded.params or {})
    end
    return
  end

  local callback = clear_pending(client, decoded.id)
  if not callback then
    return
  end

  if decoded.ok then
    callback(nil, decoded.result)
  else
    callback(decoded.error or "unknown sidecar error", nil)
  end
end

local function handle_stdout(client, data)
  if not data then
    return
  end

  for index, chunk in ipairs(data) do
    if index == 1 then
      chunk = client.stdout_tail .. chunk
      client.stdout_tail = ""
    end

    local is_last = index == #data
    if is_last and chunk ~= "" then
      client.stdout_tail = chunk
    elseif chunk ~= "" then
      handle_response(client, chunk)
    end
  end
end

if vim.g.nvim_remote_mirror_test then
  M._test_handle_stdout = handle_stdout
end

local function sidecar_args(target)
  local agent = M.config.agent
  if target.ssh then
    agent = optional_string(M.config.remote_agent) or "nrm-agent"
  end
  local args = {
    "serve",
    "--remote-root",
    target.remote_root,
    "--agent",
    agent,
  }
  if target.ssh then
    table.insert(args, "--ssh")
    table.insert(args, target.ssh)
    if optional_string(M.config.agent) then
      table.insert(args, "--local-agent")
      table.insert(args, M.config.agent)
    end
  end
  if M.config.state_dir then
    table.insert(args, "--state-dir")
    table.insert(args, M.config.state_dir)
  end
  if M.config.remote_agent_registry_url then
    table.insert(args, "--remote-agent-registry-url")
    table.insert(args, M.config.remote_agent_registry_url)
    for _, entry in ipairs(sorted_registry_keys(M.config)) do
      table.insert(args, "--remote-agent-registry-public-key")
      table.insert(args, entry.id .. "=" .. entry.key)
    end
    table.insert(args, "--remote-agent-registry-signature-threshold")
    table.insert(args, registry_integer_string(M.config.remote_agent_registry_signature_threshold))
    if M.config.remote_agent_registry_cache_dir then
      table.insert(args, "--remote-agent-registry-cache-dir")
      table.insert(args, M.config.remote_agent_registry_cache_dir)
    end
    table.insert(args, "--remote-agent-registry-cache-max-bytes")
    table.insert(args, registry_integer_string(M.config.remote_agent_registry_cache_max_bytes))
    table.insert(args, "--remote-agent-registry-timeout-ms")
    table.insert(args, registry_integer_string(M.config.remote_agent_registry_timeout_ms))
  end
  table.insert(args, "--request-timeout-ms")
  table.insert(args, tostring(M.config.request_timeout_ms))
  table.insert(args, "--ssh-connect-timeout-seconds")
  table.insert(args, tostring(M.config.ssh_connect_timeout_seconds))
  return args
end

local function listener_args(target, socket_path)
  local args = sidecar_args(target)
  args[1] = "listen"
  table.insert(args, 2, "--socket")
  table.insert(args, 3, socket_path)
  return args
end

local function path_join(root, leaf)
  return tostring(root):gsub("[/\\]+$", "") .. "/" .. leaf
end

local function executable_file_identity(path)
  path = optional_string(path)
  if not path then
    return ""
  end
  local resolved = vim.fn.exepath(path)
  if not optional_string(resolved) then
    resolved = path
  end
  local stat = uv.fs_stat(resolved)
  if not stat or stat.type ~= "file" then
    return resolved
  end
  local mtime = stat.mtime or {}
  local ctime = stat.ctime or {}
  return table.concat({
    resolved,
    tostring(stat.dev or ""),
    tostring(stat.ino or ""),
    tostring(stat.size or ""),
    tostring(mtime.sec or ""),
    tostring(mtime.nsec or ""),
    tostring(ctime.sec or ""),
    tostring(ctime.nsec or ""),
  }, ":")
end

local function default_socket_dir()
  if optional_string(M.config.socket_dir) then
    return M.config.socket_dir
  end
  if optional_string(M.config.state_dir) then
    return path_join(M.config.state_dir, "sockets")
  end
  local ok, run_dir = pcall(vim.fn.stdpath, "run")
  if ok and optional_string(run_dir) then
    return path_join(run_dir, "nvim-remote-mirror")
  end
  local user = (uv.os_getuid and tostring(uv.os_getuid())) or os.getenv("USER") or "unknown"
  local tmp = uv.os_tmpdir and uv.os_tmpdir() or "/tmp"
  return path_join(tmp, "nvim-remote-mirror-" .. user)
end

local function socket_path_for(target_arg, target)
  if optional_string(M.config.socket_path) then
    return M.config.socket_path
  end
  local agent = M.config.agent
  if target and target.ssh then
    agent = optional_string(M.config.remote_agent) or "nrm-agent"
  end
  local identity = table.concat({
    target_arg or "",
    M.config.sidecar or "",
    executable_file_identity(M.config.sidecar),
    agent or "",
    target and target.ssh and (M.config.agent or "") or "",
    M.config.state_dir or "",
    tostring(M.config.request_timeout_ms or ""),
    tostring(M.config.ssh_connect_timeout_seconds or ""),
  }, "\31")
  if M.config.remote_agent_registry_url then
    identity = identity .. "\31" .. registry_policy_fingerprint(M.config)
  end
  local hash = vim.fn.sha256(identity):sub(1, 24)
  return path_join(default_socket_dir(), hash .. ".sock")
end

local FIXED_SOCKET_AUTOMATIC_BOOTSTRAP_SKIP_REASON =
  "automatic agent bootstrap is disabled for an explicit socket_path; use a derived socket path"

local function automatic_bootstrap_skip_reason(connection)
  if connection == "socket" and optional_string(M.config.socket_path) then
    return FIXED_SOCKET_AUTOMATIC_BOOTSTRAP_SKIP_REASON
  end
  return nil
end

if vim.g.nvim_remote_mirror_test then
  M._test_parse_target = parse_target
  M._test_reconnect_arg = reconnect_arg
  M._test_sidecar_args = sidecar_args
  M._test_listener_args = listener_args
  M._test_socket_path_for = socket_path_for
  M._test_registry_policy_fingerprint = registry_policy_fingerprint
  M._test_registry_policy_matches = registry_policy_matches
end

local function fail_pending(client, message)
  for id in pairs(client.pending or {}) do
    local callback = clear_pending(client, id)
    if callback then
      pcall(callback, message, nil)
    end
  end
end

local function send_cancel_request(client, request_id)
  if not client or not client.job_id or not request_id then
    return
  end
  local cancel_id = client.next_id
  client.next_id = client.next_id + 1
  local payload = vim.json.encode({
    id = cancel_id,
    method = "cancel",
    params = {
      request_id = request_id,
    },
  }) .. "\n"
  pcall(vim.fn.chansend, client.job_id, payload)
end

local schedule_reconnect

local function fail_sidecar_send(client, message)
  local generation = M.reconnect_generation
  local reconnect = false
  if M.client == client and not client.closing then
    client.closing = true
    M.client = nil
    clear_mirror_autohydrate()
    M.connection_status = M.config.auto_reconnect and "reconnect_pending" or "disconnected"
    M.connection_target = client.target_arg
    M.connection_reason = nil
    M.connection_error = message
    M.reconnect_pending = M.config.auto_reconnect == true
    generation = bump_reconnect_generation("transport_failure", client)
    emit_workspace_event("NrmWorkspaceDisconnected", client, { reason = message })
    reconnect = M.config.auto_reconnect == true
  end
  fail_pending(client, message)
  if reconnect then
    schedule_reconnect(client.target_arg, generation, client.connection)
  end
end

local SOCKET_DIRECTORY_MODE = 448 -- 0700
local SOCKET_ALLOWED_MODE = 384 -- 0600
local SOCKET_STICKY_MODE = 512 -- 01000

local function current_process_uid()
  if uv.os_getuid then
    local ok, uid = pcall(uv.os_getuid)
    if ok and type(uid) == "number" and uid >= 0 then
      return uid
    end
  end
  if uv.os_get_passwd then
    local ok, passwd = pcall(uv.os_get_passwd)
    if ok and type(passwd) == "table" and type(passwd.uid) == "number" and passwd.uid >= 0 then
      return passwd.uid
    end
  end
  error("cannot determine the current uid for sidecar socket validation")
end

local function socket_lstat(path)
  local stat, err, code = uv.fs_lstat(path)
  if stat then
    return stat
  end
  if code == "ENOENT" then
    return nil
  end
  error("failed to inspect sidecar socket path " .. path .. ": " .. tostring(err or code))
end

local function permission_mode(stat, path)
  if type(stat.mode) ~= "number" then
    error("sidecar socket metadata did not report permissions for " .. path)
  end
  return stat.mode % 4096
end

local function validate_socket_directory(path, stat)
  if stat.type ~= "directory" then
    error("sidecar socket directory must be a directory and not a symlink: " .. path)
  end
  local uid = current_process_uid()
  if stat.uid ~= uid then
    error(
      "sidecar socket directory must be owned by the current uid: "
        .. path
        .. " (owner="
        .. tostring(stat.uid)
        .. ", current="
        .. tostring(uid)
        .. ")"
    )
  end
  local mode = permission_mode(stat, path)
  if mode ~= SOCKET_DIRECTORY_MODE then
    error("sidecar socket directory must have mode 0700: " .. path .. " (mode=" .. string.format("%04o", mode) .. ")")
  end
end

local function absolute_socket_path(path)
  local absolute = vim.fn.fnamemodify(path, ":p")
  if absolute ~= "/" then
    absolute = absolute:gsub("/+$", "")
  end
  return absolute
end

local function validate_socket_ancestor_metadata(path, stat, child_stat, uid)
  if stat.type == "link" then
    -- The symlink entry itself is protected by its parent. Its resolved target
    -- is checked separately below.
    return
  end
  if stat.type ~= "directory" then
    error("sidecar socket ancestor must be a directory or symlink: " .. path)
  end
  if stat.uid ~= uid and stat.uid ~= 0 then
    error(
      "sidecar socket ancestors must be owned by the current uid or root: "
        .. path
        .. " (owner="
        .. tostring(stat.uid)
        .. ", current="
        .. tostring(uid)
        .. ")"
    )
  end

  local mode = permission_mode(stat, path)
  local group_digit = math.floor(mode / 8) % 8
  local other_digit = mode % 8
  local group_writable = math.floor(group_digit / 2) % 2 == 1
  local other_writable = math.floor(other_digit / 2) % 2 == 1
  if group_writable or other_writable then
    local sticky = math.floor(mode / SOCKET_STICKY_MODE) % 2 == 1
    if not sticky then
      error(
        "sidecar socket ancestors must not be group/world-writable unless sticky: "
          .. path
          .. " (mode="
          .. string.format("%04o", mode)
          .. ")"
      )
    end
    if not child_stat or (child_stat.uid ~= uid and child_stat.uid ~= 0) then
      error("sidecar socket sticky ancestor does not protect its child entry: " .. path)
    end
  end
end

local function validate_socket_ancestor_chain(directory, directory_stat, uid)
  local current = absolute_socket_path(directory)
  local child_stat = directory_stat
  while current ~= "/" do
    local parent = absolute_socket_path(vim.fn.fnamemodify(current, ":h"))
    if parent == current then
      break
    end
    local stat = socket_lstat(parent)
    if not stat then
      error("sidecar socket ancestor disappeared during validation: " .. parent)
    end
    validate_socket_ancestor_metadata(parent, stat, child_stat, uid)
    current = parent
    child_stat = stat
  end
end

local function validate_socket_directory_ancestors(directory, directory_stat)
  local uid = current_process_uid()
  local lexical = absolute_socket_path(directory)
  validate_socket_ancestor_chain(lexical, directory_stat, uid)

  local resolved, err = uv.fs_realpath(directory)
  if not resolved then
    error("failed to resolve sidecar socket directory " .. directory .. ": " .. tostring(err))
  end
  resolved = absolute_socket_path(resolved)
  if resolved ~= lexical then
    local resolved_stat = socket_lstat(resolved)
    if not resolved_stat then
      error("resolved sidecar socket directory disappeared during validation: " .. resolved)
    end
    validate_socket_directory(resolved, resolved_stat)
    validate_socket_ancestor_chain(resolved, resolved_stat, uid)
  end
end

local function validate_socket_creation_anchor(anchor, anchor_stat, uid)
  validate_socket_ancestor_metadata(anchor, anchor_stat, { uid = uid }, uid)
  validate_socket_ancestor_chain(anchor, anchor_stat, uid)

  local resolved, err = uv.fs_realpath(anchor)
  if not resolved then
    error("failed to resolve sidecar socket creation ancestor " .. anchor .. ": " .. tostring(err))
  end
  resolved = absolute_socket_path(resolved)
  if resolved ~= anchor then
    local resolved_stat = socket_lstat(resolved)
    if not resolved_stat then
      error("resolved sidecar socket creation ancestor disappeared during validation: " .. resolved)
    end
    validate_socket_ancestor_metadata(resolved, resolved_stat, { uid = uid }, uid)
    validate_socket_ancestor_chain(resolved, resolved_stat, uid)
  end
end

local function prepare_socket_directory(socket_path)
  local directory = vim.fn.fnamemodify(socket_path, ":h")
  local stat = socket_lstat(directory)
  if stat then
    validate_socket_directory(directory, stat)
    validate_socket_directory_ancestors(directory, stat)
    return directory
  end

  local uid = current_process_uid()
  local missing = {}
  local anchor = absolute_socket_path(directory)
  local anchor_stat = socket_lstat(anchor)
  while not anchor_stat do
    table.insert(missing, anchor)
    local parent = absolute_socket_path(vim.fn.fnamemodify(anchor, ":h"))
    if parent == anchor then
      error("sidecar socket directory has no existing creation ancestor: " .. directory)
    end
    anchor = parent
    anchor_stat = socket_lstat(anchor)
  end
  validate_socket_creation_anchor(anchor, anchor_stat, uid)

  for index = #missing, 1, -1 do
    local component = missing[index]
    local created, mkdir_err, mkdir_code = uv.fs_mkdir(component, SOCKET_DIRECTORY_MODE)
    if not created and mkdir_code ~= "EEXIST" then
      error(
        "failed to create sidecar socket directory component " .. component .. ": " .. tostring(mkdir_err or mkdir_code)
      )
    end
    stat = socket_lstat(component)
    if not stat then
      error("failed to inspect sidecar socket directory component after creation: " .. component)
    end
    if created then
      if stat.type ~= "directory" or stat.uid ~= uid then
        validate_socket_directory(component, stat)
      end
      local chmod_ok, chmod_err = uv.fs_chmod(component, SOCKET_DIRECTORY_MODE)
      if not chmod_ok then
        error("failed to secure sidecar socket directory component " .. component .. ": " .. tostring(chmod_err))
      end
    end
    stat = socket_lstat(component)
    if not stat then
      error("sidecar socket directory component disappeared during validation: " .. component)
    end
    validate_socket_directory(component, stat)
    validate_socket_directory_ancestors(component, stat)
  end
  return directory
end

local function socket_mode_is_private(mode)
  local owner = math.floor(mode / 64) % 8
  local group = math.floor(mode / 8) % 8
  local other = mode % 8
  local special = math.floor(mode / 512) % 8
  return special == 0 and owner % 2 == 0 and group == 0 and other == 0 and mode <= SOCKET_ALLOWED_MODE
end

local function validate_existing_socket(socket_path)
  local stat = socket_lstat(socket_path)
  if not stat then
    return false
  end
  if stat.type ~= "socket" then
    error("sidecar socket path must be a Unix socket and not a symlink: " .. socket_path)
  end
  local uid = current_process_uid()
  if stat.uid ~= uid then
    error(
      "sidecar socket must be owned by the current uid: "
        .. socket_path
        .. " (owner="
        .. tostring(stat.uid)
        .. ", current="
        .. tostring(uid)
        .. ")"
    )
  end
  local mode = permission_mode(stat, socket_path)
  if not socket_mode_is_private(mode) then
    error(
      "sidecar socket permissions must not exceed 0600: "
        .. socket_path
        .. " (mode="
        .. string.format("%04o", mode)
        .. ")"
    )
  end
  return true
end

local function connect_socket_channel(client, socket_path)
  if not validate_existing_socket(socket_path) then
    return nil
  end
  local ok, channel = pcall(vim.fn.sockconnect, "pipe", socket_path, {
    on_data = function(_, data)
      if data == nil or (type(data) == "table" and #data == 1 and data[1] == "") then
        fail_sidecar_send(client, "sidecar socket closed")
        return
      end
      handle_stdout(client, data)
    end,
  })
  local channel_id = tonumber(channel)
  if ok and channel_id and channel_id > 0 then
    return channel_id
  end
  return nil
end

local function start_socket_daemon(_client, target, socket_path)
  prepare_socket_directory(socket_path)
  local command = vim.list_extend({ M.config.sidecar }, listener_args(target, socket_path))
  local job_id = vim.fn.jobstart(command, {
    detach = true,
    stdout_buffered = false,
    stderr_buffered = false,
    on_stdout = function(_, data)
      for _, line in ipairs(data or {}) do
        if line ~= "" then
          notify(line, vim.log.levels.INFO)
        end
      end
    end,
    on_stderr = function(_, data)
      for _, line in ipairs(data or {}) do
        if line ~= "" then
          notify(line, vim.log.levels.WARN)
        end
      end
    end,
  })
  if job_id <= 0 then
    error("failed to start sidecar daemon: " .. table.concat(command, " "))
  end
  return job_id
end

local function connect_or_start_socket(client, target)
  local socket_path = socket_path_for(client.target_arg, target)
  client.socket_path = socket_path
  prepare_socket_directory(socket_path)
  local channel = connect_socket_channel(client, socket_path)
  if channel then
    return channel, nil
  end

  local daemon_job_id = start_socket_daemon(client, target, socket_path)
  local deadline_ms = math.max(tonumber(M.config.daemon_start_timeout_ms) or 1000, 1)
  vim.wait(deadline_ms, function()
    channel = connect_socket_channel(client, socket_path)
    return channel ~= nil
  end, 25)
  if not channel then
    pcall(vim.fn.jobstop, daemon_job_id)
    error("failed to connect sidecar socket: " .. socket_path)
  end
  return channel, daemon_job_id
end

if vim.g.nvim_remote_mirror_test then
  M._test_prepare_socket_directory = prepare_socket_directory
  M._test_validate_existing_socket = validate_existing_socket
end

function schedule_reconnect(target_arg, generation, connection)
  generation = generation or M.reconnect_generation
  connection = connection or M.last_connection or M.config.connection
  if not M.config.auto_reconnect then
    return
  end
  if generation ~= M.reconnect_generation then
    return
  end
  if M.client then
    return
  end
  if not target_arg then
    return
  end
  if M.reconnect_attempts >= M.config.reconnect_max_attempts then
    M.connection_status = "disconnected"
    M.reconnect_pending = false
    M.connection_reason = nil
    M.connection_error = "reconnect attempts exhausted"
    notify("reconnect attempts exhausted", vim.log.levels.WARN)
    return
  end
  M.connection_status = "reconnect_pending"
  M.connection_target = target_arg
  M.reconnect_pending = true
  M.reconnect_attempts = M.reconnect_attempts + 1
  local attempt = M.reconnect_attempts
  vim.defer_fn(function()
    if generation ~= M.reconnect_generation then
      return
    end
    if M.client then
      return
    end
    M.connection_status = "reconnecting"
    M.reconnect_pending = false
    notify("reconnecting remote session, attempt " .. tostring(attempt), vim.log.levels.WARN)
    local ok, err = pcall(M.connect, target_arg, { reconnect = true, connection = connection })
    if not ok then
      M.connection_status = "reconnect_pending"
      M.reconnect_pending = true
      M.connection_reason = nil
      M.connection_error = tostring(err)
      notify("reconnect failed: " .. tostring(err), vim.log.levels.ERROR)
      schedule_reconnect(target_arg, generation, connection)
    end
  end, M.config.reconnect_delay_ms)
end

local function schedule_reconnect_stable_reset(client, generation)
  if M.reconnect_attempts == 0 then
    return
  end

  local delay = tonumber(M.config.reconnect_stable_ms) or 0
  vim.defer_fn(function()
    if M.client == client and not client.closing and generation == M.reconnect_generation then
      M.reconnect_attempts = 0
    end
  end, math.max(delay, 0))
end

local function flush_queue_summary(result)
  local counts = {
    applied = 0,
    queued = 0,
    conflict = 0,
    other = 0,
  }
  for _, attempt in ipairs(result.attempts or {}) do
    local status = attempt.status
    if counts[status] ~= nil then
      counts[status] = counts[status] + 1
    else
      counts.other = counts.other + 1
    end
  end
  return counts
end

local function notify_flush_queue_result(result, opts)
  opts = opts or {}
  local attempts = #(result.attempts or {})
  if attempts == 0 and opts.quiet_empty then
    return
  end

  local counts = flush_queue_summary(result)
  local remaining = tonumber(result.remaining) or 0
  local message = string.format(
    "replayed %d queued saves: applied=%d queued=%d conflicts=%d remaining=%d",
    attempts,
    counts.applied,
    counts.queued,
    counts.conflict,
    remaining
  )
  local level = vim.log.levels.INFO
  if counts.conflict > 0 then
    level = vim.log.levels.ERROR
  elseif counts.queued > 0 or counts.other > 0 then
    level = vim.log.levels.WARN
  end
  notify(message, level)
end

local function save_queue_entry_text(entry)
  local state = optional_string(entry.state) or "unknown"
  local path = optional_string(entry.path) or "<unknown>"
  local parts = { "[" .. state .. "]" }
  local queue_id = tonumber(entry.queue_id)
  if queue_id then
    table.insert(parts, "#" .. tostring(queue_id))
  end
  table.insert(parts, path)
  local attempts = tonumber(entry.attempts)
  if attempts and attempts > 0 then
    table.insert(parts, "attempts=" .. tostring(attempts))
  end
  local remote_conflict_path = optional_string(entry.remote_conflict_path)
  if remote_conflict_path then
    table.insert(parts, "remote=" .. remote_conflict_path)
    if entry.remote_conflict_truncated == true then
      table.insert(parts, "remote=partial")
    end
  end
  if state == "unreplayable" and not optional_string(entry.snapshot_path) then
    table.insert(parts, "snapshot=missing")
  end
  local last_error = optional_string(entry.last_error)
  if last_error then
    table.insert(parts, "error=" .. last_error:sub(1, 160))
  end
  return table.concat(parts, " ")
end

local function save_queue_level(counts)
  counts = counts or {}
  if (tonumber(counts.conflict) or 0) > 0 then
    return vim.log.levels.ERROR
  end
  if (tonumber(counts.failed) or 0) > 0 or (tonumber(counts.unreplayable) or 0) > 0 then
    return vim.log.levels.WARN
  end
  return vim.log.levels.INFO
end

function M.format_save_queue_entry(entry)
  return save_queue_entry_text(entry or {})
end

update_remote_state = function(client, result)
  if not client or not client.hello or not result then
    return
  end
  client.hello.remote_status = result.remote_status
  client.hello.remote_checked = result.remote_checked
  client.hello.remote_available = result.remote_available
  client.hello.remote_error = result.remote_error
  client.hello.retry_after_ms = result.retry_after_ms
  if type(result.registry_health) == "table" then
    client.hello.registry_health = result.registry_health
  end
  if result.remote_checked == true and result.remote_available == false then
    client.hello.agent_version = nil
    client.hello.protocol_version = nil
  end
  for _, field in ipairs({
    "agent_status",
    "agent_version",
    "expected_agent_version",
    "protocol_version",
    "expected_protocol_version",
    "remote_agent",
    "remote_agent_install_path",
    "managed_remote_agent_path",
    "local_agent_path",
    "local_agent_available",
    "local_agent_error",
    "agent_source",
    "registry_configured",
    "install_available",
    "update_available",
    "repair_command",
  }) do
    if result[field] ~= nil then
      client.hello[field] = result[field]
    end
  end
end

local function registry_summary(result)
  local registry = result and result.registry_health or nil
  if type(registry) ~= "table" then
    return "registry=unknown"
  end
  local parts = { "registry=" .. (optional_string(registry.state) or "unknown") }
  local platform = registry.platform
  if type(platform) == "table" then
    local target = optional_string(platform.target)
    if target then
      table.insert(parts, "registry_target=" .. target)
    end
  end
  local error_code = optional_string(registry.error_code)
  if error_code then
    table.insert(parts, "registry_error=" .. error_code)
  end
  return table.concat(parts, " ")
end

local function status_remote_summary(result)
  local status = optional_string(result.remote_status) or "unchecked"
  local parts = { "remote=" .. status }
  local retry_after_ms = tonumber(result.retry_after_ms)
  if retry_after_ms and retry_after_ms > 0 then
    table.insert(parts, "retry_after_ms=" .. tostring(math.floor(retry_after_ms)))
  end
  local remote_error = optional_string(result.remote_error)
  if remote_error and result.remote_available == false then
    remote_error = remote_error:gsub("%s+", " ")
    table.insert(parts, "error=" .. remote_error:sub(1, 160))
  end
  return table.concat(parts, " ")
end

local function agent_summary(result)
  result = result or {}
  local parts = {}
  local agent_status = optional_string(result.agent_status)
  if agent_status then
    table.insert(parts, "agent=" .. agent_status)
  end
  local agent_version = optional_string(result.agent_version)
  local expected_agent_version = optional_string(result.expected_agent_version)
  if agent_version then
    table.insert(parts, "agent_version=" .. agent_version)
  elseif expected_agent_version then
    table.insert(parts, "expected_agent=" .. expected_agent_version)
  end
  local repair = optional_string(result.repair_command)
  if repair then
    table.insert(parts, "repair=" .. repair)
  end
  return table.concat(parts, " ")
end

local function background_scan_summary(result)
  local state = optional_string(result.background_scan_state)
  if not state or state == "not_started" then
    return nil
  end
  local parts = { "scan=" .. state }
  if state == "in_progress" then
    local cursor = optional_string(result.background_scan_cursor)
    if cursor then
      table.insert(parts, "after=" .. cursor)
    end
  elseif state == "completed" then
    local completed_at = tonumber(result.background_scan_completed_at_ms)
    local rescan_after = tonumber(M.config.background_mirror_rescan_interval_ms)
    if completed_at and rescan_after and rescan_after > 0 then
      local due = math.max(math.floor(completed_at + rescan_after - (os.time() * 1000)), 0)
      table.insert(parts, "rescan_due_ms=" .. tostring(due))
    end
  end
  return table.concat(parts, " ")
end

local function connection_summary()
  local parts = { "connection=" .. tostring(M.connection_status or "disconnected") }
  if M.reconnect_pending then
    table.insert(parts, "reconnect=pending")
  end
  if
    (M.connection_status == "reconnect_pending" or M.connection_status == "reconnecting")
    and M.config.reconnect_max_attempts
  then
    table.insert(
      parts,
      "attempts=" .. tostring(M.reconnect_attempts) .. "/" .. tostring(M.config.reconnect_max_attempts)
    )
  end
  if M.connection_target then
    table.insert(parts, "target=" .. tostring(M.connection_target))
  end
  if M.connection_reason then
    local reason_text = tostring(M.connection_reason):gsub("%s+", " ")
    table.insert(parts, "reason=" .. reason_text:sub(1, 160))
  end
  if M.connection_error then
    local error_text = tostring(M.connection_error):gsub("%s+", " ")
    table.insert(parts, "error=" .. error_text:sub(1, 160))
  end
  return table.concat(parts, " ")
end

function M.connection_state()
  local client = M.client
  local hello = client and client.hello or {}
  return {
    status = M.connection_status or "disconnected",
    target = M.connection_target,
    reason = M.connection_reason,
    error = M.connection_error,
    reconnect_pending = M.reconnect_pending == true,
    reconnect_attempts = M.reconnect_attempts,
    reconnect_max_attempts = M.config.reconnect_max_attempts,
    has_client = client ~= nil and client.job_id ~= nil,
    last_target = M.last_target,
    transport = client and client.transport or nil,
    workspace_key = optional_string(hello.workspace_key),
    remote_root = optional_string(hello.remote_root),
    mirror_root = optional_string(hello.mirror_root),
    files_root = optional_string(hello.files_root),
    remote_status = optional_string(hello.remote_status),
    remote_checked = hello.remote_checked,
    remote_available = hello.remote_available,
    remote_error = optional_string(hello.remote_error),
    retry_after_ms = hello.retry_after_ms,
    agent_status = optional_string(hello.agent_status),
    agent_version = optional_string(hello.agent_version),
    expected_agent_version = optional_string(hello.expected_agent_version),
    protocol_version = hello.protocol_version,
    expected_protocol_version = hello.expected_protocol_version,
    remote_agent = optional_string(hello.remote_agent),
    remote_agent_install_path = optional_string(hello.remote_agent_install_path),
    managed_remote_agent_path = optional_string(hello.managed_remote_agent_path),
    local_agent_path = optional_string(hello.local_agent_path),
    local_agent_available = hello.local_agent_available,
    local_agent_error = optional_string(hello.local_agent_error),
    agent_source = optional_string(hello.agent_source),
    registry_configured = hello.registry_configured,
    registry_health = type(hello.registry_health) == "table" and hello.registry_health or nil,
    install_available = hello.install_available,
    update_available = hello.update_available,
    repair_command = optional_string(hello.repair_command),
    agent_bootstrap_automatic = client and client.agent_bootstrap_automatic == true or false,
    agent_bootstrap_state = client and optional_string(client.agent_bootstrap_state) or nil,
    agent_bootstrap_result = client and optional_string(client.agent_bootstrap_result) or nil,
    agent_bootstrap_reason = client and optional_string(client.agent_bootstrap_reason) or nil,
    agent_bootstrap_error = client and optional_string(client.agent_bootstrap_error) or nil,
  }
end

function M.current_workspace()
  local client = M.client
  if not client or not client.job_id or not client.hello then
    return nil
  end
  local hello = client.hello
  local capabilities = type(hello.capabilities) == "table" and vim.deepcopy(hello.capabilities) or {}
  return {
    workspace_key = optional_string(hello.workspace_key),
    target = M.connection_target or optional_string(client.target_arg),
    target_arg = optional_string(client.target_arg),
    transport = optional_string(client.transport),
    remote_root = optional_string(hello.remote_root),
    mirror_root = optional_string(hello.mirror_root),
    files_root = optional_string(hello.files_root),
    remote_status = optional_string(hello.remote_status),
    remote_checked = hello.remote_checked,
    remote_available = hello.remote_available,
    remote_error = optional_string(hello.remote_error),
    retry_after_ms = hello.retry_after_ms,
    registry_health = type(hello.registry_health) == "table" and hello.registry_health or nil,
    remote_host = type(hello.remote_host) == "table" and vim.deepcopy(hello.remote_host) or nil,
    capabilities = capabilities,
    runtime = {
      enabled = M.config.remote_runtime.enabled == true,
      trust = M.config.remote_runtime.trust,
      ticket = capabilities.runtime_ticket_v1 == true,
      process = capabilities.runtime_process_v1 == true,
      terminal = capabilities.runtime_pty_v1 == true,
      watch = capabilities.workspace_watch_v1 == true,
    },
  }
end

function M.workspace(query)
  return require("nvim_remote_mirror.workspace").resolve(query or {})
end

function M.files_root()
  local workspace = M.current_workspace()
  return workspace and workspace.files_root or nil
end

function M.remote_root()
  local workspace = M.current_workspace()
  return workspace and workspace.remote_root or nil
end

function M.mirror_root()
  local workspace = M.current_workspace()
  return workspace and workspace.mirror_root or nil
end

function M.is_remote_buffer(bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  if not vim.api.nvim_buf_is_valid(bufnr) then
    return false
  end
  return optional_string(vim.b[bufnr].nrm_remote_path) ~= nil
    or optional_string(vim.b[bufnr].nrm_hydrate_path) ~= nil
    or optional_string(vim.b[bufnr].nrm_workspace_key) ~= nil
    or optional_string(vim.b[bufnr].nrm_target_arg) ~= nil
    or optional_string(vim.b[bufnr].nrm_files_root) ~= nil
end

function M.remote_path(bufnr_or_local_path)
  if type(bufnr_or_local_path) == "number" then
    if not vim.api.nvim_buf_is_valid(bufnr_or_local_path) then
      return nil
    end
    local path = optional_string(vim.b[bufnr_or_local_path].nrm_remote_path)
    if not path then
      return nil
    end
    local workspace = M.current_workspace()
    if not workspace then
      return nil
    end
    local workspace_key = optional_string(vim.b[bufnr_or_local_path].nrm_workspace_key)
    if workspace_key and workspace.workspace_key and workspace_key ~= workspace.workspace_key then
      return nil
    end
    local target_arg = optional_string(vim.b[bufnr_or_local_path].nrm_target_arg)
    if target_arg and workspace.target_arg and target_arg ~= workspace.target_arg then
      return nil
    end
    local files_root = optional_string(vim.b[bufnr_or_local_path].nrm_files_root)
    if files_root and workspace.files_root then
      local buffer_root = normalize_local_path(files_root):gsub("/+$", "")
      local current_root = normalize_local_path(workspace.files_root):gsub("/+$", "")
      if buffer_root ~= current_root then
        return nil
      end
    end
    return path
  end

  local local_path = optional_string(bufnr_or_local_path)
  if not local_path then
    local bufnr = vim.api.nvim_get_current_buf()
    return M.remote_path(bufnr)
  end
  return files_root_relative_path(M.files_root(), local_path)
end

function M.local_path(remote_path)
  return files_root_local_path(M.files_root(), remote_path)
end

function M.cd()
  local root = M.files_root()
  if not root then
    error("not connected; run :RemoteConnect first")
  end
  local stat = uv.fs_stat(root)
  if not stat or stat.type ~= "directory" then
    error("remote mirror files root is not available: " .. root)
  end
  vim.cmd("tcd " .. vim.fn.fnameescape(root))
  notify("remote cwd: " .. root)
  return root
end

function M.trust_workspace(opts)
  local ok, err = require("nvim_remote_mirror.runtime").trust_workspace(opts)
  if ok then
    notify("trusted remote workspace for process execution")
  end
  return ok, err
end

function M.untrust_workspace(opts)
  local ok, err = require("nvim_remote_mirror.runtime").untrust_workspace(opts)
  if ok then
    notify("removed remote workspace process trust")
  end
  return ok, err
end

function M.open_terminal(opts)
  opts = opts or {}
  if type(opts) ~= "table" then
    return nil, "remote terminal options must be a table"
  end
  local context, context_err = M.workspace(opts.query)
  if not context then
    return nil, context_err
  end

  local authorization_complete = false
  local authorization_error
  local authorized = false
  context:authorize("terminal", function(err, granted)
    authorization_complete = true
    authorization_error = err
    authorized = granted == true
  end)
  if not authorization_complete then
    return nil, "remote terminal authorization is pending; use a synchronous workspace trust provider"
  end
  if not authorized then
    return nil, authorization_error or "remote terminal authorization was denied"
  end

  local command = opts.command
  if command == nil or (type(command) == "table" and #command == 0) then
    command = { shell = "default" }
  else
    command = { argv = vim.deepcopy(command) }
  end
  local process = {
    command = command,
    cwd = opts.cwd,
    env = opts.env,
    persistence = opts.persistence or "attached",
    max_output_bytes = opts.max_output_bytes,
    timeout_ms = opts.timeout_ms,
    initial_size = opts.initial_size,
  }

  local previous_window = vim.api.nvim_get_current_win()
  vim.cmd("botright new")
  local terminal_window = vim.api.nvim_get_current_win()
  local terminal_buffer = vim.api.nvim_get_current_buf()
  local function cleanup_terminal_layout()
    if vim.api.nvim_win_is_valid(terminal_window) then
      pcall(vim.api.nvim_win_close, terminal_window, true)
    end
    if vim.api.nvim_win_is_valid(previous_window) then
      pcall(vim.api.nvim_set_current_win, previous_window)
    end
    if vim.api.nvim_buf_is_valid(terminal_buffer) then
      pcall(vim.api.nvim_buf_delete, terminal_buffer, { force = true })
    end
  end
  if process.initial_size == nil then
    process.initial_size = {
      cols = math.max(vim.api.nvim_win_get_width(terminal_window), 1),
      rows = math.max(vim.api.nvim_win_get_height(terminal_window), 1),
    }
  end
  local handle, spawn_err = context:open_pty(process, opts.handlers)
  if not handle then
    cleanup_terminal_layout()
    return nil, spawn_err
  end

  local function fail_started_terminal(cause)
    if type(handle.kill) == "function" then
      pcall(handle.kill, handle)
    end
    cleanup_terminal_layout()
    return nil, "failed to activate the remote terminal: " .. tostring(cause)
  end
  if
    not vim.api.nvim_win_is_valid(terminal_window)
    or not vim.api.nvim_buf_is_valid(terminal_buffer)
    or vim.api.nvim_win_get_buf(terminal_window) ~= terminal_buffer
  then
    return fail_started_terminal("the terminal window or buffer was changed during TermOpen")
  end
  local metadata_ok, metadata_err = pcall(function()
    vim.b[terminal_buffer].nrm_workspace_key = context.workspace_id
    vim.b[terminal_buffer].nrm_runtime_terminal = true
  end)
  if not metadata_ok then
    return fail_started_terminal(metadata_err)
  end
  local focus_ok, focus_err = pcall(vim.api.nvim_set_current_win, terminal_window)
  if not focus_ok or vim.api.nvim_get_current_win() ~= terminal_window then
    return fail_started_terminal(focus_err or "could not select the terminal window")
  end
  if
    not vim.api.nvim_win_is_valid(terminal_window)
    or not vim.api.nvim_buf_is_valid(terminal_buffer)
    or vim.api.nvim_win_get_buf(terminal_window) ~= terminal_buffer
  then
    return fail_started_terminal("the terminal window or buffer was changed while restoring terminal focus")
  end
  -- Match Neovim's built-in terminal workflow: a freshly opened interactive
  -- shell should receive the next key instead of interpreting it as a normal-
  -- mode command. Provider-level open_pty() remains mode-neutral for plugins
  -- that own their own terminal UI.
  local insert_ok, insert_err = pcall(function()
    vim.cmd("startinsert")
  end)
  if not insert_ok then
    return fail_started_terminal(insert_err)
  end
  return handle
end

local function decorate_status_result(result)
  result = result or {}
  result.connection = M.connection_state()
  result.connected = result.connection.has_client == true
  result.connection_summary = connection_summary()
  result.remote_summary = status_remote_summary(result)
  if type(result.registry_health) ~= "table" then
    result.registry_health = result.connection.registry_health
  end
  result.registry_summary = registry_summary(result)
  result.background_scan_summary = background_scan_summary(result)
  if lsp_status_result then
    result.lsp = lsp_status_result({ notify = false })
  end
  return result
end

local function client_identity(client)
  if not client then
    return nil
  end
  local hello = client.hello or {}
  return {
    workspace_key = optional_string(hello.workspace_key),
    target_arg = optional_string(client.target_arg),
    files_root = optional_string(hello.files_root),
  }
end

local function buffer_identity(bufnr)
  if not bufnr or not vim.api.nvim_buf_is_valid(bufnr) then
    return nil
  end
  return {
    workspace_key = optional_string(vim.b[bufnr].nrm_workspace_key),
    target_arg = optional_string(vim.b[bufnr].nrm_target_arg),
    files_root = optional_string(vim.b[bufnr].nrm_files_root),
  }
end

local function identity_key(identity)
  identity = identity or {}
  return table.concat({
    identity.workspace_key or "",
    identity.target_arg or "",
    identity.files_root or "",
  }, "\30")
end

local function identity_has_scope(identity)
  return identity and (identity.workspace_key ~= nil or identity.target_arg ~= nil or identity.files_root ~= nil)
end

local function identity_relative_path(identity, local_path)
  if not identity_has_scope(identity) then
    return nil
  end
  return files_root_relative_path(identity.files_root, local_path)
end

local function deferred_flush_key(path, identity)
  return identity_key(identity) .. "\31" .. path
end

local function identity_matches_client(identity, client)
  if not identity then
    return true
  end
  local current = client_identity(client)
  if not current then
    return false
  end
  if identity.workspace_key and current.workspace_key then
    return identity.workspace_key == current.workspace_key
  end
  if identity.target_arg and current.target_arg then
    return identity.target_arg == current.target_arg
  end
  if identity.files_root and current.files_root then
    return normalize_local_path(identity.files_root):gsub("/+$", "")
      == normalize_local_path(current.files_root):gsub("/+$", "")
  end
  return true
end

local function buffer_matches_identity(bufnr, path, identity)
  if not vim.api.nvim_buf_is_valid(bufnr) or vim.b[bufnr].nrm_remote_path ~= path then
    return false
  end
  return identity_key(buffer_identity(bufnr)) == identity_key(identity)
end

local function has_deferred_flush(path, identity)
  return M.deferred_flushes[deferred_flush_key(path, identity)] ~= nil
end

local function flush_target_buffers(bufnr, identity)
  local targets = {}
  if bufnr then
    table.insert(targets, bufnr)
    return targets
  end
  for pending_bufnr in pairs((identity and identity.bufnrs) or {}) do
    table.insert(targets, pending_bufnr)
  end
  return targets
end

local function set_buffer_editable(bufnr, editable)
  if not bufnr or not vim.api.nvim_buf_is_valid(bufnr) then
    return
  end
  pcall(vim.api.nvim_set_option_value, "modifiable", editable, { buf = bufnr })
  pcall(vim.api.nvim_set_option_value, "readonly", not editable, { buf = bufnr })
end

local function set_buffer_hydrate_pending(bufnr, client, relative_path)
  if not vim.api.nvim_buf_is_valid(bufnr) then
    return
  end
  local identity = client_identity(client)
  vim.b[bufnr].nrm_hydrate_pending = true
  vim.b[bufnr].nrm_hydrate_failed = false
  vim.b[bufnr].nrm_hydrate_path = relative_path
  vim.b[bufnr].nrm_remote_path = nil
  vim.b[bufnr].nrm_remote_hash = nil
  vim.b[bufnr].nrm_workspace_key = identity and identity.workspace_key or nil
  vim.b[bufnr].nrm_target_arg = identity and identity.target_arg or nil
  vim.b[bufnr].nrm_files_root = identity and identity.files_root or nil
  vim.b[bufnr].nrm_flush_pending = false
  set_buffer_editable(bufnr, false)
end

local function set_buffer_hydrate_failed(bufnr, relative_path)
  if not vim.api.nvim_buf_is_valid(bufnr) then
    return
  end
  vim.b[bufnr].nrm_hydrate_pending = false
  vim.b[bufnr].nrm_hydrate_failed = true
  vim.b[bufnr].nrm_hydrate_path = relative_path
  vim.b[bufnr].nrm_remote_path = nil
  vim.b[bufnr].nrm_remote_hash = nil
  vim.b[bufnr].nrm_flush_pending = false
  set_buffer_editable(bufnr, false)
end

local function set_remote_buffer_identity(bufnr, client, result)
  if not result or not result.path or not vim.api.nvim_buf_is_valid(bufnr) then
    return
  end
  local identity = client_identity(client)
  set_buffer_editable(bufnr, true)
  vim.b[bufnr].nrm_hydrate_pending = false
  vim.b[bufnr].nrm_hydrate_failed = false
  vim.b[bufnr].nrm_hydrate_path = nil
  vim.b[bufnr].nrm_remote_path = result.path
  vim.b[bufnr].nrm_remote_hash = result.hash
  vim.b[bufnr].nrm_workspace_key = identity and identity.workspace_key or nil
  vim.b[bufnr].nrm_target_arg = identity and identity.target_arg or nil
  vim.b[bufnr].nrm_files_root = identity and identity.files_root or nil
  vim.b[bufnr].nrm_flush_pending = has_deferred_flush(result.path, identity)
end

local function adopt_mirror_buffer_for_save(bufnr, identity, relative_path)
  if not relative_path or relative_path == "" or not vim.api.nvim_buf_is_valid(bufnr) then
    return
  end
  set_buffer_editable(bufnr, true)
  vim.b[bufnr].nrm_hydrate_pending = false
  vim.b[bufnr].nrm_hydrate_failed = false
  vim.b[bufnr].nrm_hydrate_path = nil
  vim.b[bufnr].nrm_remote_path = relative_path
  vim.b[bufnr].nrm_remote_hash = nil
  vim.b[bufnr].nrm_workspace_key = identity and identity.workspace_key or nil
  vim.b[bufnr].nrm_target_arg = identity and identity.target_arg or nil
  vim.b[bufnr].nrm_files_root = identity and identity.files_root or nil
  vim.b[bufnr].nrm_flush_pending = has_deferred_flush(relative_path, identity)
end

local function mark_deferred_flush(bufnr, path, reason, identity, adopt)
  if not path or path == "" then
    return false
  end
  identity = identity or buffer_identity(bufnr) or client_identity(M.client)

  local key = deferred_flush_key(path, identity)
  local item = M.deferred_flushes[key]
  local is_new = item == nil
  if not item then
    item = {
      path = path,
      workspace_key = identity and identity.workspace_key or nil,
      target_arg = identity and identity.target_arg or nil,
      files_root = identity and identity.files_root or nil,
      adopt = adopt == true,
      bufnrs = {},
    }
    M.deferred_flushes[key] = item
  end
  item.adopt = item.adopt or adopt == true
  item.reason = reason
  item.updated_at = os.time()
  if bufnr and vim.api.nvim_buf_is_valid(bufnr) then
    item.bufnrs[bufnr] = true
    vim.b[bufnr].nrm_flush_pending = true
  end
  return is_new
end

local function clear_deferred_flush(path, identity)
  if not path then
    return
  end
  local key = deferred_flush_key(path, identity)
  if not M.deferred_flushes[key] then
    return
  end
  M.deferred_flushes[key] = nil
  for _, bufnr in ipairs(vim.api.nvim_list_bufs()) do
    if buffer_matches_identity(bufnr, path, identity) then
      vim.b[bufnr].nrm_flush_pending = false
    end
  end
end

local function deferred_flush_items(client)
  local items = {}
  for _, item in pairs(M.deferred_flushes) do
    if not client or identity_matches_client(item, client) then
      table.insert(items, item)
    end
  end
  table.sort(items, function(a, b)
    if a.path == b.path then
      return identity_key(a) < identity_key(b)
    end
    return a.path < b.path
  end)
  return items
end

local function schedule_deferred_flushes_on_connect(client, generation)
  if #deferred_flush_items(client) == 0 then
    return
  end
  vim.defer_fn(function()
    if M.client ~= client or client.closing or generation ~= M.reconnect_generation then
      return
    end
    M.flush_deferred()
  end, 0)
end

local function schedule_save_recovery_on_connect(client, generation)
  if not M.config.recover_local_edits_on_connect and not M.config.flush_queue_on_connect then
    return
  end

  local delay = math.max(tonumber(M.config.flush_queue_on_connect_delay_ms) or 0, 0)
  local limit = math.max(tonumber(M.config.flush_queue_on_connect_limit) or 1, 1)
  local recover_limit = math.max(math.floor(tonumber(M.config.recover_local_edits_limit) or 256), 1)

  local function still_current()
    return M.client == client and not client.closing and generation == M.reconnect_generation
  end

  local function replay_once()
    if not still_current() then
      return
    end

    M.flush_queue({
      background = true,
      limit = limit,
      quiet_empty = true,
      on_done = function(err, result)
        if err or not result or not still_current() then
          return
        end
        local counts = flush_queue_summary(result)
        local remaining = tonumber(result.remaining) or 0
        if remaining > 0 and #(result.attempts or {}) > 0 and counts.queued == 0 and counts.conflict == 0 then
          vim.defer_fn(replay_once, delay)
        end
      end,
    })
  end

  local function probe_then_replay()
    if not still_current() then
      return
    end
    if not M.config.flush_queue_on_connect then
      return
    end
    M.request("remote_probe", {}, function(err, result)
      if err or not result or result.preempted or not still_current() then
        return
      end
      update_remote_state(client, result)
      if result.remote_available then
        replay_once()
      end
    end)
  end

  local function recover_then_replay()
    if not still_current() then
      return
    end
    if not M.config.recover_local_edits_on_connect then
      probe_then_replay()
      return
    end

    local after = nil
    local function recover_page()
      if not still_current() then
        return
      end
      M.recover_local_edits({
        background = true,
        limit = recover_limit,
        after = after,
        quiet_empty = true,
        on_done = function(err, result)
          if not still_current() then
            return
          end
          if err or not result then
            probe_then_replay()
            return
          end
          local next_after = optional_string(result.next_after)
          if result.truncated and next_after then
            after = next_after
            vim.defer_fn(recover_page, 0)
            return
          end
          probe_then_replay()
        end,
      })
    end

    recover_page()
  end

  vim.defer_fn(recover_then_replay, delay)
end

local function background_interval()
  return math.max(tonumber(M.config.background_mirror_interval_ms) or 0, 0)
end

local function schedule_background_mirror(delay, generation)
  vim.defer_fn(function()
    if not M.background_mirror_running or generation ~= M.background_mirror_generation then
      return
    end
    if not M.client or not M.client.hello then
      schedule_background_mirror(background_interval(), generation)
      return
    end

    local client = M.client
    M.remote_probe(function(err, probe)
      if not M.background_mirror_running or generation ~= M.background_mirror_generation or M.client ~= client then
        return
      end
      if err or not probe or probe.remote_available ~= true then
        local retry_after = probe and tonumber(probe.retry_after_ms) or nil
        schedule_background_mirror(retry_after or background_interval(), generation)
        return
      end

      local scan_params = {
        limit = M.config.background_mirror_scan_limit,
        resume = true,
        rescan_after_ms = M.config.background_mirror_rescan_interval_ms,
      }
      if M.background_scan_after then
        scan_params.after = M.background_scan_after
      end
      M.request("scan", scan_params, function(scan_err, scan_result)
        if not M.background_mirror_running or generation ~= M.background_mirror_generation or M.client ~= client then
          return
        end
        if scan_err or not scan_result or scan_result.preempted then
          schedule_background_mirror(background_interval(), generation)
          return
        end

        if scan_result.truncated and optional_string(scan_result.next_after) then
          M.background_scan_after = scan_result.next_after
        else
          M.background_scan_after = nil
        end

        local function still_current_background()
          return M.background_mirror_running and generation == M.background_mirror_generation and M.client == client
        end

        local function finish_background_tick()
          if not still_current_background() then
            return
          end
          local refresh_limit = math.max(tonumber(M.config.background_mirror_refresh_limit) or 0, 0)
          if refresh_limit == 0 then
            schedule_background_mirror(background_interval(), generation)
            return
          end
          M.request("refresh", {
            background = true,
            limit = refresh_limit,
          }, function()
            if not still_current_background() then
              return
            end
            schedule_background_mirror(background_interval(), generation)
          end)
        end

        local prefetch_limit = math.max(tonumber(M.config.background_mirror_prefetch_limit) or 0, 0)
        if prefetch_limit == 0 then
          finish_background_tick()
          return
        end

        M.request("prefetch_known", {
          limit = prefetch_limit,
          max_file_bytes = M.config.background_mirror_max_file_bytes,
          max_total_bytes = M.config.background_mirror_max_total_bytes,
        }, function()
          if not M.background_mirror_running or generation ~= M.background_mirror_generation or M.client ~= client then
            return
          end
          finish_background_tick()
        end)
      end)
    end)
  end, math.max(tonumber(delay) or 0, 0))
end

function M.start_background_mirror()
  M.background_mirror_running = true
  M.background_mirror_generation = M.background_mirror_generation + 1
  schedule_background_mirror(0, M.background_mirror_generation)
end

function M.stop_background_mirror()
  M.background_mirror_running = false
  M.background_mirror_generation = M.background_mirror_generation + 1
end

function M.setup(opts)
  local merged = vim.tbl_deep_extend("force", vim.deepcopy(DEFAULT_CONFIG), opts or {})
  if opts and opts.remote_agent_registry_public_keys ~= nil then
    merged.remote_agent_registry_public_keys = vim.deepcopy(opts.remote_agent_registry_public_keys)
  end
  validate_registry_config(merged)
  validate_remote_runtime_config(merged)
  M.config = merged
end

local function current_connect_client(client, generation)
  return M.client == client and not client.closing and generation == M.reconnect_generation
end

local DISCONNECT_CLOSE_DELAY_MS = 250

local function monotonic_ms()
  if uv.hrtime then
    return math.floor(uv.hrtime() / 1000000)
  end
  if uv.now then
    return uv.now()
  end
  return math.floor(os.clock() * 1000)
end

local function automatic_bootstrap_disconnect_delay_ms(client)
  if not client or client.agent_bootstrap_in_flight ~= true then
    return DISCONNECT_CLOSE_DELAY_MS
  end
  local deadline_ms = tonumber(client.agent_bootstrap_deadline_ms)
  if not deadline_ms then
    return math.max(tonumber(client.agent_bootstrap_timeout_ms) or 0, DISCONNECT_CLOSE_DELAY_MS)
  end
  local remaining_ms = math.max(math.ceil(deadline_ms - monotonic_ms()), 0)
  return math.max(remaining_ms, DISCONNECT_CLOSE_DELAY_MS)
end

local function fail_workspace_info_connect(client, generation, message)
  if not current_connect_client(client, generation) then
    return
  end
  message = tostring(message)
  client.closing = true
  fail_pending(client, message)
  if client.transport == "socket" and client.job_id then
    pcall(vim.fn.chanclose, client.job_id)
  elseif client.job_id then
    pcall(vim.fn.jobstop, client.job_id)
  end
  if M.client == client then
    M.client = nil
  end
  clear_mirror_autohydrate()
  M.connection_status = M.config.auto_reconnect and "reconnect_pending" or "disconnected"
  M.connection_target = client.target_arg
  M.connection_reason = nil
  M.connection_error = message
  M.reconnect_pending = M.config.auto_reconnect == true
  notify(message, vim.log.levels.ERROR)
  schedule_reconnect(client.target_arg, generation, client.connection)
end

local function automatic_health_is_compatible(health)
  local agent_version = optional_string(health.agent_version)
  local expected_agent_version = optional_string(health.expected_agent_version)
  local protocol_version = health.protocol_version
  local expected_protocol_version = health.expected_protocol_version
  return health.remote_checked == true
    and health.remote_available == true
    and optional_string(health.agent_status) == "ok"
    and agent_version ~= nil
    and expected_agent_version ~= nil
    and agent_version == expected_agent_version
    and type(protocol_version) == "number"
    and type(expected_protocol_version) == "number"
    and protocol_version == expected_protocol_version
end

local function finish_connect(client, target_arg, is_reconnect, generation)
  if not current_connect_client(client, generation) then
    return
  end
  local result = client.hello or {}
  M.connection_status = "connected"
  M.connection_target = target_arg
  M.connection_reason = nil
  M.connection_error = nil
  M.reconnect_pending = false
  setup_mirror_autohydrate(client)
  emit_workspace_event("NrmWorkspaceConnected", client, { reconnect = is_reconnect == true })
  if is_reconnect then
    schedule_reconnect_stable_reset(client, generation)
  end

  local suffixes = {}
  if result.remote_status == "unchecked" then
    table.insert(suffixes, "remote unchecked")
  end
  if client.agent_bootstrap_state == "error" then
    table.insert(suffixes, "automatic agent install failed")
  elseif client.agent_bootstrap_state == "skipped" then
    table.insert(suffixes, "automatic agent install skipped")
  elseif client.agent_bootstrap_state == "ready" and client.agent_bootstrap_result ~= "skipped" then
    table.insert(suffixes, "remote agent ready")
  end
  local suffix = #suffixes > 0 and (" (" .. table.concat(suffixes, "; ") .. ")") or ""
  notify("connected: " .. result.remote_root .. suffix)

  if client.agent_bootstrap_state == "error" then
    notify("automatic remote agent install failed: " .. client.agent_bootstrap_error, vim.log.levels.ERROR)
  elseif client.agent_bootstrap_state == "skipped" and client.agent_bootstrap_reason then
    notify("automatic remote agent install skipped: " .. client.agent_bootstrap_reason, vim.log.levels.WARN)
  end

  schedule_deferred_flushes_on_connect(client, generation)
  schedule_save_recovery_on_connect(client, generation)
  if M.config.background_mirror then
    M.start_background_mirror()
  end
end

local function finish_workspace_info(client, result, target_arg, is_reconnect, generation)
  if not current_connect_client(client, generation) then
    return
  end
  client.hello = result
  M.last_workspace_identity = client_identity(client)

  if not client.agent_bootstrap_automatic then
    client.agent_bootstrap_state = "disabled"
    finish_connect(client, target_arg, is_reconnect, generation)
    return
  end
  if client.agent_bootstrap_skip_reason then
    client.agent_bootstrap_state = "skipped"
    client.agent_bootstrap_reason = client.agent_bootstrap_skip_reason
    finish_connect(client, target_arg, is_reconnect, generation)
    return
  end
  if type(result.capabilities) ~= "table" or result.capabilities.remote_agent_automatic_bootstrap_v1 ~= true then
    client.agent_bootstrap_state = "skipped"
    client.agent_bootstrap_reason = "sidecar does not advertise safe automatic agent bootstrap support"
    finish_connect(client, target_arg, is_reconnect, generation)
    return
  end

  client.agent_bootstrap_state = "installing"
  M.connection_status = "bootstrapping_agent"
  local params = { automatic = true }
  if client.agent_bootstrap_install_path then
    params.install_path = client.agent_bootstrap_install_path
  end
  local bootstrap_timeout_ms = request_timeout_ms("remote_agent_update", client)
  client.agent_bootstrap_in_flight = true
  client.agent_bootstrap_timeout_ms = bootstrap_timeout_ms
  client.agent_bootstrap_deadline_ms = math.min(monotonic_ms() + bootstrap_timeout_ms, LUA_MAX_SAFE_INTEGER)
  M.request("remote_agent_update", params, function(err, bootstrap_result)
    client.agent_bootstrap_in_flight = false
    client.agent_bootstrap_deadline_ms = nil
    if not current_connect_client(client, generation) then
      return
    end
    if err then
      client.agent_bootstrap_state = "error"
      client.agent_bootstrap_error = tostring(err)
      finish_connect(client, target_arg, is_reconnect, generation)
      return
    end

    if
      type(bootstrap_result) ~= "table"
      or bootstrap_result.automatic ~= true
      or (bootstrap_result.status ~= "updated" and bootstrap_result.status ~= "skipped")
      or type(bootstrap_result.remote_health) ~= "table"
      or (bootstrap_result.status == "skipped" and optional_string(bootstrap_result.reason) == nil)
    then
      client.agent_bootstrap_state = "error"
      client.agent_bootstrap_error = "sidecar returned an invalid automatic agent bootstrap result"
      finish_connect(client, target_arg, is_reconnect, generation)
      return
    end

    local health = bootstrap_result.remote_health
    local bootstrap_agent_status = optional_string(health.agent_status)
    local requires_compatible_health = bootstrap_result.status == "updated"
      or (bootstrap_result.status == "skipped" and bootstrap_agent_status == "ok")
    if requires_compatible_health and not automatic_health_is_compatible(health) then
      client.agent_bootstrap_state = "error"
      client.agent_bootstrap_error = "automatic agent bootstrap completed without compatible remote health"
      update_remote_state(client, health)
      finish_connect(client, target_arg, is_reconnect, generation)
      return
    end

    update_remote_state(client, health)
    client.agent_bootstrap_result = bootstrap_result.status
    client.agent_bootstrap_reason = optional_string(bootstrap_result.reason)
    if client.agent_bootstrap_result == "skipped" and bootstrap_agent_status ~= "ok" then
      client.agent_bootstrap_state = "skipped"
    else
      client.agent_bootstrap_state = "ready"
    end
    finish_connect(client, target_arg, is_reconnect, generation)
  end)
end

function M.connect(target, opts)
  opts = opts or {}
  target = parse_target(target)
  local target_arg = reconnect_arg(target)
  local is_reconnect = opts.reconnect == true
  M.connection_status = is_reconnect and "reconnecting" or "connecting"
  M.connection_target = target_arg
  M.connection_reason = nil
  M.connection_error = nil
  M.reconnect_pending = false
  if not opts.reconnect then
    M.reconnect_attempts = 0
    bump_reconnect_generation("connect", nil)
  end
  local generation = M.reconnect_generation

  if M.client and M.client.job_id then
    M.disconnect({ preserve_last_target = true })
  end

  local connection = opts.connection or M.config.connection or "stdio"

  local client = {
    next_id = 1,
    pending = {},
    stdout_tail = "",
    target = target,
    target_arg = target_arg,
    closing = false,
    connection = connection,
    agent_bootstrap_automatic = M.config.remote_agent_auto_install == true and optional_string(
      M.config.remote_agent_registry_url
    ) ~= nil and target.ssh ~= nil,
    agent_bootstrap_install_path = optional_string(M.config.remote_agent_install_path),
    agent_bootstrap_skip_reason = automatic_bootstrap_skip_reason(connection),
    agent_bootstrap_state = "disabled",
    expected_registry_policy_fingerprint = registry_policy_fingerprint(M.config),
    runtime_config = {
      sidecar = M.config.sidecar,
      agent = M.config.agent,
      remote_agent = M.config.remote_agent,
      state_dir = M.config.state_dir,
      request_timeout_ms = M.config.request_timeout_ms,
      ssh_connect_timeout_seconds = M.config.ssh_connect_timeout_seconds,
    },
    -- Requests must use the same timeout policy that was passed to this
    -- sidecar. A later setup() call only applies after reconnecting.
    timeout_config = {
      request_timeout_ms = M.config.request_timeout_ms,
      remote_agent_registry_timeout_ms = M.config.remote_agent_registry_timeout_ms,
      registry_enabled = optional_string(M.config.remote_agent_registry_url) ~= nil,
    },
  }

  if connection == "socket" then
    client.transport = "socket"
    local ok, channel, daemon_job_id = pcall(connect_or_start_socket, client, target)
    if not ok then
      M.connection_status = "disconnected"
      M.connection_reason = nil
      M.connection_error = tostring(channel)
      M.reconnect_pending = false
      error(channel)
    end
    client.job_id = channel
    client.daemon_job_id = daemon_job_id
  elseif connection == "stdio" then
    client.transport = "stdio"
    local command = vim.list_extend({ M.config.sidecar }, sidecar_args(target))
    client.job_id = vim.fn.jobstart(command, {
      stdout_buffered = false,
      stderr_buffered = false,
      on_stdout = function(_, data)
        handle_stdout(client, data)
      end,
      on_stderr = function(_, data)
        for _, line in ipairs(data or {}) do
          if line ~= "" then
            notify(line, vim.log.levels.WARN)
          end
        end
      end,
      on_exit = function(_, code)
        client.exited = true
        if M.client == client then
          if stop_lsp_for_client then
            stop_lsp_for_client(client, { quiet = true, force = true })
          end
          M.client = nil
          clear_mirror_autohydrate()
        end
        local unexpected = not client.closing
        if unexpected then
          fail_pending(client, "sidecar exited with code " .. tostring(code))
          M.connection_status = M.config.auto_reconnect and "reconnect_pending" or "disconnected"
          M.connection_target = client.target_arg
          M.connection_reason = nil
          M.connection_error = "sidecar exited with code " .. tostring(code)
          M.reconnect_pending = M.config.auto_reconnect == true
          local exit_generation = bump_reconnect_generation("transport_exit", client)
          emit_workspace_event("NrmWorkspaceDisconnected", client, { reason = M.connection_error })
          notify("sidecar exited with code " .. tostring(code), vim.log.levels.ERROR)
          schedule_reconnect(client.target_arg, exit_generation, client.connection)
        else
          fail_pending(client, "disconnected")
        end
      end,
    })

    if client.job_id <= 0 then
      M.connection_status = "disconnected"
      M.connection_reason = nil
      M.connection_error = "failed to start sidecar"
      M.reconnect_pending = false
      error("failed to start sidecar: " .. table.concat(command, " "))
    end
  else
    M.connection_status = "disconnected"
    M.connection_reason = nil
    M.connection_error = "unsupported sidecar connection mode: " .. tostring(connection)
    M.reconnect_pending = false
    error(M.connection_error)
  end

  M.client = client
  M.last_target = target_arg
  M.last_connection = connection
  M.request("workspace_info", {}, function(err, result)
    if not current_connect_client(client, generation) then
      return
    end
    if err then
      fail_workspace_info_connect(client, generation, err)
      return
    end
    if not registry_policy_matches(result, client.expected_registry_policy_fingerprint) then
      local mismatch = "sidecar registry policy mismatch; refusing stale or differently configured daemon"
      client.closing = true
      fail_pending(client, mismatch)
      if client.transport == "socket" and client.job_id then
        pcall(vim.fn.chanclose, client.job_id)
      elseif client.job_id then
        pcall(vim.fn.jobstop, client.job_id)
      end
      if M.client == client then
        M.client = nil
      end
      M.connection_status = "disconnected"
      M.connection_reason = nil
      M.connection_error = mismatch
      M.reconnect_pending = false
      notify(mismatch, vim.log.levels.ERROR)
      return
    end
    finish_workspace_info(client, result, target_arg, is_reconnect, generation)
  end)
end

function M.disconnect(opts)
  opts = opts or {}
  if not M.client then
    clear_mirror_autohydrate()
    if not opts.preserve_last_target then
      M.reconnect_attempts = 0
      M.connection_status = "disconnected"
      M.connection_target = nil
      M.connection_reason = "explicit disconnect"
      M.connection_error = nil
      M.reconnect_pending = false
      bump_reconnect_generation("disconnect", nil)
      emit_workspace_event("NrmWorkspaceDisconnected", nil, { reason = M.connection_reason })
    end
    return
  end
  local client = M.client
  local automatic_bootstrap_in_flight = client.agent_bootstrap_in_flight == true
  local process_close_delay_ms = automatic_bootstrap_disconnect_delay_ms(client)
  client.closing = true
  if stop_lsp_for_client then
    stop_lsp_for_client(client, { quiet = true, force = true })
  end
  pcall(M.request, "disconnect", {}, function() end)
  fail_pending(client, "disconnected")
  if client.transport == "socket" then
    vim.defer_fn(function()
      if client.job_id then
        pcall(vim.fn.chanclose, client.job_id)
      end
    end, DISCONNECT_CLOSE_DELAY_MS)
    if opts.stop_daemon and client.daemon_job_id then
      vim.defer_fn(function()
        pcall(vim.fn.jobstop, client.daemon_job_id)
      end, automatic_bootstrap_in_flight and process_close_delay_ms or DISCONNECT_CLOSE_DELAY_MS)
    end
  elseif client.job_id then
    vim.defer_fn(function()
      if not client.exited then
        pcall(vim.fn.jobstop, client.job_id)
      end
    end, process_close_delay_ms)
  end
  clear_mirror_autohydrate()
  M.client = nil
  if not opts.preserve_last_target then
    M.stop_background_mirror()
    M.reconnect_attempts = 0
    M.connection_status = "disconnected"
    M.connection_target = nil
    M.connection_reason = "explicit disconnect"
    M.connection_error = nil
    M.reconnect_pending = false
    bump_reconnect_generation("disconnect", client)
    emit_workspace_event("NrmWorkspaceDisconnected", client, { reason = M.connection_reason })
  end
end

function M.reconnect()
  if not M.last_target then
    error("no previous remote target to reconnect")
  end
  if M.client then
    M.disconnect({ preserve_last_target = true })
  end
  M.reconnect_attempts = 0
  M.connection_status = "reconnecting"
  M.connection_target = M.last_target
  M.connection_reason = nil
  M.connection_error = nil
  M.reconnect_pending = false
  bump_reconnect_generation("reconnect", nil)
  M.connect(M.last_target, { reconnect = true, connection = M.last_connection })
end

local BOOTSTRAP_TIMER_GRACE_MS = 1000

request_timeout_ms = function(method, client)
  local bootstrap = method == "remote_agent_install" or method == "remote_agent_update"
  local timeout_config = client and client.timeout_config or nil
  local configured = timeout_config and timeout_config.request_timeout_ms or M.config.request_timeout_ms
  local registry_enabled
  if timeout_config then
    registry_enabled = timeout_config.registry_enabled == true
  else
    registry_enabled = optional_string(M.config.remote_agent_registry_url) ~= nil
  end
  if bootstrap and registry_enabled then
    configured = timeout_config and timeout_config.remote_agent_registry_timeout_ms
      or M.config.remote_agent_registry_timeout_ms
  end
  local timeout_ms = math.max(tonumber(configured) or 0, 0)
  if bootstrap then
    timeout_ms = math.min(timeout_ms + BOOTSTRAP_TIMER_GRACE_MS, LUA_MAX_SAFE_INTEGER)
  end
  return timeout_ms
end

local function request_cancels_on_timeout(method, params)
  local bootstrap = method == "remote_agent_install" or method == "remote_agent_update"
  return not (bootstrap and type(params) == "table" and params.automatic == true)
end

function M.request(method, params, callback)
  local client = M.client
  if not client or not client.job_id then
    error("not connected; run :RemoteConnect first")
  end

  local id = client.next_id
  client.next_id = client.next_id + 1
  callback = callback or function() end
  local pending = {
    callback = callback,
    timer = nil,
  }
  local timeout_ms = request_timeout_ms(method, client)
  local cancel_on_timeout = request_cancels_on_timeout(method, params)
  if timeout_ms > 0 then
    local timer = uv.new_timer()
    pending.timer = timer
    timer:start(timeout_ms, 0, function()
      vim.schedule(function()
        local timed_out = clear_pending(client, id)
        if timed_out then
          if cancel_on_timeout then
            send_cancel_request(client, id)
          end
          pcall(timed_out, "request `" .. method .. "` timed out after " .. tostring(timeout_ms) .. " ms", nil)
        end
      end)
    end)
  end
  client.pending[id] = pending

  local payload = vim.json.encode({
    id = id,
    method = method,
    params = params or {},
  }) .. "\n"
  local ok, sent = pcall(vim.fn.chansend, client.job_id, payload)
  if not ok or (tonumber(sent) or 0) <= 0 then
    local reason = ok and "sidecar channel closed" or ("sidecar channel send failed: " .. tostring(sent))
    fail_sidecar_send(client, reason)
  end
end

if vim.g.nvim_remote_mirror_test then
  M._test_request_timeout_ms = request_timeout_ms
  M._test_request_cancels_on_timeout = request_cancels_on_timeout
  M._test_clear_pending = clear_pending
end

local function request_async(method, params, callback)
  callback = callback or function() end
  local ok, err = pcall(M.request, method, params or {}, callback)
  if not ok then
    callback(tostring(err), nil)
  end
end

function M.status_async(callback)
  callback = callback or function() end
  if not M.client or not M.client.job_id then
    callback(nil, decorate_status_result({}))
    return
  end

  local client = M.client
  request_async("status", {}, function(err, result)
    if err then
      callback(err, decorate_status_result({}))
      return
    end
    if M.client == client then
      update_remote_state(client, result)
    end
    callback(nil, decorate_status_result(result or {}))
  end)
end

function M.remote_probe(callback)
  local client = M.client
  if not client or not client.job_id then
    error("not connected; run :RemoteConnect first")
  end

  M.request("remote_probe", {}, function(err, result)
    if not err and M.client == client and not (result and result.preempted) then
      update_remote_state(client, result)
    end
    if callback then
      callback(err, result)
    end
  end)
end

function M.remote_health(callback)
  local client = M.client
  if not client or not client.job_id then
    error("not connected; run :RemoteConnect first")
  end

  M.request("remote_health", {}, function(err, result)
    if not err and M.client == client and not (result and result.preempted) then
      update_remote_state(client, result)
    end
    if callback then
      callback(err, result)
      return
    end
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    notify(
      vim.trim(
        status_remote_summary(result or {})
          .. " "
          .. agent_summary(result or {})
          .. " "
          .. registry_summary(result or {})
      )
    )
  end)
end

remote_agent_bootstrap_params = function(opts)
  opts = opts or {}
  local params = {}
  if opts.force == true then
    params.force = true
  end
  local install_path = optional_string(opts.install_path) or optional_string(M.config.remote_agent_install_path)
  if install_path then
    params.install_path = install_path
  end
  return params
end

local function remote_agent_bootstrap(method, opts, callback)
  local client = M.client
  if not client or not client.job_id then
    error("not connected; run :RemoteConnect first")
  end

  M.request(method, remote_agent_bootstrap_params(opts), function(err, result)
    local health = result and result.remote_health or nil
    if not err and M.client == client and health then
      update_remote_state(client, health)
    end
    if callback then
      callback(err, result)
      return
    end
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    local status = result and result.status or "ok"
    local install_path = optional_string(result and result.install_path)
    local health_summary = agent_summary(health or {})
    local message = "remote agent " .. tostring(status)
    if install_path then
      message = message .. " at " .. install_path
    end
    if health_summary ~= "" then
      message = message .. " " .. health_summary
    end
    if health then
      message = message .. " " .. registry_summary(health)
    end
    notify(message)
  end)
end

function M.install_agent(opts, callback)
  if type(opts) == "function" then
    callback = opts
    opts = {}
  end
  remote_agent_bootstrap("remote_agent_install", opts, callback)
end

function M.update_agent(opts, callback)
  if type(opts) == "function" then
    callback = opts
    opts = {}
  end
  remote_agent_bootstrap("remote_agent_update", opts, callback)
end

local function warn_cached_open(result)
  if result.force_skipped then
    notify("kept dirty local mirror for " .. result.path .. "; force rehydrate skipped", vim.log.levels.WARN)
    return
  end
  if result.restored_from_snapshot then
    notify("restored dirty local mirror snapshot for " .. result.path, vim.log.levels.WARN)
    return
  end
  if result.cached and result.cache_reason and result.cache_reason ~= "cached" then
    notify("opened cached " .. result.cache_reason .. " mirror for " .. result.path, vim.log.levels.WARN)
  end
end

local prefetch_related

local function blob_to_text(blob)
  if type(blob) == "string" then
    if blob:find("\000", 1, true) then
      return nil, "binary"
    end
    return blob, nil
  end
  local ok, bytes = pcall(vim.fn.blob2list, blob)
  if not ok then
    return nil, tostring(bytes)
  end
  local chunks = {}
  for index, byte in ipairs(bytes) do
    if byte == 0 then
      return nil, "binary"
    end
    chunks[index] = string.char(byte)
  end
  return table.concat(chunks), nil
end

local function text_to_buffer_lines(text)
  if text == "" then
    return { "" }, false
  end
  local has_final_newline = text:sub(-1) == "\n"
  local lines = vim.split(text, "\n", { plain = true })
  if has_final_newline then
    table.remove(lines, #lines)
  end
  if #lines == 0 then
    lines = { "" }
  end
  return lines, has_final_newline
end

local function apply_mirror_file_to_buffer(bufnr, local_path, result, client)
  local ok, blob = pcall(vim.fn.readblob, local_path)
  if not ok then
    notify("failed to read local mirror file " .. local_path .. ": " .. tostring(blob), vim.log.levels.ERROR)
    return false
  end
  local text, read_error = blob_to_text(blob)
  if not vim.api.nvim_buf_is_valid(bufnr) then
    return false
  end
  if read_error == "binary" then
    set_buffer_hydrate_failed(bufnr, result and result.path or vim.fn.fnamemodify(local_path, ":t"))
    notify("binary mirror file is not supported for buffer hydration: " .. local_path, vim.log.levels.ERROR)
    return false
  end
  local lines, has_final_newline = text_to_buffer_lines(text)
  set_buffer_editable(bufnr, true)
  vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, lines)
  pcall(vim.api.nvim_set_option_value, "fixendofline", false, { buf = bufnr })
  pcall(vim.api.nvim_set_option_value, "endofline", has_final_newline, { buf = bufnr })
  vim.api.nvim_set_option_value("modified", false, { buf = bufnr })
  if result then
    set_remote_buffer_identity(bufnr, client or M.client, result)
  end
  return true
end

function setup_mirror_autohydrate(client)
  clear_mirror_autohydrate()
  if not M.config.auto_hydrate_mirror_buffers then
    return
  end
  local files_root = client.hello and client.hello.files_root
  if not files_root or files_root == "" then
    return
  end

  local root = normalize_local_path(files_root):gsub("/+$", "")
  local patterns = {
    root .. "/*",
    root .. "/**/*",
  }
  M.mirror_autocmd_group = vim.api.nvim_create_augroup("NvimRemoteMirrorAutoHydrate", { clear = true })
  vim.api.nvim_create_autocmd("BufReadCmd", {
    group = M.mirror_autocmd_group,
    pattern = patterns,
    callback = function(args)
      if M.client ~= client or client.closing then
        return
      end
      local bufnr = args.buf
      local local_path = normalize_local_path(args.file or vim.api.nvim_buf_get_name(bufnr))
      local relative_path = mirror_relative_path(client, local_path)
      if not relative_path then
        return
      end
      if vim.b[bufnr].nrm_hydrate_pending and vim.b[bufnr].nrm_hydrate_path == relative_path then
        return
      end
      if vim.b[bufnr].nrm_remote_path == relative_path and not vim.b[bufnr].nrm_hydrate_failed then
        return
      end

      if uv.fs_stat(local_path) then
        apply_mirror_file_to_buffer(bufnr, local_path, {
          path = relative_path,
          local_path = local_path,
          cached = true,
        }, client)
        return
      end

      set_buffer_hydrate_pending(bufnr, client, relative_path)
      M.request("open", {
        path = relative_path,
        force = false,
        batch_max_file_bytes = M.config.open_batch_max_file_bytes,
      }, function(err, result)
        if err then
          vim.schedule(function()
            if M.client == client and vim.api.nvim_buf_is_valid(bufnr) then
              set_buffer_hydrate_failed(bufnr, relative_path)
            end
          end)
          notify("failed to hydrate " .. relative_path .. ": " .. err, vim.log.levels.ERROR)
          return
        end
        if not result then
          return
        end
        if result.preempted then
          vim.schedule(function()
            if M.client == client and vim.api.nvim_buf_is_valid(bufnr) then
              set_buffer_hydrate_failed(bufnr, relative_path)
            end
          end)
          return
        end
        vim.schedule(function()
          if M.client ~= client or client.closing or not vim.api.nvim_buf_is_valid(bufnr) then
            return
          end
          if normalize_local_path(vim.api.nvim_buf_get_name(bufnr)) ~= local_path then
            return
          end
          if vim.api.nvim_get_option_value("modified", { buf = bufnr }) then
            set_buffer_hydrate_failed(bufnr, relative_path)
            notify("skipped hydrate for modified mirror buffer " .. relative_path, vim.log.levels.WARN)
            return
          end
          if apply_mirror_file_to_buffer(bufnr, result.local_path, result, client) then
            warn_cached_open(result)
            vim.defer_fn(function()
              prefetch_related(result.path)
            end, 20)
          end
        end)
      end)
    end,
  })
end

if vim.g.nvim_remote_mirror_test then
  M._test_setup_mirror_autohydrate = setup_mirror_autohydrate
end

function prefetch_related(anchor)
  if not M.config.open_prefetch_related then
    return
  end
  if not M.client then
    return
  end
  M.request("prefetch_related", {
    anchor = anchor,
    limit = M.config.open_prefetch_related_limit,
    max_file_bytes = M.config.prefetch_max_file_bytes,
    max_total_bytes = M.config.prefetch_max_total_bytes,
  }, function(err, result)
    if err then
      notify("related prefetch failed: " .. err, vim.log.levels.WARN)
      return
    end
    if not result or result.preempted then
      return
    end
    local errors = #(result.errors or {})
    if errors > 0 or result.truncated then
      notify(
        "related prefetch hydrated "
          .. tostring(result.hydrated or 0)
          .. " files with "
          .. tostring(errors)
          .. " errors",
        vim.log.levels.WARN
      )
    end
  end)
end

function M.open(path, opts)
  opts = opts or {}
  local client = M.client
  local on_open = type(opts.on_open) == "function" and opts.on_open or nil
  local on_error = type(opts.on_error) == "function" and opts.on_error or nil
  M.request("open", {
    path = path,
    force = opts.force == true,
    batch_max_file_bytes = opts.batch_max_file_bytes or M.config.open_batch_max_file_bytes,
  }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      if on_error then
        on_error(err)
      end
      return
    end
    if not result or result.preempted then
      return
    end
    vim.schedule(function()
      if M.client ~= client then
        return
      end
      vim.cmd.edit(vim.fn.fnameescape(result.local_path))
      set_remote_buffer_identity(0, client, result)
      warn_cached_open(result)
      if on_open then
        on_open(result)
      end
      vim.defer_fn(function()
        prefetch_related(result.path)
      end, 20)
    end)
  end)
end

local function flush_remote_path(path, opts)
  opts = opts or {}
  local bufnr = opts.bufnr
  if not path or path == "" then
    return
  end
  local identity = opts.identity or buffer_identity(bufnr) or client_identity(M.client)
  if not M.client or not identity_matches_client(identity, M.client) then
    local reason = M.client and "workspace mismatch" or "disconnected"
    local is_new = mark_deferred_flush(bufnr, path, reason, identity, opts.adopt == true)
    if is_new then
      local suffix = reason == "workspace mismatch" and " until its workspace is reconnected" or " until reconnect"
      notify("deferred remote save for " .. path .. suffix, vim.log.levels.WARN)
    end
    return
  end

  local method = opts.adopt == true and "adopt" or "flush"
  M.request(method, { path = path }, function(err, result)
    if err then
      mark_deferred_flush(bufnr, path, err, identity, opts.adopt == true)
      notify("remote save deferred for " .. path .. ": " .. err, vim.log.levels.WARN)
      return
    end
    if result.status == "conflict" then
      clear_deferred_flush(result.path or path, identity)
      local suffix = ""
      if result.remote_content_truncated then
        suffix = " (remote copy truncated; full remote size " .. tostring(result.remote_size or "unknown") .. " bytes)"
      end
      notify(
        "save conflict for " .. result.path .. "; remote copy stored at " .. result.remote_path .. suffix,
        vim.log.levels.ERROR
      )
      return
    end
    if result.status == "queued" then
      clear_deferred_flush(result.path or path, identity)
      notify("remote save queued for " .. result.path .. ": " .. result.reason, vim.log.levels.WARN)
      return
    end
    clear_deferred_flush(result.path or path, identity)
    vim.schedule(function()
      for _, target_bufnr in ipairs(flush_target_buffers(bufnr, identity)) do
        if buffer_matches_identity(target_bufnr, result.path or path, identity) then
          vim.b[target_bufnr].nrm_remote_hash = result.hash
        end
      end
    end)
  end)
end

function M.flush_buffer(bufnr, opts)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  opts = opts or {}
  if vim.b[bufnr].nrm_hydrate_pending then
    notify(
      "remote save skipped while hydrate is pending for " .. tostring(vim.b[bufnr].nrm_hydrate_path or "buffer"),
      vim.log.levels.WARN
    )
    return
  end
  if vim.b[bufnr].nrm_hydrate_failed then
    notify(
      "remote save disabled because hydrate failed for " .. tostring(vim.b[bufnr].nrm_hydrate_path or "buffer"),
      vim.log.levels.ERROR
    )
    return
  end
  local buffer_identity_value = buffer_identity(bufnr)
  if not identity_has_scope(buffer_identity_value) then
    buffer_identity_value = nil
  end
  local client = M.client
  local explicit_local_path = optional_string(opts.local_path)
  local write_path = explicit_local_path or vim.api.nvim_buf_get_name(bufnr)
  local explicit_adopt = opts.adopt == true
  local path = optional_string(vim.b[bufnr].nrm_remote_path)
  if explicit_adopt and explicit_local_path then
    path = nil
  end
  local adopt_identity = nil
  if not path and client then
    local candidate = mirror_relative_path(client, write_path)
    if candidate and (explicit_adopt or auto_adoption_enabled()) then
      path = candidate
      adopt_identity = client_identity(client)
    elseif candidate then
      notify("remote save skipped for untracked mirror file " .. candidate .. "; use :RemoteAdopt", vim.log.levels.WARN)
      return
    end
  end
  if not path then
    adopt_identity = buffer_identity_value or M.last_workspace_identity
    local candidate = identity_relative_path(adopt_identity, write_path)
    if candidate and (explicit_adopt or auto_adoption_enabled()) then
      path = candidate
    elseif candidate then
      notify("remote save skipped for untracked mirror file " .. candidate .. "; use :RemoteAdopt", vim.log.levels.WARN)
      return
    end
  end
  if path and not optional_string(vim.b[bufnr].nrm_remote_path) then
    adopt_mirror_buffer_for_save(bufnr, adopt_identity, path)
  end
  flush_remote_path(path, {
    bufnr = bufnr,
    identity = adopt_identity or buffer_identity(bufnr),
    adopt = explicit_adopt,
  })
end

function M.adopt(local_path)
  local bufnr = vim.api.nvim_get_current_buf()
  local path = optional_string(local_path)
  if not path then
    path = vim.api.nvim_buf_get_name(bufnr)
  end
  if not path or path == "" then
    error("adopt requires a mirror file path or a named buffer")
  end
  M.flush_buffer(bufnr, { local_path = path, adopt = true })
end

function M.flush_deferred()
  local items = deferred_flush_items(M.client)
  for _, item in ipairs(items) do
    flush_remote_path(item.path, { deferred = true, identity = item, adopt = item.adopt == true })
  end
  return #items
end

function M.scan(limit)
  M.request("scan", { limit = limit or 10000 }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    if not result or result.preempted then
      return
    end
    notify("indexed " .. tostring(#result.entries) .. " paths")
  end)
end

local function find_label(hit)
  hit = hit or {}
  local labels = {}
  if hit.cached then
    table.insert(labels, "cached")
  else
    table.insert(labels, "known")
  end
  if hit.dirty then
    table.insert(labels, "dirty")
  end
  local validation_state = optional_string(hit.validation_state)
  if validation_state and validation_state ~= "valid" and validation_state ~= "unknown" then
    table.insert(labels, validation_state)
  end
  local path = optional_string(hit.path) or optional_string(hit.local_path) or "<unknown>"
  return path .. " [" .. table.concat(labels, ",") .. "]"
end

function M.format_find_hit(hit)
  return find_label(hit or {})
end

function M.find_paths_async(query, opts, callback)
  if type(opts) == "function" then
    callback = opts
    opts = {}
  end
  opts = opts or {}
  request_async("find_paths", {
    query = query or "",
    limit = opts.limit or M.config.find_limit,
  }, callback)
end

function M.find(query, opts)
  opts = opts or {}
  query = query or ""
  M.find_generation = M.find_generation + 1
  local generation = M.find_generation
  local client = M.client
  local function is_current()
    return generation == M.find_generation and M.client == client
  end

  M.request("find_paths", {
    query = query,
    limit = opts.limit or M.config.find_limit,
  }, function(err, result)
    if not is_current() then
      return
    end
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    if result and result.preempted then
      return
    end
    local items = {}
    for _, hit in ipairs(result.hits or {}) do
      local filename = optional_string(hit.local_path)
      if filename then
        table.insert(items, {
          filename = filename,
          lnum = 1,
          col = 1,
          text = find_label(hit),
        })
      end
    end
    vim.schedule(function()
      if not is_current() then
        return
      end
      vim.fn.setqflist({}, " ", { title = "RemoteFind " .. query, items = items })
      vim.cmd.copen()
      if result.truncated then
        notify("RemoteFind truncated at " .. tostring(result.limit) .. " paths", vim.log.levels.WARN)
      end
    end)
  end)
end

local function set_grep_quickfix(query, result, title, should_apply)
  local items = {}
  local skipped = 0
  for _, hit in ipairs(result.hits or {}) do
    local filename = optional_string(hit.local_path)
    if filename then
      table.insert(items, {
        filename = filename,
        lnum = hit.line,
        col = hit.column,
        text = hit.text,
      })
    else
      skipped = skipped + 1
    end
  end
  vim.schedule(function()
    if should_apply and not should_apply() then
      return
    end
    vim.fn.setqflist({}, " ", { title = title .. " " .. query, items = items })
    vim.cmd.copen()
  end)
  return skipped
end

local function merge_remote_with_dirty_cache(remote_result, dirty_hits)
  local merged = {}
  for key, value in pairs(remote_result or {}) do
    if key ~= "hits" then
      merged[key] = value
    end
  end

  local seen = {}
  merged.hits = {}
  local function add(hit)
    local key = table.concat({
      hit.local_path or "",
      hit.path or "",
      tostring(hit.line or ""),
      tostring(hit.column or ""),
      hit.text or "",
    }, "\31")
    if not seen[key] then
      seen[key] = true
      table.insert(merged.hits, hit)
    end
  end

  for _, hit in ipairs(remote_result.hits or {}) do
    add(hit)
  end
  for _, hit in ipairs(dirty_hits or {}) do
    add(hit)
  end

  return merged
end

function M.grep_async(query, opts, callback)
  if type(opts) == "function" then
    callback = opts
    opts = {}
  end
  opts = opts or {}
  callback = callback or function() end
  query = query or ""
  local limit = math.max(tonumber(opts.limit or M.config.grep_limit) or 0, 0)
  local grep_remote_page_files = math.max(
    math.floor(tonumber(opts.max_files or opts.remote_page_files or M.config.grep_remote_page_files) or 512),
    1
  )
  local is_current = type(opts.is_current) == "function" and opts.is_current or function()
    return true
  end
  local use_cache = opts.cache ~= false
  local result_acc = {
    hits = {},
    truncated = false,
    hydrated = 0,
    hydrate_errors = {},
    hydrate_truncated = false,
    scanned_files = 0,
    source = "remote",
  }
  local remote_has_result = false
  local remote_done = false
  local remote_error = nil
  local cache_done = not use_cache
  local cache_error = nil
  local cache_result = nil
  local dirty_cache_hits = {}
  local finished = false

  local function append_page(result)
    remote_has_result = true
    for _, hit in ipairs(result.hits or {}) do
      table.insert(result_acc.hits, hit)
    end
    result_acc.truncated = result.truncated == true
    result_acc.next_after = result.next_after
    result_acc.session_id = result.session_id
    result_acc.scanned_files = (result_acc.scanned_files or 0) + (tonumber(result.scanned_files) or 0)
    result_acc.hydrated = (result_acc.hydrated or 0) + (tonumber(result.hydrated) or 0)
    result_acc.hydrate_truncated = result_acc.hydrate_truncated or result.hydrate_truncated == true
    for _, hydrate_error in ipairs(result.hydrate_errors or {}) do
      table.insert(result_acc.hydrate_errors, hydrate_error)
    end
  end

  local function finish_once(err, result)
    if finished or not is_current() then
      return
    end
    finished = true
    callback(err, result)
  end

  local function finish_if_ready()
    if finished or not is_current() or not remote_done or not cache_done then
      return
    end

    if remote_error and not remote_has_result and #(result_acc.hits or {}) == 0 then
      if not use_cache or opts.cache_fallback == false then
        finish_once(remote_error, nil)
        return
      end
      if cache_error then
        finish_once(remote_error or cache_error, nil)
        return
      end
      cache_result = cache_result or { hits = {} }
      cache_result.source = "cache"
      cache_result.remote_error = remote_error
      finish_once(nil, cache_result)
      return
    end

    if result_acc.preempted and not remote_has_result and #(result_acc.hits or {}) == 0 then
      if use_cache and opts.cache_fallback ~= false and not cache_error then
        cache_result = cache_result or { hits = {} }
        cache_result.source = "cache"
        cache_result.remote_preempted = true
        finish_once(nil, cache_result)
        return
      end
      if cache_error then
        result_acc.cache_error = cache_error
      end
      finish_once(nil, result_acc)
      return
    end

    if remote_error then
      result_acc.remote_error = remote_error
      result_acc.truncated = true
    end
    if cache_error then
      result_acc.cache_error = cache_error
    end

    local merged = use_cache and merge_remote_with_dirty_cache(result_acc, dirty_cache_hits) or result_acc
    if remote_error then
      merged.remote_error = remote_error
      merged.truncated = true
    end
    if cache_error then
      merged.cache_error = cache_error
    end
    finish_once(nil, merged)
  end

  local function request_cache()
    if not use_cache or not is_current() then
      return
    end
    request_async("grep_cache", {
      query = query,
      limit = limit,
      max_files = opts.cache_max_files or M.config.grep_cache_max_files,
      max_file_bytes = opts.cache_max_file_bytes or M.config.grep_cache_max_file_bytes,
      max_total_bytes = opts.cache_max_total_bytes or M.config.grep_cache_max_total_bytes,
    }, function(cache_err, result)
      if not is_current() then
        return
      end
      if cache_err then
        cache_error = cache_err
      else
        cache_result = result or { hits = {} }
        dirty_cache_hits = {}
        for _, hit in ipairs(cache_result.hits or {}) do
          if hit.dirty and optional_string(hit.local_path) then
            table.insert(dirty_cache_hits, hit)
          end
        end
      end
      cache_done = true
      finish_if_ready()
    end)
  end

  local function request_page(after, session_id)
    if not is_current() then
      return
    end
    local remaining = math.max(limit - #(result_acc.hits or {}), 0)
    if remaining <= 0 then
      result_acc.truncated = true
      remote_done = true
      finish_if_ready()
      return
    end
    request_async("grep", {
      query = query,
      limit = remaining,
      after = after,
      session_id = session_id,
      max_files = grep_remote_page_files,
      hydrate = opts.hydrate ~= false,
      max_file_bytes = opts.max_file_bytes or M.config.grep_remote_max_file_bytes,
      max_total_bytes = opts.max_total_bytes or M.config.grep_remote_max_total_bytes,
    }, function(err, result)
      if not is_current() then
        return
      end
      if err then
        remote_error = err
        remote_done = true
        finish_if_ready()
        return
      end
      result = result or { hits = {} }
      if result.preempted then
        result_acc.truncated = true
        result_acc.preempted = true
        result_acc.next_after = optional_string(result.next_after) or after
        result_acc.session_id = optional_string(result.session_id) or session_id
        remote_done = true
        finish_if_ready()
        return
      end
      append_page(result)
      local next_after = optional_string(result.next_after)
      local next_session_id = optional_string(result.session_id)
      local has_more = result.truncated == true and (next_after or next_session_id) and #(result_acc.hits or {}) < limit
      if has_more then
        request_page(next_after, next_session_id)
      else
        remote_done = true
        finish_if_ready()
      end
    end)
  end

  request_page(nil, nil)
  request_cache()
end

function M.grep(query)
  M.grep_generation = M.grep_generation + 1
  local generation = M.grep_generation
  local grep_limit = math.max(tonumber(M.config.grep_limit) or 0, 0)
  local grep_remote_page_files = math.max(math.floor(tonumber(M.config.grep_remote_page_files) or 512), 1)
  local remote_result = {
    hits = {},
    truncated = false,
    hydrated = 0,
    hydrate_errors = {},
    hydrate_truncated = false,
    scanned_files = 0,
  }
  local remote_has_result = false
  local remote_applied = false
  local dirty_cache_hits = {}

  local function is_current()
    return generation == M.grep_generation
  end

  local function apply_remote_result(force)
    if not is_current() or not remote_has_result then
      return
    end
    if not force and #(remote_result.hits or {}) == 0 and #(dirty_cache_hits or {}) == 0 then
      return
    end
    remote_applied = true
    local merged = merge_remote_with_dirty_cache(remote_result, dirty_cache_hits)
    local skipped = set_grep_quickfix(query, merged, "RemoteGrep", is_current)
    if skipped > 0 then
      notify(
        "grep skipped " .. tostring(skipped) .. " remote hits without safe local mirror paths",
        vim.log.levels.WARN
      )
    end
  end

  local function append_remote_page(result)
    for _, hit in ipairs(result.hits or {}) do
      table.insert(remote_result.hits, hit)
    end
    remote_result.truncated = result.truncated == true
    remote_result.next_after = result.next_after
    remote_result.session_id = result.session_id
    remote_result.scanned_files = (remote_result.scanned_files or 0) + (tonumber(result.scanned_files) or 0)
    remote_result.hydrated = (remote_result.hydrated or 0) + (tonumber(result.hydrated) or 0)
    remote_result.hydrate_truncated = remote_result.hydrate_truncated or result.hydrate_truncated == true
    for _, hydrate_error in ipairs(result.hydrate_errors or {}) do
      table.insert(remote_result.hydrate_errors, hydrate_error)
    end
  end

  local function request_remote_page(after, session_id)
    local remaining = math.max(grep_limit - #(remote_result.hits or {}), 0)
    if remaining <= 0 then
      apply_remote_result(true)
      return
    end

    M.request("grep", {
      query = query,
      limit = remaining,
      after = after,
      session_id = session_id,
      max_files = grep_remote_page_files,
      hydrate = true,
      max_file_bytes = M.config.grep_remote_max_file_bytes,
      max_total_bytes = M.config.grep_remote_max_total_bytes,
    }, function(err, result)
      if not is_current() then
        return
      end
      if err then
        notify(err, vim.log.levels.ERROR)
        return
      end
      if not result then
        return
      end
      if result.preempted then
        remote_result.truncated = true
        remote_result.preempted = true
        remote_result.next_after = optional_string(result.next_after) or after
        remote_result.session_id = optional_string(result.session_id) or session_id
        if #(remote_result.hits or {}) > 0 or #(dirty_cache_hits or {}) > 0 or remote_applied then
          apply_remote_result(true)
        end
        notify("grep stopped before remote search completed", vim.log.levels.WARN)
        return
      end

      remote_has_result = true
      append_remote_page(result)

      local hydrate_errors = #(result.hydrate_errors or {})
      if hydrate_errors > 0 or result.hydrate_truncated then
        notify(
          "grep hydrated " .. tostring(result.hydrated or 0) .. " files with " .. tostring(hydrate_errors) .. " errors",
          vim.log.levels.WARN
        )
      end

      local next_after = optional_string(result.next_after)
      local next_session_id = optional_string(result.session_id)
      local has_more = result.truncated == true
        and (next_after or next_session_id)
        and #(remote_result.hits or {}) < grep_limit
      apply_remote_result(not has_more)
      if has_more then
        request_remote_page(next_after, next_session_id)
      end
    end)
  end

  request_remote_page(nil, nil)

  M.request("grep_cache", {
    query = query,
    limit = M.config.grep_limit,
    max_files = M.config.grep_cache_max_files,
    max_file_bytes = M.config.grep_cache_max_file_bytes,
    max_total_bytes = M.config.grep_cache_max_total_bytes,
  }, function(err, result)
    if not is_current() then
      return
    end
    if err then
      notify("cache grep failed: " .. err, vim.log.levels.WARN)
      return
    end

    dirty_cache_hits = {}
    for _, hit in ipairs(result.hits or {}) do
      if hit.dirty and optional_string(hit.local_path) then
        table.insert(dirty_cache_hits, hit)
      end
    end

    if remote_has_result and (#(remote_result.hits or {}) > 0 or remote_applied) then
      apply_remote_result(false)
      return
    end

    set_grep_quickfix(query, result, "RemoteGrep cache", function()
      return is_current() and not remote_applied
    end)
  end)
end

local function text_lines(text)
  text = tostring(text or ""):gsub("\r\n", "\n")
  if text == "" then
    return {}
  end
  local lines = vim.split(text, "\n", { plain = true })
  if lines[#lines] == "" then
    table.remove(lines, #lines)
  end
  return lines
end

local function normalize_git_path_arg(path, use_current, label)
  if not M.current_workspace() then
    error("not connected; run :RemoteConnect first")
  end
  if path == nil or path == "" then
    if use_current then
      local current = M.remote_path(0)
      if current then
        return current
      end
      error(label .. " requires a remote buffer or path")
    end
    return nil
  end
  if type(path) ~= "string" then
    error(label .. " path must be a string")
  end

  if path:sub(1, 1) == "/" or path:sub(1, 1) == "\\" or path:match("^%a:[/\\]") then
    local from_local = M.remote_path(path)
    if from_local then
      return from_local
    end
    error(label .. " path is outside the current remote mirror")
  end
  local local_path = M.local_path(path)
  if not local_path then
    error(label .. " path must be workspace-relative and stay inside the workspace")
  end
  local relative = M.remote_path(local_path)
  if not relative then
    error(label .. " path must be workspace-relative and stay inside the workspace")
  end
  return relative
end

local function normalize_git_paths(paths, label)
  local normalized = {}
  for _, path in ipairs(paths or {}) do
    local remote_path = normalize_git_path_arg(path, false, label)
    if remote_path then
      table.insert(normalized, remote_path)
    end
  end
  return normalized
end

local function git_unquote_path(path)
  if path:sub(1, 1) ~= '"' then
    return path
  end
  if path:sub(-1) == '"' then
    path = path:sub(2, -2)
  else
    path = path:sub(2)
  end
  local out = {}
  local index = 1
  while index <= #path do
    local char = path:sub(index, index)
    if char ~= "\\" then
      table.insert(out, char)
      index = index + 1
    else
      local next_char = path:sub(index + 1, index + 1)
      if next_char == "t" then
        table.insert(out, "\t")
        index = index + 2
      elseif next_char == "n" then
        table.insert(out, "\n")
        index = index + 2
      elseif next_char == "r" then
        table.insert(out, "\r")
        index = index + 2
      elseif next_char:match("[0-7]") then
        local octal = path:sub(index + 1, index + 3):match("^[0-7]+") or next_char
        table.insert(out, string.char(tonumber(octal, 8)))
        index = index + 1 + #octal
      elseif next_char ~= "" then
        table.insert(out, next_char)
        index = index + 2
      else
        index = index + 1
      end
    end
  end
  return table.concat(out)
end

local function git_status_records(stdout)
  stdout = tostring(stdout or "")
  if stdout:find("\0", 1, true) then
    local records = {}
    local start = 1
    while start <= #stdout do
      local stop = stdout:find("\0", start, true)
      if not stop then
        table.insert(records, stdout:sub(start))
        break
      end
      if stop > start then
        table.insert(records, stdout:sub(start, stop - 1))
      end
      start = stop + 1
    end
    return records, true
  end
  return text_lines(stdout), false
end

local function git_status_items(result)
  local items = {}
  local records, raw_paths = git_status_records(result and result.stdout or "")
  local index = 1
  while index <= #records do
    local line = records[index]
    if line:sub(1, 2) ~= "##" and line ~= "" then
      local path = line:sub(4)
      local renamed = path:match(".+ %-> (.+)$")
      if renamed then
        path = renamed
      end
      if not raw_paths then
        path = git_unquote_path(path)
      end
      local local_path = M.local_path(path)
      if local_path then
        table.insert(items, {
          filename = local_path,
          lnum = 1,
          col = 1,
          text = line,
        })
      end
      local status = line:sub(1, 1)
      if raw_paths and (status == "R" or status == "C") then
        index = index + 1
      end
    end
    index = index + 1
  end
  return items
end

local function git_command_failed(result)
  return result and result.truncated ~= true and result.status_code ~= nil and tonumber(result.status_code) ~= 0
end

local function git_error_text(result, fallback)
  local stderr = optional_string(result and result.stderr)
  if stderr then
    return stderr:gsub("%s+$", "")
  end
  local stdout = optional_string(result and result.stdout)
  if stdout then
    return stdout:gsub("%s+$", "")
  end
  return fallback
end

local function open_git_scratch(name, filetype, text, should_apply)
  vim.schedule(function()
    if should_apply and not should_apply() then
      return
    end
    local buf = vim.api.nvim_create_buf(true, true)
    vim.bo[buf].buftype = "nofile"
    vim.bo[buf].bufhidden = "wipe"
    vim.bo[buf].swapfile = false
    vim.bo[buf].filetype = filetype
    pcall(vim.api.nvim_buf_set_name, buf, name)
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, text_lines(text))
    vim.api.nvim_set_current_buf(buf)
  end)
end

function M.git_status_async(opts, callback)
  if type(opts) == "function" then
    callback = opts
    opts = {}
  end
  opts = opts or {}
  if opts.paths == nil and opts[1] ~= nil then
    opts = { paths = opts }
  end
  callback = callback or function() end
  request_async("git_status", {
    paths = normalize_git_paths(opts.paths or {}, "git status"),
    max_output_bytes = opts.max_output_bytes or M.config.git_output_max_bytes,
  }, callback)
end

function M.git_status(opts)
  M.git_status_generation = M.git_status_generation + 1
  local generation = M.git_status_generation
  local client = M.client
  local function is_current()
    return generation == M.git_status_generation and M.client == client
  end

  M.git_status_async(opts or {}, function(err, result)
    if not is_current() then
      return
    end
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    if result and result.preempted then
      return
    end
    if git_command_failed(result) then
      notify(git_error_text(result, "remote git status failed"), vim.log.levels.ERROR)
      return
    end
    local items = git_status_items(result or {})
    vim.schedule(function()
      if not is_current() then
        return
      end
      vim.fn.setqflist({}, " ", { title = "RemoteGitStatus", items = items })
      if #items > 0 then
        vim.cmd.copen()
      else
        notify("remote git status clean")
      end
      if result and result.truncated then
        notify("remote git status output truncated", vim.log.levels.WARN)
      end
    end)
  end)
end

function M.git_diff_async(path, opts, callback)
  if type(path) == "table" then
    if type(opts) == "function" then
      callback = opts
    end
    opts = path
    path = opts.path
  elseif type(opts) == "function" then
    callback = opts
    opts = {}
  end
  opts = opts or {}
  callback = callback or function() end
  local remote_path = normalize_git_path_arg(path, true, "git diff")
  request_async("git_diff", {
    path = remote_path,
    cached = opts.cached == true,
    max_output_bytes = opts.max_output_bytes or M.config.git_output_max_bytes,
  }, function(err, result)
    if result then
      result.path = remote_path
    end
    callback(err, result)
  end)
end

function M.git_diff(path, opts)
  M.git_diff_generation = M.git_diff_generation + 1
  local generation = M.git_diff_generation
  local client = M.client
  local function is_current()
    return generation == M.git_diff_generation and M.client == client
  end

  M.git_diff_async(path, opts or {}, function(err, result)
    if not is_current() then
      return
    end
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    if result and result.preempted then
      return
    end
    if git_command_failed(result) then
      notify(git_error_text(result, "remote git diff failed"), vim.log.levels.ERROR)
      return
    end
    if not optional_string(result and result.stdout) then
      notify("remote git diff is empty")
      return
    end
    open_git_scratch("nrm://git-diff/" .. tostring(result.path), "diff", result.stdout, is_current)
    if result.truncated then
      notify("remote git diff output truncated", vim.log.levels.WARN)
    end
  end)
end

function M.git_blame_async(path, opts, callback)
  if type(path) == "table" then
    if type(opts) == "function" then
      callback = opts
    end
    opts = path
    path = opts.path
  elseif type(opts) == "function" then
    callback = opts
    opts = {}
  end
  opts = opts or {}
  callback = callback or function() end
  local remote_path = normalize_git_path_arg(path, true, "git blame")
  request_async("git_blame", {
    path = remote_path,
    max_output_bytes = opts.max_output_bytes or M.config.git_output_max_bytes,
  }, function(err, result)
    if result then
      result.path = remote_path
    end
    callback(err, result)
  end)
end

function M.git_blame(path, opts)
  M.git_blame_generation = M.git_blame_generation + 1
  local generation = M.git_blame_generation
  local client = M.client
  local function is_current()
    return generation == M.git_blame_generation and M.client == client
  end

  M.git_blame_async(path, opts or {}, function(err, result)
    if not is_current() then
      return
    end
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    if result and result.preempted then
      return
    end
    if git_command_failed(result) then
      notify(git_error_text(result, "remote git blame failed"), vim.log.levels.ERROR)
      return
    end
    local local_path = M.local_path(result.path)
    local items = {}
    for index, line in ipairs(text_lines(result.stdout)) do
      table.insert(items, {
        filename = local_path,
        lnum = index,
        col = 1,
        text = line,
      })
    end
    vim.schedule(function()
      if not is_current() then
        return
      end
      vim.fn.setqflist({}, " ", { title = "RemoteGitBlame " .. tostring(result.path), items = items })
      if #items > 0 then
        vim.cmd.copen()
      else
        notify("remote git blame is empty")
      end
      if result.truncated then
        notify("remote git blame output truncated", vim.log.levels.WARN)
      end
    end)
  end)
end

local function status_lsp_summary()
  local lsp = lsp_status_result and lsp_status_result({ notify = false }) or { active = 0 }
  local summary = "lsp=" .. tostring(tonumber(lsp.active) or 0)
  if lsp.last_error then
    summary = summary .. " lsp_error=" .. tostring(lsp.last_error):gsub("%s+", " "):sub(1, 160)
  end
  return summary
end

function M.status()
  if not M.client or not M.client.job_id then
    notify(
      connection_summary() .. " " .. registry_summary(M.connection_state()) .. " " .. status_lsp_summary(),
      vim.log.levels.WARN
    )
    return
  end
  M.request("status", {}, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    update_remote_state(M.client, result)
    local scan_summary = background_scan_summary(result)
    notify(
      string.format(
        "known=%d cached=%d indexed=%d dirty=%d pending=%d failed=%d unreplayable=%d conflicts=%d stale=%d deleted=%d %s %s %s %s %s%s",
        result.known_files,
        result.cached_files,
        result.indexed_files or 0,
        result.dirty_files,
        result.pending_saves,
        result.failed_saves,
        result.unreplayable_saves or 0,
        result.conflicted_saves,
        result.stale_files,
        result.deleted_files,
        connection_summary(),
        status_remote_summary(result),
        agent_summary(result),
        registry_summary(result),
        status_lsp_summary(),
        scan_summary and (" " .. scan_summary) or ""
      )
    )
  end)
end

function M.save_queue(opts)
  opts = opts or {}
  M.save_queue_generation = M.save_queue_generation + 1
  local generation = M.save_queue_generation
  local client = M.client
  local function is_current()
    return generation == M.save_queue_generation and M.client == client
  end

  local params = {}
  if opts.limit then
    params.limit = opts.limit
  end
  if opts.state then
    params.state = opts.state
  end

  M.request("save_queue", params, function(err, result)
    if not is_current() then
      return
    end
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end

    local entries = result.entries or {}
    if #entries == 0 then
      notify("save queue is empty")
      return
    end

    local items = {}
    local skipped = 0
    for _, entry in ipairs(entries) do
      local filename
      if entry.state == "conflict" then
        filename = optional_string(entry.remote_conflict_path)
          or optional_string(entry.local_path)
          or optional_string(entry.snapshot_path)
      else
        filename = optional_string(entry.local_path)
          or optional_string(entry.snapshot_path)
          or optional_string(entry.remote_conflict_path)
      end
      if filename then
        table.insert(items, {
          filename = filename,
          lnum = 1,
          col = 1,
          text = save_queue_entry_text(entry),
        })
      else
        skipped = skipped + 1
      end
    end

    vim.schedule(function()
      if not is_current() then
        return
      end
      vim.fn.setqflist({}, " ", { title = "RemoteSaveQueue", items = items })
      vim.cmd.copen()
      local counts = result.counts or {}
      local total = tonumber(result.total) or #entries
      local message = string.format(
        "save queue: showing=%d total=%d pending=%d failed=%d unreplayable=%d conflicts=%d",
        #entries,
        total,
        tonumber(counts.pending) or 0,
        tonumber(counts.failed) or 0,
        tonumber(counts.unreplayable) or 0,
        tonumber(counts.conflict) or 0
      )
      if result.truncated then
        message = message .. " truncated_at=" .. tostring(result.limit or #entries)
      end
      if skipped > 0 then
        message = message .. " skipped_without_path=" .. tostring(skipped)
      end
      notify(message, save_queue_level(counts))
    end)
  end)
end

function M.save_queue_async(opts, callback)
  if type(opts) == "function" then
    callback = opts
    opts = {}
  end
  opts = opts or {}

  local params = {}
  if opts.limit then
    params.limit = opts.limit
  end
  if opts.state then
    params.state = opts.state
  end
  request_async("save_queue", params, callback)
end

function M.flush_queue(opts)
  opts = opts or {}
  local params = {
    background = opts.background == true,
  }
  if opts.limit then
    params.limit = opts.limit
  end

  M.request("flush_queue", params, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      if opts.on_done then
        opts.on_done(err, nil)
      end
      return
    end
    notify_flush_queue_result(result, opts)
    if opts.on_done then
      opts.on_done(nil, result)
    end
  end)
end

local function queue_id_param(queue_id)
  local parsed = tonumber(queue_id)
  if not parsed then
    error("queue_id must be a number")
  end
  return math.floor(parsed)
end

local function notify_conflict_resolution_result(action, result)
  result = result or {}
  local status = optional_string(result.status) or "unknown"
  local path = optional_string(result.path) or "<unknown>"
  local level = vim.log.levels.INFO
  local message
  if status == "applied" or status == "accepted_remote" then
    message = action .. " for " .. path
  elseif status == "conflict" then
    level = vim.log.levels.ERROR
    message = action .. " still conflicts for " .. path
    local remote_path = optional_string(result.remote_path)
    if remote_path then
      message = message .. "; remote copy=" .. remote_path
    end
  elseif status == "queued" then
    level = vim.log.levels.WARN
    message = action .. " queued for " .. path
    local reason = optional_string(result.reason)
    if reason then
      message = message .. ": " .. reason
    end
  else
    level = vim.log.levels.WARN
    message = action .. " returned status=" .. status .. " for " .. path
  end
  notify(message, level)
end

local function accept_conflict(method, action, queue_id, opts)
  opts = opts or {}
  request_async(method, { queue_id = queue_id_param(queue_id) }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      if opts.on_done then
        opts.on_done(err, nil)
      end
      return
    end
    notify_conflict_resolution_result(action, result)
    if opts.on_done then
      opts.on_done(nil, result)
    end
  end)
end

function M.accept_local_conflict(queue_id, opts)
  accept_conflict("accept_local_conflict", "accepted local conflict snapshot", queue_id, opts)
end

function M.accept_remote_conflict(queue_id, opts)
  accept_conflict("accept_remote_conflict", "accepted remote conflict copy", queue_id, opts)
end

function M.recover_local_edits(opts)
  opts = opts or {}
  local params = {
    background = opts.background == true,
  }
  if opts.limit then
    params.limit = opts.limit
  end
  if opts.after then
    params.after = opts.after
  end

  M.request("recover_local_edits", params, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      if opts.on_done then
        opts.on_done(err, nil)
      end
      return
    end

    result = result or {}
    local queued = #(result.queued or {})
    local errors = #(result.errors or {})
    if queued > 0 or errors > 0 or (result.truncated and not opts.quiet_empty) then
      local level = errors > 0 and vim.log.levels.WARN or vim.log.levels.INFO
      notify(
        "local edit recovery scanned "
          .. tostring(result.scanned or 0)
          .. " files, queued "
          .. tostring(queued)
          .. ", errors "
          .. tostring(errors),
        level
      )
    end

    if opts.on_done then
      opts.on_done(nil, result)
    end
  end)
end

function M.validate(path)
  path = path or M.remote_path(0)
  if not path or path == "" then
    error("validate requires a remote path or a remote buffer")
  end
  M.request("validate", { path = path }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    if not result or result.preempted then
      return
    end
    notify(result.path .. " is " .. result.status)
  end)
end

function M.refresh(paths)
  local params = {}
  if paths and #paths > 0 then
    params.paths = paths
  end
  M.request("refresh", params, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    if result and result.preempted then
      return
    end
    notify(
      string.format(
        "refresh checked=%d valid=%d stale=%d deleted=%d skipped=%d errors=%d",
        result.checked,
        result.valid,
        result.stale,
        result.deleted,
        result.skipped,
        #(result.errors or {})
      )
    )
  end)
end

function M.prefetch(paths)
  M.request("prefetch", {
    paths = paths,
    max_file_bytes = M.config.prefetch_max_file_bytes,
    max_total_bytes = M.config.prefetch_max_total_bytes,
  }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    if result and result.preempted then
      return
    end
    local suffix = ""
    if result.truncated then
      suffix = " (truncated)"
    end
    local errors = #(result.errors or {})
    if errors > 0 then
      suffix = suffix .. " with " .. tostring(errors) .. " errors"
    end
    notify("prefetched " .. tostring(result.hydrated) .. " files" .. suffix)
  end)
end

local function validate_lsp_command(command)
  if type(command) ~= "table" or #command == 0 then
    error("command must be a non-empty list")
  end
end

local function clone_list(list)
  local copy = {}
  for index, value in ipairs(list or {}) do
    copy[index] = value
  end
  return copy
end

local function clone_table(value)
  local ok, copy = pcall(vim.deepcopy, value or {})
  if ok then
    return copy
  end
  return value or {}
end

local function normalize_lsp_args(command, opts)
  if type(command) == "table" and type(command.cmd) == "table" then
    local client_opts = {}
    for key, value in pairs(command) do
      if key ~= "cmd" then
        client_opts[key] = value
      end
    end
    if opts then
      client_opts = vim.tbl_deep_extend("force", client_opts, opts)
    end
    return command.cmd, client_opts
  end
  return command, opts or {}
end

local function lsp_workspace_id(client)
  local identity = client_identity(client)
  if not identity then
    return nil
  end
  return table.concat({
    identity.workspace_key or "",
    identity.target_arg or "",
    identity.files_root or "",
  }, "\31")
end

local function lsp_client_by_id(client_id)
  if vim.lsp and type(vim.lsp.get_client_by_id) == "function" then
    return vim.lsp.get_client_by_id(client_id)
  end
  return nil
end

local function record_lsp_client(client, client_id, command, opts, config)
  M.lsp_last = {
    command = clone_list(command),
    opts = clone_table(opts),
  }
  M.lsp_last_error = nil
  if client_id == nil then
    return
  end
  local identity = client_identity(client)
  M.lsp_clients[client_id] = {
    id = client_id,
    name = config.name,
    command = clone_list(command),
    workspace_id = lsp_workspace_id(client),
    workspace_key = identity and identity.workspace_key or nil,
    target = identity and identity.target_arg or nil,
    files_root = identity and identity.files_root or nil,
  }
end

lsp_status_result = function(opts)
  opts = opts or {}
  local current_workspace = lsp_workspace_id(M.client)
  local clients = {}
  for client_id, record in pairs(M.lsp_clients) do
    local include = opts.all == true or current_workspace == nil or record.workspace_id == current_workspace
    if include then
      local lsp_client = lsp_client_by_id(client_id)
      if vim.lsp and type(vim.lsp.get_client_by_id) == "function" and not lsp_client then
        M.lsp_clients[client_id] = nil
      else
        table.insert(clients, {
          id = client_id,
          name = record.name or (lsp_client and lsp_client.name) or "remote-lsp",
          command = clone_list(record.command),
          workspace_key = record.workspace_key,
          target = record.target,
          files_root = record.files_root,
        })
      end
    end
  end
  table.sort(clients, function(left, right)
    return tostring(left.id) < tostring(right.id)
  end)
  return {
    active = #clients,
    clients = clients,
    connected = M.client ~= nil and M.client.job_id ~= nil,
    workspace_key = M.client and M.client.hello and optional_string(M.client.hello.workspace_key) or nil,
    remote_status = M.client and M.client.hello and optional_string(M.client.hello.remote_status) or nil,
    remote_available = M.client and M.client.hello and M.client.hello.remote_available or nil,
    remote_error = M.client and M.client.hello and optional_string(M.client.hello.remote_error) or nil,
    retry_after_ms = M.client and M.client.hello and M.client.hello.retry_after_ms or nil,
    last_command = M.lsp_last and clone_list(M.lsp_last.command) or nil,
    last_error = M.lsp_last_error,
  }
end

local function stop_lsp_record(client_id, force)
  local stopped = false
  local has_lookup = vim.lsp and type(vim.lsp.get_client_by_id) == "function"
  local lsp_client = lsp_client_by_id(client_id)
  if lsp_client and type(lsp_client.stop) == "function" then
    lsp_client:stop(force == true)
    stopped = true
  elseif vim.lsp and type(vim.lsp.stop_client) == "function" and (lsp_client or not has_lookup) then
    vim.lsp.stop_client(client_id, force == true)
    stopped = true
  end
  M.lsp_clients[client_id] = nil
  return stopped
end

stop_lsp_for_client = function(client, opts)
  opts = opts or {}
  M.lsp_generation = M.lsp_generation + 1
  local workspace_id = lsp_workspace_id(client)
  local stopped = 0
  for client_id, record in pairs(M.lsp_clients) do
    if opts.all == true or (workspace_id and record.workspace_id == workspace_id) then
      if stop_lsp_record(client_id, opts.force) then
        stopped = stopped + 1
      end
    end
  end
  if opts.quiet ~= true then
    if stopped > 0 then
      notify("stopped " .. tostring(stopped) .. " remote LSP client(s)")
    elseif not client and opts.all ~= true then
      notify("remote LSP inactive; not connected", vim.log.levels.WARN)
    else
      notify("no remote LSP clients to stop", vim.log.levels.WARN)
    end
  end
  return stopped
end

local function remote_unavailable_message(prefix, result)
  local message = prefix
  if result and optional_string(result.remote_error) then
    message = message .. ": " .. result.remote_error
  end
  local retry_after_ms = result and tonumber(result.retry_after_ms)
  if retry_after_ms and retry_after_ms > 0 then
    message = message .. " (retry after " .. tostring(math.floor(retry_after_ms)) .. " ms)"
  end
  return message
end

function M.lsp_client_config(command, opts)
  if not M.client or not M.client.hello then
    error("not connected; run :RemoteConnect first")
  end
  local lsp_command, client_opts = normalize_lsp_args(command, opts)
  validate_lsp_command(lsp_command)

  local cmd = {
    M.config.sidecar,
    "lsp-proxy",
    "--remote-root",
    M.client.target.remote_root,
    "--local-root",
    M.client.hello.files_root,
  }
  if M.client.target.ssh then
    table.insert(cmd, "--ssh")
    table.insert(cmd, M.client.target.ssh)
    table.insert(cmd, "--ssh-connect-timeout-seconds")
    table.insert(cmd, tostring(M.config.ssh_connect_timeout_seconds))
  end
  table.insert(cmd, "--")
  for _, value in ipairs(lsp_command) do
    table.insert(cmd, value)
  end

  return vim.tbl_deep_extend("force", {
    cmd = cmd,
    root_dir = M.client.hello.files_root,
  }, client_opts or {})
end

function M.start_lsp(command, opts)
  if not M.client or not M.client.hello then
    error("not connected; run :RemoteConnect first")
  end
  local lsp_command, client_opts = normalize_lsp_args(command, opts)
  validate_lsp_command(lsp_command)

  local client = M.client
  M.lsp_generation = M.lsp_generation + 1
  local generation = M.lsp_generation
  M.remote_probe(function(err, result)
    if M.client ~= client or generation ~= M.lsp_generation then
      return
    end
    if err then
      M.lsp_last_error = "remote probe failed before LSP start: " .. tostring(err)
      notify("remote probe failed before LSP start: " .. tostring(err), vim.log.levels.ERROR)
      return
    end
    if result and result.preempted then
      return
    end
    if not result or result.remote_available ~= true then
      M.lsp_last_error = remote_unavailable_message("remote unavailable; LSP not started", result)
      notify(M.lsp_last_error, vim.log.levels.WARN)
      return
    end

    local ok, config_or_error = pcall(M.lsp_client_config, lsp_command, client_opts)
    if not ok then
      M.lsp_last_error = tostring(config_or_error)
      notify(tostring(config_or_error), vim.log.levels.ERROR)
      return
    end
    vim.schedule(function()
      if M.client ~= client or generation ~= M.lsp_generation then
        return
      end
      M.lsp_last = {
        command = clone_list(lsp_command),
        opts = clone_table(client_opts),
      }
      local started, client_id_or_error = pcall(vim.lsp.start, config_or_error)
      if not started then
        M.lsp_last_error = tostring(client_id_or_error)
        notify("remote LSP start failed: " .. tostring(client_id_or_error), vim.log.levels.ERROR)
        return
      end
      record_lsp_client(client, client_id_or_error, lsp_command, client_opts, config_or_error)
      if client_id_or_error == nil then
        M.lsp_last_error = "remote LSP start returned no client id"
        notify(M.lsp_last_error, vim.log.levels.WARN)
      end
    end)
  end)
end

function M.lsp_status(opts)
  opts = opts or {}
  local result = lsp_status_result(opts)
  if opts.notify ~= false then
    local parts = { "remote LSP active=" .. tostring(result.active) }
    if result.workspace_key then
      table.insert(parts, "workspace=" .. tostring(result.workspace_key))
    end
    if result.last_command then
      table.insert(parts, "command=" .. table.concat(result.last_command, " "))
    end
    if result.remote_status then
      table.insert(parts, "remote=" .. tostring(result.remote_status))
    end
    if result.retry_after_ms then
      table.insert(parts, "retry_after_ms=" .. tostring(math.floor(tonumber(result.retry_after_ms) or 0)))
    end
    if result.last_error then
      table.insert(parts, "last_error=" .. tostring(result.last_error):gsub("%s+", " "):sub(1, 160))
    elseif result.active > 0 then
      local names = {}
      for _, client in ipairs(result.clients) do
        table.insert(names, tostring(client.name))
      end
      table.insert(parts, "clients=" .. table.concat(names, ","))
    elseif not result.connected then
      table.insert(parts, "not_connected")
    end
    notify(table.concat(parts, " "), result.active > 0 and vim.log.levels.INFO or vim.log.levels.WARN)
  end
  return result
end

function M.stop_lsp(opts)
  return stop_lsp_for_client(M.client, opts)
end

function M.restart_lsp(command, opts)
  local lsp_command = command
  local client_opts = opts
  if lsp_command == nil or (type(lsp_command) == "table" and #lsp_command == 0 and lsp_command.cmd == nil) then
    if not M.lsp_last then
      error("no previous remote LSP command to restart")
    end
    lsp_command = clone_list(M.lsp_last.command)
    client_opts = vim.tbl_deep_extend("force", clone_table(M.lsp_last.opts), opts or {})
  else
    lsp_command, client_opts = normalize_lsp_args(lsp_command, opts)
  end
  M.stop_lsp({ quiet = true, force = true })
  M.start_lsp(lsp_command, client_opts)
end

vim.api.nvim_create_augroup("NvimRemoteMirror", { clear = true })
vim.api.nvim_create_autocmd("BufWritePost", {
  group = "NvimRemoteMirror",
  callback = function(args)
    M.flush_buffer(args.buf, { local_path = args.file })
  end,
})

return M
