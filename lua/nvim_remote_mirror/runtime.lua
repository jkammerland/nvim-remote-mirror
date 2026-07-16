local M = {}

local TICKET_SCHEMA_VERSION = 1
local TICKET_MAX_BYTES = 256 * 1024
local TICKET_ID_PATTERN = "^[0-9a-f]+$"
local TICKET_ID_LENGTH = 64
local RESULT_SCHEMA_VERSION = 1
local RESULT_MAX_BYTES = 32 * 1024
local MAX_RUNTIME_TIMEOUT_MS = 24 * 60 * 60 * 1000
local MAX_SSH_CONNECT_TIMEOUT_SECONDS = 3600

local RESULT_KINDS = {
  process_exit = true,
  signal = true,
  timed_out = true,
  output_limit = true,
  cancelled = true,
  detached = true,
  runtime_error = true,
  transport_error = true,
}

local RESULT_FIELDS = {
  schema_version = true,
  exit_code = true,
  kind = true,
  error_code = true,
  message = true,
  output_truncated = true,
  bridge_stderr = true,
}

local REMOTE_HOST_FIELDS = {
  os = true,
  arch = true,
  shell = true,
  home = true,
  local_app_data = true,
  path_style = true,
  target = true,
}

local REMOTE_HOST_TARGETS = {
  linux = {
    x86_64 = "x86_64-unknown-linux-musl",
    aarch64 = "aarch64-unknown-linux-musl",
  },
  macos = {
    x86_64 = "x86_64-apple-darwin",
    aarch64 = "aarch64-apple-darwin",
  },
  windows = {
    x86_64 = "x86_64-pc-windows-msvc",
    aarch64 = "aarch64-pc-windows-msvc",
  },
}

local command_runner_override
local prepare_runtime_state
local run_trust_helper

local ERROR_MT = {
  __tostring = function(err)
    return err.message
  end,
}

local function runtime_error(code, message, details)
  return setmetatable({
    code = code,
    message = message,
    details = details,
  }, ERROR_MT)
end

local function optional_string(value)
  if type(value) == "string" and value ~= "" then
    return value
  end
  return nil
end

local function is_integer(value)
  return type(value) == "number" and value == math.floor(value)
end

local function contains_control(value)
  return type(value) ~= "string" or value:find("[%z\1-\31\127]") ~= nil or value:find("\194[\128-\159]") ~= nil
end

local function absolute_local_path(value)
  local path = vim.fn.fnamemodify(value, ":p")
  if path == "/" or path:match("^%a:[/\\]+$") then
    return path
  end
  return path:gsub("[/\\]+$", "")
end

local function config()
  local nrm = package.loaded["nvim_remote_mirror"] or require("nvim_remote_mirror")
  return nrm.config.remote_runtime, nrm.config
end

local function ensure_enabled()
  local runtime = config()
  if type(runtime) ~= "table" or runtime.enabled ~= true then
    return nil, runtime_error("runtime_disabled", "remote workspace process execution is disabled")
  end
  return runtime
end

local function state_root()
  local _, nrm_config = config()
  local configured = optional_string(nrm_config.state_dir)
  if configured then
    return absolute_local_path(configured)
  end
  return vim.fs.joinpath(vim.fn.stdpath("state"), "nvim-remote-mirror")
end

local function trust_digest(snapshot)
  if type(snapshot) ~= "table" or type(snapshot.authority) ~= "table" or type(snapshot.roots) ~= "table" then
    return nil, runtime_error("invalid_provider_state", "workspace authority metadata is incomplete")
  end
  local authority_id = optional_string(snapshot.authority.id)
  local authority_root = optional_string(snapshot.roots.authority)
  local authority_kind = optional_string(snapshot.authority.kind)
  if not authority_id or not authority_root or not authority_kind then
    return nil, runtime_error("invalid_provider_state", "workspace authority identity is incomplete")
  end
  if vim.fn.exists("*sha256") ~= 1 then
    return nil, runtime_error("trust_store_error", "Neovim sha256() support is required for workspace trust")
  end
  -- Only this digest is persisted. Authority names and roots never enter the
  -- trust file, and reconnect epochs/workspace mirror IDs do not affect trust.
  -- Length prefixes keep the identity unambiguous without NUL bytes, which
  -- Vimscript sha256() rejects on the supported Neovim 0.10 baseline.
  local function field(value)
    return tostring(#value) .. ":" .. value
  end
  return vim.fn.sha256(
    table.concat({ "nrm-runtime-trust-v2:", field(authority_kind), field(authority_id), field(authority_root) })
  )
end

local function set_trusted(snapshot, trusted)
  local digest, digest_err = trust_digest(snapshot)
  if not digest then
    return nil, digest_err
  end
  return run_trust_helper(trusted and "add" or "remove", digest)
end

local function prompt_for_trust(snapshot, capability)
  local root = snapshot.roots and snapshot.roots.authority or "<unknown>"
  local authority = snapshot.authority or {}
  local function prompt_text(value, fallback, maximum)
    value = optional_string(value) or fallback
    value = value:gsub("[%z\1-\31\127]", "?"):gsub("\194[\128-\159]", "?")
    if #value > maximum then
      value = value:sub(1, maximum - 3) .. "..."
    end
    return value
  end
  local kind = prompt_text(authority.kind, "remote", 128)
  local label = prompt_text(authority.label, kind, 1024)
  local identity = prompt_text(authority.id, "unavailable", 1024)
  root = prompt_text(root, "<unknown>", 16 * 1024)
  local ok, choice = pcall(
    vim.fn.confirm,
    string.format(
      "Trust this %s workspace for remote %s execution?\n\nAuthority: %s\nIdentity: %s\nRoot: %s\n\nRemote programs can execute arbitrary code.",
      kind,
      capability,
      label,
      identity,
      root
    ),
    "&Trust\n&Cancel",
    2
  )
  if not ok then
    return nil, runtime_error("authorization_failed", "failed to display the workspace trust prompt")
  end
  return choice == 1
end

function M.is_trusted(snapshot)
  local runtime, enabled_err = ensure_enabled()
  if not runtime then
    return nil, enabled_err
  end
  if runtime.trust == "always" then
    return true
  end
  if runtime.trust == "never" then
    return false
  end
  local digest, digest_err = trust_digest(snapshot)
  if not digest then
    return nil, digest_err
  end
  return run_trust_helper("check", digest)
end

function M.authorize(snapshot, capability, callback)
  local trusted, trust_err = M.is_trusted(snapshot)
  if trust_err then
    callback(trust_err, false)
    return
  end
  if trusted then
    callback(nil, true)
    return
  end
  local runtime = config()
  if runtime.trust ~= "prompt" then
    callback(
      runtime_error("workspace_untrusted", "remote workspace execution is denied by remote_runtime.trust"),
      false
    )
    return
  end
  local granted, prompt_err = prompt_for_trust(snapshot, capability)
  if prompt_err then
    callback(prompt_err, false)
    return
  end
  if not granted then
    callback(runtime_error("workspace_untrusted", "remote workspace authorization was denied"), false)
    return
  end
  local persisted, persist_err = set_trusted(snapshot, true)
  if not persisted then
    callback(persist_err, false)
    return
  end
  callback(nil, true)
end

local function shell_argv(snapshot)
  if snapshot.authority.path_style == "windows" or snapshot.authority.shell == "powershell" then
    return { "powershell.exe", "-NoLogo" }
  end
  local shell = optional_string(snapshot.authority.shell)
  if shell and shell:sub(1, 1) == "/" and #shell <= 16 * 1024 and not contains_control(shell) then
    local valid = true
    for segment in shell:gmatch("[^/]+") do
      if segment == "." or segment == ".." then
        valid = false
        break
      end
    end
    if valid then
      return { shell }
    end
  end
  return { "/bin/sh" }
end

local function remote_host_hint(snapshot)
  if not optional_string(snapshot._ssh) or type(snapshot._remote_host) ~= "table" then
    return nil
  end
  local source = snapshot._remote_host
  for key in pairs(source) do
    if type(key) ~= "string" or not REMOTE_HOST_FIELDS[key] then
      return nil
    end
  end
  for key in pairs(REMOTE_HOST_FIELDS) do
    if rawget(source, key) == nil then
      return nil
    end
  end
  for _, field in ipairs({ "os", "arch", "shell", "home", "path_style", "target" }) do
    if not optional_string(source[field]) or #source[field] > 16 * 1024 or contains_control(source[field]) then
      return nil
    end
  end
  local targets = REMOTE_HOST_TARGETS[source.os]
  if not targets or source.target ~= targets[source.arch] then
    return nil
  end
  local windows = source.os == "windows"
  if source.path_style ~= (windows and "windows" or "posix") then
    return nil
  end
  if windows then
    if source.shell ~= "powershell" or not optional_string(source.local_app_data) then
      return nil
    end
    if #source.local_app_data > 16 * 1024 or contains_control(source.local_app_data) then
      return nil
    end
  elseif source.local_app_data ~= vim.NIL then
    return nil
  end
  return {
    os = source.os,
    arch = source.arch,
    shell = source.shell,
    home = source.home,
    local_app_data = source.local_app_data,
    path_style = source.path_style,
    target = source.target,
  }
end

local function sorted_environment(snapshot, values)
  local keys = vim.tbl_keys(values)
  local windows = snapshot.authority.path_style == "windows"
  table.sort(keys, function(left, right)
    local compared_left = windows and left:lower() or left
    local compared_right = windows and right:lower() or right
    if compared_left == compared_right then
      return left < right
    end
    return compared_left < compared_right
  end)
  local result = {}
  for _, key in ipairs(keys) do
    table.insert(result, { name = key, value = values[key] })
  end
  return result
end

local function ticket_config(snapshot)
  local _, nrm_config = config()
  local captured = type(snapshot._runtime_config) == "table" and snapshot._runtime_config or {}
  local ssh = optional_string(snapshot._ssh)
  local agent
  if ssh then
    agent = optional_string(captured.remote_agent) or optional_string(nrm_config.remote_agent) or "nrm-agent"
  else
    agent = optional_string(captured.agent) or optional_string(nrm_config.agent)
  end
  local request_timeout_ms = captured.request_timeout_ms or nrm_config.request_timeout_ms
  local ssh_timeout = captured.ssh_connect_timeout_seconds or nrm_config.ssh_connect_timeout_seconds
  if not optional_string(agent) then
    return nil, runtime_error("invalid_provider_state", "runtime agent executable is not configured")
  end
  if contains_control(agent) or agent:sub(1, 1) == "-" then
    return nil, runtime_error("invalid_provider_state", "runtime agent executable is invalid")
  end
  if not is_integer(request_timeout_ms) or request_timeout_ms < 1 or request_timeout_ms > MAX_RUNTIME_TIMEOUT_MS then
    return nil, runtime_error("invalid_provider_state", "runtime request timeout is invalid")
  end
  if not is_integer(ssh_timeout) or ssh_timeout < 1 or ssh_timeout > MAX_SSH_CONNECT_TIMEOUT_SECONDS then
    return nil, runtime_error("invalid_provider_state", "runtime SSH timeout is invalid")
  end
  local sidecar = optional_string(captured.sidecar) or optional_string(nrm_config.sidecar)
  if not sidecar or contains_control(sidecar) then
    return nil, runtime_error("invalid_provider_state", "runtime sidecar executable is invalid")
  end
  local configured_state_dir = optional_string(captured.state_dir) or optional_string(nrm_config.state_dir)
  if configured_state_dir and contains_control(configured_state_dir) then
    return nil, runtime_error("invalid_provider_state", "runtime state directory is invalid")
  end
  return {
    agent = agent,
    request_timeout_ms = request_timeout_ms,
    ssh_connect_timeout_seconds = ssh_timeout,
    sidecar = sidecar,
    state_dir = configured_state_dir and absolute_local_path(configured_state_dir) or nil,
  }
end

local function runtime_ticket(snapshot, request)
  local runtime, enabled_err = ensure_enabled()
  if not runtime then
    return nil, enabled_err
  end
  if type(snapshot.capabilities) ~= "table" or snapshot.capabilities.runtime_ticket_v1 ~= true then
    return nil, runtime_error("unsupported", "connected sidecar does not support private runtime tickets")
  end
  local workspace_key = optional_string(snapshot._workspace_key) or optional_string(snapshot.workspace_id)
  if not workspace_key or #workspace_key ~= 24 or not workspace_key:match("^[0-9a-f]+$") then
    return nil, runtime_error("invalid_provider_state", "runtime workspace key is invalid")
  end
  local remote_root = snapshot.roots and optional_string(snapshot.roots.authority) or nil
  if not remote_root then
    return nil, runtime_error("invalid_provider_state", "runtime workspace root is unavailable")
  end
  local captured, captured_err = ticket_config(snapshot)
  if not captured then
    return nil, captured_err
  end
  local argv = request.command.argv and vim.deepcopy(request.command.argv) or shell_argv(snapshot)
  local cwd = request.cwd.path == "" and "WorkspaceRoot" or { WorkspaceRelative = request.cwd.path }
  local persistence = request.persistence == "attached" and "Attached"
    or { Detachable = { ttl_ms = runtime.detached_ttl_ms } }
  return {
    schema_version = TICKET_SCHEMA_VERSION,
    workspace_key = workspace_key,
    remote_root = remote_root,
    ssh = optional_string(snapshot._ssh),
    agent = captured.agent,
    ssh_connect_timeout_seconds = captured.ssh_connect_timeout_seconds,
    request_timeout_ms = captured.request_timeout_ms,
    capability = request.stdio == "pty" and "ProcessPtyV1" or "ProcessPipeV1",
    remote_host = remote_host_hint(snapshot),
    spec = {
      argv = argv,
      cwd = cwd,
      env = {
        clear = request.env.clear == true,
        set = sorted_environment(snapshot, request.env.set),
        unset = vim.deepcopy(request.env.unset),
      },
      persistence = persistence,
      terminal_size = request.initial_size and {
        columns = request.initial_size.cols,
        rows = request.initial_size.rows,
        pixel_width = request.initial_size.pixel_width,
        pixel_height = request.initial_size.pixel_height,
      } or nil,
      timeout_ms = request.timeout_ms,
      max_output_bytes = request.max_output_bytes,
    },
    _bridge = captured,
  }
end

local function default_command_runner(argv, stdin, timeout_ms)
  local ok, process = pcall(vim.system, argv, {
    stdin = stdin,
    text = true,
  })
  if not ok then
    return nil, process
  end
  local waited, result = pcall(process.wait, process, timeout_ms)
  if not waited then
    return nil, result
  end
  return result
end

local function result_unavailable(reason, details)
  details = details or {}
  details.reason = reason
  return runtime_error("result_unavailable", "remote runtime result is unavailable", details)
end

local function safe_diagnostic(value)
  local ok, rendered = pcall(tostring, value)
  if not ok or type(rendered) ~= "string" then
    return "unavailable"
  end
  return rendered:gsub("[%z\1-\31\127]+", " "):sub(1, 512)
end

prepare_runtime_state = function()
  local runtime, nrm_config = config()
  local sidecar = optional_string(nrm_config.sidecar)
  if not sidecar or contains_control(sidecar) then
    return nil, runtime_error("trust_store_error", "runtime sidecar executable is invalid")
  end
  local root = state_root()
  if not optional_string(root) or contains_control(root) then
    return nil, runtime_error("trust_store_error", "runtime state directory is invalid")
  end
  local argv = { sidecar, "runtime-state-prepare", "--state-dir", root }
  local runner = command_runner_override or default_command_runner
  local ok, result, run_err = pcall(runner, argv, nil, runtime.ticket_create_timeout_ms)
  if not ok then
    return nil,
      runtime_error("trust_store_error", "failed to prepare private runtime state", {
        reason = "invoke_failed",
        cause = safe_diagnostic(result),
      })
  end
  if not result then
    return nil,
      runtime_error("trust_store_error", "failed to prepare private runtime state", {
        reason = "invoke_failed",
        cause = safe_diagnostic(run_err),
      })
  end
  if type(result) ~= "table" or not is_integer(result.code) then
    return nil,
      runtime_error("trust_store_error", "failed to prepare private runtime state", {
        reason = "invalid_helper_response",
      })
  end
  if result.code == 124 then
    return nil,
      runtime_error("trust_store_error", "failed to prepare private runtime state", {
        reason = "timeout",
      })
  end
  if result.code ~= 0 then
    local stderr = safe_diagnostic(result.stderr or "")
    return nil,
      runtime_error("trust_store_error", "failed to prepare private runtime state", {
        reason = "helper_failed",
        exit_code = result.code,
        helper_stderr = stderr ~= "" and stderr or nil,
      })
  end
  return true
end

run_trust_helper = function(action, digest)
  if action ~= "check" and action ~= "add" and action ~= "remove" then
    return nil, runtime_error("trust_store_error", "invalid workspace trust operation")
  end
  if type(digest) ~= "string" or #digest ~= 64 or not digest:match("^[0-9a-f]+$") then
    return nil, runtime_error("trust_store_error", "invalid workspace trust digest")
  end
  local prepared, prepare_err = prepare_runtime_state()
  if not prepared then
    return nil, prepare_err
  end
  local runtime, nrm_config = config()
  local sidecar = optional_string(nrm_config.sidecar)
  local root = state_root()
  local argv = {
    sidecar,
    "runtime-trust-" .. action,
    "--state-dir",
    root,
    "--digest",
    digest,
  }
  local runner = command_runner_override or default_command_runner
  local ok, result, run_err = pcall(runner, argv, nil, runtime.ticket_create_timeout_ms)
  if not ok then
    return nil,
      runtime_error("trust_store_error", "failed to invoke workspace trust helper", {
        reason = "invoke_failed",
        operation = action,
        cause = safe_diagnostic(result),
      })
  end
  if not result then
    return nil,
      runtime_error("trust_store_error", "failed to invoke workspace trust helper", {
        reason = "invoke_failed",
        operation = action,
        cause = safe_diagnostic(run_err),
      })
  end
  if type(result) ~= "table" or not is_integer(result.code) then
    return nil,
      runtime_error("trust_store_error", "workspace trust helper returned an invalid response", {
        reason = "invalid_helper_response",
        operation = action,
      })
  end
  if result.code == 124 then
    return nil,
      runtime_error("trust_store_error", "workspace trust helper timed out", {
        reason = "timeout",
        operation = action,
      })
  end
  if result.code ~= 0 then
    local stderr = safe_diagnostic(result.stderr or "")
    return nil,
      runtime_error("trust_store_error", "workspace trust helper failed", {
        reason = "helper_failed",
        operation = action,
        exit_code = result.code,
        helper_stderr = stderr ~= "" and stderr or nil,
      })
  end
  local stdout = result.stdout or ""
  if action == "check" then
    if stdout == "trusted\n" then
      return true
    end
    if stdout == "untrusted\n" then
      return false
    end
    return nil,
      runtime_error("trust_store_error", "workspace trust helper returned an invalid status", {
        reason = "invalid_helper_response",
        operation = action,
      })
  end
  if stdout ~= "" then
    return nil,
      runtime_error("trust_store_error", "workspace trust helper returned unexpected output", {
        reason = "invalid_helper_response",
        operation = action,
      })
  end
  return true
end

local function has_duplicate_json_member(encoded)
  local seen = {}
  local index = 1
  while index <= #encoded do
    if encoded:byte(index) ~= 34 then -- '"'
      index = index + 1
    else
      local first = index
      index = index + 1
      while index <= #encoded do
        local byte = encoded:byte(index)
        if byte == 92 then -- '\\'
          index = index + 2
        elseif byte == 34 then
          break
        else
          index = index + 1
        end
      end
      if index > #encoded then
        return false
      end
      local after = index + 1
      while after <= #encoded and encoded:sub(after, after):match("%s") do
        after = after + 1
      end
      if encoded:sub(after, after) == ":" then
        local ok, name = pcall(vim.json.decode, encoded:sub(first, index))
        if ok and type(name) == "string" then
          if seen[name] then
            return true
          end
          seen[name] = true
        end
      end
      index = index + 1
    end
  end
  return false
end

local function decode_runtime_result(stdout)
  if type(stdout) ~= "string" then
    return nil, result_unavailable("invalid_output")
  end
  if #stdout > RESULT_MAX_BYTES then
    return nil, result_unavailable("oversized", { max_bytes = RESULT_MAX_BYTES })
  end
  if has_duplicate_json_member(stdout) then
    return nil, result_unavailable("duplicate_field")
  end
  local ok, decoded = pcall(vim.json.decode, stdout)
  if not ok or type(decoded) ~= "table" then
    return nil, result_unavailable("malformed")
  end
  for key in pairs(decoded) do
    if type(key) ~= "string" or not RESULT_FIELDS[key] then
      return nil, result_unavailable("unknown_field")
    end
  end
  for key in pairs(RESULT_FIELDS) do
    if rawget(decoded, key) == nil then
      return nil, result_unavailable("missing_field", { field = key })
    end
  end
  if decoded.schema_version ~= RESULT_SCHEMA_VERSION then
    return nil, result_unavailable("unsupported_schema", {
      schema_version = decoded.schema_version,
    })
  end
  if not is_integer(decoded.exit_code) or decoded.exit_code < -2147483648 or decoded.exit_code > 2147483647 then
    return nil, result_unavailable("invalid_field", { field = "exit_code" })
  end
  if type(decoded.kind) ~= "string" or not RESULT_KINDS[decoded.kind] then
    return nil, result_unavailable("invalid_field", { field = "kind" })
  end
  for _, field in ipairs({ "error_code", "message", "bridge_stderr" }) do
    local value = decoded[field]
    if value ~= vim.NIL and type(value) ~= "string" then
      return nil, result_unavailable("invalid_field", { field = field })
    end
  end
  if type(decoded.output_truncated) ~= "boolean" then
    return nil, result_unavailable("invalid_field", { field = "output_truncated" })
  end
  return decoded
end

local function result_reader_argv(metadata)
  local argv = { metadata.sidecar, "runtime-result-read" }
  if metadata.state_dir then
    vim.list_extend(argv, { "--state-dir", metadata.state_dir })
  end
  vim.list_extend(argv, { "--ticket", metadata.ticket_id })
  return argv
end

local function lifecycle_metadata(bridge)
  local metadata = bridge._result
  if
    type(metadata) ~= "table"
    or not optional_string(metadata.sidecar)
    or contains_control(metadata.sidecar)
    or (metadata.state_dir ~= nil and (not optional_string(metadata.state_dir) or contains_control(metadata.state_dir)))
    or type(metadata.ticket_id) ~= "string"
    or #metadata.ticket_id ~= TICKET_ID_LENGTH
    or not metadata.ticket_id:match(TICKET_ID_PATTERN)
  then
    return nil
  end
  return metadata
end

local function runtime_result_from_helper(result)
  if type(result) ~= "table" or not is_integer(result.code) then
    return result_unavailable("invalid_reader_response")
  end
  if result.code == 124 then
    return result_unavailable("timeout")
  end
  if result.code ~= 0 then
    local stderr = safe_diagnostic(result.stderr or "")
    return result_unavailable("read_failed", {
      exit_code = result.code,
      reader_stderr = stderr ~= "" and stderr or nil,
    })
  end
  local decoded, decode_err = decode_runtime_result(result.stdout)
  return decoded or decode_err
end

local function read_runtime_result(bridge)
  local metadata = lifecycle_metadata(bridge)
  if not metadata then
    return result_unavailable("invalid_metadata")
  end
  local runtime = config()
  local runner = command_runner_override or default_command_runner
  local ok, result, run_err = pcall(runner, result_reader_argv(metadata), nil, runtime.ticket_create_timeout_ms)
  if not ok then
    return result_unavailable("invoke_failed", { cause = safe_diagnostic(result) })
  end
  if not result then
    return result_unavailable("invoke_failed", { cause = safe_diagnostic(run_err) })
  end
  return runtime_result_from_helper(result)
end

local function read_runtime_result_async(bridge, done)
  -- Test runners and embedders can provide only the synchronous hook. Keep
  -- that path deterministic; production never waits for the helper on the
  -- Neovim main loop.
  if command_runner_override then
    local ok, result = pcall(read_runtime_result, bridge)
    done(ok and result or result_unavailable("internal_error"))
    return
  end
  local metadata = lifecycle_metadata(bridge)
  if not metadata then
    done(result_unavailable("invalid_metadata"))
    return
  end
  local runtime = config()
  local ok, spawn_err = pcall(vim.system, result_reader_argv(metadata), {
    text = true,
    timeout = runtime.ticket_create_timeout_ms,
  }, function(result)
    vim.schedule(function()
      done(runtime_result_from_helper(result))
    end)
  end)
  if not ok then
    done(result_unavailable("invoke_failed", { cause = safe_diagnostic(spawn_err) }))
  end
end

local function signal_failed(signal, reason, details)
  details = details or {}
  details.reason = reason
  details.signal = signal
  return runtime_error("signal_failed", "failed to enqueue remote runtime signal", details)
end

local function signal_helper_argv(metadata, signal)
  local argv = { metadata.sidecar, "runtime-signal" }
  if metadata.state_dir then
    vim.list_extend(argv, { "--state-dir", metadata.state_dir })
  end
  vim.list_extend(argv, { "--ticket", metadata.ticket_id, "--signal", signal })
  return argv
end

local function enqueue_runtime_signal(bridge, signal)
  local metadata = lifecycle_metadata(bridge)
  if not metadata then
    return nil, signal_failed(signal, "invalid_metadata")
  end
  local runtime = config()
  local runner = command_runner_override or default_command_runner
  local ok, result, run_err = pcall(runner, signal_helper_argv(metadata, signal), nil, runtime.ticket_create_timeout_ms)
  if not ok then
    return nil, signal_failed(signal, "invoke_failed", { cause = safe_diagnostic(result) })
  end
  if not result then
    return nil, signal_failed(signal, "invoke_failed", { cause = safe_diagnostic(run_err) })
  end
  if type(result) ~= "table" or not is_integer(result.code) then
    return nil, signal_failed(signal, "invalid_helper_response")
  end
  if result.code == 124 then
    return nil, signal_failed(signal, "timeout")
  end
  if result.code ~= 0 then
    local stderr = safe_diagnostic(result.stderr or "")
    return nil,
      signal_failed(signal, "helper_failed", {
        exit_code = result.code,
        helper_stderr = stderr ~= "" and stderr or nil,
      })
  end
  return true
end

local function create_ticket(snapshot, request)
  if request.persistence == "detached" then
    return nil,
      runtime_error(
        "persistence_unavailable",
        "detachable remote terminals are unavailable until the persistent runtime broker is implemented"
      )
  end
  local ticket, ticket_err = runtime_ticket(snapshot, request)
  if not ticket then
    return nil, ticket_err
  end
  local bridge = ticket._bridge
  ticket._bridge = nil
  local encoded = vim.json.encode(ticket)
  if #encoded > TICKET_MAX_BYTES then
    return nil, runtime_error("ticket_too_large", "runtime ticket exceeds the sidecar input limit")
  end
  if not optional_string(bridge.sidecar) then
    return nil, runtime_error("invalid_provider_state", "runtime sidecar executable is not configured")
  end
  local argv = { bridge.sidecar, "runtime-ticket-create" }
  if bridge.state_dir then
    vim.list_extend(argv, { "--state-dir", bridge.state_dir })
  end
  local runtime = config()
  local runner = command_runner_override or default_command_runner
  local ok, result, run_err = pcall(runner, argv, encoded, runtime.ticket_create_timeout_ms)
  if not ok then
    return nil,
      runtime_error("ticket_create_failed", "failed to invoke runtime ticket creation", { cause = tostring(result) })
  end
  if not result then
    return nil,
      runtime_error("ticket_create_failed", "failed to invoke runtime ticket creation", { cause = tostring(run_err) })
  end
  if result.code == 124 then
    return nil, runtime_error("ticket_create_timeout", "runtime ticket creation timed out")
  end
  if result.code ~= 0 then
    local stderr = tostring(result.stderr or ""):gsub("[%z\1-\31\127]+", " "):sub(1, 512)
    return nil,
      runtime_error("ticket_create_failed", "runtime ticket creation failed", {
        exit_code = result.code,
        stderr = stderr ~= "" and stderr or nil,
      })
  end
  local ticket_id = tostring(result.stdout or ""):match("^%s*([0-9a-f]+)%s*$")
  if not ticket_id or #ticket_id ~= TICKET_ID_LENGTH or not ticket_id:match(TICKET_ID_PATTERN) then
    return nil, runtime_error("ticket_invalid_response", "runtime ticket creation returned an invalid opaque ID")
  end
  local proxy = { bridge.sidecar, "runtime-proxy" }
  if bridge.state_dir then
    vim.list_extend(proxy, { "--state-dir", bridge.state_dir })
  end
  vim.list_extend(proxy, { "--ticket", ticket_id })
  return {
    argv = proxy,
    _result = {
      sidecar = bridge.sidecar,
      state_dir = bridge.state_dir,
      ticket_id = ticket_id,
    },
  }
end

function M.job_spec(snapshot, request)
  local bridge, bridge_err = create_ticket(snapshot, request)
  if not bridge then
    return nil, bridge_err
  end
  -- String-only consumers have no exit hook. Do not expose private lifecycle
  -- metadata; the sidecar bounds orphan results and unused ticket lifetime.
  return { argv = bridge.argv }
end

local function callback(handlers, name, ...)
  local handler = handlers[name]
  if type(handler) == "function" then
    local ok, err = pcall(handler, ...)
    if not ok then
      vim.schedule(function()
        vim.notify("remote runtime callback failed: " .. tostring(err), vim.log.levels.ERROR)
      end)
    end
  end
end

local function start_process(bridge, request, handlers)
  local exited = false
  local closed_stdin = false
  local job_id
  local options = {
    stdout_buffered = false,
    stderr_buffered = false,
    on_stdout = function(id, data, event)
      callback(handlers, "on_stdout", id, data, event)
    end,
    on_stderr = function(id, data, event)
      callback(handlers, "on_stderr", id, data, event)
    end,
    on_exit = function(id, code, event)
      exited = true
      read_runtime_result_async(bridge, function(result)
        callback(handlers, "on_exit", id, code, event, result)
      end)
    end,
  }
  local ok, started
  if request.stdio == "pty" then
    ok, started = pcall(vim.fn.termopen, bridge.argv, options)
  else
    ok, started = pcall(vim.fn.jobstart, bridge.argv, options)
  end
  if not ok then
    return nil, runtime_error("spawn_failed", "failed to start the local runtime bridge", { cause = tostring(started) })
  end
  job_id = tonumber(started)
  if not job_id or job_id <= 0 then
    return nil, runtime_error("spawn_failed", "failed to start the local runtime bridge", { job_id = started })
  end

  local function require_running()
    if exited then
      return nil, runtime_error("process_exited", "remote runtime process has already exited")
    end
    return true
  end

  local handle = {}
  function handle:write(data)
    local running, running_err = require_running()
    if not running then
      return nil, running_err
    end
    if type(data) ~= "string" then
      return nil, runtime_error("invalid_argument", "runtime input must be a string")
    end
    if closed_stdin then
      return nil, runtime_error("input_closed", "remote runtime input is closed")
    end
    local sent = vim.fn.chansend(job_id, data)
    if tonumber(sent) == nil or sent <= 0 then
      return nil, runtime_error("input_failed", "failed to write remote runtime input")
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
      return nil, runtime_error("input_failed", "failed to close remote runtime input", { cause = tostring(close_err) })
    end
    return true
  end
  function handle:signal(signal)
    local running, running_err = require_running()
    if not running then
      return nil, running_err
    end
    if signal ~= "interrupt" and signal ~= "terminate" and signal ~= "kill" and signal ~= "hangup" then
      return nil, runtime_error("invalid_argument", "unknown runtime signal")
    end
    return enqueue_runtime_signal(bridge, signal)
  end
  function handle:kill()
    if exited then
      return true
    end
    local enqueued, enqueue_err = enqueue_runtime_signal(bridge, "kill")
    if enqueued then
      return true
    end
    -- The signal mailbox is authoritative. Stopping the local bridge is only a
    -- last-resort cancellation fallback when the helper could not enqueue kill.
    local ok_stop, stopped = pcall(vim.fn.jobstop, job_id)
    if not ok_stop or stopped ~= 1 then
      return nil,
        signal_failed("kill", "fallback_failed", {
          helper_reason = enqueue_err and enqueue_err.details and enqueue_err.details.reason or nil,
        })
    end
    if enqueue_err then
      enqueue_err.details = enqueue_err.details or {}
      enqueue_err.details.fallback = "jobstop"
      return nil, enqueue_err
    end
    return nil, signal_failed("kill", "fallback_used", { fallback = "jobstop" })
  end
  function handle:resize(size)
    local running, running_err = require_running()
    if not running then
      return nil, running_err
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
      return nil, runtime_error("invalid_argument", "terminal size is invalid")
    end
    local ok_resize, resized = pcall(vim.fn.jobresize, job_id, size.cols, size.rows)
    if not ok_resize or resized ~= 1 then
      return nil, runtime_error("resize_failed", "failed to resize the local runtime terminal")
    end
    return true
  end
  return handle
end

function M.spawn(snapshot, request, handlers)
  if request.persistence == "detached" then
    return nil,
      runtime_error(
        "persistence_unavailable",
        "detachable remote terminals are unavailable until the persistent runtime broker is implemented"
      )
  end
  local bridge, bridge_err = create_ticket(snapshot, request)
  if not bridge then
    return nil, bridge_err
  end
  return start_process(bridge, request, handlers)
end

local function resolve_context(query)
  local workspace = require("nvim_remote_mirror.workspace")
  return workspace.resolve(query or {})
end

function M.trust_workspace(opts)
  opts = opts or {}
  local runtime, enabled_err = ensure_enabled()
  if not runtime then
    return nil, enabled_err
  end
  local context, context_err = opts.context, nil
  if context == nil then
    context, context_err = resolve_context(opts.query)
  end
  if not context then
    return nil, context_err
  end
  if opts.force ~= true then
    local granted, prompt_err = prompt_for_trust(context, "process and terminal")
    if prompt_err then
      return nil, prompt_err
    end
    if not granted then
      return nil, runtime_error("workspace_untrusted", "remote workspace authorization was denied")
    end
  end
  local persisted, persist_err = set_trusted(context, true)
  if not persisted then
    return nil, persist_err
  end
  return true
end

function M.untrust_workspace(opts)
  opts = opts or {}
  local context, context_err = opts.context, nil
  if context == nil then
    context, context_err = resolve_context(opts.query)
  end
  if not context then
    return nil, context_err
  end
  local persisted, persist_err = set_trusted(context, false)
  if not persisted then
    return nil, persist_err
  end
  return true
end

function M._set_command_runner(runner)
  if runner ~= nil and type(runner) ~= "function" then
    error("runtime command runner must be a function or nil")
  end
  command_runner_override = runner
end

function M._ticket_for_test(snapshot, request)
  return runtime_ticket(snapshot, request)
end

function M._reset_for_test()
  command_runner_override = nil
end

return M
