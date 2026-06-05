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

M.config = {
  sidecar = executable_or_default("nrm-sidecar"),
  agent = executable_or_default("nrm-agent"),
  state_dir = nil,
  find_limit = 200,
  grep_limit = 200,
  grep_cache_max_files = 2000,
  grep_cache_max_file_bytes = 512 * 1024,
  grep_cache_max_total_bytes = 8 * 1024 * 1024,
  request_timeout_ms = 30000,
  ssh_connect_timeout_seconds = 10,
  open_batch_max_file_bytes = 4 * 1024 * 1024,
  prefetch_max_file_bytes = 4 * 1024 * 1024,
  prefetch_max_total_bytes = 16 * 1024 * 1024,
  open_prefetch_related = false,
  open_prefetch_related_limit = 16,
  auto_hydrate_mirror_buffers = true,
  auto_reconnect = true,
  reconnect_delay_ms = 1000,
  reconnect_max_attempts = 3,
  reconnect_stable_ms = 10000,
  flush_queue_on_connect = true,
  flush_queue_on_connect_delay_ms = 500,
  flush_queue_on_connect_limit = 1,
  background_mirror = true,
  background_mirror_interval_ms = 5000,
  background_mirror_scan_limit = 256,
  background_mirror_prefetch_limit = 4,
  background_mirror_refresh_limit = 32,
  background_mirror_max_file_bytes = 128 * 1024,
  background_mirror_max_total_bytes = 512 * 1024,
}

M.client = nil
M.last_target = nil
M.reconnect_attempts = 0
M.reconnect_generation = 0
M.grep_generation = 0
M.deferred_flushes = {}
M.background_mirror_running = false
M.background_mirror_generation = 0
M.background_scan_after = nil
M.mirror_autocmd_group = nil

local setup_mirror_autohydrate

local function notify(message, level)
  vim.schedule(function()
    vim.notify(message, level or vim.log.levels.INFO, { title = "nvim-remote-mirror" })
  end)
end

local function optional_string(value)
  if type(value) == "string" and value ~= "" then
    return value
  end
  return nil
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

local function parse_target(target)
  if target == nil or target == "" then
    return { remote_root = normalize_local_root(uv.cwd()) }
  end

  local ssh_body = target:match("^ssh://(.+)$")
  if ssh_body then
    local host, path = ssh_body:match("^([^/]+)(/.*)$")
    if not host or not path then
      error("expected ssh://host/absolute/path")
    end
    return { ssh = host, remote_root = path }
  end

  return { remote_root = normalize_local_root(target) }
end

local function reconnect_arg(target)
  if target.ssh then
    return "ssh://" .. target.ssh .. target.remote_root
  end
  return target.remote_root
end

local function mirror_relative_path(client, local_path)
  local hello = client and client.hello
  local files_root = hello and hello.files_root
  if not files_root or files_root == "" then
    return nil
  end
  local root = normalize_local_path(files_root):gsub("/+$", "")
  local path = normalize_local_path(local_path)
  local prefix = root .. "/"
  if path:sub(1, #prefix) ~= prefix then
    return nil
  end
  return path:sub(#prefix + 1)
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

local function sidecar_args(target)
  local args = {
    "serve",
    "--remote-root",
    target.remote_root,
    "--agent",
    M.config.agent,
  }
  if target.ssh then
    table.insert(args, "--ssh")
    table.insert(args, target.ssh)
  end
  if M.config.state_dir then
    table.insert(args, "--state-dir")
    table.insert(args, M.config.state_dir)
  end
  table.insert(args, "--request-timeout-ms")
  table.insert(args, tostring(M.config.request_timeout_ms))
  table.insert(args, "--ssh-connect-timeout-seconds")
  table.insert(args, tostring(M.config.ssh_connect_timeout_seconds))
  return args
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

local function schedule_reconnect(target_arg, generation)
  generation = generation or M.reconnect_generation
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
    notify("reconnect attempts exhausted", vim.log.levels.WARN)
    return
  end
  M.reconnect_attempts = M.reconnect_attempts + 1
  local attempt = M.reconnect_attempts
  vim.defer_fn(function()
    if generation ~= M.reconnect_generation then
      return
    end
    if M.client then
      return
    end
    notify("reconnecting remote session, attempt " .. tostring(attempt), vim.log.levels.WARN)
    local ok, err = pcall(M.connect, target_arg, { reconnect = true })
    if not ok then
      notify("reconnect failed: " .. tostring(err), vim.log.levels.ERROR)
      schedule_reconnect(target_arg, generation)
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

local function update_remote_state(client, result)
  if not client or not client.hello or not result then
    return
  end
  client.hello.remote_status = result.remote_status
  client.hello.remote_checked = result.remote_checked
  client.hello.remote_available = result.remote_available
  client.hello.remote_error = result.remote_error
  client.hello.retry_after_ms = result.retry_after_ms
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

local function mark_deferred_flush(bufnr, path, reason)
  if not path or path == "" then
    return false
  end

  local item = M.deferred_flushes[path]
  local is_new = item == nil
  if not item then
    item = { path = path, bufnrs = {} }
    M.deferred_flushes[path] = item
  end
  item.reason = reason
  item.updated_at = os.time()
  if bufnr and vim.api.nvim_buf_is_valid(bufnr) then
    item.bufnrs[bufnr] = true
    vim.b[bufnr].nrm_flush_pending = true
  end
  return is_new
end

local function clear_deferred_flush(path)
  if not path or not M.deferred_flushes[path] then
    return
  end
  M.deferred_flushes[path] = nil
  for _, bufnr in ipairs(vim.api.nvim_list_bufs()) do
    if vim.api.nvim_buf_is_valid(bufnr) and vim.b[bufnr].nrm_remote_path == path then
      vim.b[bufnr].nrm_flush_pending = false
    end
  end
end

local function deferred_flush_paths()
  local paths = {}
  for path in pairs(M.deferred_flushes) do
    table.insert(paths, path)
  end
  table.sort(paths)
  return paths
end

local function schedule_deferred_flushes_on_connect(client, generation)
  if next(M.deferred_flushes) == nil then
    return
  end
  vim.defer_fn(function()
    if M.client ~= client or client.closing or generation ~= M.reconnect_generation then
      return
    end
    M.flush_deferred()
  end, 0)
end

local function schedule_flush_queue_on_connect(client, generation)
  if not M.config.flush_queue_on_connect then
    return
  end

  local delay = math.max(tonumber(M.config.flush_queue_on_connect_delay_ms) or 0, 0)
  local limit = math.max(tonumber(M.config.flush_queue_on_connect_limit) or 1, 1)

  local function still_current()
    return M.client == client
      and not client.closing
      and generation == M.reconnect_generation
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
        if
          remaining > 0
          and #(result.attempts or {}) > 0
          and counts.queued == 0
          and counts.conflict == 0
        then
          vim.defer_fn(replay_once, delay)
        end
      end,
    })
  end

  local function probe_then_replay()
    if not still_current() then
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

  vim.defer_fn(probe_then_replay, delay)
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
      if
        not M.background_mirror_running
        or generation ~= M.background_mirror_generation
        or M.client ~= client
      then
        return
      end
      if err or not probe or probe.remote_available ~= true then
        local retry_after = probe and tonumber(probe.retry_after_ms) or nil
        schedule_background_mirror(retry_after or background_interval(), generation)
        return
      end

      local scan_params = {
        limit = M.config.background_mirror_scan_limit,
      }
      if M.background_scan_after then
        scan_params.after = M.background_scan_after
      end
      M.request("scan", scan_params, function(scan_err, scan_result)
        if
          not M.background_mirror_running
          or generation ~= M.background_mirror_generation
          or M.client ~= client
        then
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
          return M.background_mirror_running
            and generation == M.background_mirror_generation
            and M.client == client
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
          if
            not M.background_mirror_running
            or generation ~= M.background_mirror_generation
            or M.client ~= client
          then
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
  M.config = vim.tbl_deep_extend("force", M.config, opts or {})
end

function M.connect(target, opts)
  opts = opts or {}
  target = parse_target(target)
  local target_arg = reconnect_arg(target)
  local is_reconnect = opts.reconnect == true
  if not opts.reconnect then
    M.reconnect_generation = M.reconnect_generation + 1
    M.reconnect_attempts = 0
  end
  local generation = M.reconnect_generation

  if M.client and M.client.job_id then
    M.disconnect({ preserve_last_target = true })
  end

  local client = {
    next_id = 1,
    pending = {},
    stdout_tail = "",
    target = target,
    target_arg = target_arg,
    closing = false,
  }

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
      if M.client == client then
        M.client = nil
        clear_mirror_autohydrate()
      end
      local unexpected = not client.closing
      if unexpected then
        local exit_generation = M.reconnect_generation
        fail_pending(client, "sidecar exited with code " .. tostring(code))
        notify("sidecar exited with code " .. tostring(code), vim.log.levels.ERROR)
        schedule_reconnect(client.target_arg, exit_generation)
      else
        fail_pending(client, "disconnected")
      end
    end,
  })

  if client.job_id <= 0 then
    error("failed to start sidecar: " .. table.concat(command, " "))
  end

  M.client = client
  M.last_target = target_arg
  M.request("hello", {}, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    client.hello = result
    setup_mirror_autohydrate(client)
    if is_reconnect then
      schedule_reconnect_stable_reset(client, generation)
    end
    local remote_suffix = result.remote_status == "unchecked" and " (remote unchecked)" or ""
    notify("connected: " .. result.remote_root .. remote_suffix)
    schedule_deferred_flushes_on_connect(client, generation)
    schedule_flush_queue_on_connect(client, generation)
    if M.config.background_mirror then
      M.start_background_mirror()
    end
  end)
end

function M.disconnect(opts)
  opts = opts or {}
  if not M.client then
    clear_mirror_autohydrate()
    if not opts.preserve_last_target then
      M.reconnect_generation = M.reconnect_generation + 1
      M.reconnect_attempts = 0
    end
    return
  end
  local client = M.client
  client.closing = true
  pcall(M.request, "disconnect", {}, function() end)
  fail_pending(client, "disconnected")
  vim.defer_fn(function()
    if client.job_id then
      pcall(vim.fn.jobstop, client.job_id)
    end
  end, 250)
  clear_mirror_autohydrate()
  M.client = nil
  if not opts.preserve_last_target then
    M.stop_background_mirror()
    M.reconnect_generation = M.reconnect_generation + 1
    M.reconnect_attempts = 0
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
  M.reconnect_generation = M.reconnect_generation + 1
  M.connect(M.last_target, { reconnect = true })
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
  local timeout_ms = math.max(tonumber(M.config.request_timeout_ms) or 0, 0)
  if timeout_ms > 0 then
    local timer = uv.new_timer()
    pending.timer = timer
    timer:start(timeout_ms, 0, function()
      vim.schedule(function()
        local timed_out = clear_pending(client, id)
        if timed_out then
          send_cancel_request(client, id)
          pcall(
            timed_out,
            "request `" .. method .. "` timed out after " .. tostring(timeout_ms) .. " ms",
            nil
          )
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
  vim.fn.chansend(client.job_id, payload)
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

local function warn_cached_open(result)
  if result.force_skipped then
    notify(
      "kept dirty local mirror for " .. result.path .. "; force rehydrate skipped",
      vim.log.levels.WARN
    )
    return
  end
  if result.restored_from_snapshot then
    notify("restored dirty local mirror snapshot for " .. result.path, vim.log.levels.WARN)
    return
  end
  if result.cached and result.cache_reason and result.cache_reason ~= "cached" then
    notify(
      "opened cached " .. result.cache_reason .. " mirror for " .. result.path,
      vim.log.levels.WARN
    )
  end
end

local prefetch_related

local function apply_mirror_file_to_buffer(bufnr, local_path, result)
  local ok, lines = pcall(vim.fn.readfile, local_path, "b")
  if not ok then
    notify("failed to read local mirror file " .. local_path .. ": " .. tostring(lines), vim.log.levels.ERROR)
    return false
  end
  if not vim.api.nvim_buf_is_valid(bufnr) then
    return false
  end
  vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, lines)
  vim.api.nvim_set_option_value("modified", false, { buf = bufnr })
  if result then
    vim.b[bufnr].nrm_remote_path = result.path
    vim.b[bufnr].nrm_remote_hash = result.hash
    vim.b[bufnr].nrm_flush_pending = M.deferred_flushes[result.path] ~= nil
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

      if uv.fs_stat(local_path) then
        apply_mirror_file_to_buffer(bufnr, local_path, {
          path = relative_path,
          local_path = local_path,
          cached = true,
        })
        return
      end

      M.request(
        "open",
        {
          path = relative_path,
          force = false,
          batch_max_file_bytes = M.config.open_batch_max_file_bytes,
        },
        function(err, result)
          if err then
            notify("failed to hydrate " .. relative_path .. ": " .. err, vim.log.levels.ERROR)
            return
          end
          if not result or result.preempted then
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
              notify("skipped hydrate for modified mirror buffer " .. relative_path, vim.log.levels.WARN)
              return
            end
            if apply_mirror_file_to_buffer(bufnr, result.local_path, result) then
              warn_cached_open(result)
              vim.defer_fn(function()
                prefetch_related(result.path)
              end, 20)
            end
          end)
        end
      )
    end,
  })
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
  M.request("open", {
    path = path,
    force = opts.force == true,
    batch_max_file_bytes = opts.batch_max_file_bytes or M.config.open_batch_max_file_bytes,
  }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    if not result or result.preempted then
      return
    end
    vim.schedule(function()
      vim.cmd.edit(vim.fn.fnameescape(result.local_path))
      vim.b.nrm_remote_path = result.path
      vim.b.nrm_remote_hash = result.hash
      vim.b.nrm_flush_pending = M.deferred_flushes[result.path] ~= nil
      warn_cached_open(result)
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
  if not M.client then
    local is_new = mark_deferred_flush(bufnr, path, "disconnected")
    if is_new then
      notify("deferred remote save for " .. path .. " until reconnect", vim.log.levels.WARN)
    end
    return
  end

  M.request("flush", { path = path }, function(err, result)
    if err then
      mark_deferred_flush(bufnr, path, err)
      notify("remote save deferred for " .. path .. ": " .. err, vim.log.levels.WARN)
      return
    end
    if result.status == "conflict" then
      clear_deferred_flush(result.path or path)
      notify(
        "save conflict for " .. result.path .. "; remote copy stored at " .. result.remote_path,
        vim.log.levels.ERROR
      )
      return
    end
    if result.status == "queued" then
      clear_deferred_flush(result.path or path)
      notify(
        "remote save queued for " .. result.path .. ": " .. result.reason,
        vim.log.levels.WARN
      )
      return
    end
    clear_deferred_flush(result.path or path)
    vim.schedule(function()
      if bufnr and vim.api.nvim_buf_is_valid(bufnr) then
        vim.b[bufnr].nrm_remote_hash = result.hash
      end
    end)
  end)
end

function M.flush_buffer(bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local path = vim.b[bufnr].nrm_remote_path
  flush_remote_path(path, { bufnr = bufnr })
end

function M.flush_deferred()
  local paths = deferred_flush_paths()
  for _, path in ipairs(paths) do
    flush_remote_path(path, { deferred = true })
  end
  return #paths
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
  return hit.path .. " [" .. table.concat(labels, ",") .. "]"
end

function M.find(query, opts)
  opts = opts or {}
  query = query or ""
  M.request("find_paths", {
    query = query,
    limit = opts.limit or M.config.find_limit,
  }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
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

function M.grep(query)
  M.grep_generation = M.grep_generation + 1
  local generation = M.grep_generation
  local remote_result = nil
  local remote_applied = false
  local dirty_cache_hits = {}

  local function is_current()
    return generation == M.grep_generation
  end

  local function apply_remote_result()
    if not is_current() or not remote_result then
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

  M.request("grep", {
    query = query,
    limit = M.config.grep_limit,
    hydrate = true,
    max_file_bytes = M.config.prefetch_max_file_bytes,
    max_total_bytes = M.config.prefetch_max_total_bytes,
  }, function(err, result)
    if not is_current() then
      return
    end
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    if not result or result.preempted then
      return
    end
    remote_result = result
    apply_remote_result()
    local hydrate_errors = #(result.hydrate_errors or {})
    if hydrate_errors > 0 or result.hydrate_truncated then
      notify(
        "grep hydrated "
          .. tostring(result.hydrated or 0)
          .. " files with "
          .. tostring(hydrate_errors)
          .. " errors",
        vim.log.levels.WARN
      )
    end
  end)

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

    if remote_result then
      apply_remote_result()
      return
    end

    if #(result.hits or {}) > 0 then
      set_grep_quickfix(query, result, "RemoteGrep cache", function()
        return is_current() and not remote_applied
      end)
    end
  end)
end

function M.status()
  M.request("status", {}, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    update_remote_state(M.client, result)
    notify(
      string.format(
        "known=%d cached=%d indexed=%d dirty=%d pending=%d failed=%d conflicts=%d stale=%d deleted=%d %s",
        result.known_files,
        result.cached_files,
        result.indexed_files or 0,
        result.dirty_files,
        result.pending_saves,
        result.failed_saves,
        result.conflicted_saves,
        result.stale_files,
        result.deleted_files,
        status_remote_summary(result)
      )
    )
  end)
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

function M.validate(path)
  path = path or vim.b.nrm_remote_path
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
  validate_lsp_command(command)

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
  for _, value in ipairs(command) do
    table.insert(cmd, value)
  end

  return vim.tbl_deep_extend("force", {
    cmd = cmd,
    root_dir = M.client.hello.files_root,
  }, opts or {})
end

function M.start_lsp(command, opts)
  if not M.client or not M.client.hello then
    error("not connected; run :RemoteConnect first")
  end
  validate_lsp_command(command)

  local client = M.client
  M.remote_probe(function(err, result)
    if M.client ~= client then
      return
    end
    if err then
      notify("remote probe failed before LSP start: " .. tostring(err), vim.log.levels.ERROR)
      return
    end
    if result and result.preempted then
      return
    end
    if not result or result.remote_available ~= true then
      notify(
        remote_unavailable_message("remote unavailable; LSP not started", result),
        vim.log.levels.WARN
      )
      return
    end

    local ok, config_or_error = pcall(M.lsp_client_config, command, opts)
    if not ok then
      notify(tostring(config_or_error), vim.log.levels.ERROR)
      return
    end
    vim.schedule(function()
      vim.lsp.start(config_or_error)
    end)
  end)
end

vim.api.nvim_create_augroup("NvimRemoteMirror", { clear = true })
vim.api.nvim_create_autocmd("BufWritePost", {
  group = "NvimRemoteMirror",
  callback = function(args)
    M.flush_buffer(args.buf)
  end,
})

return M
