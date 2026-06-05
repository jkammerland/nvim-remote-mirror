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
  grep_limit = 200,
  request_timeout_ms = 30000,
  ssh_connect_timeout_seconds = 10,
  prefetch_max_file_bytes = 4 * 1024 * 1024,
  prefetch_max_total_bytes = 16 * 1024 * 1024,
  open_prefetch_related = false,
  open_prefetch_related_limit = 16,
  auto_reconnect = true,
  reconnect_delay_ms = 1000,
  reconnect_max_attempts = 3,
  reconnect_stable_ms = 10000,
}

M.client = nil
M.last_target = nil
M.reconnect_attempts = 0
M.reconnect_generation = 0

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

local function handle_response(client, line)
  local ok, decoded = pcall(vim.json.decode, line)
  if not ok then
    notify("invalid sidecar response: " .. line, vim.log.levels.ERROR)
    return
  end

  local pending = client.pending[decoded.id]
  if not pending then
    return
  end
  client.pending[decoded.id] = nil

  if decoded.ok then
    pending(nil, decoded.result)
  else
    pending(decoded.error or "unknown sidecar error", nil)
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
  for id, callback in pairs(client.pending or {}) do
    client.pending[id] = nil
    pcall(callback, message, nil)
  end
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
    if is_reconnect then
      schedule_reconnect_stable_reset(client, generation)
    end
    notify("connected: " .. result.remote_root)
  end)
end

function M.disconnect(opts)
  opts = opts or {}
  if not M.client then
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
  M.client = nil
  if not opts.preserve_last_target then
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
  client.pending[id] = callback or function() end

  local payload = vim.json.encode({
    id = id,
    method = method,
    params = params or {},
  }) .. "\n"
  vim.fn.chansend(client.job_id, payload)
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

local function prefetch_related(anchor)
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
    if result.preempted then
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
  M.request("open", { path = path, force = opts.force == true }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    vim.schedule(function()
      vim.cmd.edit(vim.fn.fnameescape(result.local_path))
      vim.b.nrm_remote_path = result.path
      vim.b.nrm_remote_hash = result.hash
      warn_cached_open(result)
      vim.defer_fn(function()
        prefetch_related(result.path)
      end, 20)
    end)
  end)
end

function M.flush_buffer(bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local path = vim.b[bufnr].nrm_remote_path
  if not path or not M.client then
    return
  end

  M.request("flush", { path = path }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    if result.status == "conflict" then
      notify(
        "save conflict for " .. result.path .. "; remote copy stored at " .. result.remote_path,
        vim.log.levels.ERROR
      )
      return
    end
    if result.status == "queued" then
      notify(
        "remote save queued for " .. result.path .. ": " .. result.reason,
        vim.log.levels.WARN
      )
      return
    end
    vim.schedule(function()
      if vim.api.nvim_buf_is_valid(bufnr) then
        vim.b[bufnr].nrm_remote_hash = result.hash
      end
    end)
  end)
end

function M.scan(limit)
  M.request("scan", { limit = limit or 10000 }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    if result.preempted then
      return
    end
    notify("indexed " .. tostring(#result.entries) .. " paths")
  end)
end

function M.grep(query)
  M.request("grep", {
    query = query,
    limit = M.config.grep_limit,
    hydrate = true,
    max_file_bytes = M.config.prefetch_max_file_bytes,
    max_total_bytes = M.config.prefetch_max_total_bytes,
  }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    local items = {}
    for _, hit in ipairs(result.hits or {}) do
      table.insert(items, {
        filename = optional_string(hit.local_path) or hit.path,
        lnum = hit.line,
        col = hit.column,
        text = hit.text,
      })
    end
    vim.schedule(function()
      vim.fn.setqflist({}, " ", { title = "RemoteGrep " .. query, items = items })
      vim.cmd.copen()
    end)
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
end

function M.status()
  M.request("status", {}, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    notify(
      string.format(
        "known=%d cached=%d dirty=%d pending=%d failed=%d conflicts=%d stale=%d deleted=%d",
        result.known_files,
        result.cached_files,
        result.dirty_files,
        result.pending_saves,
        result.failed_saves,
        result.conflicted_saves,
        result.stale_files,
        result.deleted_files
      )
    )
  end)
end

function M.flush_queue()
  M.request("flush_queue", {}, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    notify("replayed " .. tostring(#(result.attempts or {})) .. " queued saves")
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
    if result.preempted then
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
    if result.preempted then
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

function M.lsp_client_config(command, opts)
  if not M.client or not M.client.hello then
    error("not connected; run :RemoteConnect first")
  end
  if type(command) ~= "table" or #command == 0 then
    error("command must be a non-empty list")
  end

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

vim.api.nvim_create_augroup("NvimRemoteMirror", { clear = true })
vim.api.nvim_create_autocmd("BufWritePost", {
  group = "NvimRemoteMirror",
  callback = function(args)
    M.flush_buffer(args.buf)
  end,
})

return M
