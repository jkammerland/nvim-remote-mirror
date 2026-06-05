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
}

M.client = nil

local function notify(message, level)
  vim.schedule(function()
    vim.notify(message, level or vim.log.levels.INFO, { title = "nvim-remote-mirror" })
  end)
end

local function parse_target(target)
  if target == nil or target == "" then
    return { remote_root = uv.cwd() }
  end

  local ssh_body = target:match("^ssh://(.+)$")
  if ssh_body then
    local host, path = ssh_body:match("^([^/]+)(/.*)$")
    if not host or not path then
      error("expected ssh://host/absolute/path")
    end
    return { ssh = host, remote_root = path }
  end

  return { remote_root = target }
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

function M.setup(opts)
  M.config = vim.tbl_deep_extend("force", M.config, opts or {})
end

function M.connect(target)
  target = parse_target(target)

  if M.client and M.client.job_id then
    M.disconnect()
  end

  local client = {
    next_id = 1,
    pending = {},
    stdout_tail = "",
    target = target,
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
      if code ~= 0 then
        notify("sidecar exited with code " .. tostring(code), vim.log.levels.ERROR)
      end
    end,
  })

  if client.job_id <= 0 then
    error("failed to start sidecar: " .. table.concat(command, " "))
  end

  M.client = client
  M.request("hello", {}, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    client.hello = result
    notify("connected: " .. result.remote_root)
  end)
end

function M.disconnect()
  if not M.client then
    return
  end
  local client = M.client
  M.request("disconnect", {}, function() end)
  vim.defer_fn(function()
    if client.job_id then
      pcall(vim.fn.jobstop, client.job_id)
    end
  end, 250)
  M.client = nil
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

function M.open(path)
  M.request("open", { path = path }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    vim.schedule(function()
      vim.cmd.edit(vim.fn.fnameescape(result.local_path))
      vim.b.nrm_remote_path = result.path
      vim.b.nrm_remote_hash = result.hash
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
    notify("indexed " .. tostring(#result.entries) .. " paths")
  end)
end

function M.grep(query)
  M.request("grep", { query = query, limit = M.config.grep_limit }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    local items = {}
    for _, hit in ipairs(result.hits or {}) do
      table.insert(items, {
        filename = hit.path,
        lnum = hit.line,
        col = hit.column,
        text = hit.text,
      })
    end
    vim.schedule(function()
      vim.fn.setqflist({}, " ", { title = "RemoteGrep " .. query, items = items })
      vim.cmd.copen()
    end)
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
        "known=%d cached=%d dirty=%d pending=%d failed=%d conflicts=%d stale=%d",
        result.known_files,
        result.cached_files,
        result.dirty_files,
        result.pending_saves,
        result.failed_saves,
        result.conflicted_saves,
        result.stale_files
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

function M.prefetch(paths)
  M.request("prefetch", { paths = paths }, function(err, result)
    if err then
      notify(err, vim.log.levels.ERROR)
      return
    end
    notify("prefetched " .. tostring(result.hydrated) .. " files")
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
