vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function assert_contains(text, needle, message)
  if not tostring(text):find(needle, 1, true) then
    error((message or "missing text") .. ": expected " .. vim.inspect(text) .. " to contain " .. vim.inspect(needle))
  end
end

local function wait_until(predicate, message)
  local ok = vim.wait(1000, predicate)
  if not ok then
    error(message or "timed out")
  end
end

local function fake_client(workspace_key, target_arg, files_root)
  return {
    target_arg = target_arg or "ssh://host/repo",
    target = {
      ssh = "host",
      remote_root = "/remote/repo",
    },
    transport = "stdio",
    pending = {},
    hello = {
      workspace_key = workspace_key,
      remote_root = "/remote/repo",
      mirror_root = "/mirror",
      files_root = files_root or ("/mirror/" .. workspace_key .. "/files"),
      remote_status = "available",
      remote_checked = true,
      remote_available = true,
    },
  }
end

local function main()
  local original_client = nrm.client
  local original_remote_probe = nrm.remote_probe
  local original_request = nrm.request
  local original_notify = vim.notify
  local original_lsp_start = vim.lsp.start
  local original_lsp_stop_client = vim.lsp.stop_client
  local original_lsp_get_client_by_id = vim.lsp.get_client_by_id

  vim.notify = function() end

  local active_clients = {}
  local stopped = {}
  vim.lsp.get_client_by_id = function(id)
    return active_clients[id]
  end
  vim.lsp.stop_client = function(id, force)
    table.insert(stopped, { id = id, force = force })
    active_clients[id] = nil
  end

  local next_client_id = 10
  local start_configs = {}
  vim.lsp.start = function(lsp_config)
    local id = next_client_id
    next_client_id = next_client_id + 1
    table.insert(start_configs, lsp_config)
    active_clients[id] = {
      id = id,
      name = lsp_config.name or "remote-lsp",
      stop = function(_, force)
        table.insert(stopped, { id = id, force = force })
        active_clients[id] = nil
      end,
    }
    return id
  end

  nrm.client = fake_client("workspace-a")
  nrm.lsp_clients = {}
  nrm.lsp_last = nil
  nrm.lsp_last_error = nil

  local config = nrm.lsp_client_config({ "rust-analyzer" }, { name = "remote-rust" })
  assert_eq(config.name, "remote-rust")
  assert_eq(config.root_dir, "/mirror/workspace-a/files")
  assert_eq(config.cmd[#config.cmd], "rust-analyzer")
  assert_contains(table.concat(config.cmd, " "), "lsp-proxy")

  config = nrm.lsp_client_config({
    name = "remote-rust-spec",
    cmd = { "rust-analyzer", "--stdio" },
  })
  assert_eq(config.name, "remote-rust-spec")
  assert_eq(config.cmd[#config.cmd - 1], "rust-analyzer")
  assert_eq(config.cmd[#config.cmd], "--stdio")

  local ok, err = pcall(nrm.lsp_client_config, { name = "bad-spec" })
  assert_eq(ok, false)
  assert_contains(err, "command must be a non-empty list")

  nrm.remote_probe = function(callback)
    callback(nil, { remote_available = true })
  end
  nrm.start_lsp({
    name = "remote-rust-spec",
    cmd = { "rust-analyzer" },
  })
  wait_until(function()
    return #start_configs == 1
  end, "LSP did not start")
  assert_eq(start_configs[1].name, "remote-rust-spec")
  local status = nrm.lsp_status({ notify = false })
  assert_eq(status.active, 1)
  assert_eq(status.clients[1].name, "remote-rust-spec")
  assert_eq(status.clients[1].workspace_key, "workspace-a")
  assert_eq(status.last_command[1], "rust-analyzer")

  nrm.remote_probe = function(callback)
    callback(nil, {
      remote_available = false,
      remote_error = "ssh connect failed",
      retry_after_ms = 1250,
    })
  end
  nrm.start_lsp({ "rust-analyzer" })
  assert_contains(nrm.lsp_status({ notify = false }).last_error, "ssh connect failed")
  assert_contains(nrm.lsp_status({ notify = false }).last_error, "retry after 1250 ms")
  assert_eq(#start_configs, 1)

  nrm.remote_probe = function(callback)
    callback("probe failed", nil)
  end
  nrm.start_lsp({ "rust-analyzer" })
  assert_contains(nrm.lsp_status({ notify = false }).last_error, "probe failed")

  local stale_client = fake_client("workspace-stale")
  nrm.client = stale_client
  nrm.remote_probe = function(callback)
    callback(nil, { remote_available = true })
  end
  nrm.start_lsp({ "rust-analyzer" })
  nrm.client = fake_client("workspace-new")
  vim.wait(50, function()
    return #start_configs > 1
  end)
  assert_eq(#start_configs, 1, "stale scheduled start should be ignored")

  nrm.client = fake_client("workspace-a")
  local probe_callbacks = {}
  nrm.remote_probe = function(callback)
    table.insert(probe_callbacks, callback)
  end
  nrm.start_lsp({ "old-server" })
  nrm.start_lsp({ "new-server" })
  assert_eq(#probe_callbacks, 2)
  probe_callbacks[1](nil, { remote_available = true })
  vim.wait(50, function()
    return #start_configs > 1
  end)
  assert_eq(#start_configs, 1, "older same-workspace start should be ignored")
  probe_callbacks[2](nil, { remote_available = true })
  wait_until(function()
    return #start_configs == 2
  end, "newer same-workspace start did not run")
  local new_start_cmd = start_configs[#start_configs].cmd
  assert_eq(new_start_cmd[#new_start_cmd], "new-server")

  nrm.client = fake_client("workspace-a")
  nrm.remote_probe = function(callback)
    callback(nil, { remote_available = true })
  end
  vim.lsp.start = function()
    error("boom")
  end
  nrm.start_lsp({ "rust-analyzer" })
  wait_until(function()
    return nrm.lsp_status({ notify = false }).last_error
      and nrm.lsp_status({ notify = false }).last_error:find("boom", 1, true)
  end, "thrown LSP start error was not recorded")

  vim.lsp.start = function()
    table.insert(start_configs, { name = "nil-start" })
    return nil
  end
  nrm.start_lsp({ "rust-analyzer" })
  wait_until(function()
    return nrm.lsp_status({ notify = false }).last_error == "remote LSP start returned no client id"
  end, "nil LSP start was not recorded")

  vim.lsp.start = original_lsp_start
  vim.lsp.start = function(lsp_config)
    local id = next_client_id
    next_client_id = next_client_id + 1
    table.insert(start_configs, lsp_config)
    active_clients[id] = {
      id = id,
      name = lsp_config.name or "remote-lsp",
      stop = function(_, force)
        table.insert(stopped, { id = id, force = force })
        active_clients[id] = nil
      end,
    }
    return id
  end

  nrm.lsp_clients = {}
  active_clients = {}
  stopped = {}
  start_configs = {}
  next_client_id = 30
  nrm.client = fake_client("workspace-a")
  nrm.remote_probe = function(callback)
    callback(nil, { remote_available = true })
  end
  nrm.start_lsp({ "rust-analyzer" }, { name = "remote-a" })
  wait_until(function()
    return #start_configs == 1
  end, "workspace A LSP did not start")

  local workspace_a_client = nrm.client
  nrm.client = fake_client("workspace-b", "ssh://host/other", "/mirror/workspace-b/files")
  nrm.start_lsp({ "lua-language-server" }, { name = "remote-b" })
  wait_until(function()
    return #start_configs == 2
  end, "workspace B LSP did not start")
  assert_eq(nrm.lsp_status({ notify = false }).active, 1)
  assert_eq(nrm.lsp_status({ notify = false }).clients[1].name, "remote-b")

  nrm.client = workspace_a_client
  nrm.request = function() end
  nrm.disconnect({ preserve_last_target = true })
  assert_eq(#stopped, 1)
  assert_eq(stopped[1].id, 30)
  assert_eq(stopped[1].force, true)
  assert_eq(active_clients[31] ~= nil, true)

  nrm.client = fake_client("workspace-b", "ssh://host/other", "/mirror/workspace-b/files")
  nrm.lsp_last = {
    command = { "lua-language-server" },
    opts = { name = "remote-b" },
  }
  nrm.restart_lsp()
  wait_until(function()
    return #start_configs == 3
  end, "LSP restart did not start a new client")
  assert_eq(stopped[#stopped].id, 31)
  assert_eq(start_configs[#start_configs].name, "remote-b")
  local restarted_cmd = start_configs[#start_configs].cmd
  assert_eq(restarted_cmd[#restarted_cmd], "lua-language-server")

  nrm.lsp_last = nil
  ok, err = pcall(nrm.restart_lsp)
  assert_eq(ok, false)
  assert_contains(err, "no previous remote LSP command")

  vim.cmd("runtime plugin/nvim_remote_mirror.lua")
  assert_eq(vim.fn.exists(":RemoteLspStart"), 2)
  assert_eq(vim.fn.exists(":RemoteLspStop"), 2)
  assert_eq(vim.fn.exists(":RemoteLspRestart"), 2)
  assert_eq(vim.fn.exists(":RemoteLspStatus"), 2)

  nrm.client = original_client
  nrm.remote_probe = original_remote_probe
  nrm.request = original_request
  vim.notify = original_notify
  vim.lsp.start = original_lsp_start
  vim.lsp.stop_client = original_lsp_stop_client
  vim.lsp.get_client_by_id = original_lsp_get_client_by_id
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
