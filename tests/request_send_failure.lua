vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function assert_contains(text, needle, message)
  if not tostring(text):find(needle, 1, true) then
    error((message or "missing text") .. ": expected " .. vim.inspect(text) .. " to contain " .. vim.inspect(needle))
  end
end

local function fake_client()
  return {
    job_id = 99,
    next_id = 1,
    pending = {},
    closing = false,
    target_arg = "ssh://host/repo",
    hello = { workspace_key = "workspace-events" },
  }
end

local function reset()
  nrm.config.auto_reconnect = false
  nrm.config.request_timeout_ms = 10000
  nrm.connection_status = "connected"
  nrm.connection_target = "ssh://host/repo"
  nrm.connection_reason = nil
  nrm.connection_error = nil
  nrm.reconnect_pending = false
end

local original_chansend = vim.fn.chansend
local epoch_events = {}
local epoch_autocmd = vim.api.nvim_create_autocmd("User", {
  pattern = "NrmWorkspaceEpochChanged",
  callback = function(args)
    table.insert(epoch_events, vim.deepcopy(args.data))
  end,
})

local function main()
  reset()
  local client = fake_client()
  nrm.client = client
  local generation = nrm.reconnect_generation
  local older_error = nil
  client.pending[42] = {
    callback = function(err)
      older_error = err
    end,
    timer = nil,
  }

  vim.fn.chansend = function()
    return 0
  end
  local request_error = nil
  nrm.request("status", {}, function(err)
    request_error = err
  end)

  assert_eq(request_error, "sidecar channel closed")
  assert_eq(older_error, "sidecar channel closed")
  assert_eq(next(client.pending), nil, "failed send must clear pending callbacks")
  assert_eq(nrm.client, nil, "failed send must clear active client")
  assert_eq(nrm.connection_status, "disconnected")
  assert_eq(nrm.connection_error, "sidecar channel closed")
  assert_eq(client.closing, true, "failed transport was left eligible for a second exit event")
  assert_eq(nrm.reconnect_generation, generation + 1)
  assert_eq(epoch_events[#epoch_events], {
    epoch = generation + 1,
    workspace_key = "workspace-events",
    target = "ssh://host/repo",
    state = "disconnected",
    reason = "transport_failure",
  })

  reset()
  client = fake_client()
  nrm.client = client
  generation = nrm.reconnect_generation
  vim.fn.chansend = function()
    error("broken pipe")
  end
  request_error = nil
  nrm.request("open", { path = "a.txt" }, function(err)
    request_error = err
  end)

  assert_contains(request_error, "sidecar channel send failed")
  assert_contains(request_error, "broken pipe")
  assert_eq(next(client.pending), nil)
  assert_eq(nrm.client, nil)
  assert_eq(nrm.connection_status, "disconnected")
  assert_contains(nrm.connection_error, "broken pipe")
  assert_eq(client.closing, true)
  assert_eq(nrm.reconnect_generation, generation + 1)
  assert_eq(epoch_events[#epoch_events].state, "disconnected")
  assert_eq(epoch_events[#epoch_events].target, "ssh://host/repo")
end

local ok, err = xpcall(main, debug.traceback)
vim.fn.chansend = original_chansend
pcall(vim.api.nvim_del_autocmd, epoch_autocmd)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
