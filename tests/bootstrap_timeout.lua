vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local original_chansend = vim.fn.chansend

local function main()
  nrm.config.request_timeout_ms = 250
  nrm.config.remote_agent_registry_timeout_ms = 7000
  nrm.config.remote_agent_registry_url = nil

  assert_eq(nrm._test_request_timeout_ms("status"), 250)
  assert_eq(nrm._test_request_timeout_ms("remote_agent_install"), 1250)
  assert_eq(nrm._test_request_timeout_ms("remote_agent_update"), 1250)
  assert_eq(nrm._test_request_cancels_on_timeout("status", {}), true)
  assert_eq(nrm._test_request_cancels_on_timeout("remote_agent_update", {}), true)
  assert_eq(nrm._test_request_cancels_on_timeout("remote_agent_update", { automatic = true }), false)
  assert_eq(nrm._test_request_cancels_on_timeout("remote_agent_install", { automatic = true }), false)

  nrm.config.remote_agent_registry_url = "https://registry.example.test/v{version}/manifest.json"
  assert_eq(nrm._test_request_timeout_ms("remote_agent_install"), 8000)
  assert_eq(nrm._test_request_timeout_ms("remote_agent_update"), 8000)
  assert_eq(nrm._test_request_timeout_ms("status"), 250)

  nrm.config.remote_agent_registry_timeout_ms = 9007199254740991
  assert_eq(nrm._test_request_timeout_ms("remote_agent_install"), 9007199254740991)

  local connected = {
    timeout_config = {
      request_timeout_ms = 400,
      remote_agent_registry_timeout_ms = 6000,
      registry_enabled = true,
    },
  }
  nrm.config.request_timeout_ms = 1
  nrm.config.remote_agent_registry_timeout_ms = 2
  nrm.config.remote_agent_registry_url = nil
  assert_eq(nrm._test_request_timeout_ms("status", connected), 400)
  assert_eq(nrm._test_request_timeout_ms("remote_agent_install", connected), 7000)
  connected.timeout_config.registry_enabled = false
  nrm.config.remote_agent_registry_url = "https://changed.example.test/v{version}/manifest.json"
  assert_eq(nrm._test_request_timeout_ms("remote_agent_install", connected), 1400)

  nrm.config.remote_agent_registry_url = nil
  nrm.config.request_timeout_ms = 25
  local client = {
    job_id = 99,
    next_id = 1,
    pending = {},
    stdout_tail = "",
    closing = false,
  }
  nrm.client = client
  local sent_requests = {}
  vim.fn.chansend = function(_, payload)
    table.insert(sent_requests, vim.json.decode(payload))
    return #payload
  end

  local callback_count = 0
  nrm.request("remote_agent_install", {}, function()
    callback_count = callback_count + 1
  end)
  local pending = client.pending[1]
  assert_eq(type(pending), "table")
  assert_eq(pending.timer:is_active(), true)

  local callback = nrm._test_clear_pending(client, 1)
  callback(nil, { status = "installed" })
  assert_eq(callback_count, 1)
  assert_eq(client.pending[1], nil)
  assert_eq(pending.timer:is_closing(), true, "completed requests must cancel their bootstrap timer")
  vim.wait(50)
  assert_eq(callback_count, 1, "a canceled timer must not invoke a stale callback")

  sent_requests = {}
  nrm.config.request_timeout_ms = 1
  local automatic_callback_count = 0
  local automatic_error = nil
  local automatic_result = nil
  nrm.request("remote_agent_update", { automatic = true }, function(err, result)
    automatic_callback_count = automatic_callback_count + 1
    automatic_error = err
    automatic_result = result
  end)
  local automatic_pending = client.pending[2]
  assert_eq(type(automatic_pending), "table")
  assert_eq(automatic_pending.timer:is_active(), true)

  assert(
    vim.wait(2000, function()
      return automatic_callback_count == 1
    end, 10),
    "automatic update timer did not fire"
  )
  assert_eq(automatic_callback_count, 1, "automatic update timeout callback must run once")
  assert_eq(automatic_result, nil)
  assert(
    type(automatic_error) == "string" and automatic_error:find("request `remote_agent_update` timed out", 1, true),
    "automatic update timeout did not report the request: " .. vim.inspect(automatic_error)
  )
  assert_eq(client.pending[2], nil)
  assert_eq(automatic_pending.timer:is_closing(), true)
  assert_eq(#sent_requests, 1, "automatic update timeout must not send a cancel frame")
  assert_eq(sent_requests[1].method, "remote_agent_update")
  assert_eq(sent_requests[1].params.automatic, true)
  vim.wait(50)
  assert_eq(automatic_callback_count, 1, "automatic update timeout callback ran more than once")
end

local ok, err = xpcall(main, debug.traceback)
vim.fn.chansend = original_chansend
nrm.client = nil
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
