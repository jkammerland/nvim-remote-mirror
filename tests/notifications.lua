vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function fake_client()
  return {
    stdout_tail = "",
    pending = {},
    hello = {
      workspace_key = "workspace",
      remote_status = "connected",
      remote_checked = true,
      remote_available = true,
      agent_status = "ok",
      agent_version = "0.1.0",
      expected_agent_version = "0.2.0",
      protocol_version = 7,
      expected_protocol_version = 8,
      remote_agent = "/opt/nrm/bin/nrm-agent",
      registry_configured = true,
    },
  }
end

local function json_line(value)
  return vim.json.encode(value)
end

local function main()
  local client = fake_client()
  nrm.client = client
  local callback_result = nil
  client.pending[7] = {
    timer = nil,
    callback = function(err, result)
      if err then
        error(err)
      end
      callback_result = result
    end,
  }

  nrm._test_handle_stdout(client, {
    json_line({
      method = "workspace/remote_health",
      params = {
        workspace_key = "workspace",
        remote_status = "unavailable",
        remote_checked = true,
        remote_available = false,
        remote_error = "ssh connect failed",
        retry_after_ms = 1500,
        agent_status = "missing_agent",
        registry_health = {
          state = "error",
          source = "registry",
          manifest_url = "https://registry.example.test/<redacted>",
          error_code = "insufficient_signatures",
          error = "signed registry retrieval failed (insufficient_signatures)",
        },
      },
    }),
    json_line({
      id = 7,
      ok = true,
      result = {
        value = 42,
      },
    }),
    "",
  })

  assert_eq(client.hello.remote_status, "unavailable")
  assert_eq(client.hello.remote_checked, true)
  assert_eq(client.hello.remote_available, false)
  assert_eq(client.hello.remote_error, "ssh connect failed")
  assert_eq(client.hello.retry_after_ms, 1500)
  assert_eq(client.hello.registry_health.state, "error")
  assert_eq(client.hello.registry_health.error_code, "insufficient_signatures")
  assert_eq(client.hello.agent_status, "missing_agent")
  assert_eq(client.hello.agent_version, nil, "unavailable health retained a stale agent version")
  assert_eq(client.hello.protocol_version, nil, "unavailable health retained a stale protocol version")
  assert_eq(client.hello.expected_agent_version, "0.2.0", "partial health erased the expected agent version")
  assert_eq(client.hello.expected_protocol_version, 8, "partial health erased the expected protocol version")
  assert_eq(client.hello.remote_agent, "/opt/nrm/bin/nrm-agent", "partial health erased the configured agent")
  assert_eq(client.hello.registry_configured, true, "partial health erased static registry state")
  assert_eq(nrm.connection_state().registry_health.error_code, "insufficient_signatures")
  assert_eq(callback_result.value, 42)
  assert_eq(client.pending[7], nil)

  nrm._test_handle_stdout(client, {
    json_line({
      method = "workspace/remote_health",
      params = {
        workspace_key = "workspace",
        remote_status = "connected",
        remote_checked = true,
        remote_available = true,
        agent_status = "ok",
        agent_version = "0.2.0",
        protocol_version = 8,
        registry_health = {
          state = "error",
          source = "registry",
          error_code = "network_timeout",
          error = "signed registry retrieval failed (network_timeout)",
        },
      },
    }),
    "",
  })
  assert_eq(client.hello.remote_status, "connected")
  assert_eq(client.hello.remote_available, true)
  assert_eq(client.hello.agent_version, "0.2.0")
  assert_eq(client.hello.protocol_version, 8)
  assert_eq(client.hello.registry_health.state, "error")
  assert_eq(client.hello.registry_health.error_code, "network_timeout")

  nrm._test_handle_stdout(client, {
    json_line({
      method = "workspace/remote_health",
      params = {
        workspace_key = "workspace",
        remote_status = "unavailable",
        remote_checked = true,
        remote_available = false,
        agent_status = "version_mismatch",
        agent_version = "0.1.0",
        protocol_version = 7,
      },
    }),
    "",
  })
  assert_eq(client.hello.agent_version, "0.1.0", "explicit unavailable agent version was discarded")
  assert_eq(client.hello.protocol_version, 7, "explicit unavailable protocol version was discarded")
  assert_eq(client.hello.expected_agent_version, "0.2.0")
  assert_eq(client.hello.expected_protocol_version, 8)
  nrm.client = nil
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
