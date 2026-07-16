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
      runtime = {
        contract_version = 2,
        support = { process = true, terminal = true, watch = false },
        authority = { state = "unchecked", revision = 0 },
      },
    },
    runtime_readiness = {
      contract_version = 2,
      support = { process = true, terminal = true, watch = false },
      authority = { state = "unchecked", revision = 0 },
    },
  }
end

local function json_line(value)
  return vim.json.encode(value)
end

local function agent_capabilities()
  return {
    scan = true,
    read = true,
    write_cas = true,
    checksum = true,
    grep = true,
    lsp_proxy = false,
    batch_read = true,
    batch_validate = true,
    chunked_write = true,
    request_ids = true,
    cancellation = false,
    streaming = false,
    multiplexing = false,
    git = true,
    runtime_process_v1 = true,
    runtime_pty_v1 = true,
    workspace_watch_v1 = true,
  }
end

local function main()
  local client = fake_client()
  nrm.client = client
  local readiness_events = {}
  vim.api.nvim_create_autocmd("User", {
    pattern = "NrmWorkspaceReadinessChanged",
    callback = function(event)
      table.insert(readiness_events, event.data)
    end,
  })
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
        runtime = {
          contract_version = 2,
          support = { process = true, terminal = true, watch = false },
          authority = { state = "unavailable", revision = 1, reason = "ssh connect failed", retry_after_ms = 1500 },
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
  assert_eq(readiness_events[1].readiness_state, "unavailable")
  assert_eq(readiness_events[1].readiness_revision, 1)
  assert_eq(nrm.reconnect_generation, 0, "readiness notification bumped the workspace epoch")

  local events_before_countdown = #readiness_events
  nrm._test_handle_stdout(client, {
    json_line({
      method = "workspace/remote_health",
      params = {
        remote_status = "unavailable",
        remote_checked = true,
        remote_available = false,
        remote_error = "ssh connect failed",
        retry_after_ms = 1400,
        agent_status = "missing_agent",
        runtime = {
          contract_version = 2,
          support = { process = true, terminal = true, watch = false },
          authority = { state = "unavailable", revision = 1, reason = "ssh connect failed", retry_after_ms = 1400 },
        },
      },
    }),
    "",
  })
  assert_eq(client.runtime_readiness.authority.retry_after_ms, 1400, "same-revision retry countdown was rejected")
  assert_eq(client.hello.retry_after_ms, 1400)
  assert_eq(#readiness_events, events_before_countdown, "retry countdown emitted a semantic readiness event")

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
        runtime = {
          contract_version = 2,
          support = { process = true, terminal = true, watch = false },
          authority = {
            state = "ready",
            revision = 2,
            agent_version = "0.2.0",
            protocol_version = 8,
            capabilities = agent_capabilities(),
            effective = { process = true, terminal = true, watch = false },
          },
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
  local events_after_ready = #readiness_events
  nrm._test_handle_stdout(client, {
    json_line({
      method = "workspace/remote_health",
      params = {
        runtime = {
          contract_version = 2,
          support = { process = true, terminal = true, watch = false },
          authority = {
            state = "ready",
            revision = 2,
            agent_version = "0.2.0",
            protocol_version = 8,
            capabilities = agent_capabilities(),
            effective = { process = true, terminal = true, watch = false },
          },
        },
      },
    }),
    "",
  })
  assert_eq(#readiness_events, events_after_ready, "identical readiness emitted a duplicate event")

  local before_missing_runtime = vim.deepcopy(client.hello)
  nrm._test_handle_stdout(client, {
    json_line({
      method = "workspace/remote_health",
      params = {
        remote_status = "unavailable",
        remote_checked = true,
        remote_available = false,
        remote_error = "notification omitted runtime",
      },
    }),
    "",
  })
  assert(
    vim.deep_equal(client.hello, before_missing_runtime),
    "readiness notification without a v2 runtime contract partially replaced valid state"
  )
  assert_eq(#readiness_events, events_after_ready, "runtime-less readiness notification emitted an event")

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
        runtime = {
          contract_version = 2,
          support = { process = true, terminal = true, watch = false },
          authority = { state = "unavailable", revision = 3, reason = "version_mismatch" },
        },
      },
    }),
    "",
  })
  assert_eq(client.hello.agent_version, "0.1.0", "explicit unavailable agent version was discarded")
  assert_eq(client.hello.protocol_version, 7, "explicit unavailable protocol version was discarded")
  assert_eq(client.hello.expected_agent_version, "0.2.0")
  assert_eq(client.hello.expected_protocol_version, 8)

  local before_stale_revision = vim.deepcopy(client.hello)
  local events_before_stale_revision = #readiness_events
  nrm._test_handle_stdout(client, {
    json_line({
      method = "workspace/remote_health",
      params = {
        remote_status = "connected",
        remote_checked = true,
        remote_available = true,
        agent_status = "ok",
        runtime = {
          contract_version = 2,
          support = { process = true, terminal = true, watch = false },
          authority = {
            state = "ready",
            revision = 2,
            agent_version = "0.2.0",
            protocol_version = 8,
            capabilities = agent_capabilities(),
            effective = { process = true, terminal = true, watch = false },
          },
        },
      },
    }),
    "",
  })
  assert(
    vim.deep_equal(client.hello, before_stale_revision),
    "lower readiness revision replaced newer same-epoch health"
  )
  assert_eq(#readiness_events, events_before_stale_revision, "lower readiness revision emitted an event")

  nrm._test_handle_stdout(client, {
    json_line({
      method = "workspace/remote_health",
      params = {
        remote_status = "unavailable",
        remote_checked = true,
        remote_available = false,
        runtime = {
          contract_version = 2,
          support = { process = true, terminal = true, watch = false },
          authority = { state = "unavailable", revision = 3, reason = "different failure" },
        },
      },
    }),
    "",
  })
  assert(
    vim.deep_equal(client.hello, before_stale_revision),
    "conflicting readiness payload reused an existing revision"
  )
  assert_eq(#readiness_events, events_before_stale_revision, "conflicting equal revision emitted an event")

  local before = vim.deepcopy(client.hello)
  nrm._test_handle_stdout(client, {
    json_line({
      method = "workspace/remote_health",
      params = {
        remote_status = "connected",
        agent_status = "ok",
        runtime = {
          contract_version = 2,
          support = { process = true, terminal = true, watch = false },
          authority = {
            state = "ready",
            revision = 4,
            agent_version = "0.2.0",
            protocol_version = 8,
            capabilities = {},
            effective = { process = true, terminal = "yes", watch = false },
          },
        },
      },
    }),
    "",
  })
  assert(vim.deep_equal(client.hello, before), "malformed readiness notification partially replaced valid state")
  assert_eq(#readiness_events, 3, "malformed readiness notification emitted an event")

  nrm._test_handle_stdout(client, {
    json_line({
      method = "workspace/remote_health",
      params = {
        runtime = {
          contract_version = 2,
          support = { process = true, terminal = true, watch = false },
          authority = {
            state = "ready",
            revision = 4,
            agent_version = "0.2.0",
            protocol_version = 8,
            capabilities = agent_capabilities(),
            effective = { process = true, terminal = true, watch = false },
            reason = "ready states cannot carry failure diagnostics",
          },
        },
      },
    }),
    "",
  })
  assert(vim.deep_equal(client.hello, before), "ready readiness accepted unavailable-only failure fields")
  assert_eq(#readiness_events, 3, "invalid ready failure fields emitted an event")
  nrm.client = nil
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
