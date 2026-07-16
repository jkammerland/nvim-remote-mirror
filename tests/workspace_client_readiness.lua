vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")
local workspace = require("nvim_remote_mirror.workspace")

local KEY = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

local function assert_eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
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
    workspace_watch_v1 = false,
  }
end

local function runtime(state, revision)
  local value = {
    contract_version = 2,
    support = { process = true, terminal = true, watch = false },
    authority = { state = state, revision = revision },
  }
  if state == "ready" then
    value.authority.agent_version = "0.1.0"
    value.authority.protocol_version = 8
    value.authority.capabilities = agent_capabilities()
    value.authority.effective = { process = true, terminal = true, watch = false }
  end
  return value
end

local function main()
  workspace._reset_for_test()
  nrm.setup({
    remote_runtime = { enabled = true, trust = "always" },
    remote_agent_auto_install = true,
    remote_agent_registry_url = "file:///tmp/releases/v{version}/nrm-agent-manifest-v1.json",
    remote_agent_registry_public_keys = { ["release-a"] = KEY },
  })
  nrm.reconnect_generation = 12
  nrm.connection_status = "connected"
  nrm.connection_target = "ssh://host.example.test/repo"
  nrm.client = {
    job_id = 1,
    stdout_tail = "",
    pending = {},
    target_arg = nrm.connection_target,
    runtime_readiness = runtime("unchecked", 0),
    hello = {
      workspace_key = "workspace-readiness",
      remote_root = "/repo",
      mirror_root = "/mirror",
      files_root = "/mirror/files",
      runtime = runtime("unchecked", 0),
      capabilities = {},
    },
  }

  local requests = {}
  local original_request = nrm.request
  nrm.request = function(method, _, callback)
    table.insert(requests, { method = method, callback = callback })
  end
  local events = {}
  vim.api.nvim_create_autocmd("User", {
    pattern = "NrmWorkspaceReadinessChanged",
    callback = function(event)
      table.insert(events, event.data)
    end,
  })

  local context = assert(nrm.workspace())
  assert_eq(context:capability_status("process").state, "unchecked")
  local results = {}
  assert(context:prepare("process", function(err, prepared)
    table.insert(results, { err = err, prepared = prepared })
  end))
  assert_eq(context:capability_status("process").state, "checking")
  assert(context:prepare("terminal", function(err, prepared)
    table.insert(results, { err = err, prepared = prepared })
  end))
  assert_eq(#requests, 1, "concurrent preparations did not coalesce their health probe")
  assert_eq(requests[1].method, "remote_health")
  nrm._test_handle_stdout(nrm.client, {
    vim.json.encode({
      method = "workspace/remote_health",
      params = { runtime = runtime("unchecked", 0) },
    }),
    "",
  })
  assert_eq(
    context:capability_status("process").state,
    "checking",
    "an unrelated same-revision notification cleared an in-flight readiness check"
  )
  requests[1].callback(nil, {
    remote_status = "connected",
    remote_checked = true,
    remote_available = true,
    runtime = runtime("ready", 1),
  })
  assert_eq(#results, 2)
  assert_eq(results[1].err, nil)
  assert_eq(results[2].err, nil)
  assert_eq(results[1].prepared.capability, "process")
  assert_eq(results[2].prepared.capability, "terminal")
  assert_eq(context:capability_status("process").state, "ready")
  assert_eq(nrm.reconnect_generation, 12, "readiness transition bumped the workspace epoch")
  assert_eq(events[1].readiness_state, "checking")
  assert_eq(events[#events].readiness_state, "ready")

  -- A malformed synchronous response fails closed and preserves the last valid observation.
  nrm.client.runtime_readiness = runtime("unchecked", 2)
  nrm.client.hello.runtime = runtime("unchecked", 2)
  local malformed_err
  assert(context:prepare("process", function(err)
    malformed_err = err
  end))
  assert_eq(#requests, 2)
  requests[2].callback(nil, {
    remote_status = "unavailable",
    runtime = {
      contract_version = 2,
      support = { process = true, terminal = true, watch = false },
      authority = { state = "ready", revision = 3, effective = {} },
    },
  })
  assert_eq(malformed_err.code, "provider_error")
  assert_eq(nrm.client.hello.remote_status, "connected", "malformed response partially updated legacy health")
  assert_eq(nrm.client.runtime_readiness.authority.revision, 2)

  -- A failed or timed-out coalesced probe must release every waiter exactly
  -- once, even when one user callback throws, and a later prepare must retry.
  local failure_calls = { process = 0, terminal = 0 }
  assert(context:prepare("process", function(failure_err)
    assert_eq(failure_err.code, "capability_not_ready")
    failure_calls.process = failure_calls.process + 1
    error("intentional waiter callback failure")
  end))
  assert(context:prepare("terminal", function(failure_err)
    assert_eq(failure_err.code, "capability_not_ready")
    failure_calls.terminal = failure_calls.terminal + 1
  end))
  assert_eq(#requests, 3, "failed coalesced preparations started more than one probe")
  requests[3].callback("request timed out")
  assert_eq(failure_calls, { process = 1, terminal = 1 })
  assert_eq(context:capability_status("process").state, "unchecked")

  local retry_prepared
  assert(context:prepare("process", function(retry_err, prepared)
    assert_eq(retry_err, nil)
    retry_prepared = prepared
  end))
  assert_eq(#requests, 4, "prepare remained stuck after a failed readiness probe")
  requests[4].callback(nil, { runtime = runtime("ready", 3) })
  assert(retry_prepared, "retry after a failed readiness probe did not complete")

  -- A newer notification may overtake the probe response. The lower response
  -- is ignored, but it still completes the local checking overlay and waiters
  -- use the newer observation.
  nrm.client.runtime_readiness = runtime("unchecked", 4)
  nrm.client.hello.runtime = runtime("unchecked", 4)
  local raced_prepared
  assert(context:prepare("process", function(race_err, prepared)
    assert_eq(race_err, nil)
    raced_prepared = prepared
  end))
  assert_eq(#requests, 5)
  nrm._test_handle_stdout(nrm.client, {
    vim.json.encode({
      method = "workspace/remote_health",
      params = { runtime = runtime("ready", 6) },
    }),
    "",
  })
  assert_eq(context:capability_status("process").state, "checking")
  requests[5].callback(nil, { runtime = runtime("ready", 5) })
  assert_eq(raced_prepared.revision, 6)
  assert_eq(context:capability_status("process").state, "ready")

  -- A late response after an epoch change cannot authorize the replacement workspace.
  nrm.client.runtime_readiness = runtime("unchecked", 7)
  nrm.client.hello.runtime = runtime("unchecked", 7)
  local stale_err
  assert(context:prepare("terminal", function(err)
    stale_err = err
  end))
  assert_eq(#requests, 6)
  nrm.reconnect_generation = 13
  requests[6].callback(nil, { runtime = runtime("ready", 8) })
  assert_eq(stale_err.code, "stale_context")

  for _, request in ipairs(requests) do
    assert_eq(request.method, "remote_health", "prepare attempted an install or update mutation")
  end

  -- Explicit disconnect marks the client closing before pending requests are
  -- drained. A preparation completed by that drain is stale, not a retryable
  -- authority-health failure.
  nrm.client.runtime_readiness = runtime("unchecked", 9)
  nrm.client.hello.runtime = runtime("unchecked", 9)
  local disconnect_context = assert(nrm.workspace())
  local pending_probe
  nrm.request = function(method, _, callback)
    if method == "remote_health" then
      pending_probe = callback
      return
    end
    if method == "disconnect" then
      pending_probe("disconnected")
      callback(nil, {})
      return
    end
    error("unexpected method " .. tostring(method))
  end
  local disconnect_err
  assert(disconnect_context:prepare("process", function(err)
    disconnect_err = err
  end))
  nrm.disconnect()
  assert_eq(disconnect_err.code, "stale_context")

  nrm.request = original_request
  workspace._reset_for_test()
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
