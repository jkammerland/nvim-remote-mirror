vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")

local KEY = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

local function assert_eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local original_jobstart = vim.fn.jobstart
local original_chansend = vim.fn.chansend
local original_jobstop = vim.fn.jobstop
local original_notify = vim.notify
local original_defer_fn = vim.defer_fn

local job_opts = nil
local next_job_id = 40
local stopped_jobs = {}

local function reply(request, result, err)
  job_opts.on_stdout(nil, {
    vim.json.encode({
      id = request.id,
      ok = err == nil,
      result = result,
      error = err,
    }),
    "",
  })
end

local function workspace_info(capabilities)
  return {
    sidecar_version = "0.1.0",
    protocol_version = 7,
    registry_policy_fingerprint = nrm._test_registry_policy_fingerprint(nrm.config),
    workspace_key = "workspace",
    remote_root = "/repo",
    mirror_root = "/mirror/workspace",
    files_root = "/mirror/workspace/files",
    remote_status = "unchecked",
    remote_checked = false,
    remote_available = false,
    capabilities = capabilities,
  }
end

local function automatic_capabilities()
  return {
    remote_agent_bootstrap = true,
    remote_agent_automatic_bootstrap_v1 = true,
  }
end

local function quiet_options(overrides)
  return vim.tbl_extend("force", {
    auto_reconnect = false,
    background_mirror = false,
    recover_local_edits_on_connect = false,
    flush_queue_on_connect = false,
  }, overrides or {})
end

local function registry_options(overrides)
  return quiet_options(vim.tbl_extend("force", {
    remote_agent_auto_install = true,
    remote_agent_install_path = "/opt/nrm/bin/nrm-agent",
    remote_agent_registry_url = "file:///tmp/releases/v{version}/nrm-agent-manifest-v1.json",
    remote_agent_registry_public_keys = { ["release-a"] = KEY },
    remote_agent_registry_signature_threshold = 1,
  }, overrides or {}))
end

local function reset_client()
  if nrm.client then
    nrm.client.closing = true
  end
  nrm.client = nil
  nrm.connection_status = "disconnected"
end

local function connect_with(handler, target)
  local methods = {}
  vim.fn.chansend = function(_, payload)
    local request = vim.json.decode(payload)
    table.insert(methods, request.method)
    handler(request)
    return #payload
  end
  nrm.connect(target)
  return methods
end

local function main()
  vim.notify = function() end
  vim.fn.jobstart = function(_, opts)
    next_job_id = next_job_id + 1
    job_opts = opts
    return next_job_id
  end
  vim.fn.jobstop = function(job)
    table.insert(stopped_jobs, job)
    return 1
  end

  nrm.setup(quiet_options())

  local disabled_methods = connect_with(function(request)
    assert_eq(request.method, "workspace_info")
    reply(request, workspace_info(automatic_capabilities()))
  end, "ssh://host/repo")
  assert_eq(disabled_methods, { "workspace_info" }, "registry-disabled connect attempted bootstrap")
  assert_eq(nrm.connection_state().agent_bootstrap_state, "disabled")
  reset_client()

  nrm.setup(registry_options({ remote_agent_auto_install = false }))
  local opted_out_methods = connect_with(function(request)
    assert_eq(request.method, "workspace_info")
    reply(request, workspace_info(automatic_capabilities()))
  end, "ssh://host/repo")
  assert_eq(opted_out_methods, { "workspace_info" }, "opted-out connect attempted bootstrap")
  reset_client()

  nrm.setup(quiet_options({ remote_agent_auto_install = true }))
  local reset_methods = connect_with(function(request)
    assert_eq(request.method, "workspace_info")
    reply(request, workspace_info(automatic_capabilities()))
  end, "ssh://host/repo")
  assert_eq(reset_methods, { "workspace_info" }, "omitted registry config remained active after setup reset")
  assert_eq(nrm.connection_state().agent_bootstrap_state, "disabled")
  reset_client()

  nrm.setup(registry_options())
  local local_methods = connect_with(function(request)
    assert_eq(request.method, "workspace_info")
    reply(request, workspace_info(automatic_capabilities()))
  end, "/repo")
  assert_eq(local_methods, { "workspace_info" }, "local connect attempted remote bootstrap")
  reset_client()

  local legacy_methods = connect_with(function(request)
    assert_eq(request.method, "workspace_info")
    reply(request, workspace_info({ remote_agent_bootstrap = true }))
  end, "ssh://host/repo")
  assert_eq(legacy_methods, { "workspace_info" }, "older sidecar capability allowed automatic mutation")
  assert_eq(nrm.connection_state().agent_bootstrap_state, "skipped")
  assert_eq(nrm.connection_status, "connected")
  reset_client()

  local automatic_params = nil
  local success_methods = connect_with(function(request)
    if request.method == "workspace_info" then
      reply(request, workspace_info(automatic_capabilities()))
      return
    end
    assert_eq(request.method, "remote_agent_update")
    automatic_params = request.params
    reply(request, {
      status = "updated",
      automatic = true,
      remote_health = {
        remote_status = "connected",
        remote_checked = true,
        remote_available = true,
        agent_status = "ok",
        agent_version = "0.1.0",
        expected_agent_version = "0.1.0",
        protocol_version = 7,
        expected_protocol_version = 7,
      },
    })
  end, "ssh://host/repo")
  assert_eq(success_methods, { "workspace_info", "remote_agent_update" })
  assert_eq(automatic_params.automatic, true)
  assert_eq(automatic_params.install_path, "/opt/nrm/bin/nrm-agent")
  assert_eq(automatic_params.force, nil, "automatic bootstrap must never request force")
  assert_eq(nrm.connection_status, "connected")
  assert_eq(nrm.connection_state().agent_bootstrap_state, "ready")
  assert_eq(nrm.connection_state().agent_bootstrap_result, "updated")
  assert_eq(nrm.connection_state().agent_status, "ok")
  reset_client()

  nrm.setup(registry_options({ remote_agent_install_path = "/opt/nrm/bin/connected-agent" }))
  local pending_workspace_info = nil
  local snapshotted_params = nil
  local snapshotted_methods = connect_with(function(request)
    if request.method == "workspace_info" then
      pending_workspace_info = request
      return
    end
    assert_eq(request.method, "remote_agent_update")
    snapshotted_params = request.params
    reply(request, {
      status = "updated",
      automatic = true,
      remote_health = {
        remote_status = "connected",
        remote_checked = true,
        remote_available = true,
        agent_status = "ok",
        agent_version = "0.1.0",
        expected_agent_version = "0.1.0",
        protocol_version = 7,
        expected_protocol_version = 7,
      },
    })
  end, "ssh://host/repo")
  assert_eq(snapshotted_methods, { "workspace_info" })
  nrm.setup(registry_options({ remote_agent_install_path = "/opt/nrm/bin/next-agent" }))
  reply(pending_workspace_info, workspace_info(automatic_capabilities()))
  assert_eq(snapshotted_methods, { "workspace_info", "remote_agent_update" })
  assert_eq(
    snapshotted_params.install_path,
    "/opt/nrm/bin/connected-agent",
    "setup changed the automatic install path of an existing connection"
  )
  reset_client()
  nrm.setup(registry_options())

  local compatible_methods = connect_with(function(request)
    if request.method == "workspace_info" then
      reply(request, workspace_info(automatic_capabilities()))
      return
    end
    reply(request, {
      status = "skipped",
      reason = "automatic bootstrap skipped because the remote agent is already compatible",
      automatic = true,
      remote_health = {
        remote_status = "connected",
        remote_checked = true,
        remote_available = true,
        agent_status = "ok",
        agent_version = "0.1.0",
        expected_agent_version = "0.1.0",
        protocol_version = 7,
        expected_protocol_version = 7,
      },
    })
  end, "ssh://host/repo")
  assert_eq(compatible_methods, { "workspace_info", "remote_agent_update" })
  assert_eq(nrm.connection_state().agent_bootstrap_state, "ready")
  assert_eq(nrm.connection_state().agent_bootstrap_result, "skipped")
  assert_eq(
    nrm.connection_state().agent_bootstrap_reason,
    "automatic bootstrap skipped because the remote agent is already compatible"
  )
  reset_client()

  local inconsistent_compatible_methods = connect_with(function(request)
    if request.method == "workspace_info" then
      reply(request, workspace_info(automatic_capabilities()))
      return
    end
    reply(request, {
      status = "skipped",
      reason = "automatic bootstrap skipped because the remote agent is already compatible",
      automatic = true,
      remote_health = {
        remote_status = "connected",
        remote_checked = true,
        remote_available = true,
        agent_status = "ok",
        agent_version = "0.1.0",
        expected_agent_version = "0.1.0",
        protocol_version = 7,
        expected_protocol_version = 8,
      },
    })
  end, "ssh://host/repo")
  assert_eq(inconsistent_compatible_methods, { "workspace_info", "remote_agent_update" })
  assert_eq(nrm.connection_state().agent_bootstrap_state, "error", "inconsistent compatible-agent skip was accepted")
  reset_client()

  local skipped_methods = connect_with(function(request)
    if request.method == "workspace_info" then
      reply(request, workspace_info(automatic_capabilities()))
      return
    end
    reply(request, {
      status = "skipped",
      reason = "automatic bootstrap left remote agent unchanged for status `remote_root_missing`",
      automatic = true,
      remote_health = {
        remote_status = "unavailable",
        remote_checked = true,
        remote_available = false,
        agent_status = "remote_root_missing",
      },
    })
  end, "ssh://host/repo")
  assert_eq(skipped_methods, { "workspace_info", "remote_agent_update" })
  assert_eq(nrm.connection_status, "connected")
  assert_eq(nrm.connection_state().agent_bootstrap_state, "skipped")
  assert_eq(nrm.connection_state().agent_status, "remote_root_missing")
  reset_client()

  local failure_methods = connect_with(function(request)
    if request.method == "workspace_info" then
      reply(request, workspace_info(automatic_capabilities()))
      return
    end
    reply(request, nil, "registry_signature_invalid: insufficient trusted signatures")
  end, "ssh://host/repo")
  assert_eq(failure_methods, { "workspace_info", "remote_agent_update" })
  assert_eq(nrm.connection_status, "connected", "registry failure must keep local mirror connected")
  assert_eq(nrm.connection_error, nil, "registry failure must not masquerade as sidecar connection failure")
  assert_eq(nrm.connection_state().agent_bootstrap_state, "error")
  if not tostring(nrm.connection_state().agent_bootstrap_error):find("registry_signature_invalid", 1, true) then
    error("automatic bootstrap error was not retained")
  end
  reset_client()

  local reasonless_methods = connect_with(function(request)
    if request.method == "workspace_info" then
      reply(request, workspace_info(automatic_capabilities()))
      return
    end
    reply(request, {
      status = "skipped",
      automatic = true,
      remote_health = { remote_status = "unavailable", remote_available = false, agent_status = "unavailable" },
    })
  end, "ssh://host/repo")
  assert_eq(reasonless_methods, { "workspace_info", "remote_agent_update" })
  assert_eq(nrm.connection_state().agent_bootstrap_state, "error")
  if not tostring(nrm.connection_state().agent_bootstrap_error):find("invalid automatic", 1, true) then
    error("reasonless automatic bootstrap skip was accepted")
  end
  reset_client()

  local malformed_methods = connect_with(function(request)
    if request.method == "workspace_info" then
      reply(request, workspace_info(automatic_capabilities()))
      return
    end
    reply(request, {
      status = "updated",
      remote_health = { remote_status = "connected", remote_available = true, agent_status = "ok" },
    })
  end, "ssh://host/repo")
  assert_eq(malformed_methods, { "workspace_info", "remote_agent_update" })
  assert_eq(nrm.connection_status, "connected")
  assert_eq(nrm.connection_state().agent_bootstrap_state, "error")
  if not tostring(nrm.connection_state().agent_bootstrap_error):find("invalid automatic", 1, true) then
    error("malformed automatic bootstrap result was accepted")
  end
  reset_client()

  local incompatible_methods = connect_with(function(request)
    if request.method == "workspace_info" then
      reply(request, workspace_info(automatic_capabilities()))
      return
    end
    reply(request, {
      status = "updated",
      automatic = true,
      remote_health = {
        remote_status = "connected",
        remote_checked = true,
        remote_available = true,
        agent_status = "ok",
        agent_version = "0.1.0",
        expected_agent_version = "0.2.0",
        protocol_version = 7,
        expected_protocol_version = 7,
      },
    })
  end, "ssh://host/repo")
  assert_eq(incompatible_methods, { "workspace_info", "remote_agent_update" })
  assert_eq(nrm.connection_status, "connected")
  assert_eq(nrm.connection_state().agent_bootstrap_state, "error")
  assert_eq(nrm.connection_state().agent_status, "ok")
  reset_client()

  for _, case in ipairs({
    {
      label = "unchecked",
      health = {
        remote_status = "connected",
        remote_checked = false,
        remote_available = true,
        agent_status = "ok",
        agent_version = "0.1.0",
        expected_agent_version = "0.1.0",
        protocol_version = 7,
        expected_protocol_version = 7,
      },
    },
    {
      label = "unavailable",
      health = {
        remote_status = "unavailable",
        remote_checked = true,
        remote_available = false,
        agent_status = "ok",
        agent_version = "0.1.0",
        expected_agent_version = "0.1.0",
        protocol_version = 7,
        expected_protocol_version = 7,
      },
    },
    {
      label = "protocol mismatch",
      health = {
        remote_status = "connected",
        remote_checked = true,
        remote_available = true,
        agent_status = "ok",
        agent_version = "0.1.0",
        expected_agent_version = "0.1.0",
        protocol_version = 7,
        expected_protocol_version = 8,
      },
    },
  }) do
    local methods = connect_with(function(request)
      if request.method == "workspace_info" then
        reply(request, workspace_info(automatic_capabilities()))
        return
      end
      reply(request, {
        status = "updated",
        automatic = true,
        remote_health = case.health,
      })
    end, "ssh://host/repo")
    assert_eq(methods, { "workspace_info", "remote_agent_update" })
    assert_eq(nrm.connection_state().agent_bootstrap_state, "error", case.label .. " updated health was accepted")
    reset_client()
  end

  local delayed_request = nil
  local delayed_methods = connect_with(function(request)
    if request.method == "workspace_info" then
      reply(request, workspace_info(automatic_capabilities()))
    elseif request.method == "remote_agent_update" then
      delayed_request = request
    end
  end, "ssh://host/repo")
  assert_eq(delayed_methods, { "workspace_info", "remote_agent_update" })
  assert_eq(nrm.connection_status, "bootstrapping_agent")
  local delayed_job_id = nrm.client.job_id
  local deferred = {}
  vim.defer_fn = function(callback, delay)
    table.insert(deferred, { callback = callback, delay = delay })
  end
  nrm.disconnect()
  assert_eq(nrm.connection_status, "disconnected")
  assert_eq(#deferred, 1, "stdio disconnect should schedule one bounded process stop")
  if deferred[1].delay <= 250 then
    error("automatic bootstrap disconnect retained the unsafe 250 ms stdio stop delay")
  end
  assert_eq(#stopped_jobs, 0, "automatic bootstrap disconnect stopped the sidecar immediately")
  deferred[1].callback()
  assert_eq(stopped_jobs[#stopped_jobs], delayed_job_id)
  vim.defer_fn = original_defer_fn
  reply(delayed_request, {
    status = "updated",
    automatic = true,
    remote_health = { remote_status = "connected", remote_available = true, agent_status = "ok" },
  })
  assert_eq(nrm.connection_status, "disconnected", "stale bootstrap callback completed a disconnected session")

  -- Drain notifications while the test stub is still installed.
  vim.wait(10, function()
    return false
  end)
end

local ok, err = xpcall(main, debug.traceback)
vim.fn.jobstart = original_jobstart
vim.fn.chansend = original_chansend
vim.fn.jobstop = original_jobstop
vim.notify = original_notify
vim.defer_fn = original_defer_fn
nrm.client = nil
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
