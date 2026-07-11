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

local function main()
  local original_request = nrm.request
  vim.notify = function() end

  nrm.client = {
    job_id = 1,
    transport = "socket",
    target_arg = "ssh://host/repo",
    hello = {},
  }
  nrm.connection_status = "connected"

  local requests = {}
  nrm.request = function(method, params, callback)
    table.insert(requests, { method = method, params = params or {} })
    if method == "remote_health" then
      callback(nil, {
        remote_status = "connected",
        remote_checked = true,
        remote_available = true,
        agent_status = "ok",
        agent_version = "0.1.0",
        expected_agent_version = "0.1.0",
        registry_health = {
          state = "not_checked",
          source = "registry",
          manifest_url = "https://registry.example.test/<redacted>",
        },
      })
      return
    end
    if method == "remote_agent_install" or method == "remote_agent_update" then
      callback(nil, {
        status = method == "remote_agent_install" and "installed" or "updated",
        install_path = params.install_path or "$HOME/.local/bin/nrm-agent",
        remote_health = {
          remote_status = "connected",
          remote_checked = true,
          remote_available = true,
          agent_status = "ok",
          agent_version = "0.1.0",
          expected_agent_version = "0.1.0",
          registry_health = {
            state = "verified",
            source = "registry",
            platform = { target = "x86_64-unknown-linux-musl" },
            signing_key_ids = { "release-a" },
            artifact_sha256 = string.rep("a", 64),
          },
        },
      })
      return
    end
    error("unexpected method " .. tostring(method))
  end

  local health_result
  nrm.remote_health(function(err, result)
    assert_eq(err, nil)
    health_result = result
  end)
  assert_eq(requests[#requests].method, "remote_health")
  assert_eq(health_result.agent_status, "ok")
  assert_eq(nrm.connection_state().agent_status, "ok")
  assert_eq(nrm.connection_state().registry_health.state, "not_checked")

  nrm.setup({ remote_agent_install_path = "$HOME/.local/bin/nrm-agent" })
  local install_result
  nrm.install_agent({ force = true }, function(err, result)
    assert_eq(err, nil)
    install_result = result
  end)
  assert_eq(requests[#requests].method, "remote_agent_install")
  assert_eq(requests[#requests].params.force, true)
  assert_eq(requests[#requests].params.install_path, "$HOME/.local/bin/nrm-agent")
  assert_eq(install_result.status, "installed")
  assert_eq(nrm.connection_state().registry_health.state, "verified")

  local update_result
  nrm.update_agent({ install_path = "/opt/nrm-agent" }, function(err, result)
    assert_eq(err, nil)
    update_result = result
  end)
  assert_eq(requests[#requests].method, "remote_agent_update")
  assert_eq(requests[#requests].params.force, nil)
  assert_eq(requests[#requests].params.install_path, "/opt/nrm-agent")
  assert_eq(update_result.status, "updated")

  vim.cmd("runtime plugin/nvim_remote_mirror.lua")
  assert_eq(vim.fn.exists(":RemoteHealth"), 2)
  assert_eq(vim.fn.exists(":RemoteInstallAgent"), 2)
  assert_eq(vim.fn.exists(":RemoteUpdateAgent"), 2)

  vim.cmd("RemoteInstallAgent! /tmp/nrm-agent")
  assert_eq(requests[#requests].method, "remote_agent_install")
  assert_eq(requests[#requests].params.force, true)
  assert_eq(requests[#requests].params.install_path, "/tmp/nrm-agent")

  vim.cmd("RemoteUpdateAgent /tmp/updated-agent")
  assert_eq(requests[#requests].method, "remote_agent_update")
  assert_eq(requests[#requests].params.force, nil)
  assert_eq(requests[#requests].params.install_path, "/tmp/updated-agent")

  nrm.client = nil
  local ok, err = pcall(nrm.remote_health)
  assert_eq(ok, false)
  assert_contains(err, "not connected")

  nrm.request = original_request
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
