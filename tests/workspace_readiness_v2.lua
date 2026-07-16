vim.opt.runtimepath:prepend(vim.fn.getcwd())

local workspace = require("nvim_remote_mirror.workspace")

local function assert_eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function assert_error(value, err, code)
  assert_eq(value, nil, "operation unexpectedly succeeded")
  assert_eq(type(err), "table")
  assert_eq(err.code, code)
  return err
end

local function descriptor()
  return {
    api_version = 2,
    provider = "test",
    workspace_id = "readiness-v2",
    epoch = 3,
    state = "online",
    mode = "mirror",
    authority = { id = "authority-v2", kind = "ssh", path_style = "posix" },
    roots = { editor = "/mirror/files", authority = "/remote/repo" },
    support = { process = true, terminal = true, watch = false },
  }
end

local function main()
  workspace._reset_for_test()
  local epoch = 3
  local readiness = {
    process = { state = "unchecked", revision = 0 },
    terminal = { state = "unchecked", revision = 0 },
  }
  local pending = {}
  local trusted = true
  local trust_behavior
  local authorize_behavior
  local status_override
  local workspace_state = "online"
  local prepare_behavior
  workspace._set_backend({
    resolve = function()
      return descriptor()
    end,
    current_epoch = function()
      return epoch
    end,
    current_state = function()
      return workspace_state
    end,
    capability_status = function(_, name)
      if status_override then
        return vim.deepcopy(status_override)
      end
      local value = readiness[name] or { state = "unsupported", revision = 0 }
      local supported = name ~= "watch" and value.supported ~= false
      local enabled = value.enabled ~= false
      return {
        name = name,
        state = value.state,
        supported = supported,
        enabled = enabled,
        effective = value.effective,
        revision = value.revision,
        reason = value.reason,
      }
    end,
    prepare_capability = function(_, name, callback)
      if prepare_behavior then
        return prepare_behavior(name, callback)
      end
      table.insert(pending, { name = name, callback = callback })
      return true
    end,
    is_trusted = function()
      if trust_behavior then
        return trust_behavior()
      end
      return trusted
    end,
    authorize = function(_, _, callback)
      if authorize_behavior then
        return authorize_behavior(callback)
      end
      callback(nil, true)
      return true
    end,
    job_spec = function()
      return { argv = { "/usr/bin/true" } }
    end,
    spawn = function()
      return {
        write = function() end,
        close_stdin = function() end,
        signal = function() end,
        kill = function() end,
      }
    end,
  })

  local context = assert(workspace.resolve())
  assert_eq(context.api_version, 2)
  assert_eq(context.capabilities, nil, "v2 leaked the removed frozen capability table")
  assert_eq(context:supports("process"), true)
  assert_eq(context:supports("watch"), false)
  assert_eq(context:capability_status("process"), {
    name = "process",
    state = "unchecked",
    supported = true,
    enabled = true,
    revision = 0,
  })

  for _, invalid_status in ipairs({
    {
      name = "process",
      state = "unchecked",
      supported = true,
      enabled = true,
      revision = 0,
      unknown = true,
    },
    { name = "terminal", state = "unchecked", supported = true, enabled = true, revision = 0 },
    { name = "process", state = "unchecked", supported = true, enabled = true, revision = -1 },
    { name = "process", state = "unsupported", supported = true, enabled = true, effective = false, revision = 0 },
    { name = "process", state = "disabled", supported = true, enabled = true, effective = false, revision = 0 },
    { name = "process", state = "ready", supported = true, enabled = true, revision = 0 },
  }) do
    status_override = invalid_status
    local invalid_value, invalid_err = context:capability_status("process")
    assert_error(invalid_value, invalid_err, "provider_error")
  end
  status_override = nil

  -- Unchecked direct execution remains compatible; known uncertainty does not.
  assert(context:job_spec({ command = { argv = { "true" } } }))
  readiness.process = { state = "checking", revision = 0 }
  local value, err = context:job_spec({ command = { argv = { "true" } } })
  assert_error(value, err, "capability_not_ready")
  readiness.process = { state = "unavailable", revision = 0, reason = "ssh_failed" }
  value, err = context:job_spec({ command = { argv = { "true" } } })
  assert_error(value, err, "capability_not_ready")
  readiness.process = { state = "unavailable", revision = 0, effective = false, reason = "not_negotiated" }
  value, err = context:job_spec({ command = { argv = { "true" } } })
  assert_error(value, err, "capability_unavailable")
  readiness.process = { state = "disabled", revision = 0, enabled = false, effective = false }
  value, err = context:job_spec({ command = { argv = { "true" } } })
  assert_error(value, err, "capability_disabled")
  readiness.terminal = { state = "unavailable", revision = 0, reason = "missing_agent" }
  value, err = context:open_pty({ command = { shell = "default" } })
  assert_error(value, err, "capability_not_ready")
  readiness.process = { state = "checking", revision = 0 }

  local calls = 0
  assert_eq(
    context:prepare("process", function(prepare_err, prepared)
      assert_eq(prepare_err, nil)
      assert(prepared, "prepare returned no facade")
      calls = calls + 1
    end),
    true
  )
  assert_eq(calls, 0, "delayed provider callback was treated as synchronous")
  assert_eq(#pending, 1)
  readiness.process = { state = "ready", revision = 1, effective = true }
  pending[1].callback(nil, readiness.process)
  pending[1].callback(nil, readiness.process)
  assert_eq(calls, 1, "accepted prepare callback was not exactly-once")

  local prepared
  assert(context:prepare("process", function(prepare_err, prepared_value)
    assert_eq(prepare_err, nil)
    prepared = prepared_value
  end))
  assert(prepared, "cached ready capability did not prepare inline")
  assert_eq(prepared.capability, "process")
  assert_eq(prepared.workspace, context)
  assert_eq(prepared.workspace_id, "readiness-v2")
  assert_eq(prepared.epoch, 3)
  assert_eq(prepared.revision, 1)
  assert(prepared:job_spec({ command = { argv = { "true" } } }))
  readiness.process = { state = "disabled", revision = 1, enabled = false, effective = false }
  value, err = prepared:job_spec({ command = { argv = { "true" } } })
  assert_error(value, err, "capability_disabled")
  readiness.process = { state = "ready", revision = 1, effective = true }
  trusted = false
  value, err = prepared:job_spec({ command = { argv = { "true" } } })
  assert_error(value, err, "workspace_untrusted")
  trusted = true
  readiness.process = { state = "ready", revision = 2, effective = true }
  value, err = prepared:job_spec({ command = { argv = { "true" } } })
  assert_error(value, err, "stale_preparation")

  local provider_inline_calls = 0
  readiness.process = { state = "unchecked", revision = 2 }
  prepare_behavior = function(_, callback)
    readiness.process = { state = "ready", revision = 3, effective = true }
    callback(nil)
    error("provider threw after its callback")
  end
  assert(context:prepare("process", function(inline_err)
    assert_eq(inline_err, nil)
    provider_inline_calls = provider_inline_calls + 1
  end))
  assert_eq(provider_inline_calls, 1, "callback-then-throw was delivered more than once")

  readiness.process = { state = "unchecked", revision = 3 }
  prepare_behavior = function(_, callback)
    readiness.process = { state = "ready", revision = 4, effective = true }
    callback(nil)
    return false, { code = "provider_error", message = "late false return" }
  end
  assert(context:prepare("process", function(inline_err)
    assert_eq(inline_err, nil)
    provider_inline_calls = provider_inline_calls + 1
  end))
  assert_eq(provider_inline_calls, 2, "callback-then-false was delivered more than once")

  readiness.process = { state = "ready", revision = 4, effective = true }
  trusted = false
  authorize_behavior = function()
    return false, { code = "provider_error", message = "authorization was not accepted" }
  end
  local refusal_calls = 0
  local refusal_err
  assert(context:prepare("process", function(auth_err)
    refusal_calls = refusal_calls + 1
    refusal_err = auth_err
  end))
  assert_eq(refusal_calls, 1, "authorization refusal left preparation pending")
  assert_eq(refusal_err.code, "provider_error")

  local pending_authorize
  authorize_behavior = function(callback)
    pending_authorize = callback
    return true
  end
  local auth_epoch_err
  assert(context:prepare("process", function(auth_err)
    auth_epoch_err = auth_err
  end))
  epoch = 4
  pending_authorize(nil, true)
  pending_authorize(nil, true)
  assert_eq(auth_epoch_err.code, "stale_context")
  epoch = 3

  local auth_revision_err
  assert(context:prepare("process", function(auth_err)
    auth_revision_err = auth_err
  end))
  readiness.process = { state = "ready", revision = 5, effective = true }
  pending_authorize(nil, true)
  assert_eq(auth_revision_err.code, "capability_not_ready")
  trusted = true
  authorize_behavior = nil

  -- Trust checks can run provider code. Recheck epoch and online state after
  -- they return so a cached grant cannot authorize a replacement workspace.
  readiness.process = { state = "ready", revision = 4, effective = true }
  local trust_race_err
  trust_behavior = function()
    epoch = 4
    return true
  end
  assert(context:prepare("process", function(race_err)
    trust_race_err = race_err
  end))
  assert_eq(trust_race_err.code, "stale_context")
  epoch = 3
  trust_behavior = function()
    workspace_state = "offline"
    return true
  end
  local offline_race_err
  assert(context:prepare("process", function(race_err)
    offline_race_err = race_err
  end))
  assert_eq(offline_race_err.code, "workspace_offline")
  workspace_state = "online"
  trust_behavior = nil

  readiness.process = { state = "unchecked", revision = 4 }
  prepare_behavior = nil
  local stale_callback_err
  assert(context:prepare("process", function(stale_err)
    stale_callback_err = stale_err
  end))
  epoch = 4
  readiness.process = { state = "ready", revision = 5, effective = true }
  pending[#pending].callback(nil)
  assert_eq(stale_callback_err.code, "stale_context")
  epoch = 3

  local callback_called = false
  value, err = context:prepare("unknown", function()
    callback_called = true
  end)
  assert_error(value, err, "invalid_argument")
  assert_eq(callback_called, false, "invalid prepare accepted its callback")

  workspace._reset_for_test()
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
