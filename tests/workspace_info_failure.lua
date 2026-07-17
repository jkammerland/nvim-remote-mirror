vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")
local runtime = require("nvim_remote_mirror.workspace_runtime")

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
local next_job_id = 70
local stopped_jobs = {}
local workspace_error = "workspace_info failed"
local pending_workspace_reply = nil

local function successful_workspace_info(request)
  return {
    id = request.id,
    ok = true,
    result = {
      sidecar_version = "0.1.0",
      protocol_version = 5,
      registry_policy_fingerprint = "disabled",
      workspace_key = "workspace",
      remote_root = "/remote/repo",
      mirror_root = "/mirror/workspace",
      files_root = "/mirror/workspace/files",
      remote_status = "unchecked",
      remote_checked = false,
      remote_available = false,
      commands = { "workspace_info", "open" },
      notifications = { "workspace/remote_health" },
      runtime = {
        contract_version = 2,
        support = { process = true, terminal = true, watch = false },
        authority = { state = "unchecked", revision = 0 },
      },
    },
  }
end

local function main()
  runtime._reset_for_test()
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
  vim.fn.chansend = function(_, payload)
    local request = vim.json.decode(payload)
    assert_eq(request.method, "workspace_info")
    if pending_workspace_reply == false then
      pending_workspace_reply = function()
        job_opts.on_stdout(nil, { vim.json.encode(successful_workspace_info(request)), "" })
      end
      return #payload
    end
    job_opts.on_stdout(nil, {
      vim.json.encode({
        id = request.id,
        ok = false,
        error = workspace_error,
      }),
      "",
    })
    return #payload
  end

  nrm.setup({
    sidecar = vim.fn.fnamemodify(vim.v.progpath, ":p"),
    auto_reconnect = false,
    background_mirror = false,
    recover_local_edits_on_connect = false,
    flush_queue_on_connect = false,
  })
  nrm.connect("ssh://host/repo")
  assert_eq(nrm.client, nil, "failed workspace_info retained a client")
  assert_eq(nrm.connection_status, "disconnected")
  assert_eq(nrm.connection_target, "ssh://host/repo")
  assert_eq(nrm.connection_error, workspace_error)
  assert_eq(nrm.reconnect_pending, false)
  assert_eq(stopped_jobs, { 71 })
  assert_eq(runtime._binding_for_test(vim.api.nvim_get_current_tabpage()), nil)

  local deferred = {}
  vim.defer_fn = function(callback, delay)
    table.insert(deferred, { callback = callback, delay = delay })
  end
  workspace_error = "workspace_info timed out"
  nrm.setup({
    sidecar = vim.fn.fnamemodify(vim.v.progpath, ":p"),
    auto_reconnect = true,
    reconnect_delay_ms = 7,
    reconnect_max_attempts = 3,
  })
  nrm.connect("ssh://host/repo")
  assert_eq(nrm.client, nil, "failed workspace_info retained a reconnect client")
  assert_eq(nrm.connection_status, "reconnect_pending")
  assert_eq(nrm.connection_error, workspace_error)
  assert_eq(nrm.reconnect_pending, true)
  assert_eq(nrm.reconnect_attempts, 1)
  assert_eq(stopped_jobs, { 71, 72 })
  assert_eq(#deferred, 1, "failed workspace_info did not schedule one reconnect")
  assert_eq(deferred[1].delay, 7)

  -- The deferred reconnect must retain the token captured by the original
  -- connect, not capture whichever tab happens to be current when it runs.
  -- A user opt-out while the reconnect Hello is pending must then invalidate
  -- that retained token so the late success cannot restore remote authority.
  local origin_tab = vim.api.nvim_get_current_tabpage()
  local origin_token = assert(runtime._capture_binding_token(origin_tab))
  vim.cmd("runtime plugin/nvim_remote_mirror.lua")
  vim.cmd("tabnew")
  local other_tab = vim.api.nvim_get_current_tabpage()
  pending_workspace_reply = false
  deferred[1].callback()
  assert_eq(nrm.connection_status, "reconnecting")
  assert_eq(nrm.client.workspace_binding_token.tabpage, origin_tab, "deferred reconnect recaptured the current tab")
  assert_eq(nrm.client.workspace_binding_token.revision, origin_token.revision)
  assert(type(pending_workspace_reply) == "function", "deferred reconnect did not request workspace_info")

  vim.api.nvim_set_current_tabpage(origin_tab)
  vim.cmd("RemoteUseLocal")
  vim.api.nvim_set_current_tabpage(other_tab)
  pending_workspace_reply()

  assert_eq(nrm.connection_status, "connected")
  assert_eq(runtime._binding_for_test(origin_tab), nil, "late reconnect undid :RemoteUseLocal")
  assert_eq(runtime._binding_for_test(other_tab), nil, "late reconnect bound the reply-time tab")
  vim.api.nvim_set_current_tabpage(origin_tab)
  assert_eq(assert(runtime.resolve()).provider, "local")

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
runtime._reset_for_test()
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
