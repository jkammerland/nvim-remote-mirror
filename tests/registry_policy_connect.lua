vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")

local KEY = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local original_jobstart = vim.fn.jobstart
local original_chansend = vim.fn.chansend
local original_jobstop = vim.fn.jobstop
local original_notify = vim.notify

local function main()
  nrm.setup({
    sidecar = vim.fn.fnamemodify(vim.v.progpath, ":p"),
    remote_agent_registry_url = "file:///tmp/releases/v{version}/manifest.json",
    remote_agent_registry_public_keys = { ["release-a"] = KEY },
    auto_reconnect = false,
    background_mirror = false,
    recover_local_edits_on_connect = false,
    flush_queue_on_connect = false,
  })

  local job_opts = nil
  local stopped_job = nil
  vim.notify = function() end
  vim.fn.jobstart = function(_, opts)
    job_opts = opts
    return 42
  end
  vim.fn.jobstop = function(job)
    stopped_job = job
    return 1
  end
  vim.fn.chansend = function(_, payload)
    local request = vim.json.decode(payload)
    assert_eq(request.method, "workspace_info")
    job_opts.on_stdout(nil, {
      vim.json.encode({
        id = request.id,
        ok = true,
        result = {
          registry_policy_fingerprint = "disabled",
          workspace_key = "stale-daemon",
          remote_root = "/repo",
          mirror_root = "/mirror/stale",
          files_root = "/mirror/stale/files",
        },
      }),
      "",
    })
    return #payload
  end

  nrm.connect("/repo")

  assert_eq(nrm.connection_status, "disconnected")
  assert_eq(nrm.client, nil)
  assert_eq(stopped_job, 42)
  if not tostring(nrm.connection_error):find("registry policy mismatch", 1, true) then
    error("expected registry policy mismatch, got " .. tostring(nrm.connection_error))
  end
end

local ok, err = xpcall(main, debug.traceback)
vim.fn.jobstart = original_jobstart
vim.fn.chansend = original_chansend
vim.fn.jobstop = original_jobstop
vim.notify = original_notify
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
