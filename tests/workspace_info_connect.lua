vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error(
      (message or "assertion failed")
        .. ": expected "
        .. vim.inspect(expected)
        .. ", got "
        .. vim.inspect(actual)
    )
  end
end

local original_jobstart = vim.fn.jobstart
local original_chansend = vim.fn.chansend
local original_notify = vim.notify

local function main()
  nrm.setup({
    auto_reconnect = false,
    background_mirror = false,
    recover_local_edits_on_connect = false,
    flush_queue_on_connect = false,
    request_timeout_ms = 10000,
  })

  local job_opts = nil
  local sent_method = nil

  vim.notify = function() end
  vim.fn.jobstart = function(_, opts)
    job_opts = opts
    return 42
  end
  vim.fn.chansend = function(_, payload)
    local decoded = vim.json.decode(payload)
    sent_method = decoded.method
    job_opts.on_stdout(nil, {
      vim.json.encode({
        id = decoded.id,
        ok = true,
        result = {
          sidecar_version = "0.1.0",
          protocol_version = 5,
          workspace_key = "workspace",
          remote_root = "/remote/repo",
          mirror_root = "/mirror/workspace",
          files_root = "/mirror/workspace/files",
          remote_status = "unchecked",
          remote_checked = false,
          remote_available = false,
          commands = { "workspace_info", "open" },
          notifications = { "workspace/remote_health" },
        },
      }),
      "",
    })
    return #payload
  end

  nrm.connect("/remote/repo")

  assert_eq(sent_method, "workspace_info")
  assert_eq(nrm.connection_status, "connected")
  assert_eq(nrm.client.hello.workspace_key, "workspace")
  assert_eq(nrm.client.hello.files_root, "/mirror/workspace/files")
  vim.wait(20, function()
    return false
  end)
end

local ok, err = xpcall(main, debug.traceback)
vim.fn.jobstart = original_jobstart
vim.fn.chansend = original_chansend
vim.notify = original_notify
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
