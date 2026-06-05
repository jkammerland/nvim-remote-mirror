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

local function fake_client(workspace_key, target_arg, files_root)
  return {
    job_id = 1,
    closing = false,
    target_arg = target_arg,
    hello = {
      workspace_key = workspace_key,
      files_root = files_root,
    },
  }
end

local calls = {}
nrm.request = function(method, params, callback)
  table.insert(calls, { method = method, params = params })
  if method == "flush" then
    callback(nil, {
      status = "applied",
      path = params.path,
      hash = "hash:" .. params.path,
    })
  end
end

vim.notify = function() end

local function main()
  local buf = vim.api.nvim_create_buf(true, false)
  vim.api.nvim_set_current_buf(buf)
  vim.b[buf].nrm_remote_path = "src/main.rs"
  vim.b[buf].nrm_workspace_key = "workspace-a"
  vim.b[buf].nrm_target_arg = "ssh://a.example/repo"
  vim.b[buf].nrm_files_root = "/mirror/a/files"

  nrm.client = fake_client("workspace-b", "ssh://b.example/repo", "/mirror/b/files")
  nrm.flush_buffer(buf)
  assert_eq(#calls, 0, "cross-workspace flush must not call sidecar")
  assert_eq(vim.b[buf].nrm_flush_pending, true, "cross-workspace flush should be deferred")
  assert(next(nrm.deferred_flushes) ~= nil, "deferred flush should be recorded")
  assert_eq(nrm.flush_deferred(), 0, "workspace B must not replay workspace A saves")

  nrm.client = fake_client("workspace-a", "ssh://a.example/repo", "/mirror/a/files")
  assert_eq(nrm.flush_deferred(), 1, "workspace A should replay its deferred save")
  assert_eq(#calls, 1, "deferred save should flush once")
  assert_eq(calls[1].method, "flush")
  assert_eq(calls[1].params.path, "src/main.rs")

  vim.wait(100, function()
    return vim.b[buf].nrm_remote_hash == "hash:src/main.rs"
  end)
  assert_eq(vim.b[buf].nrm_flush_pending, false, "successful replay should clear pending flag")
  assert_eq(vim.b[buf].nrm_remote_hash, "hash:src/main.rs")
  assert(next(nrm.deferred_flushes) == nil, "successful replay should clear deferred save")
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
