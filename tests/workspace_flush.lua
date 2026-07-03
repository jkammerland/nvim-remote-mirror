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
  if method == "flush" or method == "adopt" then
    callback(nil, {
      status = "applied",
      path = params.path,
      hash = "hash:" .. params.path,
    })
  end
end

vim.notify = function() end

local function deferred_count()
  local count = 0
  for _ in pairs(nrm.deferred_flushes) do
    count = count + 1
  end
  return count
end

local function main()
  nrm.deferred_flushes = {}
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

  local files_root = vim.fn.tempname()
  vim.fn.mkdir(files_root .. "/src", "p")
  vim.fn.writefile({ "new" }, files_root .. "/src/new.rs")
  local new_buf = vim.api.nvim_create_buf(true, false)
  vim.api.nvim_buf_set_name(new_buf, files_root .. "/src/new.rs")
  nrm.client = fake_client("workspace-new", "ssh://new.example/repo", files_root)

  nrm.flush_buffer(new_buf)

  assert_eq(calls[#calls].params.path, "src/main.rs", "untracked mirror files should not auto-save by default")
  assert_eq(vim.b[new_buf].nrm_remote_path, nil)

  vim.api.nvim_set_current_buf(new_buf)
  nrm.adopt()

  assert_eq(calls[#calls].method, "adopt")
  assert_eq(calls[#calls].params.path, "src/new.rs")
  assert_eq(vim.b[new_buf].nrm_remote_path, "src/new.rs")

  local write_target = files_root .. "/src/write-target.rs"
  vim.fn.writefile({ "write target" }, write_target)
  local write_buf = vim.api.nvim_create_buf(true, false)
  nrm.client = fake_client("workspace-write", "ssh://write.example/repo", files_root)

  vim.api.nvim_set_current_buf(write_buf)
  nrm.adopt(write_target)

  assert_eq(calls[#calls].method, "adopt")
  assert_eq(calls[#calls].params.path, "src/write-target.rs")
  assert_eq(vim.b[write_buf].nrm_remote_path, "src/write-target.rs")

  local explicit_target = files_root .. "/src/explicit-target.rs"
  vim.fn.writefile({ "explicit target" }, explicit_target)
  local tracked_buf = vim.api.nvim_create_buf(true, false)
  vim.api.nvim_buf_set_name(tracked_buf, files_root .. "/src/current.rs")
  vim.b[tracked_buf].nrm_remote_path = "src/current.rs"
  vim.b[tracked_buf].nrm_workspace_key = "workspace-write"
  vim.b[tracked_buf].nrm_target_arg = "ssh://write.example/repo"
  vim.b[tracked_buf].nrm_files_root = files_root

  vim.api.nvim_set_current_buf(tracked_buf)
  nrm.adopt(explicit_target)

  assert_eq(calls[#calls].method, "adopt")
  assert_eq(calls[#calls].params.path, "src/explicit-target.rs")
  assert_eq(vim.b[tracked_buf].nrm_remote_path, "src/current.rs")

  local offline_path = files_root .. "/src/offline.rs"
  vim.fn.writefile({ "offline" }, offline_path)
  local offline_buf = vim.api.nvim_create_buf(true, false)
  vim.api.nvim_buf_set_name(offline_buf, offline_path)
  nrm.client = nil
  nrm.last_workspace_identity = {
    workspace_key = "workspace-offline",
    target_arg = "ssh://offline.example/repo",
    files_root = files_root,
  }
  local call_count = #calls

  vim.api.nvim_set_current_buf(offline_buf)
  nrm.adopt()

  assert_eq(#calls, call_count, "disconnected new save must not call sidecar immediately")
  assert_eq(vim.b[offline_buf].nrm_remote_path, "src/offline.rs")
  assert_eq(vim.b[offline_buf].nrm_flush_pending, true)
  assert_eq(deferred_count(), 1)

  nrm.client = fake_client("workspace-offline", "ssh://offline.example/repo", files_root)
  assert_eq(nrm.flush_deferred(), 1)
  assert_eq(calls[#calls].method, "adopt")
  assert_eq(calls[#calls].params.path, "src/offline.rs")
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
