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

local function assert_contains(text, needle, message)
  if not tostring(text):find(needle, 1, true) then
    error((message or "missing text") .. ": expected " .. vim.inspect(text) .. " to contain " .. vim.inspect(needle))
  end
end

local notifications = {}
vim.notify = function(message)
  table.insert(notifications, tostring(message))
end

local function main()
  local old_cwd = vim.fn.getcwd()
  local root = vim.fn.tempname()
  vim.fn.mkdir(root .. "/files/src", "p")

  nrm.client = nil
  nrm.connection_status = "disconnected"
  nrm.connection_target = nil
  assert_eq(nrm.current_workspace(), nil)
  assert_eq(nrm.files_root(), nil)
  assert_eq(nrm.remote_root(), nil)
  assert_eq(nrm.local_path("src/main.rs"), nil)
  assert_eq(nrm.remote_path(root .. "/files/src/main.rs"), nil)
  local ok, err = pcall(nrm.cd)
  assert_eq(ok, false)
  assert_contains(err, "not connected")

  nrm.client = {
    job_id = 1,
    transport = "socket",
    target_arg = "ssh://host/repo",
    hello = {
      workspace_key = "workspace-a",
      remote_root = "/remote/repo",
      mirror_root = root,
      files_root = root .. "/files",
      remote_status = "available",
      remote_checked = true,
      remote_available = true,
    },
  }
  nrm.connection_target = "ssh://host/repo"
  nrm.connection_status = "connected"

  local workspace = nrm.current_workspace()
  assert_eq(workspace.workspace_key, "workspace-a")
  assert_eq(workspace.target, "ssh://host/repo")
  assert_eq(workspace.transport, "socket")
  assert_eq(workspace.remote_root, "/remote/repo")
  assert_eq(workspace.files_root, root .. "/files")
  assert_eq(nrm.files_root(), root .. "/files")
  assert_eq(nrm.remote_root(), "/remote/repo")

  assert_eq(nrm.local_path("src/main.rs"), root .. "/files/src/main.rs")
  assert_eq(nrm.local_path("src/./main.rs"), root .. "/files/src/main.rs")
  assert_eq(nrm.local_path("src/../README.md"), nil)
  assert_eq(nrm.local_path("../outside.rs"), nil)
  assert_eq(nrm.local_path("..\\outside.rs"), nil)
  assert_eq(nrm.local_path("a/../../outside.rs"), nil)
  assert_eq(nrm.local_path("."), nil)
  assert_eq(nrm.local_path("/tmp/outside.rs"), nil)
  assert_eq(nrm.remote_path(root .. "/files/src/main.rs"), "src/main.rs")
  assert_eq(nrm.remote_path(root .. "/files/src/../README.md"), "README.md")
  assert_eq(nrm.remote_path(root .. "/other/main.rs"), nil)

  local buf = vim.api.nvim_create_buf(true, false)
  vim.b[buf].nrm_remote_path = "src/main.rs"
  vim.b[buf].nrm_workspace_key = "workspace-a"
  vim.b[buf].nrm_target_arg = "ssh://host/repo"
  vim.b[buf].nrm_files_root = root .. "/files"
  assert_eq(nrm.is_remote_buffer(buf), true)
  assert_eq(nrm.remote_path(buf), "src/main.rs")

  vim.b[buf].nrm_workspace_key = "workspace-b"
  assert_eq(nrm.remote_path(buf), nil)
  vim.b[buf].nrm_workspace_key = "workspace-a"
  assert_eq(nrm.remote_path(buf), "src/main.rs")

  local pending = vim.api.nvim_create_buf(true, false)
  vim.b[pending].nrm_hydrate_path = "src/pending.rs"
  vim.b[pending].nrm_files_root = root .. "/files"
  assert_eq(nrm.is_remote_buffer(pending), true)
  assert_eq(nrm.remote_path(pending), nil)

  local plain = vim.api.nvim_create_buf(true, false)
  assert_eq(nrm.is_remote_buffer(plain), false)
  assert_eq(nrm.remote_path(plain), nil)

  local cd_root = nrm.cd()
  assert_eq(cd_root, root .. "/files")
  assert_eq(vim.fn.getcwd(), root .. "/files")
  vim.wait(50, function()
    return #notifications > 0
  end)
  assert_contains(notifications[#notifications], "remote cwd: " .. root .. "/files")

  nrm.client.hello.files_root = root .. "/missing"
  ok, err = pcall(nrm.cd)
  assert_eq(ok, false)
  assert_contains(err, "remote mirror files root is not available")

  vim.cmd("tcd " .. vim.fn.fnameescape(old_cwd))
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
