vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")
local uv = vim.uv or vim.loop

local original_fs_lstat = uv.fs_lstat
local original_fs_mkdir = uv.fs_mkdir
local original_fs_chmod = uv.fs_chmod
local original_fs_realpath = uv.fs_realpath
local original_os_getuid = uv.os_getuid
local original_os_get_passwd = uv.os_get_passwd

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function assert_rejected(callback, expected)
  local ok, err = pcall(callback)
  if ok then
    error("expected socket security validation to reject the path")
  end
  if not tostring(err):find(expected, 1, true) then
    error("expected error containing " .. expected .. ", got " .. tostring(err))
  end
end

local function main()
  local socket_path = "/tmp/nrm-socket-security/leaf/sidecar.sock"
  local socket_dir = "/tmp/nrm-socket-security/leaf"
  local socket_parent = "/tmp/nrm-socket-security"
  local stats = {
    [socket_parent] = { type = "directory", uid = 4242, mode = 448 },
    ["/tmp"] = { type = "directory", uid = 0, mode = 1023 },
    ["/"] = { type = "directory", uid = 0, mode = 493 },
  }
  local mkdir_calls = {}
  local chmod_calls = {}

  uv.os_getuid = function()
    return 4242
  end
  uv.os_get_passwd = function()
    return { uid = 4242 }
  end
  uv.fs_lstat = function(path)
    local stat = stats[path]
    if stat then
      return vim.deepcopy(stat)
    end
    return nil, "ENOENT: no such file or directory: " .. path, "ENOENT"
  end
  uv.fs_realpath = function(path)
    return path
  end
  local function mkdir(path, mode)
    table.insert(mkdir_calls, { path = path, mode = mode })
    if stats[path] then
      return nil, "EEXIST: file already exists: " .. path, "EEXIST"
    end
    stats[path] = { type = "directory", uid = 4242, mode = mode }
    return true
  end
  uv.fs_mkdir = mkdir
  uv.fs_chmod = function(path, mode)
    table.insert(chmod_calls, { path = path, mode = mode })
    if not stats[path] then
      return nil, "ENOENT: no such file or directory: " .. path, "ENOENT"
    end
    stats[path].mode = mode
    return true
  end

  assert_eq(nrm._test_prepare_socket_directory(socket_path), socket_dir)
  assert_eq(#mkdir_calls, 1)
  assert_eq(mkdir_calls[1].path, socket_dir)
  assert_eq(mkdir_calls[1].mode, 448)
  assert_eq(#chmod_calls, 1)
  assert_eq(chmod_calls[1].path, socket_dir)
  assert_eq(chmod_calls[1].mode, 448)

  local nested_parent = socket_parent .. "/nested"
  local nested_dir = nested_parent .. "/leaf"
  local nested_socket = nested_dir .. "/sidecar.sock"
  mkdir_calls = {}
  chmod_calls = {}
  assert_eq(nrm._test_prepare_socket_directory(nested_socket), nested_dir)
  assert_eq(#mkdir_calls, 2, "nested creation did not use one mkdir per component")
  assert_eq(mkdir_calls[1].path, nested_parent)
  assert_eq(mkdir_calls[2].path, nested_dir)
  assert_eq(#chmod_calls, 2, "nested creation did not secure each new component")

  for _, case in ipairs({
    {
      stat = { type = "link", uid = 4242, mode = 448 },
      expected = "must be a directory and not a symlink",
    },
    {
      stat = { type = "directory", uid = 4243, mode = 448 },
      expected = "must be owned by the current uid",
    },
    {
      stat = { type = "directory", uid = 4242, mode = 493 },
      expected = "must have mode 0700",
    },
  }) do
    stats[socket_dir] = case.stat
    assert_rejected(function()
      nrm._test_prepare_socket_directory(socket_path)
    end, case.expected)
  end

  stats[socket_dir] = { type = "directory", uid = 4242, mode = 448 }
  stats[socket_parent] = { type = "directory", uid = 4242, mode = 511 }
  assert_rejected(function()
    nrm._test_prepare_socket_directory(socket_path)
  end, "must not be group/world-writable unless sticky")

  stats[socket_dir] = nil
  mkdir_calls = {}
  chmod_calls = {}
  assert_rejected(function()
    nrm._test_prepare_socket_directory(socket_path)
  end, "must not be group/world-writable unless sticky")
  assert_eq(#mkdir_calls, 0, "unsafe creation ancestor was mutated")
  assert_eq(#chmod_calls, 0, "unsafe creation ancestor was chmodded")

  stats[socket_parent] = { type = "directory", uid = 4242, mode = 1023 }
  assert_eq(
    nrm._test_prepare_socket_directory(socket_path),
    socket_dir,
    "sticky shared ancestor did not protect the private socket leaf"
  )
  assert_eq(#mkdir_calls, 1, "sticky creation did not create exactly one component")

  stats[socket_dir] = nil
  mkdir_calls = {}
  chmod_calls = {}
  uv.fs_mkdir = function(path, mode)
    table.insert(mkdir_calls, { path = path, mode = mode })
    stats[path] = { type = "link", uid = 4243, mode = 448 }
    return nil, "EEXIST: file already exists: " .. path, "EEXIST"
  end
  assert_rejected(function()
    nrm._test_prepare_socket_directory(socket_path)
  end, "must be a directory and not a symlink")
  assert_eq(#chmod_calls, 0, "a raced existing component was chmodded")
  uv.fs_mkdir = mkdir

  stats[socket_dir] = { type = "directory", uid = 4242, mode = 448 }
  stats[socket_parent] = { type = "directory", uid = 4243, mode = 493 }
  assert_rejected(function()
    nrm._test_prepare_socket_directory(socket_path)
  end, "ancestors must be owned by the current uid or root")
  stats[socket_parent] = { type = "directory", uid = 4242, mode = 448 }

  stats[socket_dir] = { type = "directory", uid = 4242, mode = 448 }
  stats[socket_path] = nil
  assert_eq(nrm._test_validate_existing_socket(socket_path), false)

  for _, case in ipairs({
    {
      stat = { type = "link", uid = 4242, mode = 384 },
      expected = "must be a Unix socket and not a symlink",
    },
    {
      stat = { type = "file", uid = 4242, mode = 384 },
      expected = "must be a Unix socket and not a symlink",
    },
    {
      stat = { type = "socket", uid = 4243, mode = 384 },
      expected = "must be owned by the current uid",
    },
    {
      stat = { type = "socket", uid = 4242, mode = 432 },
      expected = "permissions must not exceed 0600",
    },
    {
      stat = { type = "socket", uid = 4242, mode = 448 },
      expected = "permissions must not exceed 0600",
    },
  }) do
    stats[socket_path] = case.stat
    assert_rejected(function()
      nrm._test_validate_existing_socket(socket_path)
    end, case.expected)
  end

  for _, mode in ipairs({ 0, 128, 256, 384 }) do
    stats[socket_path] = { type = "socket", uid = 4242, mode = mode }
    assert_eq(nrm._test_validate_existing_socket(socket_path), true, "rejected private socket mode")
  end

  uv.os_getuid = nil
  stats[socket_path] = { type = "socket", uid = 4242, mode = 384 }
  assert_eq(
    nrm._test_validate_existing_socket(socket_path),
    true,
    "did not fall back to os_get_passwd for the current uid"
  )

  uv.fs_lstat = function()
    return nil, "EACCES: permission denied", "EACCES"
  end
  assert_rejected(function()
    nrm._test_validate_existing_socket(socket_path)
  end, "failed to inspect sidecar socket path")
end

local ok, err = xpcall(main, debug.traceback)
uv.fs_lstat = original_fs_lstat
uv.fs_mkdir = original_fs_mkdir
uv.fs_chmod = original_fs_chmod
uv.fs_realpath = original_fs_realpath
uv.os_getuid = original_os_getuid
uv.os_get_passwd = original_os_get_passwd
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
