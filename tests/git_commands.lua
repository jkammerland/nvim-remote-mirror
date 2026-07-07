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

local notifications = {}
vim.notify = function(message, level)
  table.insert(notifications, { message = tostring(message), level = level })
end

local function wait_until(predicate, message)
  if not vim.wait(1000, predicate) then
    error(message)
  end
end

local function setup_remote_workspace()
  local root = vim.fn.tempname()
  local files_root = root .. "/files"
  vim.fn.mkdir(files_root .. "/src", "p")
  vim.fn.writefile({ "local" }, files_root .. "/src/main.rs")
  nrm.client = {
    job_id = 1,
    transport = "local",
    target_arg = "local",
    hello = {
      workspace_key = "workspace-git",
      remote_root = "/remote/repo",
      mirror_root = root,
      files_root = files_root,
      remote_status = "connected",
      remote_available = true,
    },
  }
  nrm.connection_status = "connected"
  nrm.connection_target = "local"

  local buf = vim.api.nvim_create_buf(true, false)
  vim.api.nvim_set_current_buf(buf)
  vim.api.nvim_buf_set_name(buf, files_root .. "/src/main.rs")
  vim.b[buf].nrm_remote_path = "src/main.rs"
  vim.b[buf].nrm_workspace_key = "workspace-git"
  vim.b[buf].nrm_target_arg = "local"
  vim.b[buf].nrm_files_root = files_root
  return root, files_root, buf
end

local function main()
  local _, files_root, remote_buf = setup_remote_workspace()
  vim.cmd("runtime plugin/nvim_remote_mirror.lua")
  assert_eq(vim.fn.exists(":RemoteGitStatus"), 2)
  assert_eq(vim.fn.exists(":RemoteGitDiff"), 2)
  assert_eq(vim.fn.exists(":RemoteGitBlame"), 2)

  local requests = {}
  nrm.request = function(method, params, callback)
    table.insert(requests, { method = method, params = params, callback = callback })
    if method == "git_status" then
      callback(nil, {
        stdout = '## main\0 M src/main.rs\0?? src/new.rs\0 M src/space name.rs\0 M "quoted.lua\0R  src/newname.rs\0src/oldname.rs\0',
        stderr = "",
        status_code = 0,
        truncated = true,
      })
    else
      error("unexpected method " .. tostring(method))
    end
  end

  nrm.git_status({ paths = { "src/./main.rs" } })
  wait_until(function()
    return vim.fn.getqflist({ title = true }).title == "RemoteGitStatus"
  end, "git status quickfix was not populated")
  assert_eq(requests[1].method, "git_status")
  assert_eq(requests[1].params.paths[1], "src/main.rs")
  local qf = vim.fn.getqflist()
  assert_eq(#qf, 5)
  assert_contains(qf[1].text, "src/main.rs")
  assert_contains(qf[2].text, "src/new.rs")
  assert_contains(qf[3].text, "space name.rs")
  assert_eq(vim.api.nvim_buf_get_name(qf[4].bufnr), files_root .. '/"quoted.lua')
  assert_contains(qf[5].text, "src/newname.rs")
  assert_eq(
    table
      .concat(
        vim.tbl_map(function(item)
          return item.text
        end, qf),
        "\n"
      )
      :find("oldname", 1, true),
    nil
  )
  wait_until(function()
    return #notifications > 0
  end, "expected truncation notification")
  assert_contains(notifications[#notifications].message, "truncated")
  vim.cmd("cclose")

  requests = {}
  nrm.request = function(method, params, callback)
    table.insert(requests, { method = method, params = params, callback = callback })
  end
  nrm.git_status()
  nrm.git_status()
  requests[2].callback(nil, {
    stdout = " M src/newer.rs\n",
    stderr = "",
    status_code = 0,
    truncated = false,
  })
  requests[1].callback(nil, {
    stdout = " M src/stale.rs\n",
    stderr = "",
    status_code = 0,
    truncated = false,
  })
  wait_until(function()
    local title = vim.fn.getqflist({ title = true }).title
    local list = vim.fn.getqflist()
    return title == "RemoteGitStatus" and #list == 1 and list[1].text:find("src/newer.rs", 1, true)
  end, "stale git status callback replaced newer quickfix")
  vim.cmd("cclose")

  vim.api.nvim_set_current_buf(remote_buf)
  local old_cwd = vim.fn.getcwd()
  vim.cmd("tcd " .. vim.fn.fnameescape(files_root .. "/src"))
  nrm.request = function(method, params, callback)
    assert_eq(method, "git_diff")
    assert_eq(params.path, "README.md")
    callback(nil, {
      stdout = "diff --git a/README.md b/README.md\n+changed\n",
      stderr = "",
      status_code = 0,
      truncated = false,
    })
  end
  nrm.git_diff("README.md")
  wait_until(function()
    return vim.bo.filetype == "diff"
  end, "git diff scratch buffer was not opened")
  assert_contains(table.concat(vim.api.nvim_buf_get_lines(0, 0, -1, false), "\n"), "+changed")
  vim.cmd("tcd " .. vim.fn.fnameescape(old_cwd))

  nrm.request = function(method, params, callback)
    assert_eq(method, "git_diff")
    assert_eq(params.path, "src/foo bar.lua")
    callback(nil, {
      stdout = "diff --git a/src/foo bar.lua b/src/foo bar.lua\n+space\n",
      stderr = "",
      status_code = 0,
      truncated = false,
    })
  end
  vim.cmd([[RemoteGitDiff src/foo\ bar.lua]])
  wait_until(function()
    return table.concat(vim.api.nvim_buf_get_lines(0, 0, -1, false), "\n"):find("+space", 1, true)
  end, "escaped-space RemoteGitDiff did not use fargs")

  vim.api.nvim_set_current_buf(remote_buf)
  nrm.request = function(method, params, callback)
    assert_eq(method, "git_blame")
    assert_eq(params.path, "src/main.rs")
    callback(nil, {
      stdout = "abc (User 2026-01-01 1) first\nabc (User 2026-01-01 2) second\n",
      stderr = "",
      status_code = 0,
      truncated = false,
    })
  end
  nrm.git_blame()
  wait_until(function()
    return vim.fn.getqflist({ title = true }).title == "RemoteGitBlame src/main.rs"
  end, "git blame quickfix was not populated")
  qf = vim.fn.getqflist()
  assert_eq(#qf, 2)
  assert_eq(vim.api.nvim_buf_get_name(qf[1].bufnr), files_root .. "/src/main.rs")
  assert_eq(qf[2].lnum, 2)
  assert_contains(qf[2].text, "second")

  local called = false
  nrm.request = function()
    called = true
  end
  local ok, err = pcall(nrm.git_diff, "../outside.rs")
  assert_eq(ok, false)
  assert_contains(err, "workspace-relative")
  assert_eq(called, false)

  local diff_async_called = false
  nrm.request = function(method, params, callback)
    assert_eq(method, "git_diff")
    assert_eq(params.path, "src/main.rs")
    callback(nil, { stdout = "diff", stderr = "", status_code = 0, truncated = false })
  end
  nrm.git_diff_async({ path = "src/main.rs" }, function(err2, result)
    assert_eq(err2, nil)
    assert_eq(result.stdout, "diff")
    diff_async_called = true
  end)
  assert_eq(diff_async_called, true)

  nrm.client = nil
  called = false
  nrm.request = function()
    called = true
  end
  ok, err = pcall(nrm.git_status, { paths = { "src/main.rs" } })
  assert_eq(ok, false)
  assert_contains(err, "not connected")
  assert_eq(called, false)
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
