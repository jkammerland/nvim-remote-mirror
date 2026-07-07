vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function fake_client(name)
  return {
    job_id = 1,
    closing = false,
    target_arg = "ssh://" .. name .. "/repo",
    hello = {
      workspace_key = name,
      files_root = "/mirror/" .. name .. "/files",
    },
  }
end

local requests = {}
nrm.request = function(method, params, callback)
  assert_eq(method, "find_paths")
  table.insert(requests, {
    params = params,
    callback = callback,
  })
end

vim.notify = function() end

local function find_result(path)
  return {
    hits = {
      {
        path = path,
        local_path = "/tmp/" .. path,
        cached = true,
        validation_state = "valid",
        dirty = false,
      },
    },
    truncated = false,
  }
end

local function qf_title()
  return vim.fn.getqflist({ title = 1 }).title
end

local function qf_first_text()
  local items = vim.fn.getqflist({ items = 1 }).items
  return items[1] and items[1].text or nil
end

local function wait_for_title(title)
  local ok = vim.wait(200, function()
    return qf_title() == title
  end)
  assert_eq(ok, true, "quickfix title should update")
end

local function main()
  nrm.client = fake_client("workspace-a")
  nrm.find("old")
  nrm.find("new")
  assert_eq(#requests, 2)

  requests[2].callback(nil, find_result("new.rs"))
  wait_for_title("RemoteFind new")
  assert_eq(qf_first_text(), "new.rs [cached]")

  requests[1].callback(nil, find_result("old.rs"))
  vim.wait(50, function()
    return false
  end)
  assert_eq(qf_title(), "RemoteFind new", "stale find must not replace quickfix")
  assert_eq(qf_first_text(), "new.rs [cached]")

  nrm.find("client-a")
  local client_a_request = requests[#requests]
  nrm.client = fake_client("workspace-b")
  client_a_request.callback(nil, find_result("client-a.rs"))
  vim.wait(50, function()
    return false
  end)
  assert_eq(qf_title(), "RemoteFind new", "old client find must not replace quickfix")
  assert_eq(qf_first_text(), "new.rs [cached]")
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
