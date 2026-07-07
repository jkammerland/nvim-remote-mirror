vim.opt.runtimepath:prepend(vim.fn.getcwd())

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function upvalue(fn, name)
  for index = 1, debug.getinfo(fn, "u").nups do
    local found_name, value = debug.getupvalue(fn, index)
    if found_name == name then
      return value
    end
  end
  error("missing upvalue " .. name)
end

local function fake_client(files_root)
  return {
    job_id = 1,
    closing = false,
    target_arg = "ssh://host/repo",
    hello = {
      workspace_key = "workspace",
      files_root = files_root,
    },
  }
end

local calls = {}
local open_callbacks = {}
nrm.request = function(method, params, callback)
  table.insert(calls, { method = method, params = params })
  if method == "open" then
    open_callbacks[params.path] = callback
  elseif method == "flush" then
    callback(nil, {
      status = "applied",
      path = params.path,
      hash = "saved:" .. params.path,
    })
  end
end
vim.notify = function() end

local function edit_path(path)
  vim.cmd.edit(vim.fn.fnameescape(path))
  return vim.api.nvim_get_current_buf()
end

local function count_method(method)
  local count = 0
  for _, call in ipairs(calls) do
    if call.method == method then
      count = count + 1
    end
  end
  return count
end

local function main()
  local files_root = vim.fn.tempname()
  vim.fn.mkdir(files_root, "p")
  local client = fake_client(files_root)
  nrm.client = client
  nrm.config.auto_hydrate_mirror_buffers = true
  upvalue(nrm.connect, "setup_mirror_autohydrate")(client)

  local failed_path = files_root .. "/src/fail.rs"
  local failed_buf = edit_path(failed_path)
  assert_eq(vim.b[failed_buf].nrm_hydrate_pending, true)
  assert_eq(vim.b[failed_buf].nrm_remote_path, nil)
  assert_eq(vim.api.nvim_get_option_value("modifiable", { buf = failed_buf }), false)
  assert_eq(count_method("open"), 1, "autohydrate should request each buffer once")

  nrm.flush_buffer(failed_buf)
  assert_eq(count_method("flush"), 0, "pending hydrate save must not call flush")

  open_callbacks["src/fail.rs"]("remote unavailable", nil)
  vim.wait(100, function()
    return vim.b[failed_buf].nrm_hydrate_failed == true
  end)
  assert_eq(vim.b[failed_buf].nrm_hydrate_pending, false)
  assert_eq(vim.b[failed_buf].nrm_hydrate_failed, true)
  assert_eq(vim.b[failed_buf].nrm_remote_path, nil)
  assert_eq(vim.api.nvim_get_option_value("modifiable", { buf = failed_buf }), false)

  nrm.flush_buffer(failed_buf)
  assert_eq(count_method("flush"), 0, "failed hydrate save must not call flush")

  local ok_path = files_root .. "/src/ok.rs"
  vim.fn.mkdir(vim.fn.fnamemodify(ok_path, ":h"), "p")
  local ok_buf = edit_path(ok_path)
  assert_eq(vim.b[ok_buf].nrm_hydrate_pending, true)
  assert_eq(count_method("open"), 2, "second autohydrate buffer should add one request")
  vim.fn.writefile({ "fn hydrated() {}" }, ok_path)
  open_callbacks["src/ok.rs"](nil, {
    path = "src/ok.rs",
    local_path = ok_path,
    hash = "remote-hash",
  })
  vim.wait(100, function()
    return vim.b[ok_buf].nrm_remote_path == "src/ok.rs"
  end)
  assert_eq(vim.b[ok_buf].nrm_hydrate_pending, false)
  assert_eq(vim.b[ok_buf].nrm_hydrate_failed, false)
  assert_eq(vim.api.nvim_get_option_value("modifiable", { buf = ok_buf }), true)
  assert_eq(vim.api.nvim_buf_get_lines(ok_buf, 0, -1, false)[1], "fn hydrated() {}")

  nrm.flush_buffer(ok_buf)
  assert_eq(count_method("flush"), 1)
  assert_eq(calls[#calls].method, "flush")
  assert_eq(calls[#calls].params.path, "src/ok.rs")

  local no_eol_path = files_root .. "/src/no-eol.rs"
  local no_eol_buf = edit_path(no_eol_path)
  vim.fn.writefile({ "fn no_eol() {}" }, no_eol_path, "b")
  open_callbacks["src/no-eol.rs"](nil, {
    path = "src/no-eol.rs",
    local_path = no_eol_path,
    hash = "no-eol-hash",
  })
  vim.wait(100, function()
    return vim.b[no_eol_buf].nrm_remote_path == "src/no-eol.rs"
  end)
  assert_eq(vim.api.nvim_buf_get_lines(no_eol_buf, 0, -1, false)[1], "fn no_eol() {}")
  assert_eq(vim.api.nvim_get_option_value("endofline", { buf = no_eol_buf }), false)

  local empty_path = files_root .. "/src/empty.rs"
  local empty_buf = edit_path(empty_path)
  vim.fn.writefile({}, empty_path, "b")
  open_callbacks["src/empty.rs"](nil, {
    path = "src/empty.rs",
    local_path = empty_path,
    hash = "empty-hash",
  })
  vim.wait(100, function()
    return vim.b[empty_buf].nrm_remote_path == "src/empty.rs"
  end)
  assert_eq(#vim.api.nvim_buf_get_lines(empty_buf, 0, -1, false), 1)
  assert_eq(vim.api.nvim_buf_get_lines(empty_buf, 0, -1, false)[1], "")

  local binary_path = files_root .. "/src/binary.bin"
  local binary_buf = edit_path(binary_path)
  local binary_file = assert(io.open(binary_path, "wb"))
  binary_file:write("a\000b")
  binary_file:close()
  open_callbacks["src/binary.bin"](nil, {
    path = "src/binary.bin",
    local_path = binary_path,
    hash = "binary-hash",
  })
  vim.wait(100, function()
    return vim.b[binary_buf].nrm_hydrate_failed == true
  end)
  assert_eq(vim.b[binary_buf].nrm_remote_path, nil)
  assert_eq(vim.api.nvim_get_option_value("modifiable", { buf = binary_buf }), false)
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
