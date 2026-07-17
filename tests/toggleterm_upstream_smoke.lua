local toggleterm_dir = vim.env.NRM_TOGGLETERM_DIR
if type(toggleterm_dir) ~= "string" or toggleterm_dir == "" then
  print("ToggleTerm upstream smoke: skipped (NRM_TOGGLETERM_DIR is unset)")
  return
end

if vim.fn.isdirectory(toggleterm_dir) ~= 1 then
  error("NRM_TOGGLETERM_DIR is not a directory: " .. toggleterm_dir)
end

local repo = vim.fn.getcwd()
vim.opt.runtimepath:prepend(repo)
vim.opt.runtimepath:prepend(toggleterm_dir)

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function wait_for_file(path)
  if not vim.wait(5000, function()
    return vim.uv.fs_stat(path) ~= nil
  end, 20) then
    error("terminal did not create expected file: " .. path)
  end
end

local original_cwd = vim.fn.getcwd()
local temp_base = vim.fn.tempname() .. "-$HOME"
local literal_root = temp_base .. "/foo*/literal workspace"
local wildcard_sibling = temp_base .. "/fooX/literal workspace"
local integration
local binding
local managed
local raw

local function cleanup()
  if raw and type(raw.shutdown) == "function" then
    pcall(raw.shutdown, raw)
  end
  if integration and binding then
    pcall(integration.shutdown, {
      scope_id = binding.scope_id,
      key = "upstream-smoke",
    })
  end
  pcall(vim.uv.chdir, original_cwd)
  pcall(function()
    vim.system({ "rm", "-rf", "--", temp_base }):wait()
  end)
end

local ok, err = xpcall(function()
  assert_eq(vim.fn.has("win32"), 0, "the pinned upstream smoke is a Linux CI test")
  assert_eq(vim.system({ "mkdir", "-p", "--", literal_root, wildcard_sibling }):wait().code, 0)
  assert_eq(vim.uv.chdir(literal_root), 0)
  vim.o.shell = assert(vim.fn.exepath("sh"))

  local config = require("toggleterm.config")
  local on_open_autochdir = {}
  require("toggleterm").setup({
    autochdir = true,
    close_on_exit = true,
    direction = "float",
    persist_mode = false,
    shade_terminals = false,
    start_in_insert = false,
    on_open = function()
      table.insert(on_open_autochdir, config.get("autochdir"))
    end,
  })
  assert_eq(vim.fn.exists(":ToggleTerm"), 2)

  integration = require("nvim_remote_mirror.integrations.toggleterm")
  binding = assert(integration.resolve({ authority = "local" }))
  local callback_err
  local accepted, accept_err = integration.open({
    key = "upstream-smoke",
    binding = binding,
    cwd = { space = "workspace", path = "" },
    direction = "float",
    display_name = "upstream smoke",
  }, function(open_err, term)
    callback_err = open_err
    managed = term
  end)
  assert_eq(accepted, true, tostring(accept_err))
  assert_eq(callback_err, nil)
  assert(managed, "managed ToggleTerm callback did not return a terminal")
  assert(managed.id >= 2147483648, "managed terminal ID entered ToggleTerm's ordinary Ex-count range")
  assert_eq(managed.hidden, true)
  assert_eq(integration.is_managed(managed), true)
  assert_eq(managed:is_open(), true)
  assert_eq(config.get("autochdir"), true, "managed first open leaked the temporary autochdir override")

  local first_pwd = literal_root .. "/first.cwd"
  managed:send("pwd > " .. vim.fn.shellescape(first_pwd), false)
  wait_for_file(first_pwd)
  assert_eq(assert(vim.fn.readfile(first_pwd)[1], "first cwd result is empty"), literal_root)

  assert(integration.toggle({ key = "upstream-smoke", binding = binding }))
  assert_eq(managed:is_open(), false)
  managed.dir = "/"
  local reopened
  assert(integration.toggle({ key = "upstream-smoke", binding = binding }, function(reopen_err, term)
    assert_eq(reopen_err, nil)
    reopened = term
  end))
  assert_eq(reopened, managed, "managed reopen replaced the live terminal")
  assert_eq(managed:is_open(), true)
  assert_eq(managed.dir, literal_root, "reopen lost the literal cwd")
  assert_eq(config.get("autochdir"), true, "managed reopen leaked the temporary autochdir override")

  local second_pwd = literal_root .. "/second.cwd"
  managed:send("pwd > " .. vim.fn.shellescape(second_pwd), false)
  wait_for_file(second_pwd)
  assert_eq(assert(vim.fn.readfile(second_pwd)[1], "second cwd result is empty"), literal_root)

  -- Raw :ToggleTerm is deliberately local. A hidden broker terminal must not
  -- be selected from ToggleTerm's saved view or ordinary low-ID allocator.
  assert(integration.toggle({ key = "upstream-smoke", binding = binding }))
  assert_eq(managed:is_open(), false)
  -- ToggleTerm v2.13.1 itself expands environment variables in a raw
  -- autochdir cwd. Exercise the local escape hatch from an ordinary cwd; the
  -- managed literal-cwd behavior above is owned and protected by this adapter.
  assert_eq(vim.uv.chdir(original_cwd), 0)
  vim.cmd("ToggleTerm direction=float")
  for _, term in ipairs(require("toggleterm.terminal").get_all(true)) do
    if term ~= managed and not integration.is_managed(term) then
      raw = term
      break
    end
  end
  assert(raw, "raw :ToggleTerm did not create a local terminal")
  assert(raw.id > 0 and raw.id < 2147483648, "raw :ToggleTerm inherited a managed terminal ID")
  assert_eq(raw.hidden, false)
  assert_eq(raw:is_open(), true)
  assert_eq(managed:is_open(), false, "raw :ToggleTerm reopened the broker terminal")
  assert_eq(integration.lookup(managed).term, managed, "raw :ToggleTerm replaced the broker record")

  local raw_pwd = temp_base .. "/raw.cwd"
  raw:send("pwd > " .. vim.fn.shellescape(raw_pwd), false)
  wait_for_file(raw_pwd)
  assert_eq(
    assert(vim.fn.readfile(raw_pwd)[1], "raw cwd result is empty"),
    original_cwd,
    "raw :ToggleTerm was not local"
  )

  vim.cmd("ToggleTerm direction=float")
  assert_eq(raw:is_open(), false)
  assert_eq(managed:is_open(), false)
  assert_eq(integration.lookup(managed).term, managed)
  assert_eq(config.get("autochdir"), true)

  assert(#on_open_autochdir >= 3, "expected first-open, reopen, and raw callbacks")
  for _, restored in ipairs(on_open_autochdir) do
    assert_eq(restored, true, "ToggleTerm on_open observed the temporary autochdir override")
  end
end, debug.traceback)

cleanup()
if not ok then
  error(err)
end

print("ToggleTerm v2.13.1 upstream smoke: ok")
