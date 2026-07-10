vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function assert_rejected(target)
  local ok = pcall(nrm._test_parse_target, target)
  if ok then
    error("accepted invalid target " .. vim.inspect(target))
  end
end

local function main()
  local posix = nrm._test_parse_target("ssh://user@host.example/home/me/repo")
  assert_eq(posix.ssh, "user@host.example")
  assert_eq(posix.remote_root, "/home/me/repo")

  local ipv6 = nrm._test_parse_target("ssh://[2001:db8::1]/repo")
  assert_eq(ipv6.ssh, "[2001:db8::1]")
  assert_eq(ipv6.remote_root, "/repo")

  for _, target in ipairs({
    "ssh://-oProxyCommand=evil/repo",
    "ssh://user@-oProxyCommand=evil/repo",
    "ssh://host name/repo",
    "ssh://host\tname/repo",
    "ssh://host\nname/repo",
    "ssh://host\0name/repo",
    "ssh://host" .. string.char(127) .. "name/repo",
    "ssh://user@@host/repo",
    "ssh://host:22/repo",
    "ssh://[2001:db8::1/repo",
    "ssh://2001:db8::1/repo",
    "ssh://host",
  }) do
    assert_rejected(target)
  end

  local original_jobstart = vim.fn.jobstart
  local starts = 0
  vim.fn.jobstart = function()
    starts = starts + 1
    return 1
  end
  local ok = pcall(nrm.connect, "ssh://-Fattacker/repo")
  vim.fn.jobstart = original_jobstart
  assert_eq(ok, false, "invalid target should fail connect")
  assert_eq(starts, 0, "invalid target should fail before starting the sidecar")
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
