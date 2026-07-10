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

local function assert_ssh_target(target, expected_root, expected_reconnect)
  local parsed = nrm._test_parse_target(target)
  assert_eq(parsed.remote_root, expected_root)
  local reconnect = nrm._test_reconnect_arg(parsed)
  assert_eq(reconnect, expected_reconnect or target)
  local reparsed = nrm._test_parse_target(reconnect)
  assert_eq(reparsed.ssh, parsed.ssh, "canonical target changed the ssh destination")
  assert_eq(reparsed.remote_root, expected_root, "canonical target changed the remote root")
  assert_eq(nrm._test_reconnect_arg(reparsed), reconnect, "canonical target was not stable")
end

local function main()
  local posix = nrm._test_parse_target("ssh://user@host.example/home/me/repo")
  assert_eq(posix.ssh, "user@host.example")
  assert_eq(posix.remote_root, "/home/me/repo")

  local ipv6 = nrm._test_parse_target("ssh://[2001:db8::1]/repo")
  assert_eq(ipv6.ssh, "[2001:db8::1]")
  assert_eq(ipv6.remote_root, "/repo")

  assert_ssh_target("ssh://host/B:/repos/project", "B:/repos/project")
  assert_ssh_target("ssh://host/b:/", "B:/", "ssh://host/B:/")
  assert_ssh_target("ssh://host/", "/")
  assert_ssh_target("ssh://host/home/me/a%20repo", "/home/me/a repo")
  assert_ssh_target("ssh://host/home/me/a repo", "/home/me/a repo", "ssh://host/home/me/a%20repo")
  assert_ssh_target("ssh://host/repo%2520name", "/repo%20name", "ssh://host/repo%2520name")
  assert_ssh_target("ssh://host/a%23b%3Fc", "/a#b?c", "ssh://host/a%23b%3Fc")
  assert_ssh_target("ssh://host/%E2%82%AC", "/\226\130\172", "ssh://host/%E2%82%AC")
  assert_ssh_target("ssh://host/%42%3a/repos", "B:/repos", "ssh://host/B:/repos")

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
    "ssh://",
    "ssh://host/%",
    "ssh://host/%0",
    "ssh://host/%GG",
    "ssh://host/repo%2",
    "ssh://host/repo%2x",
    "ssh://host/%00repo",
    "ssh://host/%01repo",
    "ssh://host/repo%0Aname",
    "ssh://host/repo%7Fname",
    "ssh://host/%C2%85repo",
    "ssh://host/" .. string.char(0xC2, 0x85) .. "repo",
    "ssh://host/%FFrepo",
    "ssh://host/%C0%80repo",
    "ssh://host/%E0%80%80repo",
    "ssh://host/%ED%A0%80repo",
    "ssh://host/%F4%90%80%80repo",
    "ssh://host/%E2%82repo",
    "ssh://host/repo" .. string.char(0) .. "name",
    "ssh://host/repo\nname",
    "ssh://host/repo" .. string.char(127) .. "name",
    "ssh://host//server/share",
    "ssh://host/%2Fserver/share",
    "ssh://host/%5Cserver/share",
    "ssh://host/B:relative",
    "ssh://host/B:",
    "ssh://host/B%3Arelative",
    "ssh://host/B%3A%5Crepos",
    "ssh://host/B:/repos%5Cproject",
    "ssh://host/B://repos",
    "ssh://host/B:/repo/../other",
    "ssh://host/B:/repo/./other",
    "ssh://host/B:/repo./other",
    "ssh://host/B:/repo%20/other",
    "ssh://host/B:/repo:stream/other",
    "ssh://host/repo//nested",
    "ssh://host/repo/../other",
    "ssh://host/1:/repos",
    "ssh://host/BB:/repos",
    "ssh://host/:/repos",
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
