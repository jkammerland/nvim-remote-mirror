vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function arg_after(args, name)
  for index = 1, #args - 1 do
    if args[index] == name then
      return args[index + 1]
    end
  end
  return nil
end

local function main()
  nrm.setup({
    agent = "/local/build/nrm-agent",
    remote_agent = "nrm-agent",
  })

  local local_args = nrm._test_sidecar_args({ remote_root = "/repo" })
  assert_eq(arg_after(local_args, "--agent"), "/local/build/nrm-agent")

  local ssh_args = nrm._test_sidecar_args({ ssh = "host", remote_root = "/repo" })
  assert_eq(arg_after(ssh_args, "--agent"), "nrm-agent")
  assert_eq(arg_after(ssh_args, "--local-agent"), "/local/build/nrm-agent")
  assert_eq(arg_after(ssh_args, "--ssh"), "host")

  nrm.setup({
    agent = "/local/build/nrm-agent",
    remote_agent = "/opt/nrm/bin/nrm-agent",
  })
  ssh_args = nrm._test_sidecar_args({ ssh = "host", remote_root = "/repo" })
  assert_eq(arg_after(ssh_args, "--agent"), "/opt/nrm/bin/nrm-agent")
  assert_eq(arg_after(ssh_args, "--local-agent"), "/local/build/nrm-agent")
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
