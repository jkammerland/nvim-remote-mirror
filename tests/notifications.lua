vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function fake_client()
  return {
    stdout_tail = "",
    pending = {},
    hello = {
      workspace_key = "workspace",
      remote_status = "unchecked",
      remote_checked = false,
      remote_available = false,
    },
  }
end

local function json_line(value)
  return vim.json.encode(value)
end

local function main()
  local client = fake_client()
  nrm.client = client
  local callback_result = nil
  client.pending[7] = {
    timer = nil,
    callback = function(err, result)
      if err then
        error(err)
      end
      callback_result = result
    end,
  }

  nrm._test_handle_stdout(client, {
    json_line({
      method = "workspace/remote_health",
      params = {
        workspace_key = "workspace",
        remote_status = "unavailable",
        remote_checked = true,
        remote_available = false,
        remote_error = "ssh connect failed",
        retry_after_ms = 1500,
        registry_health = {
          state = "error",
          source = "registry",
          manifest_url = "https://registry.example.test/<redacted>",
          error_code = "insufficient_signatures",
          error = "signed registry retrieval failed (insufficient_signatures)",
        },
      },
    }),
    json_line({
      id = 7,
      ok = true,
      result = {
        value = 42,
      },
    }),
    "",
  })

  assert_eq(client.hello.remote_status, "unavailable")
  assert_eq(client.hello.remote_checked, true)
  assert_eq(client.hello.remote_available, false)
  assert_eq(client.hello.remote_error, "ssh connect failed")
  assert_eq(client.hello.retry_after_ms, 1500)
  assert_eq(client.hello.registry_health.state, "error")
  assert_eq(client.hello.registry_health.error_code, "insufficient_signatures")
  assert_eq(nrm.connection_state().registry_health.error_code, "insufficient_signatures")
  assert_eq(callback_result.value, 42)
  assert_eq(client.pending[7], nil)

  nrm._test_handle_stdout(client, {
    json_line({
      method = "workspace/remote_health",
      params = {
        workspace_key = "workspace",
        remote_status = "connected",
        remote_checked = true,
        remote_available = true,
        registry_health = {
          state = "error",
          source = "registry",
          error_code = "network_timeout",
          error = "signed registry retrieval failed (network_timeout)",
        },
      },
    }),
    "",
  })
  assert_eq(client.hello.remote_status, "connected")
  assert_eq(client.hello.remote_available, true)
  assert_eq(client.hello.registry_health.state, "error")
  assert_eq(client.hello.registry_health.error_code, "network_timeout")
  nrm.client = nil
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
