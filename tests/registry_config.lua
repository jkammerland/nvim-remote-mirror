vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")

local KEY_A = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
local KEY_Z = "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw="

local function assert_eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function registry_options(keys)
  return {
    remote_agent_registry_url = "https://example.test/releases/v{version}/nrm-agent-manifest-v1.json",
    remote_agent_registry_public_keys = keys or { ["release-a"] = KEY_A },
    remote_agent_registry_signature_threshold = 1,
    remote_agent_registry_cache_dir = "/tmp/nrm registry cache",
    remote_agent_registry_cache_max_bytes = 4096,
    remote_agent_registry_timeout_ms = 7000,
  }
end

local function values_after(args, name)
  local values = {}
  for index = 1, #args - 1 do
    if args[index] == name then
      table.insert(values, args[index + 1])
    end
  end
  return values
end

local function assert_rejected(options, expected)
  local ok, err = pcall(nrm.setup, options)
  if ok then
    error("accepted invalid registry configuration " .. vim.inspect(options))
  end
  if expected and not tostring(err):find(expected, 1, true) then
    error("expected error containing " .. expected .. ", got " .. tostring(err))
  end
end

local function main()
  local default_args = nrm._test_sidecar_args({ ssh = "host", remote_root = "/repo" })
  assert_eq(values_after(default_args, "--remote-agent-registry-url"), {})
  assert_eq(nrm._test_registry_policy_fingerprint(nrm.config), "disabled")
  assert_eq(nrm._test_registry_policy_matches({ registry_policy_fingerprint = "disabled" }, "disabled"), true)
  assert_eq(nrm._test_registry_policy_matches({}, "disabled"), false)
  assert_rejected({ remote_agent_registry_public_keys = { ["release-a"] = KEY_A } }, "require")

  nrm.setup(registry_options({ ["release-z"] = KEY_Z, ["release-a"] = KEY_A }))
  local args = nrm._test_sidecar_args({ ssh = "host", remote_root = "/repo" })
  assert_eq(values_after(args, "--remote-agent-registry-url"), {
    "https://example.test/releases/v{version}/nrm-agent-manifest-v1.json",
  })
  assert_eq(values_after(args, "--remote-agent-registry-public-key"), {
    "release-a=" .. KEY_A,
    "release-z=" .. KEY_Z,
  })
  assert_eq(values_after(args, "--remote-agent-registry-signature-threshold"), { "1" })
  assert_eq(values_after(args, "--remote-agent-registry-cache-dir"), { "/tmp/nrm registry cache" })
  assert_eq(values_after(args, "--remote-agent-registry-cache-max-bytes"), { "4096" })
  assert_eq(values_after(args, "--remote-agent-registry-timeout-ms"), { "7000" })
  assert_eq(
    nrm._test_registry_policy_fingerprint(nrm.config),
    "59697bb3ee09d89a1122612967070aa5bb29f3c4f420a6c0d64405bba134abf2"
  )
  assert_eq(
    nrm._test_registry_policy_matches(
      { registry_policy_fingerprint = nrm._test_registry_policy_fingerprint(nrm.config) },
      "59697bb3ee09d89a1122612967070aa5bb29f3c4f420a6c0d64405bba134abf2"
    ),
    true
  )

  local first = nrm._test_socket_path_for("ssh://host/repo", { ssh = "host", remote_root = "/repo" })
  nrm.setup(registry_options({ ["release-a"] = KEY_A, ["release-z"] = KEY_Z }))
  local reordered = nrm._test_socket_path_for("ssh://host/repo", { ssh = "host", remote_root = "/repo" })
  assert_eq(reordered, first, "registry key table order changed socket identity")
  nrm.setup(vim.tbl_extend("force", registry_options(), { remote_agent_registry_timeout_ms = 7001 }))
  local changed = nrm._test_socket_path_for("ssh://host/repo", { ssh = "host", remote_root = "/repo" })
  if changed == first then
    error("registry policy change did not change socket identity")
  end

  nrm.setup({
    remote_agent_registry_url = "file:///tmp/releases/v{version}/nrm-agent-manifest-v1.json",
    remote_agent_registry_public_keys = { ["release-a"] = KEY_A },
    remote_agent_registry_signature_threshold = 1,
  })

  assert_rejected({ remote_agent_registry_url = "https://example.test/no-placeholder.json" }, "exactly one")
  assert_rejected({ remote_agent_registry_url = "https://example.test/{version}/{version}.json" }, "exactly one")
  assert_rejected(
    { remote_agent_registry_url = "https://example.test/{version}/{channel}.json" },
    "unsupported placeholder"
  )
  assert_rejected({ remote_agent_registry_url = "http://example.test/v{version}.json" }, "https://")
  assert_rejected({ remote_agent_registry_url = "https:///v{version}.json" }, "HTTPS host")
  assert_rejected({ remote_agent_registry_url = "file://server/share/v{version}.json" }, "absolute file://")
  assert_rejected({ remote_agent_registry_url = "file:////server/v{version}.json" }, "local absolute")
  assert_rejected({ remote_agent_registry_url = "https://user@example.test/v{version}.json" }, "credentials")
  assert_rejected({ remote_agent_registry_url = "https://example.test/v{version}.json?token=x" }, "queries")
  assert_rejected({ remote_agent_registry_public_keys = { ["bad id"] = KEY_A } }, "key IDs")
  assert_rejected({ remote_agent_registry_public_keys = { ["release-a"] = "AAAA" } }, "32-byte")
  assert_rejected({
    remote_agent_registry_public_keys = { ["release-a"] = KEY_A, ["release-b"] = KEY_A },
  }, "distinct key material")
  assert_rejected({
    remote_agent_registry_url = "https://example.test/v{version}.json",
    remote_agent_registry_public_keys = { ["release-a"] = KEY_A },
    remote_agent_registry_signature_threshold = 2,
  }, "threshold")
  assert_rejected({ remote_agent_registry_cache_max_bytes = 0 }, "positive integer")
  assert_rejected({ remote_agent_registry_timeout_ms = 1.5 }, "positive integer")
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
