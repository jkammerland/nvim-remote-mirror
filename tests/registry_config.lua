vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")

local KEY_A = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
local KEY_Z = "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw="
local WEAK_KEYS = {
  "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "xxdqcD1N2E+6PAt2DRBnDyogU/osOczGTsf9d5KsA3o=",
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA=",
  "JuiVj8KyJ7BFw/SJ8u+Y8NXfrAXTxjM5sTgCiG1T/AU=",
  "7P///////////////////////////////////////38=",
  "JuiVj8KyJ7BFw/SJ8u+Y8NXfrAXTxjM5sTgCiG1T/IU=",
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "xxdqcD1N2E+6PAt2DRBnDyogU/osOczGTsf9d5KsA/o=",
}

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
  assert_rejected({ remote_agent_registry_url = "https://example.test/releases/v{version}/" }, "manifest file")
  assert_rejected({ remote_agent_registry_url = "file:///tmp/releases/v{version}/" }, "manifest file")
  for _, authority in ipairs({
    ":443",
    "example.test:65536",
    "[2606:4700:4700::1111]:65536",
    "bad[host",
    "bad]host",
    [[127.0.0.1\example.test]],
    "%31%32%37.0.0.1",
  }) do
    assert_rejected({ remote_agent_registry_url = "https://" .. authority .. "/v{version}.json" }, "valid HTTPS host")
  end
  assert_rejected({ remote_agent_registry_url = "https://[32.1.2.3::]/v{version}.json" }, "valid IPv6 host")
  for _, host in ipairs({
    "localhost",
    "LOCALHOST.",
    "registry.localhost",
    "localhost..",
    "127.0.0.1",
    "0.1.2.3",
    "10.1.2.3",
    "100.64.0.1",
    "169.254.1.1",
    "172.31.255.255",
    "192.0.0.1",
    "192.0.2.1",
    "192.88.99.1",
    "192.168.1.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "[::1]",
    "[fc00::1]",
    "[fe80::1]",
    "[2001:db8::1]",
  }) do
    assert_rejected({ remote_agent_registry_url = "https://" .. host .. "/v{version}.json" }, "non-global literal host")
  end
  for _, host in ipairs({ "127.1", "2130706433", "0177.0.0.1", "0x7f000001", "0x7f.0.0.1" }) do
    assert_rejected({ remote_agent_registry_url = "https://" .. host .. "/v{version}.json" }, "canonical IPv4")
  end
  nrm.setup(vim.tbl_extend("force", registry_options(), {
    remote_agent_registry_url = "https://8.8.8.8/v{version}.json",
  }))
  nrm.setup(vim.tbl_extend("force", registry_options(), {
    remote_agent_registry_url = "https://[2606:4700:4700::1111]/v{version}.json",
  }))
  assert_rejected({ remote_agent_registry_public_keys = { ["bad id"] = KEY_A } }, "key IDs")
  assert_rejected({ remote_agent_registry_public_keys = { ["release-a"] = "AAAA" } }, "32-byte")
  for index, key in ipairs(WEAK_KEYS) do
    assert_rejected({
      remote_agent_registry_public_keys = { ["weak-" .. tostring(index)] = key },
    }, "weak Ed25519")
  end
  assert_rejected({
    remote_agent_registry_public_keys = { ["release-a"] = KEY_A, ["release-b"] = KEY_A },
  }, "distinct key material")
  local many_keys = {}
  local key_prefix = vim.base64.decode(KEY_A):sub(1, 31)
  for index = 0, 32 do
    many_keys[string.format("release-%02d", index)] = vim.base64.encode(key_prefix .. string.char(index))
  end
  assert_rejected({ remote_agent_registry_public_keys = many_keys }, "at most 32")
  assert_rejected({
    remote_agent_registry_url = "https://example.test/v{version}.json",
    remote_agent_registry_public_keys = { ["release-a"] = KEY_A },
    remote_agent_registry_signature_threshold = 2,
  }, "threshold")
  assert_rejected({ remote_agent_registry_cache_max_bytes = 0 }, "positive integer")
  assert_rejected({ remote_agent_registry_timeout_ms = 1.5 }, "positive integer")
  assert_rejected({ remote_agent_registry_cache_max_bytes = 9007199254740992 }, "maximum safe integer")
  assert_rejected({ remote_agent_registry_timeout_ms = 9007199254740992 }, "maximum safe integer")

  nrm.setup(vim.tbl_extend("force", registry_options(), {
    remote_agent_registry_cache_max_bytes = 9007199254740991,
    remote_agent_registry_timeout_ms = 9007199254740991,
  }))
  local safe_integer_args = nrm._test_sidecar_args({ ssh = "host", remote_root = "/repo" })
  assert_eq(values_after(safe_integer_args, "--remote-agent-registry-cache-max-bytes"), { "9007199254740991" })
  assert_eq(values_after(safe_integer_args, "--remote-agent-registry-timeout-ms"), { "9007199254740991" })
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(err)
  vim.cmd("cquit")
end
vim.cmd("qa")
