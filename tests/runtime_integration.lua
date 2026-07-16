vim.opt.runtimepath:prepend(vim.fn.getcwd())
vim.g.nvim_remote_mirror_test = true

local nrm = require("nvim_remote_mirror")
local runtime = require("nvim_remote_mirror.runtime")
local workspace = require("nvim_remote_mirror.workspace")
local function assert_eq(actual, expected, message)
  if not vim.deep_equal(actual, expected) then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function assert_contains(text, needle, message)
  if not tostring(text):find(needle, 1, true) then
    error((message or "missing text") .. ": expected " .. vim.inspect(text) .. " to contain " .. vim.inspect(needle))
  end
end

local function assert_not_contains(text, needle, message)
  if tostring(text):find(needle, 1, true) then
    error(
      (message or "unexpected text") .. ": expected " .. vim.inspect(text) .. " not to contain " .. vim.inspect(needle)
    )
  end
end

local function assert_error(value, err, code)
  assert_eq(value, nil, "operation unexpectedly succeeded")
  assert_eq(type(err), "table")
  assert_eq(err.code, code)
  return err
end

local function assert_setup_error(options, needle)
  local ok, err = pcall(nrm.setup, options)
  assert_eq(ok, false, "invalid setup unexpectedly succeeded")
  assert_contains(err, needle)
end

local function fake_client(root, workspace_key)
  return {
    job_id = 1,
    transport = "stdio",
    target_arg = "ssh://build.example.test/B:/repos/runtime-demo",
    hello = {
      workspace_key = workspace_key,
      remote_root = "B:/repos/runtime-demo",
      mirror_root = root .. "/mirror",
      files_root = root .. "/mirror/files",
      remote_host = {
        os = "windows",
        arch = "aarch64",
        shell = "powershell",
        home = "C:\\Users\\runtime-demo",
        local_app_data = "C:\\Users\\runtime-demo\\AppData\\Local",
        path_style = "windows",
        target = "aarch64-pc-windows-msvc",
      },
      capabilities = {
        runtime_ticket_v1 = true,
        runtime_process_v1 = true,
        runtime_pty_v1 = true,
        workspace_watch_v1 = false,
      },
    },
  }
end

local function main()
  workspace._reset_for_test()
  runtime._reset_for_test()

  local root = vim.fn.tempname()
  local sidecar = "/opt/NRM Sidecar/nrm-sidecar"
  local workspace_key = string.rep("a", 24)
  nrm.setup({
    sidecar = sidecar,
    state_dir = root,
    request_timeout_ms = 30000,
    ssh_connect_timeout_seconds = 17,
    remote_agent = "nrm-agent-runtime",
    remote_runtime = {
      enabled = true,
      trust = "prompt",
      detached_ttl_ms = 86400000,
      ticket_create_timeout_ms = 4321,
    },
  })
  nrm.client = fake_client(root, workspace_key)
  nrm.connection_target = nrm.client.target_arg
  nrm.connection_status = "connected"
  nrm.reconnect_generation = 7

  local current = nrm.current_workspace()
  assert_eq(current.remote_host.target, "aarch64-pc-windows-msvc")
  assert_eq(current.capabilities.runtime_process_v1, true)
  assert_eq(current.runtime, {
    enabled = true,
    trust = "prompt",
    ticket = true,
    process = true,
    terminal = true,
    watch = false,
  })

  local detected_remote_host = vim.deepcopy(nrm.client.hello.remote_host)
  local context = assert(nrm.workspace())
  assert_eq(context._remote_host, nil, "workspace context exposed its private remote host hint")
  assert_eq(context.authority.home, nil, "workspace authority exposed private remote home metadata")
  assert_eq(context.authority.label, "ssh://build.example.test")
  local value, err = nrm.workspace(false)
  assert_error(value, err, "invalid_argument")
  nrm.client.hello.remote_host.home = "C:\\Users\\mutated-after-resolve"
  local state_prepare_calls = {}
  local state_prepare_response = { code = 0, stdout = "", stderr = "" }
  local trust_helper_calls = {}
  local trust_helper_response
  local trusted_digests = {}
  local function maybe_state_prepare(argv, stdin, timeout_ms)
    if type(argv) ~= "table" then
      return nil, false
    end
    if argv[2] == "runtime-state-prepare" then
      table.insert(state_prepare_calls, {
        argv = vim.deepcopy(argv),
        stdin = stdin,
        timeout_ms = timeout_ms,
      })
      local response = state_prepare_response
      if type(response) == "function" then
        response = response()
      end
      return vim.deepcopy(response), true
    end
    local action = type(argv[2]) == "string" and argv[2]:match("^runtime%-trust%-(%a+)$") or nil
    if action ~= "check" and action ~= "add" and action ~= "remove" then
      return nil, false
    end
    local call = {
      action = action,
      argv = vim.deepcopy(argv),
      stdin = stdin,
      timeout_ms = timeout_ms,
      digest = argv[6],
    }
    table.insert(trust_helper_calls, call)
    local response = trust_helper_response
    if type(response) == "function" then
      response = response(call)
    end
    if response then
      return vim.deepcopy(response), true
    end
    if action == "add" then
      trusted_digests[call.digest] = true
      return { code = 0, stdout = "", stderr = "" }, true
    elseif action == "remove" then
      trusted_digests[call.digest] = nil
      return { code = 0, stdout = "", stderr = "" }, true
    end
    return {
      code = 0,
      stdout = trusted_digests[call.digest] and "trusted\n" or "untrusted\n",
      stderr = "",
    },
      true
  end
  local ticket_runs = 0
  runtime._set_command_runner(function(argv, stdin, timeout_ms)
    local prepared, is_prepare = maybe_state_prepare(argv, stdin, timeout_ms)
    if is_prepare then
      return prepared
    end
    ticket_runs = ticket_runs + 1
    return { code = 0, stdout = string.rep("0a", 32) .. "\n", stderr = "" }
  end)
  value, err = context:job_spec({ command = { argv = { "true" } } })
  assert_error(value, err, "workspace_untrusted")
  assert_eq(ticket_runs, 0, "untrusted execution created a ticket")
  assert_eq(state_prepare_calls[1], {
    argv = { sidecar, "runtime-state-prepare", "--state-dir", root },
    timeout_ms = 4321,
  })
  assert_not_contains(table.concat(state_prepare_calls[1].argv, "\0"), "build.example.test")

  state_prepare_response = { code = 124, stdout = "", stderr = "" }
  value, err = runtime.is_trusted(context)
  assert_error(value, err, "trust_store_error")
  assert_eq(err.details.reason, "timeout")
  state_prepare_response = { code = 9, stdout = "", stderr = "unsafe helper\nerror\0" }
  value, err = runtime.is_trusted(context)
  assert_error(value, err, "trust_store_error")
  assert_eq(err.details.reason, "helper_failed")
  assert_eq(err.details.helper_stderr, "unsafe helper error ")
  state_prepare_response = { code = 0, stdout = "", stderr = "" }

  local original_confirm = vim.fn.confirm
  local trust_prompts = {}
  vim.fn.confirm = function(message)
    table.insert(trust_prompts, message)
    return 2
  end
  local authorization_error
  context:authorize("terminal", function(auth_err, granted)
    authorization_error = auth_err
    assert_eq(granted, false)
  end)
  assert_eq(authorization_error.code, "workspace_untrusted")
  assert_eq(ticket_runs, 0, "denied authorization created a ticket")
  assert_contains(trust_prompts[1], "Authority: ssh://build.example.test")
  assert_contains(trust_prompts[1], "Identity: " .. context.authority.id)

  for _, authority in ipairs({
    { id = "authority-one", kind = "ssh", label = "ssh://one.example.test" },
    { id = "authority-two", kind = "ssh", label = "ssh://two.example.test" },
  }) do
    runtime.authorize(
      {
        authority = authority,
        roots = { authority = "B:/repos/runtime-demo" },
      },
      "terminal",
      function(_, granted)
        assert_eq(granted, false)
      end
    )
  end
  assert_contains(trust_prompts[2], "Authority: ssh://one.example.test")
  assert_contains(trust_prompts[3], "Authority: ssh://two.example.test")
  assert(trust_prompts[2] ~= trust_prompts[3], "distinct authorities produced indistinguishable trust prompts")
  vim.fn.confirm = original_confirm

  local prepares_before_trust_write = #state_prepare_calls
  assert(runtime.trust_workspace({ context = context, force = true }))
  assert_eq(
    #state_prepare_calls,
    prepares_before_trust_write + 1,
    "trust persistence did not prepare state before its atomic native update"
  )
  assert_eq(runtime.is_trusted(context), true)
  trust_helper_response = function(call)
    if call.action == "remove" then
      return { code = 8, stdout = "", stderr = "native trust update rejected" }
    end
  end
  value, err = runtime.untrust_workspace({ context = context })
  assert_error(value, err, "trust_store_error")
  assert_eq(err.details.reason, "helper_failed")
  trust_helper_response = nil
  assert_eq(runtime.is_trusted(context), true, "failed state preparation modified the trust store")
  local add_call
  for _, call in ipairs(trust_helper_calls) do
    if call.action == "add" then
      add_call = call
    end
  end
  assert(add_call, "workspace trust add helper was not invoked")
  assert_eq(add_call.action, "add")
  assert_eq(#add_call.digest, 64)
  assert(add_call.digest:match("^[0-9a-f]+$"))
  assert_eq(add_call.argv, {
    sidecar,
    "runtime-trust-add",
    "--state-dir",
    root,
    "--digest",
    add_call.digest,
  })
  assert_not_contains(table.concat(add_call.argv, "\0"), "build.example.test", "trust helper leaked authority")
  assert_not_contains(table.concat(add_call.argv, "\0"), "runtime-demo", "trust helper leaked workspace root")

  trust_helper_response = function(call)
    if call.action == "check" then
      return { code = 0, stdout = "maybe\n", stderr = "" }
    end
  end
  value, err = runtime.is_trusted(context)
  assert_error(value, err, "trust_store_error")
  assert_eq(err.details.reason, "invalid_helper_response")
  trust_helper_response = function(call)
    if call.action == "check" then
      return { code = 124, stdout = "", stderr = "" }
    end
  end
  value, err = runtime.is_trusted(context)
  assert_error(value, err, "trust_store_error")
  assert_eq(err.details.reason, "timeout")
  trust_helper_response = nil

  local captured = {}
  local ticket_id = string.rep("1b", 32)
  runtime._set_command_runner(function(argv, stdin, timeout_ms)
    local prepared, is_prepare = maybe_state_prepare(argv, stdin, timeout_ms)
    if is_prepare then
      return prepared
    end
    captured = {
      argv = vim.deepcopy(argv),
      stdin = stdin,
      timeout_ms = timeout_ms,
    }
    return { code = 0, stdout = ticket_id .. "\n", stderr = "" }
  end)
  local bridge = assert(context:job_spec({
    command = { argv = { "printf", "%s", "$(remote); 'quoted'" } },
    cwd = { space = "workspace", path = "src/tools" },
    env = {
      clear = true,
      set = {
        NRM_SECRET = "do-not-leak;$(env)",
        LANG = "C.UTF-8",
      },
      unset = { "PAGER" },
    },
    max_output_bytes = 8192,
    timeout_ms = 9000,
  }))
  assert_eq(captured.argv, { sidecar, "runtime-ticket-create", "--state-dir", root })
  assert_eq(captured.timeout_ms, 4321)
  assert_eq(bridge.argv, { sidecar, "runtime-proxy", "--state-dir", root, "--ticket", ticket_id })
  -- job_spec deliberately exposes no result lifecycle metadata. Its unused
  -- tickets expire after 30 seconds and orphan results after five minutes.
  assert_eq(bridge._result, nil)
  assert_eq(bridge.env, nil)
  assert_not_contains(bridge.command, "remote);", "bridge command leaked remote argv")
  assert_not_contains(bridge.command, "do-not-leak", "bridge command leaked remote environment")
  assert_not_contains(bridge.command, "build.example.test", "bridge command leaked remote target")
  assert_not_contains(table.concat(bridge.argv, "\0"), "remote);", "bridge argv leaked remote argv")
  assert_not_contains(table.concat(bridge.argv, "\0"), "do-not-leak", "bridge argv leaked remote environment")
  assert_not_contains(table.concat(bridge.argv, "\0"), "build.example.test", "bridge argv leaked remote target")

  local ticket = vim.json.decode(captured.stdin)
  assert_eq(ticket.schema_version, 1)
  assert_eq(ticket.workspace_key, workspace_key)
  assert_eq(ticket.remote_root, "B:/repos/runtime-demo")
  assert_eq(ticket.ssh, "build.example.test")
  assert_eq(ticket.agent, "nrm-agent-runtime")
  assert_eq(ticket.ssh_connect_timeout_seconds, 17)
  assert_eq(ticket.request_timeout_ms, 30000)
  assert_eq(ticket.capability, "ProcessPipeV1")
  assert_eq(ticket.remote_host, detected_remote_host)
  assert_eq(ticket.spec.argv, { "printf", "%s", "$(remote); 'quoted'" })
  assert_eq(ticket.spec.cwd, { WorkspaceRelative = "src/tools" })
  assert_eq(ticket.spec.env, {
    clear = true,
    set = {
      { name = "LANG", value = "C.UTF-8" },
      { name = "NRM_SECRET", value = "do-not-leak;$(env)" },
    },
    unset = { "PAGER" },
  })
  assert_eq(ticket.spec.persistence, "Attached")
  assert_eq(ticket.spec.timeout_ms, 9000)
  assert_eq(ticket.spec.max_output_bytes, 8192)
  assert_eq(ticket.spec.terminal_size, nil)
  assert_eq(ticket._bridge, nil)
  assert_not_contains(bridge.command, detected_remote_host.home, "bridge command leaked remote host home")
  assert_not_contains(
    table.concat(bridge.argv, "\0"),
    detected_remote_host.local_app_data,
    "bridge argv leaked remote host app-data"
  )
  nrm.client.hello.remote_host = vim.deepcopy(detected_remote_host)

  assert(context:job_spec({
    command = { shell = "default" },
    stdio = "pty",
    initial_size = { cols = 132, rows = 40, pixel_width = 1200, pixel_height = 800 },
  }))
  ticket = vim.json.decode(captured.stdin)
  assert_eq(ticket.capability, "ProcessPtyV1")
  assert_eq(ticket.spec.argv, { "powershell.exe", "-NoLogo" })
  assert_eq(ticket.spec.cwd, "WorkspaceRoot")
  assert_eq(ticket.spec.terminal_size, {
    columns = 132,
    rows = 40,
    pixel_width = 1200,
    pixel_height = 800,
  })
  assert_eq(ticket.spec.max_output_bytes, nil)

  local posix_snapshot = {
    authority = {
      path_style = "posix",
      shell = "/usr/bin/zsh",
    },
    capabilities = { runtime_ticket_v1 = true },
    roots = { authority = "/srv/runtime-demo" },
    _workspace_key = workspace_key,
    _runtime_config = {
      agent = "nrm-agent",
      request_timeout_ms = 30000,
      sidecar = sidecar,
      ssh_connect_timeout_seconds = 17,
      state_dir = root,
    },
  }
  local default_shell_request = {
    command = { shell = "default" },
    cwd = { path = "" },
    env = { clear = false, set = {}, unset = {} },
    persistence = "attached",
    stdio = "pty",
  }
  local valid_runtime_config = posix_snapshot._runtime_config
  for _, invalid_config in ipairs({ false, "corrupt" }) do
    posix_snapshot._runtime_config = invalid_config
    value, err = runtime._ticket_for_test(posix_snapshot, default_shell_request)
    assert_error(value, err, "invalid_provider_state")
  end
  posix_snapshot._runtime_config = valid_runtime_config
  ticket = assert(runtime._ticket_for_test(posix_snapshot, default_shell_request))
  assert_eq(ticket.spec.argv, { "/usr/bin/zsh" })
  assert_eq(ticket.remote_host, nil, "incomplete remote host hint was serialized")
  posix_snapshot._ssh = "posix.example.test"
  posix_snapshot._remote_host = {
    os = "linux",
    arch = "x86_64",
    shell = "/usr/bin/zsh",
    home = "/home/runtime-demo",
    local_app_data = vim.NIL,
    path_style = "posix",
    target = "x86_64-unknown-linux-musl",
  }
  ticket = assert(runtime._ticket_for_test(posix_snapshot, default_shell_request))
  assert_eq(ticket.remote_host, posix_snapshot._remote_host)
  posix_snapshot._remote_host.target = "aarch64-unknown-linux-musl"
  ticket = assert(runtime._ticket_for_test(posix_snapshot, default_shell_request))
  assert_eq(ticket.remote_host, nil, "stale remote host target hint was serialized")
  posix_snapshot._remote_host.target = "x86_64-unknown-linux-musl"
  posix_snapshot._remote_host.unexpected = true
  ticket = assert(runtime._ticket_for_test(posix_snapshot, default_shell_request))
  assert_eq(ticket.remote_host, nil, "malformed remote host hint was serialized")
  posix_snapshot._remote_host = nil
  posix_snapshot._ssh = nil
  for _, invalid_shell in ipairs({ "zsh", "/bin/../untrusted", "/bin/./untrusted", "/bin/zsh\0extra" }) do
    posix_snapshot.authority.shell = invalid_shell
    ticket = assert(runtime._ticket_for_test(posix_snapshot, default_shell_request))
    assert_eq(ticket.spec.argv, { "/bin/sh" }, "invalid detected POSIX shell did not fail closed")
  end

  local runner_calls = 0
  runtime._set_command_runner(function(argv, stdin, timeout_ms)
    local prepared, is_prepare = maybe_state_prepare(argv, stdin, timeout_ms)
    if is_prepare then
      return prepared
    end
    runner_calls = runner_calls + 1
    return { code = 0, stdout = ticket_id, stderr = "" }
  end)
  nrm.reconnect_generation = 8
  value, err = context:job_spec({ command = { argv = { "true" } } })
  assert_error(value, err, "stale_context")
  assert_eq(runner_calls, 0, "stale context created a ticket")
  nrm.reconnect_generation = 7

  runtime._set_command_runner(function(argv, stdin, timeout_ms)
    local prepared, is_prepare = maybe_state_prepare(argv, stdin, timeout_ms)
    if is_prepare then
      return prepared
    end
    return { code = 124, stdout = "", stderr = "" }
  end)
  value, err = context:job_spec({ command = { argv = { "true" } } })
  assert_error(value, err, "ticket_create_timeout")
  runtime._set_command_runner(function(argv, stdin, timeout_ms)
    local prepared, is_prepare = maybe_state_prepare(argv, stdin, timeout_ms)
    if is_prepare then
      return prepared
    end
    return { code = 2, stdout = "", stderr = "failure\nsecret control\0data" }
  end)
  value, err = context:job_spec({ command = { argv = { "true" } } })
  assert_error(value, err, "ticket_create_failed")
  runtime._set_command_runner(function(argv, stdin, timeout_ms)
    local prepared, is_prepare = maybe_state_prepare(argv, stdin, timeout_ms)
    if is_prepare then
      return prepared
    end
    return { code = 0, stdout = "../../not-a-ticket\n", stderr = "" }
  end)
  value, err = context:job_spec({ command = { argv = { "true" } } })
  assert_error(value, err, "ticket_invalid_response")

  local started = {}
  local calls = {}
  local result_reads = {}
  local signal_calls = {}
  local valid_runtime_result = {
    schema_version = 1,
    exit_code = 23,
    kind = "process_exit",
    error_code = vim.NIL,
    message = vim.NIL,
    output_truncated = false,
    bridge_stderr = "bridge diagnostic only",
  }
  local result_response = {
    code = 0,
    stdout = vim.json.encode(valid_runtime_result),
    stderr = "",
  }
  local signal_response = { code = 0, stdout = "", stderr = "" }
  runtime._set_command_runner(function(argv, stdin, timeout_ms)
    local prepared, is_prepare = maybe_state_prepare(argv, stdin, timeout_ms)
    if is_prepare then
      return prepared
    end
    if argv[2] == "runtime-result-read" then
      table.insert(result_reads, {
        argv = vim.deepcopy(argv),
        stdin = stdin,
        timeout_ms = timeout_ms,
      })
      return vim.deepcopy(result_response)
    end
    if argv[2] == "runtime-signal" then
      table.insert(signal_calls, {
        argv = vim.deepcopy(argv),
        stdin = stdin,
        timeout_ms = timeout_ms,
      })
      return vim.deepcopy(signal_response)
    end
    captured = { argv = argv, stdin = stdin, timeout_ms = timeout_ms }
    return { code = 0, stdout = ticket_id .. "\n", stderr = "" }
  end)
  local originals = {
    jobstart = vim.fn.jobstart,
    termopen = vim.fn.termopen,
    chansend = vim.fn.chansend,
    chanclose = vim.fn.chanclose,
    jobstop = vim.fn.jobstop,
    jobresize = vim.fn.jobresize,
  }
  local jobstop_result = 1
  local termopen_switch_window
  local termopen_close_window = false
  local termopen_refocus_replacement
  local termopen_refocus_armed = false
  local refocus_autocmd = vim.api.nvim_create_autocmd("WinEnter", {
    callback = function()
      if
        termopen_refocus_armed
        and started.pty
        and vim.api.nvim_win_is_valid(started.pty.window)
        and vim.api.nvim_get_current_win() == started.pty.window
      then
        termopen_refocus_armed = false
        vim.api.nvim_win_set_buf(started.pty.window, termopen_refocus_replacement)
      end
    end,
  })
  vim.fn.jobstart = function(argv, options)
    started.pipe = { argv = vim.deepcopy(argv), options = options }
    return 41
  end
  vim.fn.termopen = function(argv, options)
    started.pty = {
      argv = vim.deepcopy(argv),
      options = options,
      window = vim.api.nvim_get_current_win(),
      buffer = vim.api.nvim_get_current_buf(),
    }
    termopen_refocus_armed = termopen_refocus_replacement ~= nil
    if termopen_close_window then
      vim.api.nvim_win_close(started.pty.window, true)
    elseif termopen_switch_window then
      vim.api.nvim_set_current_win(termopen_switch_window)
    end
    return 42
  end
  vim.fn.chansend = function(job, data)
    table.insert(calls, { "send", job, data })
    return #data
  end
  vim.fn.chanclose = function(job, stream)
    table.insert(calls, { "close", job, stream })
    return 1
  end
  vim.fn.jobstop = function(job)
    table.insert(calls, { "stop", job })
    return jobstop_result
  end
  vim.fn.jobresize = function(job, cols, rows)
    table.insert(calls, { "resize", job, cols, rows })
    return 1
  end

  local stream_events = { stdout = {}, stderr = {} }
  local pipe_exit
  local handle = assert(context:spawn({ command = { argv = { "printf", "pipe-value" } } }, {
    on_stdout = function(...)
      table.insert(stream_events.stdout, { ... })
    end,
    on_stderr = function(...)
      table.insert(stream_events.stderr, { ... })
    end,
    on_exit = function(...)
      pipe_exit = { ... }
    end,
  }))
  assert_eq(started.pipe.argv, { sidecar, "runtime-proxy", "--state-dir", root, "--ticket", ticket_id })
  assert(handle:write("raw\0bytes"))
  assert(handle:close_stdin())
  assert(handle:signal("terminate"))
  assert(handle:kill())
  assert_eq(calls[1], { "send", 41, "raw\0bytes" })
  assert_eq(calls[2], { "close", 41, "stdin" })
  assert_eq(#calls, 2, "successful remote kill unexpectedly stopped the local bridge")
  assert_eq(signal_calls[1], {
    argv = {
      sidecar,
      "runtime-signal",
      "--state-dir",
      root,
      "--ticket",
      ticket_id,
      "--signal",
      "terminate",
    },
    timeout_ms = 4321,
  })
  assert_eq(signal_calls[2].argv, {
    sidecar,
    "runtime-signal",
    "--state-dir",
    root,
    "--ticket",
    ticket_id,
    "--signal",
    "kill",
  })
  for _, call in ipairs(signal_calls) do
    local rendered = table.concat(call.argv, "\0")
    assert_not_contains(rendered, "pipe-value", "signal helper leaked remote argv")
    assert_not_contains(rendered, "do-not-leak", "signal helper leaked remote environment")
    assert_not_contains(rendered, "build.example.test", "signal helper leaked remote target")
  end
  started.pipe.options.on_stdout(41, { "raw child stdout", "" }, "stdout")
  started.pipe.options.on_stderr(41, { "raw child stderr", "" }, "stderr")
  started.pipe.options.on_exit(41, 23, "exit")
  assert_eq(result_reads[1], {
    argv = { sidecar, "runtime-result-read", "--state-dir", root, "--ticket", ticket_id },
    timeout_ms = 4321,
  })
  assert_eq(stream_events.stdout, { { 41, { "raw child stdout", "" }, "stdout" } })
  assert_eq(stream_events.stderr, { { 41, { "raw child stderr", "" }, "stderr" } })
  assert_eq({ pipe_exit[1], pipe_exit[2], pipe_exit[3] }, { 41, 23, "exit" })
  assert_eq(pipe_exit[4], valid_runtime_result)
  assert_eq(#stream_events.stdout, 1, "structured result contaminated stdout")
  assert_eq(#stream_events.stderr, 1, "structured result contaminated stderr")

  vim.cmd("enew!")
  local pty_exit
  handle = assert(context:open_pty({ command = { shell = "default" } }, {
    on_exit = function(...)
      pty_exit = { ... }
    end,
  }))
  assert_eq(started.pty.argv, { sidecar, "runtime-proxy", "--state-dir", root, "--ticket", ticket_id })
  assert(handle:resize({ cols = 90, rows = 30 }))
  assert(handle:signal("interrupt"))
  assert_eq(calls[3], { "resize", 42, 90, 30 })
  assert_eq(#calls, 3, "PTY interrupt was injected into stdin")
  assert_eq(signal_calls[3].argv, {
    sidecar,
    "runtime-signal",
    "--state-dir",
    root,
    "--ticket",
    ticket_id,
    "--signal",
    "interrupt",
  })

  local unknown_result = vim.deepcopy(valid_runtime_result)
  unknown_result.unexpected = true
  result_response = { code = 0, stdout = vim.json.encode(unknown_result), stderr = "" }
  started.pty.options.on_exit(42, 125, "exit")
  assert_eq(pty_exit[4].code, "result_unavailable")
  assert_eq(pty_exit[4].details.reason, "unknown_field")
  assert_eq(result_reads[2].argv, {
    sidecar,
    "runtime-result-read",
    "--state-dir",
    root,
    "--ticket",
    ticket_id,
  })

  signal_response = { code = 124, stdout = "", stderr = "" }
  local timeout_handle = assert(context:spawn({ command = { argv = { "sleep", "30" } } }))
  value, err = timeout_handle:signal("hangup")
  assert_error(value, err, "signal_failed")
  assert_eq(err.details.reason, "timeout")
  local stops_before_fallback = #calls
  value, err = timeout_handle:kill()
  assert_error(value, err, "signal_failed")
  assert_eq(err.details.reason, "timeout")
  assert_eq(err.details.fallback, "jobstop")
  assert_eq(#calls, stops_before_fallback + 1)
  assert_eq(calls[#calls], { "stop", 41 })
  assert_eq(signal_calls[#signal_calls].argv, {
    sidecar,
    "runtime-signal",
    "--state-dir",
    root,
    "--ticket",
    ticket_id,
    "--signal",
    "kill",
  })
  result_response = { code = 0, stdout = vim.json.encode(valid_runtime_result), stderr = "" }
  started.pipe.options.on_exit(41, 125, "exit")

  signal_response = { code = 7, stdout = "", stderr = "helper failure\nwith controls\0" }
  local failed_handle = assert(context:spawn({ command = { argv = { "sleep", "30" } } }))
  value, err = failed_handle:signal("terminate")
  assert_error(value, err, "signal_failed")
  assert_eq(err.details.reason, "helper_failed")
  assert_eq(err.details.helper_stderr, "helper failure with controls ")
  local signals_before_invalid = #signal_calls
  value, err = failed_handle:signal("stop")
  assert_error(value, err, "invalid_argument")
  assert_eq(#signal_calls, signals_before_invalid, "invalid signal reached the helper")

  jobstop_result = 0
  value, err = failed_handle:kill()
  assert_error(value, err, "signal_failed")
  assert_eq(err.details.reason, "fallback_failed")
  assert_eq(err.details.helper_reason, "helper_failed")
  jobstop_result = 1
  signal_response = { code = 0, stdout = "", stderr = "" }
  assert(failed_handle:kill())
  result_response = { code = 0, stdout = vim.json.encode(valid_runtime_result), stderr = "" }
  started.pipe.options.on_exit(41, 125, "exit")
  for _, call in ipairs(signal_calls) do
    local rendered = table.concat(call.argv, "\0")
    assert_not_contains(rendered, "sleep", "signal helper leaked a later remote argv")
    assert_not_contains(rendered, "NRM_SECRET", "signal helper leaked remote environment metadata")
    assert_not_contains(rendered, detected_remote_host.home, "signal helper leaked remote host metadata")
  end

  local function exit_with_result(response, handlers)
    result_response = response
    local final_result
    local configured_handlers = handlers
      or {
        on_exit = function(_, _, _, runtime_result)
          final_result = runtime_result
        end,
      }
    assert(context:spawn({ command = { argv = { "true" } } }, configured_handlers))
    started.pipe.options.on_exit(41, 125, "exit")
    return final_result
  end

  local unavailable = exit_with_result({ code = 0, stdout = "{", stderr = "" })
  assert_eq(unavailable.code, "result_unavailable")
  assert_eq(unavailable.details.reason, "malformed")

  unavailable = exit_with_result({
    code = 0,
    stdout = '{"schema_version":1,"schema_version":1,"exit_code":0,"kind":"process_exit",'
      .. '"error_code":null,"message":null,"output_truncated":false,"bridge_stderr":null}',
    stderr = "",
  })
  assert_eq(unavailable.code, "result_unavailable")
  assert_eq(unavailable.details.reason, "duplicate_field")

  unavailable = exit_with_result({ code = 0, stdout = string.rep("x", 32 * 1024 + 1), stderr = "" })
  assert_eq(unavailable.code, "result_unavailable")
  assert_eq(unavailable.details.reason, "oversized")

  unavailable = exit_with_result({ code = 9, stdout = "", stderr = "reader failure\nwith controls\0" })
  assert_eq(unavailable.code, "result_unavailable")
  assert_eq(unavailable.details.reason, "read_failed")
  assert_eq(unavailable.details.reader_stderr, "reader failure with controls ")

  local reads_before_no_handler = #result_reads
  exit_with_result({ code = 0, stdout = vim.json.encode(valid_runtime_result), stderr = "" }, {})
  assert_eq(#result_reads, reads_before_no_handler + 1, "on_exit without a handler did not consume its result")

  local legacy_exit
  exit_with_result({ code = 0, stdout = vim.json.encode(valid_runtime_result), stderr = "" }, {
    on_exit = function(id, code, event)
      legacy_exit = { id, code, event }
    end,
  })
  assert_eq(legacy_exit, { 41, 125, "exit" }, "three-argument on_exit handler compatibility")

  local async_exit
  assert(context:spawn({ command = { argv = { "true" } } }, {
    on_exit = function(_, _, _, runtime_result)
      async_exit = runtime_result
    end,
  }))
  local async_job_exit = started.pipe.options.on_exit
  local original_system = vim.system
  local async_helper
  vim.system = function(argv, options, on_exit)
    async_helper = { argv = vim.deepcopy(argv), options = vim.deepcopy(options), on_exit = on_exit }
    return {}
  end
  runtime._set_command_runner(nil)
  async_job_exit(41, 0, "exit")
  assert_eq(async_exit, nil, "production on_exit blocked for its result helper")
  assert_eq(async_helper.argv, { sidecar, "runtime-result-read", "--state-dir", root, "--ticket", ticket_id })
  assert_eq(async_helper.options.text, true)
  assert_eq(async_helper.options.timeout, 4321)
  async_helper.on_exit({ code = 0, stdout = vim.json.encode(valid_runtime_result), stderr = "" })
  assert(
    vim.wait(1000, function()
      return async_exit ~= nil
    end),
    "asynchronous runtime result callback did not complete"
  )
  assert_eq(async_exit, valid_runtime_result)
  vim.system = original_system

  runner_calls = 0
  runtime._set_command_runner(function(argv, stdin, timeout_ms)
    local prepared, is_prepare = maybe_state_prepare(argv, stdin, timeout_ms)
    if is_prepare then
      return prepared
    end
    runner_calls = runner_calls + 1
    return { code = 0, stdout = ticket_id, stderr = "" }
  end)
  value, err = context:open_pty({ command = { shell = "default" }, persistence = "detached" })
  assert_error(value, err, "persistence_unavailable")
  assert_eq(runner_calls, 0, "unsupported detached terminal created a ticket")

  local terminal_cleanup_signals = 0
  runtime._set_command_runner(function(argv, stdin, timeout_ms)
    local prepared, is_prepare = maybe_state_prepare(argv, stdin, timeout_ms)
    if is_prepare then
      return prepared
    end
    if argv[2] == "runtime-signal" then
      terminal_cleanup_signals = terminal_cleanup_signals + 1
      return { code = 0, stdout = "", stderr = "" }
    end
    captured = { argv = argv, stdin = stdin }
    return { code = 0, stdout = ticket_id, stderr = "" }
  end)
  local window_before_terminal = vim.api.nvim_get_current_win()
  termopen_switch_window = window_before_terminal
  value, err = nrm.open_terminal(false)
  assert_eq(value, nil, "false terminal options unexpectedly succeeded")
  assert_contains(err, "remote terminal options must be a table")
  value, err = nrm.open_terminal({ command = { "printf", "false-persistence" }, persistence = false })
  assert_error(value, err, "invalid_process_spec")
  local terminal_handle = assert(nrm.open_terminal({ command = { "printf", "%s", "$(terminal-metachar)" } }))
  termopen_switch_window = nil
  assert_eq(vim.api.nvim_get_current_win(), started.pty.window, "TermOpen window switch stole terminal focus")
  assert_eq(vim.api.nvim_get_current_buf(), started.pty.buffer)
  ticket = vim.json.decode(captured.stdin)
  assert_eq(ticket.spec.argv, { "printf", "%s", "$(terminal-metachar)" })
  assert_not_contains(table.concat(started.pty.argv, "\0"), "terminal-metachar")
  assert(terminal_handle:kill())
  vim.cmd("close!")

  local signal_count_before_invalid_window = terminal_cleanup_signals
  termopen_close_window = true
  value, err = nrm.open_terminal({ command = { "printf", "closed-window" } })
  termopen_close_window = false
  assert_eq(value, nil, "terminal with a deleted TermOpen window unexpectedly succeeded")
  assert_contains(err, "terminal window or buffer was changed during TermOpen")
  assert_eq(
    terminal_cleanup_signals,
    signal_count_before_invalid_window + 1,
    "failed terminal did not kill its remote process"
  )

  local replacement_buffer = vim.api.nvim_create_buf(false, true)
  local signal_count_before_replaced_buffer = terminal_cleanup_signals
  termopen_switch_window = window_before_terminal
  termopen_refocus_replacement = replacement_buffer
  value, err = nrm.open_terminal({ command = { "printf", "replaced-buffer" } })
  termopen_switch_window = nil
  termopen_refocus_replacement = nil
  termopen_refocus_armed = false
  assert_eq(value, nil, "terminal with a replaced WinEnter buffer unexpectedly succeeded")
  assert_contains(err, "terminal window or buffer was changed while restoring terminal focus")
  assert_eq(
    terminal_cleanup_signals,
    signal_count_before_replaced_buffer + 1,
    "terminal with a replaced WinEnter buffer did not kill its remote process"
  )
  if vim.api.nvim_buf_is_valid(replacement_buffer) then
    vim.api.nvim_buf_delete(replacement_buffer, { force = true })
  end

  vim.api.nvim_del_autocmd(refocus_autocmd)
  for name, original in pairs(originals) do
    vim.fn[name] = original
  end

  vim.g.loaded_nvim_remote_mirror = nil
  vim.cmd("runtime plugin/nvim_remote_mirror.lua")
  assert_eq(vim.fn.exists(":RemoteTrustWorkspace"), 2)
  assert_eq(vim.fn.exists(":RemoteUntrustWorkspace"), 2)
  assert_eq(vim.fn.exists(":RemoteTerminal"), 2)
  local terminal_options
  local original_open_terminal = nrm.open_terminal
  nrm.open_terminal = function(options)
    terminal_options = options
    return {}
  end
  vim.cmd("RemoteTerminal printf %s literal-metachar")
  assert_eq(terminal_options.command, { "printf", "%s", "literal-metachar" })
  assert_eq(terminal_options.persistence, "attached")
  vim.cmd("RemoteTerminal!")
  assert_eq(terminal_options.command, {})
  assert_eq(terminal_options.persistence, "detached")
  nrm.open_terminal = original_open_terminal

  local trust_options
  local untrust_called = false
  local original_trust_workspace = nrm.trust_workspace
  local original_untrust_workspace = nrm.untrust_workspace
  nrm.trust_workspace = function(options)
    trust_options = options
    return true
  end
  nrm.untrust_workspace = function()
    untrust_called = true
    return true
  end
  vim.cmd("RemoteTrustWorkspace!")
  assert_eq(trust_options.force, true)
  vim.cmd("RemoteTrustWorkspace")
  assert_eq(trust_options.force, false)
  vim.cmd("RemoteUntrustWorkspace")
  assert_eq(untrust_called, true)
  nrm.trust_workspace = original_trust_workspace
  nrm.untrust_workspace = original_untrust_workspace

  assert(runtime.untrust_workspace({ context = context }))
  assert_eq(runtime.is_trusted(context), false)

  assert_setup_error({ remote_runtime = { trust = "unsafe" } }, "remote_runtime.trust")
  assert_setup_error({ remote_runtime = { ticket_create_timeout_ms = 0 } }, "ticket_create_timeout_ms")
  assert_setup_error({ remote_runtime = { detached_ttl_ms = 0 } }, "detached_ttl_ms")
  assert_setup_error({ remote_runtime = { unknown = true } }, "unknown option")

  runtime._reset_for_test()
  workspace._reset_for_test()
  vim.fn.delete(root, "rf")
end

local ok, err = xpcall(main, debug.traceback)
if not ok then
  vim.api.nvim_err_writeln(tostring(err))
  vim.cmd("cquit")
end
vim.cmd("qa")
