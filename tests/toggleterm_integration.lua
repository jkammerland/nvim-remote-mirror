vim.opt.runtimepath:prepend(vim.fn.getcwd())

local integration = require("nvim_remote_mirror.integrations.toggleterm")

local function assert_eq(actual, expected, message)
  if actual ~= expected then
    error((message or "assertion failed") .. ": expected " .. vim.inspect(expected) .. ", got " .. vim.inspect(actual))
  end
end

local function assert_error(value, err, code)
  assert_eq(value, nil, "operation unexpectedly succeeded")
  assert_eq(type(err), "table")
  assert_eq(err.code, code)
  return err
end

local pending = nil
local prepare_mode = "inline"
local prepare_count = 0
local ticket_count = 0
local terminal_count = 0
local notifications = {}
local current_tab = 7
local current_buf = 11
local resolve_calls = 0
local last_resolve_query = "unset"

local prepared = {}
function prepared:job_spec()
  ticket_count = ticket_count + 1
  return {
    argv = { "/usr/bin/nrm-sidecar", "runtime-proxy", "--ticket", tostring(ticket_count) },
    command = "'/usr/bin/nrm-sidecar' 'runtime-proxy' '--ticket' '" .. tostring(ticket_count) .. "'",
    cwd = "/tmp/mirror",
    env = { TEST_LOCAL_ENV = "1" },
    clear_env = true,
    input = { newline = "\r" },
    authority = { kind = "ssh", path_style = "windows" },
  }
end

local context = {
  provider = "nrm",
  workspace_id = "workspace-a",
  epoch = 4,
  authority = { id = "authority-a", kind = "ssh", path_style = "windows" },
}
function context:is_current()
  return true
end
function context:prepare(_, callback)
  prepare_count = prepare_count + 1
  if prepare_mode == "inline" then
    callback(nil, prepared)
  else
    pending = callback
  end
  return true
end

local function new_fake_terminal(opts)
  terminal_count = terminal_count + 1
  local term = {
    opts = opts,
    job_id = terminal_count + 100,
    bufnr = terminal_count + 200,
    open_state = false,
    open_count = 0,
    close_count = 0,
    focus_count = 0,
    shutdown_count = 0,
  }
  function term:open(_, direction)
    self.direction = direction
    self.open_state = true
    self.open_count = self.open_count + 1
  end
  function term:close()
    self.open_state = false
    self.close_count = self.close_count + 1
  end
  function term:focus()
    self.focus_count = self.focus_count + 1
  end
  function term:is_open()
    return self.open_state
  end
  function term:shutdown()
    self.open_state = false
    self.shutdown_count = self.shutdown_count + 1
  end
  return term
end

local controller = integration._test.new_controller({
  resolve = function(query)
    resolve_calls = resolve_calls + 1
    last_resolve_query = query
    return context
  end,
  terminal_new = new_fake_terminal,
  managed_terminal_id = function()
    return -41 - terminal_count
  end,
  is_alive = function(term)
    return term.dead ~= true
  end,
  current_tab = function()
    return current_tab
  end,
  current_buf = function()
    return current_buf
  end,
  notify = function(message, level)
    table.insert(notifications, { message = message, level = level })
  end,
  stamp = function(term, scope_id, key)
    term.stamped_scope = scope_id
    term.stamped_key = key
  end,
})

local invalid_value, invalid_err = controller:toggle(false)
assert_error(invalid_value, invalid_err, "invalid_argument")
invalid_value, invalid_err = controller:toggle({ key = false })
assert_error(invalid_value, invalid_err, "invalid_argument")
invalid_value, invalid_err = controller:toggle({ key = "visible", hidden = false })
assert_error(invalid_value, invalid_err, "invalid_argument")

local callbacks = 0
assert(controller:toggle({ key = "shell", direction = "float" }, function(err, term)
  callbacks = callbacks + 1
  assert_eq(err, nil)
  assert_eq(type(term), "table")
end))
assert_eq(callbacks, 1)
assert_eq(prepare_count, 1)
assert_eq(ticket_count, 1)
assert_eq(terminal_count, 1)

local first = assert(controller:lookup({ scope_id = integration.scope_id(context), key = "shell" }))
assert_eq(first.term.opts.cmd:find("runtime-proxy", 1, true) ~= nil, true)
assert_eq(first.term.opts.dir, "/tmp/mirror")
assert_eq(first.term.opts.newline_chr, "\r")
assert_eq(first.term.opts.env.TEST_LOCAL_ENV, "1")
assert_eq(first.term.opts.clear_env, true)
assert_eq(first.term.opts.hidden, true)
assert_eq(first.term.opts.id, -41)
assert_eq(first.term.open_count, 1)
assert_eq(first.term.stamped_scope, integration.scope_id(context))
assert_eq(resolve_calls, 1)
assert_eq(last_resolve_query, nil, "default resolution must retain the broker's implicit tab/buffer guard")

-- Broker terminals stay out of ordinary non-hidden listings. Hiding alone is
-- not numeric isolation; the reserved ID range and command guard are tested
-- separately below.
local upstream_visible = {}
for _, record in pairs(controller.records[integration.scope_id(context)]) do
  if record.term and record.term.opts.hidden ~= true then
    table.insert(upstream_visible, record.term)
  end
end
assert_eq(#upstream_visible, 0, "raw ToggleTerm could adopt a broker-owned remote terminal")

-- Hiding and reopening preserves the live PTY and does not mint a new ticket.
assert(controller:toggle({ key = "shell", binding = first.binding, direction = "horizontal" }))
assert_eq(first.term.close_count, 1)
assert(controller:toggle({ key = "shell", binding = first.binding, direction = "horizontal" }))
assert_eq(first.term.open_count, 2)
assert_eq(first.term.direction, "horizontal")
assert_eq(prepare_count, 1)
assert_eq(ticket_count, 1)

-- Process exit removes the consumed ticket; the next open prepares afresh.
first.term.dead = true
first.term.opts.on_exit(first.term, 0, "exit")
assert_eq(controller:lookup({ scope_id = integration.scope_id(context), key = "shell" }), nil)
assert(controller:toggle({ key = "shell" }))
assert_eq(prepare_count, 2)
assert_eq(ticket_count, 2)
assert_eq(terminal_count, 2)
local replacement = assert(controller:lookup({ scope_id = integration.scope_id(context), key = "shell" }))
first.term.opts.on_exit(first.term, 0, "late-exit")
assert_eq(
  controller:lookup({ scope_id = integration.scope_id(context), key = "shell" }),
  replacement,
  "a stale exit callback removed the replacement terminal"
)

-- Repeated actions while readiness is pending coalesce to one preparation.
prepare_mode = "delayed"
assert(controller:toggle({ key = "slot:1001", direction = "float" }))
assert(controller:toggle({ key = "slot:1001", direction = "vertical" }))
assert_eq(prepare_count, 3)
assert_eq(ticket_count, 2)
pending(nil, prepared)
assert_eq(ticket_count, 3)
assert_eq(terminal_count, 3)
local slot = assert(controller:lookup({ scope_id = integration.scope_id(context), key = "slot:1001" }))
assert_eq(slot.term.direction, "vertical")

-- A stale/failing preparation never starts or falls back to a local terminal.
assert(controller:toggle({ key = "stale" }))
assert_eq(prepare_count, 4)
pending({ code = "stale_context", message = "authority changed" })
assert_eq(ticket_count, 3)
assert_eq(terminal_count, 3)
assert_eq(controller:lookup({ scope_id = integration.scope_id(context), key = "stale" }), nil)
assert_eq(#notifications > 0, true)

-- Shutdown is scope/key-specific and never affects a neighboring terminal.
local slot_term = slot.term
assert(controller:shutdown({ binding = slot.binding, key = "slot:1001" }))
assert_eq(slot_term.shutdown_count, 1)
assert_eq(controller:lookup({ scope_id = integration.scope_id(context), key = "slot:1001" }), nil)
assert_eq(controller:lookup({ scope_id = integration.scope_id(context), key = "shell" }) ~= nil, true)

-- Cancelling a pending slot prevents a late readiness callback from minting a ticket.
local tickets_before_cancel = ticket_count
assert(controller:toggle({ key = "cancel-pending" }))
local cancelled_prepare = pending
local cancelled_binding = assert(controller:resolve())
assert(controller:shutdown({ binding = cancelled_binding, key = "cancel-pending" }))
cancelled_prepare(nil, prepared)
assert_eq(ticket_count, tickets_before_cancel)
assert_eq(controller:lookup({ scope_id = cancelled_binding.scope_id, key = "cancel-pending" }), nil)

-- Creating the UI after a ticket was minted may fail, but must burn the ticket
-- and never retry through a local terminal.
prepare_mode = "inline"
local factory_controller = integration._test.new_controller({
  resolve = function()
    return context
  end,
  terminal_new = function()
    error("factory unavailable")
  end,
  current_tab = function()
    return current_tab
  end,
  current_buf = function()
    return current_buf
  end,
  notify = function() end,
})
local factory_callback = 0
local tickets_before_factory = ticket_count
assert(factory_controller:toggle({ key = "factory-failure" }, function(err, term)
  factory_callback = factory_callback + 1
  assert_eq(err.code, "terminal_create_failed")
  assert_eq(term, nil)
end))
assert_eq(factory_callback, 1)
assert_eq(ticket_count, tickets_before_factory + 1)
assert_eq(factory_controller:lookup({ scope_id = integration.scope_id(context), key = "factory-failure" }), nil)

-- A delayed preparation may not open its PTY in whichever tab happens to be
-- current when readiness completes, including for an explicit query.
prepare_mode = "delayed"
current_tab = 7
local tab_race_callback = 0
local tickets_before_tab_race = ticket_count
assert(controller:toggle({ key = "tab-race", query = { authority = "remote" } }, function(err, term)
  tab_race_callback = tab_race_callback + 1
  assert_eq(err.code, "stale_context")
  assert_eq(term, nil)
end))
local tab_race_prepare = pending
current_tab = 8
tab_race_prepare(nil, prepared)
assert_eq(tab_race_callback, 1)
assert_eq(ticket_count, tickets_before_tab_race)
assert_eq(controller:lookup({ scope_id = integration.scope_id(context), key = "tab-race" }), nil)
current_tab = 7
prepare_mode = "inline"

-- Bindings are authority-scoped values; a mutated scope cannot alias another
-- authority's terminal registry.
local bad_binding = {
  context = context,
  scope_id = "runtime-mismatched",
}
local bad_value, bad_err = controller:toggle({ key = "bad-binding", binding = bad_binding })
assert_error(bad_value, bad_err, "invalid_argument")

-- ToggleTerm can swallow opener failures. Verify post-open liveness and clean
-- up both silent failures and exceptions after a partial start.
local silent_shutdowns = 0
local silent_controller = integration._test.new_controller({
  resolve = function()
    return context
  end,
  terminal_new = function()
    local term = { job_id = 0, bufnr = 0 }
    function term:open() end
    function term:is_open()
      return false
    end
    function term:shutdown()
      silent_shutdowns = silent_shutdowns + 1
    end
    return term
  end,
  is_alive = function()
    return false
  end,
  current_tab = function()
    return current_tab
  end,
  notify = function() end,
  stamp = function() end,
})
local silent_callback = 0
assert(silent_controller:toggle({ key = "silent-open" }, function(err, term)
  silent_callback = silent_callback + 1
  assert_eq(err.code, "terminal_open_failed")
  assert_eq(term, nil)
end))
assert_eq(silent_callback, 1)
assert_eq(silent_shutdowns, 1)

local partial_shutdowns = 0
local partial_jobstops = 0
local partial_controller = integration._test.new_controller({
  resolve = function()
    return context
  end,
  terminal_new = function()
    local term = { job_id = 321, bufnr = 654 }
    function term:open()
      error("opener failed after spawn")
    end
    function term:is_open()
      return false
    end
    function term:shutdown()
      partial_shutdowns = partial_shutdowns + 1
      error("shutdown failed after partial start")
    end
    return term
  end,
  is_alive = function()
    return true
  end,
  jobstop = function(job_id)
    assert_eq(job_id, 321)
    partial_jobstops = partial_jobstops + 1
    return 1
  end,
  current_tab = function()
    return current_tab
  end,
  notify = function() end,
  stamp = function() end,
})
local partial_callback = 0
assert(partial_controller:toggle({ key = "partial-open" }, function(err, term)
  partial_callback = partial_callback + 1
  assert_eq(err.code, "terminal_open_failed")
  assert_eq(term, nil)
end))
assert_eq(partial_callback, 1)
assert_eq(partial_shutdowns, 1)
assert_eq(partial_jobstops, 1, "a failed ToggleTerm shutdown did not stop the live bridge job")
assert_eq(
  partial_controller:lookup({ scope_id = integration.scope_id(context), key = "partial-open" }),
  nil,
  "a successfully stopped partial bridge remained registered"
)

local reopen_term
local reopen_shutdowns = 0
local reopen_controller = integration._test.new_controller({
  resolve = function()
    return context
  end,
  terminal_new = function(opts)
    reopen_term = new_fake_terminal(opts)
    local shutdown = reopen_term.shutdown
    function reopen_term:shutdown()
      reopen_shutdowns = reopen_shutdowns + 1
      shutdown(self)
    end
    return reopen_term
  end,
  is_alive = function()
    return true
  end,
  current_tab = function()
    return current_tab
  end,
  current_buf = function()
    return current_buf
  end,
  notify = function() end,
  stamp = function() end,
})
assert(reopen_controller:toggle({ key = "reopen-failure" }))
local reopen_binding = assert(reopen_controller:resolve())
assert(reopen_controller:toggle({ key = "reopen-failure", binding = reopen_binding }))
function reopen_term:open()
  self.open_state = false
end
local reopen_callback = 0
assert(reopen_controller:toggle({ key = "reopen-failure", binding = reopen_binding }, function(err, term)
  reopen_callback = reopen_callback + 1
  assert_eq(err.code, "terminal_open_failed")
  assert_eq(term, nil)
end))
assert_eq(reopen_callback, 1)
assert_eq(reopen_shutdowns, 1)

-- A bridge whose shutdown and jobstop both failed remains quarantined. Its
-- stamped current buffer must not bypass cleanup_failed handling and make it
-- focusable/toggleable again.
local quarantined_term
local quarantined_close_count = 0
local quarantine_shutdown_succeeds = false
local quarantine_controller = integration._test.new_controller({
  resolve = function()
    return context
  end,
  terminal_new = function()
    quarantined_term = { job_id = 777, bufnr = 778 }
    function quarantined_term:open()
      error("partial open")
    end
    function quarantined_term:is_open()
      return true
    end
    function quarantined_term:close()
      quarantined_close_count = quarantined_close_count + 1
    end
    function quarantined_term:shutdown()
      if not quarantine_shutdown_succeeds then
        error("shutdown still blocked")
      end
    end
    return quarantined_term
  end,
  is_alive = function()
    return true
  end,
  jobstop = function()
    return 0
  end,
  current_tab = function()
    return current_tab
  end,
  current_buf = function()
    return quarantined_term
  end,
  notify = function() end,
  stamp = function(term, scope_id, key)
    term.__nrm_workspace_runtime = { scope_id = scope_id, key = key }
  end,
})
assert(quarantine_controller:toggle({ key = "cleanup-bypass" }))
local quarantine_binding = assert(quarantine_controller:resolve())
local quarantine_record = assert(quarantine_controller:lookup(quarantined_term))
assert_eq(quarantine_record.state, "cleanup_failed")
local quarantine_value, quarantine_err = quarantine_controller:toggle({ key = "cleanup-bypass" })
assert_error(quarantine_value, quarantine_err, "terminal_cleanup_failed")
assert_eq(quarantined_close_count, 0, "cleanup-failed bridge was toggled through its stamped current buffer")
quarantine_shutdown_succeeds = true
assert(quarantine_controller:shutdown({ binding = quarantine_binding, key = "cleanup-bypass" }))

local shutdown_term
local shutdown_controller = integration._test.new_controller({
  resolve = function()
    return context
  end,
  terminal_new = function(opts)
    shutdown_term = new_fake_terminal(opts)
    return shutdown_term
  end,
  is_alive = function()
    return true
  end,
  current_tab = function()
    return current_tab
  end,
  notify = function() end,
  stamp = function() end,
})
assert(shutdown_controller:toggle({ key = "shutdown-retry" }))
local shutdown_binding = assert(shutdown_controller:resolve())
local shutdown_record = assert(shutdown_controller:lookup({
  scope_id = shutdown_binding.scope_id,
  key = "shutdown-retry",
}))
function shutdown_term:shutdown()
  error("sharing violation")
end
local shutdown_value, shutdown_err = shutdown_controller:shutdown({
  binding = shutdown_binding,
  key = "shutdown-retry",
})
assert_error(shutdown_value, shutdown_err, "terminal_shutdown_failed")
assert_eq(
  shutdown_controller:lookup({ scope_id = shutdown_binding.scope_id, key = "shutdown-retry" }),
  shutdown_record,
  "failed shutdown lost the live terminal record"
)
function shutdown_term:shutdown()
  self.open_state = false
end
assert(shutdown_controller:shutdown({ binding = shutdown_binding, key = "shutdown-retry" }))
assert_eq(shutdown_controller:lookup({ scope_id = shutdown_binding.scope_id, key = "shutdown-retry" }), nil)

-- A stale/offline authority may still hide an already visible bridge, but it
-- must never reopen that hidden PTY. The rejected reopen also disposes the
-- consumed bridge so a later reconnect can prepare a fresh ticket.
local running_current = true
local running_context = vim.deepcopy(context)
function running_context:is_current()
  if running_current then
    return true
  end
  return false, { code = "stale_context", message = "workspace went offline" }
end
function running_context:prepare(_, callback)
  callback(nil, prepared)
  return true
end
local running_term
local running_controller = integration._test.new_controller({
  resolve = function()
    return running_context
  end,
  terminal_new = function(opts)
    running_term = new_fake_terminal(opts)
    return running_term
  end,
  is_alive = function()
    return true
  end,
  current_tab = function()
    return current_tab
  end,
  current_buf = function()
    return current_buf
  end,
  notify = function() end,
  stamp = function() end,
})
assert(running_controller:toggle({ key = "offline-reopen" }))
local running_binding = assert(running_controller:resolve())
running_current = false
assert(running_controller:toggle({ key = "offline-reopen", binding = running_binding }))
assert_eq(running_term.close_count, 1, "stale visible bridge could not be hidden")
local running_callback = 0
assert(running_controller:toggle({ key = "offline-reopen", binding = running_binding }, function(err, term)
  running_callback = running_callback + 1
  assert_eq(err.code, "stale_context")
  assert_eq(term, nil)
end))
assert_eq(running_callback, 1)
assert_eq(running_term.open_count, 1, "offline ToggleTerm bridge was reopened")
assert_eq(running_term.shutdown_count, 1, "rejected offline bridge was not disposed")
assert_eq(running_controller:lookup({ scope_id = running_binding.scope_id, key = "offline-reopen" }), nil)

-- Reserved managed IDs above the Ex count range keep counted commands
-- collision-free. The narrow raw command guard preserves upstream counted
-- behavior and filters broker windows only from the uncounted smart-toggle scan.
local guarded_command
local command_creates = 0
local counted_toggle
local raw_open_count = 0
local raw_close_count = 0
local local_windows_open = false
local managed_window = {}
local raw_term = {}
function raw_term:open(size, direction)
  self.size = size
  self.direction = direction
  raw_open_count = raw_open_count + 1
end
local command_guard = integration._test.new_local_command_guard({
  command_exists = function()
    return true
  end,
  is_initialized = function()
    return true
  end,
  create_command = function(callback)
    command_creates = command_creates + 1
    guarded_command = callback
  end,
  parse = function()
    return { size = nil, dir = nil, direction = "float", name = nil }
  end,
  toggle_counted = function(...)
    counted_toggle = { ... }
  end,
  find_open_windows = function(is_managed)
    assert_eq(is_managed(managed_window), true)
    return local_windows_open, local_windows_open and { { term_id = 3 } } or {}
  end,
  close_terminal_view = function(windows)
    assert_eq(windows[1].term_id, 3)
    raw_close_count = raw_close_count + 1
  end,
  open_terminal_view = function()
    return false
  end,
  get_toggled_id = function()
    return nil
  end,
  get_or_create = function()
    return raw_term
  end,
  is_managed = function(value)
    return value == managed_window
  end,
})
local missing_command_guard = integration._test.new_local_command_guard({
  command_exists = function()
    return false
  end,
})
local missing_guard_value, missing_guard_err = missing_command_guard:install()
assert_error(missing_guard_value, missing_guard_err, "toggleterm_not_initialized")
local lazy_stub_replaced = false
local lazy_stub_guard = integration._test.new_local_command_guard({
  command_exists = function()
    return true
  end,
  is_initialized = function()
    return false
  end,
  create_command = function()
    lazy_stub_replaced = true
  end,
})
local lazy_stub_value, lazy_stub_err = lazy_stub_guard:install()
assert_error(lazy_stub_value, lazy_stub_err, "toggleterm_not_initialized")
assert_eq(lazy_stub_replaced, false, "the adapter replaced ToggleTerm's lazy-loading command stub")
assert(command_guard:install())
assert(command_guard:install())
assert_eq(command_creates, 1)
guarded_command({ args = "", count = 1 })
assert_eq(counted_toggle[1], 1)
assert_eq(counted_toggle[4], "float")
guarded_command({ args = "", count = 0 })
assert_eq(raw_open_count, 1)
assert_eq(raw_close_count, 0)
local_windows_open = true
guarded_command({ args = "", count = 0 })
assert_eq(raw_open_count, 1)
assert_eq(raw_close_count, 1)

-- The production allocator stays above Neovim's Ex count range and skips
-- occupied managed IDs. High sorted IDs do not consume the ordinary 1..n
-- sequence used by ToggleTerm's first-gap allocator.
local saved_terminal_module = package.loaded["toggleterm.terminal"]
local managed_ids = { [2147483648] = true }
package.loaded["toggleterm.terminal"] = {
  get = function(id)
    return managed_ids[id] and {} or nil
  end,
}
local managed_id = integration._test.default_managed_terminal_id()
assert_eq(managed_id, 2147483649)
managed_ids[managed_id] = true
local sorted_ids = { 1, 2, 3, 2147483648, managed_id }
local ordinary_next = 1
for index, id in ipairs(sorted_ids) do
  if index ~= id then
    ordinary_next = index
    break
  end
end
assert_eq(ordinary_next, 4, "managed IDs disturbed ToggleTerm's ordinary allocator")
package.loaded["toggleterm.terminal"] = saved_terminal_module

-- Managed opens temporarily suppress ToggleTerm's global autochdir so the
-- broker-validated cwd remains authoritative, then restore it before user
-- on_open callbacks run and on every failure path.
local saved_config_module = package.loaded["toggleterm.config"]
local toggleterm_config = { autochdir = true }
package.loaded["toggleterm.config"] = {
  get = function(key)
    if key ~= nil then
      return toggleterm_config[key]
    end
    return toggleterm_config
  end,
}
local saw_managed_open = false
local saw_restored_on_open = false
local literal_base = vim.fn.tempname()
local literal_root = literal_base .. "-$HOME"
local authoritative_cwd = vim.fs.joinpath(literal_root, "foo*", "literal workspace")
local wildcard_sibling = vim.fs.joinpath(literal_root, "fooX", "literal workspace")
assert_eq(vim.fn.mkdir(authoritative_cwd, "p"), 1)
assert_eq(vim.fn.mkdir(wildcard_sibling, "p"), 1)
local autochdir_term = {
  on_open = function()
    saw_restored_on_open = toggleterm_config.autochdir == true
  end,
}
function autochdir_term:open()
  saw_managed_open = toggleterm_config.autochdir == false
  self.dir = vim.fn.expand(vim.fn.expand(self.dir))
  assert_eq(self.dir, authoritative_cwd)
  self:on_open()
end
assert_eq(integration._test.default_open_terminal(autochdir_term, nil, "float", authoritative_cwd), nil)
assert_eq(saw_managed_open, true, "managed open did not suppress ToggleTerm autochdir")
assert_eq(saw_restored_on_open, true, "managed open exposed temporary config to on_open")
assert_eq(toggleterm_config.autochdir, true, "managed open did not restore ToggleTerm autochdir")
autochdir_term.dir = "/tmp/wrong-after-first-open"
autochdir_term.bufnr = vim.api.nvim_create_buf(false, true)
function autochdir_term:open()
  self.dir = vim.fn.expand(self.dir)
  assert_eq(self.dir, authoritative_cwd)
  self:on_open()
end
integration._test.default_open_terminal(autochdir_term, nil, "float", authoritative_cwd)
assert_eq(autochdir_term.dir, authoritative_cwd, "reopen did not reset the authoritative cwd")
local failing_autochdir_term = {}
function failing_autochdir_term:open()
  assert_eq(toggleterm_config.autochdir, false)
  error("open failure")
end
local autochdir_open_ok = pcall(integration._test.default_open_terminal, failing_autochdir_term)
assert_eq(autochdir_open_ok, false)
assert_eq(toggleterm_config.autochdir, true, "failed managed open leaked ToggleTerm config")
package.loaded["toggleterm.config"] = saved_config_module
assert_eq(vim.fn.delete(literal_root, "rf"), 0)

-- Broker contexts are opaque immutable proxies and cannot be deep-copied.
-- Passing a resolved binding must retain the proxy by reference.
local runtime = require("nvim_remote_mirror.workspace_runtime")
runtime._reset_for_test()
local actual_context = assert(runtime.resolve({ authority = "local" }))
local actual_binding = {
  context = actual_context,
  scope_id = assert(integration.scope_id(actual_context)),
  provider = actual_context.provider,
  workspace_id = actual_context.workspace_id,
  authority_id = actual_context.authority.id,
}
local proxy_controller = integration._test.new_controller({
  terminal_new = new_fake_terminal,
  is_alive = function()
    return true
  end,
  current_tab = function()
    return vim.api.nvim_get_current_tabpage()
  end,
  current_buf = function()
    return vim.api.nvim_get_current_buf()
  end,
  notify = function() end,
  stamp = function() end,
})
assert(proxy_controller:toggle({ key = "proxy-binding", binding = actual_binding }))
assert_eq(
  proxy_controller:lookup({ scope_id = actual_binding.scope_id, key = "proxy-binding" }).binding.context,
  actual_context
)
runtime._reset_for_test()

print("toggleterm integration tests: ok")
