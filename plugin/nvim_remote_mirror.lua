if vim.g.loaded_nvim_remote_mirror then
  return
end
vim.g.loaded_nvim_remote_mirror = true

local nrm = require("nvim_remote_mirror")

vim.api.nvim_create_user_command("RemoteConnect", function(opts)
  nrm.connect(opts.args)
end, {
  nargs = "?",
  complete = "file",
})

vim.api.nvim_create_user_command("RemoteDisconnect", function()
  nrm.disconnect()
end, {})

vim.api.nvim_create_user_command("RemoteReconnect", function()
  nrm.reconnect()
end, {})

vim.api.nvim_create_user_command("RemoteOpen", function(opts)
  nrm.open(opts.args, { force = opts.bang })
end, {
  nargs = 1,
  complete = "file",
  bang = true,
})

vim.api.nvim_create_user_command("RemoteScan", function(opts)
  local limit = tonumber(opts.args)
  nrm.scan(limit)
end, {
  nargs = "?",
})

vim.api.nvim_create_user_command("RemoteGrep", function(opts)
  nrm.grep(opts.args)
end, {
  nargs = 1,
})

vim.api.nvim_create_user_command("RemotePrefetch", function(opts)
  local paths = vim.split(opts.args, "%s+", { trimempty = true })
  nrm.prefetch(paths)
end, {
  nargs = "+",
  complete = "file",
})

vim.api.nvim_create_user_command("RemoteMirrorStart", function()
  nrm.start_background_mirror()
end, {})

vim.api.nvim_create_user_command("RemoteMirrorStop", function()
  nrm.stop_background_mirror()
end, {})

vim.api.nvim_create_user_command("RemoteFlush", function()
  nrm.flush_buffer(0)
end, {})

vim.api.nvim_create_user_command("RemoteFlushQueue", function()
  nrm.flush_queue()
end, {})

vim.api.nvim_create_user_command("RemoteValidate", function(opts)
  local path = opts.args ~= "" and opts.args or nil
  nrm.validate(path)
end, {
  nargs = "?",
  complete = "file",
})

vim.api.nvim_create_user_command("RemoteRefresh", function(opts)
  local paths = vim.split(opts.args, "%s+", { trimempty = true })
  nrm.refresh(paths)
end, {
  nargs = "*",
  complete = "file",
})

vim.api.nvim_create_user_command("RemoteStatus", function()
  nrm.status()
end, {})
