-- User commands. No heavy requires at load time; setup() does the installing.

if vim.g.loaded_straps_classifier then
  return
end
vim.g.loaded_straps_classifier = true

vim.api.nvim_create_user_command("StrapsClassifierAudit", function()
  require("straps_classifier").audit()
end, { desc = "straps_classifier: open the classification audit" })

vim.api.nvim_create_user_command("StrapsClassifierStatus", function()
  local s = require("straps_classifier").status()
  local lines = {
    "installed: " .. tostring(s.installed),
    "api key:   " .. (s.api_key and "resolves" or "MISSING — every tool call is denied"),
  }
  if s.install_error then
    lines[#lines + 1] = "error:     " .. s.install_error
  end
  vim.notify(table.concat(lines, "\n"))
end, { desc = "straps_classifier: report install and key status" })
