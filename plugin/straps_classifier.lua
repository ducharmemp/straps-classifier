-- User commands. No heavy requires at load time; setup() does the installing.

if vim.g.loaded_straps_classifier then
  return
end
vim.g.loaded_straps_classifier = true

vim.api.nvim_create_user_command("StrapsClassifierAudit", function()
  require("straps_classifier").audit()
end, { desc = "straps_classifier: open the classification audit" })

vim.api.nvim_create_user_command("StrapsClassifierStatus", function()
  local lines, level = require("straps_classifier").status_report()
  vim.notify(table.concat(lines, "\n"), level)
end, { desc = "straps_classifier: report install and key status" })
