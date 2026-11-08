local M = {}

function M.check()
  local health = vim.health
  local plugin = require("straps_classifier")
  local s = plugin.status()

  health.start("straps_classifier: install")
  if not s.setup_ran then
    health.error("setup() has not run; tool calls are NOT classified")
  elseif s.installed then
    health.ok("guard installed")
  else
    health.error("guard not installed: " .. tostring(s.install_error) .. "; tool calls are NOT classified")
  end

  health.start("straps_classifier: api key")
  if s.api_key then
    health.ok("fn.typesafe_api_key resolves")
  else
    health.warn("no key; every classified tool call is denied: " .. tostring(s.api_key_error))
  end

  health.start("straps_classifier: audit")
  local total, causes = require("straps_classifier.audit").counts()
  health.info(("allows: %d, denies: %d"):format(total.allow, total.deny))
  local names = vim.tbl_keys(causes)
  table.sort(names)
  for _, cause in ipairs(names) do
    health.info(("failure %s: %d"):format(cause, causes[cause]))
  end
end

return M
