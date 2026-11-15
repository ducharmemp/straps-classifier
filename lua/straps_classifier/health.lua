local M = {}

function M.check()
  local health = vim.health
  local plugin = require("straps_classifier")
  local s = plugin.status()

  health.start("straps_classifier: install")
  if not s.setup_ran then
    health.error("setup() has not run; tool calls are NOT classified")
  elseif s.installed then
    health.ok(s.contextual and "contextual core integration installed; legacy classifier chain bypassed" or "guard installed")
  else
    health.error((s.contextual and "contextual core integration not installed: " or "guard not installed: ")
      .. tostring(s.install_error) .. "; tool calls are NOT classified")
  end

  if s.contextual then
    health.start("straps_classifier: contextual assessment")
    health.info("TypeSafe key resolution does not apply to contextual mode")
    if s.contextual.disclosure_approved then
      health.info("provider disclosure approved; installation alone does not establish assessment readiness")
    else
      health.warn("provider disclosure is not approved; contextual assessment unavailable")
    end
    for _, dependency in ipairs(s.contextual.missing or {}) do
      health.warn("unavailable dependency: " .. dependency)
    end
    if s.contextual.unavailable then health.warn("unassessed: " .. s.contextual.unavailable) end
  else
    health.start("straps_classifier: api key")
    health.info("adapter: " .. tostring(s.adapter) .. " (" .. tostring(s.model) .. ")")
    if s.api_key then
      health.ok(s.adapter == "anthropic" and "straps Anthropic provider key resolves" or "fn.typesafe_api_key resolves")
    else
      health.warn("no key; every classified tool call is denied: " .. tostring(s.api_key_error))
    end
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
