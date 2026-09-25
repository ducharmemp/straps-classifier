-- Turns TypeSafe answers into an action. Pure: no I/O, no registry, no vim
-- state beyond vim.deep_equal. Every threshold decision in the plugin lives
-- here so tests can drive it directly.

local questions = require("straps_classifier.questions")

local M = {}

-- Probability formatted for a reason string: two decimals, no trailing noise.
local function pct(p)
  return string.format("%.2f", p)
end

-- A file edit whose content mentions a protected entry reads as a redefinition
-- to the model however the question is worded. Code knows the tool only edits
-- a file, so the answer is not consulted; a written payload is
-- writes_harmful_content's job.
local SKIP_FOR_CAPABILITY = {
  redefines_protected = { edit = true },
}

local function skipped(id, capability)
  local by_cap = SKIP_FOR_CAPABILITY[id]
  return by_cap ~= nil and capability ~= nil and by_cap[capability] == true
end

--- route(answers, cfg, capability) -> action, reason
--- action is "deny" or "ok". reason is human text naming what decided it.
---
--- Deny when any hazard noul reaches deny_threshold, or the signal
--- runs_script_outside_root reaches it while opaque_action is "deny", or
--- damage reaches damage_deny, or the returned damage legend is not the one
--- we asked with. Missing or malformed answers deny.
function M.route(answers, cfg, capability)
  if type(answers) ~= "table" then
    return "deny", "no answers returned"
  end

  local deny_at = cfg.deny_threshold or 0.85
  local damage_at = cfg.damage_deny or 2.5
  local opaque_action = cfg.opaque_action or "deny"

  for _, q in ipairs(questions.QUESTIONS) do
    local a = answers[q.id]
    if q.type == "noul" then
      if type(a) ~= "table" or type(a.noul) ~= "number" then
        return "deny", ("missing or malformed answer for %q"):format(q.id)
      end
    elseif q.type == "score" then
      if type(a) ~= "table" or type(a.score) ~= "number" then
        return "deny", ("missing or malformed %s answer"):format(q.id)
      end
    end
  end

  -- The legend pins the meaning of the damage number. A legend we did not ask
  -- with means the scale moved under the threshold, so the number is not
  -- comparable and the verdict is not trustworthy.
  local damage = answers.damage
  local legend = damage.legend
  if type(legend) ~= "table" then
    return "deny", "damage answer carried no legend"
  end
  for i, text in ipairs(questions.DAMAGE_LEVELS) do
    if legend[tostring(i - 1)] ~= text then
      return "deny", ("damage legend does not match the questions asked (level %d)"):format(i - 1)
    end
  end

  -- Highest hazard first, so the reason names the strongest signal.
  local top_id, top_p = nil, -1
  for _, id in ipairs(questions.ids("hazard")) do
    if not skipped(id, capability) then
      local p = answers[id].noul
      if p > top_p then
        top_id, top_p = id, p
      end
    end
  end

  if top_p >= deny_at then
    return "deny", ("%s=%s (>= %s)"):format(top_id, pct(top_p), pct(deny_at))
  end

  local opaque = answers.runs_script_outside_root.noul
  local note = ""
  if opaque >= deny_at then
    if opaque_action == "deny" then
      return "deny", ("opaque: runs_script_outside_root=%s (>= %s)"):format(pct(opaque), pct(deny_at))
    end
    note = ("; opaque runs_script_outside_root=%s logged"):format(pct(opaque))
  end

  if damage.score >= damage_at then
    return "deny", ("damage=%s (>= %s)"):format(pct(damage.score), pct(damage_at))
  end

  return "ok", ("highest %s=%s%s"):format(top_id, pct(top_p), note)
end

return M
