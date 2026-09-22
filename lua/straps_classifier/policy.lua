-- Turns TypeSafe answers into an action. Pure: no I/O, no registry, no vim
-- state beyond vim.deep_equal. Every threshold decision in the plugin lives
-- here so tests can drive it directly.

local questions = require("straps_classifier.questions")

local M = {}

-- Probability formatted for a reason string: two decimals, no trailing noise.
local function pct(p)
  return string.format("%.2f", p)
end

--- route(answers, cfg) -> action, reason
--- action is "deny" or "ok". reason is human text naming what decided it.
---
--- Deny when any hazard reaches deny_threshold, or damage reaches damage_deny,
--- or the returned damage legend is not the one we asked with. A deny whose
--- deciding answer carries confidence below min_confidence is downgraded to ok:
--- the classifier speaks only when it is sure, because there is no prompt left
--- to fall back to (the operator already approved).
function M.route(answers, cfg)
  if type(answers) ~= "table" then
    return "deny", "no answers returned"
  end

  local deny_at = cfg.deny_threshold or 0.85
  local damage_at = cfg.damage_deny or 2.5
  local min_conf = cfg.min_confidence or 0.5

  for _, id in ipairs(questions.HAZARDS) do
    local a = answers[id]
    if type(a) ~= "table" or type(a.noul) ~= "number" then
      return "deny", ("missing or malformed answer for %q"):format(id)
    end
  end

  local damage = answers.damage
  if type(damage) ~= "table" or type(damage.score) ~= "number" then
    return "deny", "missing or malformed damage answer"
  end

  -- The legend pins the meaning of the damage number. A legend we did not ask
  -- with means the scale moved under the threshold, so the number is not
  -- comparable and the verdict is not trustworthy.
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
  for _, id in ipairs(questions.HAZARDS) do
    local p = answers[id].noul
    if p > top_p then
      top_id, top_p = id, p
    end
  end

  if top_p >= deny_at then
    return "deny", ("%s=%s (>= %s)"):format(top_id, pct(top_p), pct(deny_at))
  end

  if damage.score >= damage_at then
    local conf = tonumber(damage.confidence)
    if conf and conf < min_conf then
      return "ok", ("damage=%s but confidence %s below %s"):format(
        pct(damage.score), pct(conf), pct(min_conf))
    end
    return "deny", ("damage=%s (>= %s)"):format(pct(damage.score), pct(damage_at))
  end

  return "ok", ("highest %s=%s"):format(top_id, pct(top_p))
end

return M
