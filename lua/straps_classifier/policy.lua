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

M.ASK_CUTOFFS = {
  viable = 0.6,
  disfavored = 0.6,
  steer_confidence = 0.6,
  asymmetric_detail = 0.7,
  decoy_present = 0.7,
  fairness = 2.0,
  marked_recommended = 0.7,
  deciding_factor = 0.5,
  unstated_steer = 0.75,
}

local DEFAULT_MARK = M.ASK_CUTOFFS.marked_recommended

M.DO_NOT_ASK = { permission_seeking = true, already_answered = true }

local REWORK = " Ask again with the reworked question."

--- One cutoff per command-battery noul (the hazards and the signal), from
--- cfg.cutoffs by id, else deny_threshold.
function M.cutoffs(cfg)
  local deny_at = cfg.deny_threshold or 0.85
  local over = type(cfg.cutoffs) == "table" and cfg.cutoffs or {}
  local cut = {}
  for _, id in ipairs(questions.ids()) do
    cut[id] = tonumber(over[id]) or deny_at
  end
  return cut, deny_at
end

--- Every ask cutoff a config may set, with its effective default: the code
--- verdict cutoffs above, plus one per fixed hazard, which defaults to the
--- ask deny threshold.
function M.ask_cutoffs(cfg)
  local deny_at = cfg.ask_deny_threshold or cfg.deny_threshold or 0.85
  local over = type(cfg.ask_cutoffs) == "table" and cfg.ask_cutoffs or {}
  local cut = {}
  for k, v in pairs(M.ASK_CUTOFFS) do
    cut[k] = tonumber(over[k]) or v
  end
  for _, id in ipairs(questions.ids("hazard", "ask")) do
    cut[id] = tonumber(over[id]) or deny_at
  end
  return cut, deny_at
end

local function unit(x)
  return type(x) == "number" and x >= 0 and x <= 1
end

local function short(label)
  label = tostring(label)
  if #label > 60 then
    label = label:sub(1, 57) .. "..."
  end
  return ("%q"):format(label)
end

local function malformed_signal(q, a)
  if type(a) ~= "table" then
    return true
  end
  if q.type == "noul" then
    return not unit(a.noul)
  elseif q.type == "choice" then
    return type(a.choice) ~= "string" or q.criteria[a.choice] == nil or not unit(a.confidence)
  elseif q.type == "score" then
    if type(a.score) ~= "number" or not (a.score >= 0 and a.score <= #q.criteria - 1)
      or type(a.legend) ~= "table" then
      return true
    end
    for i, text in ipairs(q.criteria) do
      if a.legend[tostring(i - 1)] ~= text then
        return true
      end
    end
    return false
  end
  return true
end

local function malformed_signals(answers, n)
  for _, q in ipairs(questions.questions_for("ask", n)) do
    if q.role == "signal" and malformed_signal(q, answers[q.id]) then
      return q.id
    end
  end
  return nil
end

local function favored_option(answers, labels, cut)
  local steer = answers.steer
  local favored = tonumber(steer.choice)
  if not favored or not labels[favored] or steer.confidence < cut.steer_confidence then
    return nil
  end
  return favored
end

local function hobsons(answers, labels, cut)
  if cut.viable > 1 then
    return nil
  end
  local real, fake = {}, {}
  for i = 1, #labels do
    local p = answers["viable_" .. i].noul
    if p >= cut.viable then
      real[#real + 1] = i
    else
      fake[#fake + 1] = ("%d %s (viable=%s)"):format(i, short(labels[i]), pct(p))
    end
  end
  if #real > 1 then
    return nil
  end
  local described = " If one of those options is a real approach described badly, describe it"
    .. " as a competent engineer would build it instead."
  if not real[1] then
    return ("Hobson's choice (0 of %d options viable): none of the options is a real choice"
      .. " (%s). Propose two or more genuinely different approaches a reasonable person"
      .. " could pick, or ask without options.%s" .. REWORK)
      :format(#labels, table.concat(fake, ", "), described)
  end
  local keep = ("option %d %s"):format(real[1], short(labels[real[1]]))
  return ("Hobson's choice (1 of %d options viable): only %s is a real choice; options %s are"
    .. " not real alternatives. Either propose two or more genuinely different approaches"
    .. " a reasonable person could pick, or drop the options and present %s as a single"
    .. " recommendation with its deciding factor.%s" .. REWORK)
    :format(#labels, keep, table.concat(fake, ", "), keep, described)
end

local function unsupported(answers, cut)
  local marked = answers.marked_recommended.noul
  local deciding = answers.states_deciding_factor.noul
  if cut.deciding_factor > 1 or marked < cut.marked_recommended or deciding >= cut.deciding_factor then
    return nil
  end
  return ("unsupported recommendation (marked_recommended=%s, states_deciding_factor=%s):"
    .. " the option you marked recommended has no stated reason tied to the request or the"
    .. " code; an effort or time estimate does not count. State the deciding factor that"
    .. " separates it from the other options, or remove the mark." .. REWORK)
    :format(pct(marked), pct(deciding))
end

local function stacked(answers, labels, cut)
  local favored = favored_option(answers, labels, cut)
  if not favored then
    return nil
  end
  local steer = answers.steer
  local fired = {}
  if answers.asymmetric_detail.noul >= cut.asymmetric_detail then
    fired[#fired + 1] = "asymmetric_detail=" .. pct(answers.asymmetric_detail.noul)
  end
  if answers.decoy_present.noul >= cut.decoy_present then
    fired[#fired + 1] = "decoy_present=" .. pct(answers.decoy_present.noul)
  end
  if answers.fairness.score >= cut.fairness then
    fired[#fired + 1] = "fairness=" .. pct(answers.fairness.score)
  end
  if #fired == 0 then
    return nil
  end
  local losers, names = {}, {}
  for j = 1, #labels do
    local d = answers["disfavored_" .. j].noul
    if j ~= favored and d >= cut.disfavored then
      losers[#losers + 1] = ("%d %s (disfavored=%s)"):format(j, short(labels[j]), pct(d))
      names[#names + 1] = tostring(j)
    end
  end
  local fix = " Give every option both its benefits and its drawbacks at comparable detail"
  if #losers > 0 then
    fix = (" Option %s is described only to lose (%s): give option %s its benefits, and drop"
      .. " any step or cost the approach does not need. Give every option comparable detail")
      :format(table.concat(names, " and "), table.concat(losers, ", "), table.concat(names, " and "))
  end
  return ("stacked deck (steer=option %d at %s; %s): the options are real alternatives, but"
    .. " the framing is rigged toward option %d %s.%s, remove any option that exists only"
    .. " to make another look better, and keep a recommendation only with its deciding"
    .. " factor." .. REWORK)
    :format(favored, pct(steer.confidence), table.concat(fired, ", "), favored, short(labels[favored]), fix)
end

local function unstated(answers, labels, cut)
  if cut.unstated_steer > 1 then
    return nil
  end
  local steer = answers.steer
  local favored = tonumber(steer.choice)
  if not favored or not labels[favored] or steer.confidence < cut.unstated_steer then
    return nil
  end
  local mark_at = cut.marked_recommended <= 1 and cut.marked_recommended or DEFAULT_MARK
  local marked = answers.marked_recommended.noul
  if marked >= mark_at then
    return nil
  end
  return ("unstated recommendation (steer=option %d at %s, marked_recommended=%s): the options"
    .. " push toward option %d %s without saying so. Either mark it recommended and state the"
    .. " deciding factor that separates it from the others, or give every option its benefits"
    .. " and its costs at comparable detail." .. REWORK)
    :format(favored, pct(steer.confidence), pct(marked), favored, short(labels[favored]))
end

local function strongest(answers, ids, pick)
  local top_id, top_p = nil, -1
  for _, id in ipairs(ids) do
    if pick(id) and answers[id].noul > top_p then
      top_id, top_p = id, answers[id].noul
    end
  end
  return top_id, top_p
end

local function over_cutoff(answers, ids, cut, pick)
  local top_id, top_margin = nil, nil
  for _, id in ipairs(ids) do
    if pick(id) then
      local margin = answers[id].noul - cut[id]
      if margin >= 0 and (top_margin == nil or margin > top_margin) then
        top_id, top_margin = id, margin
      end
    end
  end
  return top_id
end

local function route_ask(answers, cfg, labels)
  labels = labels or {}
  local n = #labels
  local cut, deny_at = M.ask_cutoffs(cfg)
  local hazards = questions.ids("hazard", "ask")
  for _, id in ipairs(hazards) do
    local a = answers[id]
    if type(a) ~= "table" or not unit(a.noul) then
      return "deny", ("missing or malformed answer for %q"):format(id)
    end
  end
  local bad = malformed_signals(answers, n)
  if bad then
    return "deny", ("missing or malformed answer for %q"):format(bad)
  end

  local stop_id = over_cutoff(answers, hazards, cut, function(id) return M.DO_NOT_ASK[id] end)
  if stop_id then
    return "deny", ("do not ask (%s=%s >= %s): %s")
      :format(stop_id, pct(answers[stop_id].noul), pct(cut[stop_id]), questions.fix(stop_id))
  end

  if deny_at <= 1 then
    local reason
    if n >= 2 then
      reason = hobsons(answers, labels, cut) or stacked(answers, labels, cut) or unstated(answers, labels, cut)
    end
    reason = reason or unsupported(answers, cut)
    if reason then
      return "deny", reason
    end
  end

  local top_id = over_cutoff(answers, hazards, cut, function(id) return not M.DO_NOT_ASK[id] end)
  if top_id then
    return "deny", ("question needs rework (%s=%s >= %s): %s" .. REWORK)
      :format(top_id, pct(answers[top_id].noul), pct(cut[top_id]), questions.fix(top_id))
  end
  local all_id, all_p = strongest(answers, hazards, function() return true end)
  return "ok", ("highest %s=%s"):format(all_id, pct(all_p))
end

--- route(answers, cfg, capability, kind, labels) -> action, reason
--- action is "deny" or "ok". reason is human text naming what decided it.
---
--- kind "ask" routes the rigged-choice battery (see route_ask). Any other kind
--- routes the command hazards: deny when any hazard noul reaches its cutoff
--- (cfg.cutoffs[id], else deny_threshold; above 1 disables that hazard), or
--- the signal runs_script_outside_root reaches its cutoff while opaque_action
--- is "deny", or damage reaches damage_deny, or the returned damage legend is
--- not the one we asked with. Missing or malformed answers deny. labels (ask
--- only) are the option labels the per-option signals were built for.
function M.route(answers, cfg, capability, kind, labels)
  if type(answers) ~= "table" then
    return "deny", "no answers returned"
  end
  if kind == "ask" then
    return route_ask(answers, cfg, labels)
  end

  local damage_at = cfg.damage_deny or 2.5
  local opaque_action = cfg.opaque_action or "deny"

  for _, q in ipairs(questions.QUESTIONS) do
    local a = answers[q.id]
    if not require("straps_classifier.response").answer(q, a) then
      return "deny", ("missing or malformed answer for %q (type, value, confidence, or legend)"):format(q.id)
    end
  end

  local damage = answers.damage

  local cut = M.cutoffs(cfg)
  local hazards = questions.ids("hazard")
  local over = over_cutoff(answers, hazards, cut, function(id) return not skipped(id, capability) end)
  if over then
    return "deny", ("%s=%s (>= %s)"):format(over, pct(answers[over].noul), pct(cut[over]))
  end

  local opaque = answers.runs_script_outside_root.noul
  local note = ""
  if opaque >= cut.runs_script_outside_root then
    if opaque_action == "deny" then
      return "deny", ("opaque: runs_script_outside_root=%s (>= %s)"):format(pct(opaque), pct(cut.runs_script_outside_root))
    end
    note = ("; opaque runs_script_outside_root=%s logged"):format(pct(opaque))
  end

  local top_id, top_p = strongest(answers, hazards, function(id) return not skipped(id, capability) end)

  if damage.score >= damage_at then
    return "deny", ("damage=%s (>= %s)"):format(pct(damage.score), pct(damage_at))
  end

  return "ok", ("highest %s=%s%s"):format(top_id, pct(top_p), note)
end

return M
