local questions = require("straps_classifier.contextual_questions")
local M = {}

local function probability(value)
  return type(value) == "number" and value == value and value >= 0 and value <= 1
end

local function text(value) return type(value) == "string" and value:find("%S") ~= nil end

local function list(value)
  if type(value) ~= "table" or getmetatable(value) ~= nil then return false end
  local n = #value
  for k in pairs(value) do
    if type(k) ~= "number" or k < 1 or k > n or k % 1 ~= 0 then return false end
  end
  return true
end

function M.decide(assessment, config)
  local result = { decision = "deny", reasons = {}, effects = {}, source_ids = {} }
  local seen = {}
  local function reason(code, detail, ids)
    local copied = {}
    for _, id in ipairs(ids or {}) do
      copied[#copied + 1] = id
      if not seen[id] then result.source_ids[#result.source_ids + 1], seen[id] = id, true end
    end
    result.reasons[#result.reasons + 1] = { code = code, detail = detail, source_ids = copied }
  end
  local function unavailable(detail)
    reason("unassessed", detail)
    return result
  end
  if type(config) ~= "table" or not probability(config.positive_threshold) or not probability(config.conflict_threshold)
    or config.positive_threshold == 0 or config.conflict_threshold == 0 then
    return unavailable("explicit nonzero calibrated thresholds required")
  end
  if type(assessment) ~= "table" then return unavailable("missing assessment") end
  if assessment.status == "failed" then
    reason("assessment_failed", assessment.error or "assessment failed")
    return result
  end
  if assessment.status ~= "assessed" then return unavailable("assessment incomplete") end
  if assessment.context_valid ~= true or assessment.capability_allowed ~= true then
    reason("core_restriction", "execution context or capability restriction")
    return result
  end
  local known = {}
  if not list(assessment.source_ids) or #assessment.source_ids == 0 then return unavailable("missing validated sources") end
  for _, id in ipairs(assessment.source_ids) do
    if not text(id) or known[id] then return unavailable("invalid source IDs") end
    known[id] = true
  end
  local function evidence(item)
    if type(item) ~= "table" or not probability(item.score) or not text(item.explanation) or not list(item.source_ids) then return false end
    for _, id in ipairs(item.source_ids) do if not known[id] then return false end end
    return true
  end
  if type(assessment.checks) ~= "table" then return unavailable("missing checks") end
  local checks = assessment.checks
  for _, id in ipairs(questions.authorization_ids()) do
    if not evidence(checks[id]) then return unavailable("invalid check: " .. id) end
    reason(id, checks[id].explanation, checks[id].source_ids)
  end
  if not list(assessment.effects) or #assessment.effects == 0 then return unavailable("material effects must be enumerated") end
  local covered, effect_ids = true, {}
  for _, effect in ipairs(assessment.effects) do
    if type(effect) ~= "table" or not text(effect.id) or effect_ids[effect.id] or not text(effect.target)
      or not text(effect.kind) or not evidence(effect.coverage) then return unavailable("invalid effect") end
    effect_ids[effect.id] = true
    result.effects[#result.effects + 1] = {
      id = effect.id, target = effect.target, kind = effect.kind,
      coverage = { score = effect.coverage.score, explanation = effect.coverage.explanation, source_ids = {} },
    }
    for i, id in ipairs(effect.coverage.source_ids) do result.effects[#result.effects].coverage.source_ids[i] = id end
    reason("effect_coverage", effect.coverage.explanation, effect.coverage.source_ids)
    if effect.coverage.score < config.positive_threshold or #effect.coverage.source_ids == 0 then covered = false end
  end
  local hard = false
  for _, id in ipairs({ "wrong_work_mode", "unrelated_action", "violates_constraint", "uses_revoked_authority", "untrusted_authority", "expands_delegation" }) do
    if checks[id].score >= config.conflict_threshold then hard = true end
  end
  if hard then return result end
  local connection = checks.task_connection
  if connection.score < config.positive_threshold or #connection.source_ids == 0 then
    reason("task_connection_missing", "positive task connection is required")
    return result
  end
  local boundary = checks.target_out_of_scope.score >= config.conflict_threshold
    or checks.effect_out_of_scope.score >= config.conflict_threshold
    or checks.crosses_approval_boundary.score >= config.conflict_threshold
    or checks.unresolved_authorization.score >= config.conflict_threshold
  if covered and not boundary and checks.authorization_coverage.score >= config.positive_threshold
    and #checks.authorization_coverage.source_ids > 0 then
    result.decision = "allow"
    return result
  end
  local decision = assessment.unresolved_decision
  if type(decision) == "table" and text(decision.id) and text(decision.description) and decision.bounded == true
    and evidence(decision.connection) and decision.connection.score >= config.positive_threshold and #decision.connection.source_ids > 0 then
    result.decision = "ask"
    result.decision_identity = { boundary = decision.id, targets = {}, effects = {} }
    local targets = {}
    for _, effect in ipairs(result.effects) do
      result.decision_identity.effects[#result.decision_identity.effects + 1] = effect.kind
      if not targets[effect.target] then
        result.decision_identity.targets[#result.decision_identity.targets + 1] = effect.target
        targets[effect.target] = true
      end
    end
    table.sort(result.decision_identity.targets)
    table.sort(result.decision_identity.effects)
    reason("bounded_decision", decision.description, decision.connection.source_ids)
    return result
  end
  reason("authorization_missing", "uncovered authority lacks a bounded in-task decision")
  return result
end

return M
