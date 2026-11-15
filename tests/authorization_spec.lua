local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(vim.fn.fnamemodify(here, ":p"), ":h:h")
package.path = root .. "/lua/?.lua;" .. package.path
local policy = require("straps_classifier.authorization")
local questions = require("straps_classifier.contextual_questions")
local config = { positive_threshold = 0.9, conflict_threshold = 0.8 }

local function fixture()
  local a = { status = "assessed", context_valid = true, capability_allowed = true, source_ids = { "human:1" }, checks = {}, effects = {} }
  for _, id in ipairs(questions.authorization_ids()) do
    a.checks[id] = { score = 0, explanation = id, source_ids = { "human:1" } }
  end
  a.checks.task_connection.score = 1
  a.checks.authorization_coverage.score = 1
  a.effects[1] = { id = "read", target = "/project", kind = "read", coverage = { score = 1, explanation = "adopted read", source_ids = { "human:1" } } }
  return a
end

local cases = {
  { "complete positive evidence allows", function() return fixture(), config end, "allow" },
  { "missing explicit thresholds denies", function() return fixture(), {} end, "deny" },
  { "failed assessment denies", function() local a = fixture(); a.status = "failed"; return a, config end, "deny" },
  { "unassessed assessment denies", function() local a = fixture(); a.status = "unassessed"; return a, config end, "deny" },
  { "invalid context denies", function() local a = fixture(); a.context_valid = false; return a, config end, "deny" },
  { "capability ceiling denies", function() local a = fixture(); a.capability_allowed = false; return a, config end, "deny" },
  { "negative evidence alone cannot allow", function() local a = fixture(); a.checks.task_connection.score = 0; return a, config end, "deny" },
  { "positive connection needs source", function() local a = fixture(); a.checks.task_connection.source_ids = {}; return a, config end, "deny" },
  { "every effect needs coverage", function() local a = fixture(); a.effects[2] = { id = "upload", target = "remote", kind = "disclosure", coverage = { score = 0, explanation = "uncovered", source_ids = { "human:1" } } }; return a, config end, "deny" },
  { "missing effects denies", function() local a = fixture(); a.effects = {}; return a, config end, "deny" },
  { "unknown source denies", function() local a = fixture(); a.checks.task_connection.source_ids = { "agent:1" }; return a, config end, "deny" },
  { "missing check denies", function() local a = fixture(); a.checks.unrelated_action = nil; return a, config end, "deny" },
  { "nonfinite score denies", function() local a = fixture(); a.checks.task_connection.score = 0/0; return a, config end, "deny" },
  { "reserved decision without description denies", function() local a = fixture(); a.checks.crosses_approval_boundary.score = 1; return a, config end, "deny" },
  { "bounded connected decision asks", function() local a = fixture(); a.effects[1].coverage.score = 0; a.unresolved_decision = { id = "restart", description = "restart service under investigation", bounded = true, connection = { score = 1, explanation = "restore adopted service", source_ids = { "human:1" } } }; return a, config end, "ask" },
  { "unbounded decision denies", function() local a = fixture(); a.effects[1].coverage.score = 0; a.unresolved_decision = { id = "restart", description = "restart", bounded = false, connection = { score = 1, explanation = "task", source_ids = { "human:1" } } }; return a, config end, "deny" },
}
for _, id in ipairs({ "wrong_work_mode", "unrelated_action", "violates_constraint", "uses_revoked_authority", "untrusted_authority", "expands_delegation" }) do
  cases[#cases + 1] = { id .. " denies", function()
    local a = fixture(); a.checks[id].score = config.conflict_threshold
    a.unresolved_decision = { id = "override", description = "bounded", bounded = true, connection = a.checks.task_connection }
    return a, config
  end, "deny" }
end

for _, case in ipairs(cases) do
  it(case[1], function()
    local a, cfg = case[2]()
    assert.equals(case[3], policy.decide(a, cfg).decision)
  end)
end

it("distinguishes failed assessment reason", function()
  local a = fixture(); a.status = "failed"
  assert.equals("assessment_failed", policy.decide(a, config).reasons[1].code)
end)
it("distinguishes unassessed reason", function()
  local a = fixture(); a.status = "unassessed"
  assert.equals("unassessed", policy.decide(a, config).reasons[1].code)
end)
it("preserves all check reasons", function()
  assert.equals(#questions.authorization_ids() + 1, #policy.decide(fixture(), config).reasons)
end)
it("preserves material effect target", function()
  assert.equals("/project", policy.decide(fixture(), config).effects[1].target)
end)
it("preserves source IDs", function()
  assert.same({ "human:1" }, policy.decide(fixture(), config).source_ids)
end)
it("detaches returned effect evidence", function()
  local a = fixture(); local out = policy.decide(a, config)
  out.effects[1].coverage.source_ids[1] = "forged"
  assert.equals("human:1", a.effects[1].coverage.source_ids[1])
end)
for _, id in ipairs({ "target_out_of_scope", "effect_out_of_scope", "crosses_approval_boundary", "unresolved_authorization" }) do
  it(id .. " asks only with bounded connected decision", function()
    local a = fixture(); a.checks[id].score = config.conflict_threshold
    a.unresolved_decision = { id = "restart", description = "restart service", bounded = true, connection = a.checks.task_connection }
    assert.equals("ask", policy.decide(a, config).decision)
    a.unresolved_decision = nil
    assert.equals("deny", policy.decide(a, config).decision)
  end)
end
for _, id in ipairs({ "task_connection", "authorization_coverage" }) do
  it(id .. " includes positive threshold boundary", function()
    local a = fixture(); a.checks[id].score = config.positive_threshold
    assert.equals("allow", policy.decide(a, config).decision)
    a.checks[id].score = config.positive_threshold - 0.001
    assert.equals("deny", policy.decide(a, config).decision)
  end)
end
it("effect coverage includes positive threshold boundary", function()
  local a = fixture(); a.effects[1].coverage.score = config.positive_threshold
  assert.equals("allow", policy.decide(a, config).decision)
  a.effects[1].coverage.score = config.positive_threshold - 0.001
  assert.equals("deny", policy.decide(a, config).decision)
end)
it("subthreshold conflict permits covered call", function()
  local a = fixture(); a.checks.violates_constraint.score = config.conflict_threshold - 0.001
  assert.equals("allow", policy.decide(a, config).decision)
end)
it("coverage requires positive source", function()
  local a = fixture(); a.checks.authorization_coverage.source_ids = {}
  assert.equals("deny", policy.decide(a, config).decision)
end)
it("effect coverage requires positive source", function()
  local a = fixture(); a.effects[1].coverage.source_ids = {}
  assert.equals("deny", policy.decide(a, config).decision)
end)
for _, mutation in ipairs({
  { "blank explanation", function(a) a.checks.task_connection.explanation = " " end },
  { "invalid probability", function(a) a.checks.task_connection.score = 1.001 end },
  { "duplicate effect", function(a) a.effects[2] = a.effects[1] end },
  { "unknown effect source", function(a) a.effects[1].coverage.source_ids = { "agent:1" } end },
  { "invalid source list", function(a) a.source_ids = { named = "human:1" } end },
  { "duplicate source ID", function(a) a.source_ids[2] = "human:1" end },
}) do
  it("rejects malformed evidence " .. mutation[1], function()
    local a = fixture(); mutation[2](a)
    local out = policy.decide(a, config)
    assert.equals("deny", out.decision)
    assert.equals("unassessed", out.reasons[#out.reasons].code)
  end)
end
it("bounded decision needs its own sourced threshold connection", function()
  local a = fixture(); a.effects[1].coverage.score = 0
  a.unresolved_decision = { id = "restart", description = "restart", bounded = true,
    connection = { score = config.positive_threshold, explanation = "task", source_ids = { "human:1" } } }
  assert.equals("ask", policy.decide(a, config).decision)
  a.unresolved_decision.connection.score = config.positive_threshold - 0.001
  assert.equals("deny", policy.decide(a, config).decision)
  a.unresolved_decision.connection.score = 1; a.unresolved_decision.connection.source_ids = {}
  assert.equals("deny", policy.decide(a, config).decision)
end)
it("preserves individual reason evidence", function()
  local a = fixture(); a.checks.violates_constraint.explanation = "do not restart"; a.checks.violates_constraint.score = 1
  local out = policy.decide(a, config)
  local found
  for _, reason in ipairs(out.reasons) do if reason.code == "violates_constraint" then found = reason end end
  assert.same({ code = "violates_constraint", detail = "do not restart", source_ids = { "human:1" } }, found)
end)
it("returns detached question definitions", function()
  local a = questions.authorization(); a[1].id = "forged"
  assert.equals("wrong_work_mode", questions.authorization()[1].id)
end)
