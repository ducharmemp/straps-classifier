local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(vim.fn.fnamemodify(here, ":p"), ":h:h")
local core = vim.fn.fnamemodify(os.getenv("STRAPS_ROOT") or "../straps", ":p")
package.path = root .. "/lua/?.lua;" .. core .. "/lua/?.lua;" .. package.path
vim.opt.rtp:prepend(core)
local mutations = {
  schema = { 'if not exact(output, { "checks", "effects" }, { "unresolved_decision" })', 'if false' },
  check = { 'if not evidence(output.checks[id])', 'if false' },
  effect = { 'or not text(effect.target) or not text(effect.kind) or not evidence(effect.coverage)', 'or false' },
  spec = { 'if not valid then return deny(reason) end', 'if false then return deny(reason) end' },
  spec_binding = { 'if not vim.deep_equal(unwrap(held.payload.spec), held.spec)', 'if false' },
  sources = { 'if not known[id] or seen[id]', 'if false' },
  original = { 'if type(source.original) ~= "table" or source.original.id ~= id or not vim.deep_equal(disclosed[id], source.original)', 'if false' },
  original_payload = { 'evidence = held.payload,', 'evidence = (function() local payload = vim.deepcopy(held.payload); payload.sources = nil; return payload end)(),' },
}
local mutation = mutations[os.getenv("ASSESSMENT_MUTATION")]
if mutation then
  local source = table.concat(vim.fn.readfile(root .. "/lua/straps_classifier/assessment.lua"), "\n")
  local start, finish = assert(source:find(mutation[1], 1, true))
  package.loaded["straps_classifier.assessment"] = assert(loadstring(source:sub(1, start - 1) .. mutation[2] .. source:sub(finish + 1)))()
end
local assessment = require("straps_classifier.assessment")
local questions = require("straps_classifier.contextual_questions")
local function wrap(value)
  if type(value) ~= "table" then return { value = value, sensitivity = "public", required = true, filtered = false } end
  local out = {}
  for key, child in pairs(value) do out[key] = wrap(child) end
  return out
end
local function fixture()
  local identity = {}
  for _, key in ipairs({ "provider_id", "model", "backend", "backend_definition", "endpoint", "config", "account", "credentials", "transport", "disclosure_revision" }) do identity[key] = key end
  local spec = { schema_version = 1, task_id = "task", instruction_revision = 1 }
  for _, key in ipairs({ "outcome", "mode", "targets", "effects", "constraints", "reserved_decisions", "latitude", "unresolved_scope" }) do spec[key] = { value = {}, sources = { "human:1" } } end
  spec.outcome.value, spec.mode.value = "Read project", "investigation"
  local original = { id = "human:1", payload = { text = "  Read project\nDo not publish.\n" } }
  local ticket = { spec = spec, sources = { ["human:1"] = { trusted = true, revoked = false, original = original } },
    payload = { sources = { ["human:1"] = wrap(original) }, spec = wrap(spec), call = wrap({ name = "read_file", input = { path = "/project" } }), evidence = wrap("observed project") } }
  local output = { checks = {}, effects = { { id = "read", target = "/project", kind = "read", coverage = { score = 1, explanation = "authorized project read", source_ids = { "human:1" } } } } }
  for _, id in ipairs(questions.authorization_ids()) do output.checks[id] = { score = 0, explanation = id, source_ids = { "human:1" } } end
  output.checks.task_connection.score, output.checks.authorization_coverage.score = 1, 1
  local calls = {}
  local config = { identity = identity, resolve_identity = function() return vim.deepcopy(identity) end,
    limits = { max_bytes = 65536, max_depth = 30, max_items = 4000 },
    disclosure = { approved = true, provider_id = identity.provider_id, revision = identity.disclosure_revision,
      allowed_classes = { public = true }, inspect = function(bytes) return bytes:find("SECRET", 1, true) and "reject" or "clear" end },
    transport = function(req)
      calls[#calls + 1] = req
      return { text = vim.json.encode(output), metadata = { complete = true, refused = false, incomplete = false, tool_output = false, stop_reason = "end_turn" } }
    end }
  return { config = config, ticket = ticket, output = output, calls = calls, ctx = { cancelled = function() return false end } }
end
local function run(f) return assert(assessment.new(f.config, { positive_threshold = 0.9, conflict_threshold = 0.8 }))(f.ticket, f.ctx) end
local function unassessed(f)
  local result = run(f)
  assert.equals("deny", result.decision)
  assert.equals("unassessed", result.reasons[1].code)
  assert.same({}, result.effects)
  assert.same({}, result.source_ids)
end
it("returns policy allow with validated sources and effects", function()
  local f = fixture()
  local result = run(f)
  assert.equals("allow", result.decision)
  assert.same({ "human:1" }, result.source_ids)
  assert.equals("/project", result.effects[1].target)
  assert.equals("assess_call", vim.json.decode(f.calls[1].messages[1].content).operation)
end)
it("discloses exact original source bytes bound to their IDs", function()
  local f = fixture()
  assert.equals("allow", run(f).decision)
  local evidence = vim.json.decode(f.calls[1].messages[1].content).evidence.sources
  assert.is_table(evidence)
  assert.same(f.ticket.sources["human:1"].original, evidence["human:1"])
end)
it("discloses standing and adopted originals together without normalizing bytes", function()
  local f = fixture()
  local standing = { id = "standing:1", path = "/project/AGENTS.md", text = "\nNever publish.  \n", hash = "snapshot-hash" }
  f.ticket.sources[standing.id] = { trusted = true, revoked = false, original = standing }
  f.ticket.payload.sources[standing.id] = wrap(standing)
  assert.equals("allow", run(f).decision)
  local evidence = vim.json.decode(f.calls[1].messages[1].content).evidence.sources
  assert.is_table(evidence)
  assert.same(standing, evidence[standing.id])
  assert.same(f.ticket.sources["human:1"].original, evidence["human:1"])
end)
it("refuses missing mismatched and secret original evidence before dispatch", function()
  for _, change in ipairs({
    function(f) f.ticket.payload.sources = nil end,
    function(f) f.ticket.payload.sources["human:1"] = nil end,
    function(f) f.ticket.payload.sources["human:1"].payload.text.value = "expanded authority" end,
    function(f) f.ticket.sources["human:1"].original = nil end,
    function(f) f.ticket.sources["human:1"].original.id = "other" end,
    function(f) f.ticket.sources["human:1"].original.payload.text = "SECRET"; f.ticket.payload.sources["human:1"] = wrap(f.ticket.sources["human:1"].original) end,
  }) do
    local f = fixture(); change(f); unassessed(f); assert.equals(0, #f.calls)
  end
end)
it("retains policy deny and bounded ask", function()
  local f = fixture()
  f.output.checks.violates_constraint.score = 1
  assert.equals("deny", run(f).decision)
  f = fixture()
  f.output.effects[1].coverage.score = 0
  f.output.unresolved_decision = { id = "restart", description = "restart adopted service", bounded = true, connection = f.output.checks.task_connection }
  assert.equals("ask", run(f).decision)
end)
it("rejects permission facts and unknown fields at every output level", function()
  for _, field in ipairs({ "context_valid", "capability_allowed", "status", "source_ids", "decision", "other" }) do
    local f = fixture(); f.output[field] = true; unassessed(f)
  end
  for _, location in ipairs({ "checks", "check", "effect", "coverage", "decision", "connection" }) do
    local f = fixture()
    f.output.unresolved_decision = { id = "restart", description = "restart", bounded = true, connection = vim.deepcopy(f.output.checks.task_connection) }
    local target = location == "checks" and f.output.checks or location == "check" and f.output.checks.task_connection
      or location == "effect" and f.output.effects[1] or location == "coverage" and f.output.effects[1].coverage
      or location == "decision" and f.output.unresolved_decision or f.output.unresolved_decision.connection
    target.unknown = true; unassessed(f)
  end
end)
it("rejects bad scores explanations citations and missing checks", function()
  for _, id in ipairs(questions.authorization_ids()) do
    local f = fixture(); f.output.checks[id] = nil; unassessed(f)
    for _, score in ipairs({ -1, 2, "1" }) do f = fixture(); f.output.checks[id].score = score; unassessed(f) end
    f = fixture(); f.output.checks[id].explanation = " "; unassessed(f)
    f = fixture(); f.output.checks[id].source_ids = { "unknown" }; unassessed(f)
    f = fixture(); f.output.checks[id].source_ids = { "human:1", "human:1" }; unassessed(f)
  end
end)
it("rejects malformed effects and decisions", function()
  for _, field in ipairs({ "id", "target", "kind", "coverage" }) do local f = fixture(); f.output.effects[1][field] = nil; unassessed(f) end
  local f = fixture(); f.output.effects[1].target = " "; unassessed(f)
  f = fixture(); f.output.effects = {}; unassessed(f)
  f = fixture(); f.output.effects[2] = vim.deepcopy(f.output.effects[1]); unassessed(f)
  f = fixture(); f.output.effects[1].coverage.source_ids = { "unknown" }; unassessed(f)
  f = fixture(); f.output.unresolved_decision = { id = "restart" }; unassessed(f)
end)
it("binds disclosed spec and rejects revoked sources secrets failures and cancellation", function()
  local f = fixture(); f.ticket.spec.mode.value = "other"; f.ticket.payload.spec = wrap(f.ticket.spec); unassessed(f); assert.equals(0, #f.calls)
  f = fixture(); f.ticket.payload.spec.mode.value.value = "planning"; unassessed(f); assert.equals(0, #f.calls)
  f = fixture(); f.ticket.sources["human:1"].revoked = true; unassessed(f); assert.equals(0, #f.calls)
  f = fixture(); f.ticket.payload.call.input.path.value = "SECRET"; unassessed(f); assert.equals(0, #f.calls)
  f = fixture(); f.ctx.cancelled = function() return true end; unassessed(f); assert.equals(0, #f.calls)
  f = fixture(); f.config.transport = function() error("provider unavailable") end; unassessed(f)
end)
