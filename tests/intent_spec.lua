local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(vim.fn.fnamemodify(here, ":p"), ":h:h")
package.path = root .. "/lua/?.lua;" .. package.path
if os.getenv("INTENT_MUTATION") == "density" then
  local source = table.concat(vim.fn.readfile(root .. "/lua/straps_classifier/intent.lua"), "\n")
  local target = "for index = 1, count do if rawget(value, index) == nil then return false end end"
  local start, finish = source:find(target, 1, true)
  assert(start, "density mutation target missing")
  source = source:sub(1, start - 1) .. source:sub(finish + 1)
  package.loaded["straps_classifier.intent"] = assert(loadstring(source))()
end
local intent = require("straps_classifier.intent")
local questions = require("straps_classifier.contextual_questions")
local limits = { max_bytes = 4096, max_depth = 12, max_items = 100 }
local sources = { h1 = { trusted = true, revoked = false } }
local function fixture()
  local spec = { schema_version = 1, task_id = "task1", instruction_revision = 1 }
  for _, field in ipairs({ "outcome", "mode", "targets", "effects", "constraints", "reserved_decisions", "latitude", "unresolved_scope" }) do
    spec[field] = { value = {}, sources = { "h1" } }
  end
  spec.outcome.value, spec.mode.value = "repair service", "investigation"
  return spec
end
local function sparse(first, suffix)
  local values = { first, first, first, suffix }
  values[2] = nil
  return values
end
local function checks()
  local out = {}
  for _, id in ipairs(questions.synthesis_ids()) do out[id] = { score = 0, explanation = "checked", sources = { "h1" }, field = "outcome" } end
  return out
end
local function disclosure()
  return { approved = true, provider_id = "chosen", revision = "r1", allowed_classes = { public = true }, limits = limits,
    inspect = function(bytes) if bytes:find("SECRET", 1, true) then return "credential" end; return "clear" end }
end
local function leaf(value, sensitivity) return { value = value, sensitivity = sensitivity or "public", required = true, filtered = false } end

it("serializes empty task lists as arrays", function() assert.is_truthy(intent.serialize_task(fixture(), sources, limits):find('"value":[]', 1, true)) end)
it("serializes empty generic maps as objects", function() assert.equals('{}', intent.serialize({}, limits)) end)
it("rejects invalid task before serialization", function() local s = fixture(); s.schema_version = 2; assert.is_nil(intent.serialize_task(s, sources, limits)) end)
it("validates exact versioned proposal", function() assert.is_true(intent.validate(fixture(), sources)) end)
local mutations = {
  { "unknown schema version", function(s) s.schema_version = 2 end },
  { "extra root field", function(s) s.permission = true end },
  { "invalid revision", function(s) s.instruction_revision = 0 end },
  { "invalid task ID", function(s) s.task_id = "" end },
  { "unsupported mode", function(s) s.mode.value = "auto" end },
  { "extra authority field", function(s) s.outcome.trusted = true end },
  { "unknown source", function(s) s.outcome.sources = { "agent" } end },
  { "duplicate source", function(s) s.outcome.sources = { "h1", "h1" } end },
  { "missing source", function(s) s.constraints.sources = {} end },
  { "invalid array member", function(s) s.targets.value = { false } end },
  { "sparse array", function(s) s.effects.value = { [2] = "read" } end },
}
for _, case in ipairs(mutations) do
  it("rejects " .. case[1], function() local s = fixture(); case[2](s); assert.is_nil(intent.validate(s, sources)) end)
end
it("rejects sparse constraints with an omitted suffix", function()
  local s = fixture()
  s.constraints.value = sparse("preserve files", "never dispatch")
  assert.is_nil(intent.validate(s, sources))
end)
it("refuses sparse constraints before task serialization", function()
  local s = fixture()
  s.constraints.value = sparse("preserve files", "never dispatch")
  assert.is_nil(intent.serialize_task(s, sources, limits))
end)
it("rejects sparse task sources with an omitted suffix", function()
  local s = fixture()
  s.constraints.sources = sparse("h1", "unknown")
  assert.is_nil(intent.validate(s, sources))
end)
it("rejects sparse synthesis sources with an omitted suffix", function()
  local c = checks()
  c.hidden_ambiguity.sources = sparse("h1", "unknown")
  assert.is_nil(intent.validate_synthesis(fixture(), sources, c, { defect_threshold = 0.8 }))
end)
it("refuses sparse generic arrays instead of omitting suffixes", function()
  assert.is_nil(intent.serialize(sparse("preserve files", "never dispatch"), limits))
end)
it("rejects revoked sources", function() assert.is_nil(intent.validate(fixture(), { h1 = { trusted = true, revoked = true } })) end)
it("rejects untrusted sources", function() assert.is_nil(intent.validate(fixture(), { h1 = { trusted = false, revoked = false } })) end)
it("accepts separate complete synthesis checks", function() assert.is_true(intent.validate_synthesis(fixture(), sources, checks(), { defect_threshold = 0.8 })) end)
it("requires explicit synthesis threshold", function() assert.is_nil(intent.validate_synthesis(fixture(), sources, checks(), {})) end)
it("rejects incomplete synthesis battery", function() local c = checks(); c.hidden_ambiguity = nil; assert.is_nil(intent.validate_synthesis(fixture(), sources, c, { defect_threshold = 0.8 })) end)
for _, id in ipairs(questions.synthesis_ids()) do
  it("rejects synthesis defect " .. id, function() local c = checks(); c[id].score = 0.8; assert.is_nil(intent.validate_synthesis(fixture(), sources, c, { defect_threshold = 0.8 })) end)
end
it("requires synthesis affected field", function() local c = checks(); c.hidden_ambiguity.field = "unknown"; assert.is_nil(intent.validate_synthesis(fixture(), sources, c, { defect_threshold = 0.8 })) end)
it("requires synthesis source", function() local c = checks(); c.hidden_ambiguity.sources = { "agent" }; assert.is_nil(intent.validate_synthesis(fixture(), sources, c, { defect_threshold = 0.8 })) end)
it("serializes deterministically", function() assert.equals('{"a":true,"b":"x"}', intent.serialize({ b = "x", a = true }, limits)) end)
it("escapes control bytes", function() assert.equals('"\\u000a\\\""', intent.serialize('\n"', limits)) end)
it("refuses byte overflow", function() assert.is_nil(intent.serialize("oversized", { max_bytes = 2, max_depth = 2, max_items = 2 })) end)
it("refuses depth overflow", function() assert.is_nil(intent.serialize({ a = {} }, { max_bytes = 100, max_depth = 1, max_items = 10 })) end)
it("refuses item overflow", function() assert.is_nil(intent.serialize({ a = 1, b = 2 }, { max_bytes = 100, max_depth = 5, max_items = 2 })) end)
for _, classification in ipairs({ "array", "object" }) do
it("bounds " .. classification .. " classification visits before serialization refusal", function()
  local input, visits = {}, 0
  for index = 1, 10000 do input[classification == "array" and index or "key" .. index] = index end
  local source = table.concat(vim.fn.readfile(root .. "/lua/straps_classifier/intent.lua"), "\n")
  if os.getenv("INTENT_MUTATION") == "classification" then
    local target = classification == "array" and 'if remaining and count > remaining then error("serialization structural overflow", 0) end'
      or 'if #keys > limits.max_items - items then error("serialization structural overflow", 0) end'
    local start, finish = assert(source:find(target, 1, true))
    source = source:sub(1, start - 1) .. source:sub(finish + 1)
  end
  local chunk = assert(loadstring(source, "@" .. root .. "/lua/straps_classifier/intent.lua"))
  local environment = setmetatable({ pairs = function(value)
    local iterator, state, key = pairs(value)
    return function(current, previous)
      local next_key, child = iterator(current, previous)
      if value == input and next_key ~= nil then visits = visits + 1 end
      return next_key, child
    end, state, key
  end }, { __index = _G })
  setfenv(chunk, environment)
  local isolated = chunk()
  local bound = { max_bytes = 4096, max_depth = 8, max_items = 16 }
  local result, reason = isolated.serialize(input, bound)
  assert.is_nil(result)
  assert.matches("serialization structural overflow", reason, 1, true)
  assert.is_true(visits <= bound.max_items + 1, classification .. " classification visited " .. visits .. " entries for max_items=" .. bound.max_items)
end)
end
it("refuses missing limits", function() assert.is_nil(intent.serialize({}, {})) end)
it("refuses cycles", function() local t = {}; t.self = t; assert.is_nil(intent.serialize(t, limits)) end)
it("refuses executable values", function() assert.is_nil(intent.serialize({ fn = function() end }, limits)) end)
it("refuses metatables", function() assert.is_nil(intent.serialize(setmetatable({}, {}), limits)) end)
it("refuses nonfinite numbers", function() assert.is_nil(intent.serialize(math.huge, limits)) end)
it("accepts recursively classified payload", function() assert.is_true(intent.validate_disclosure({ tool = { input = leaf("read") } }, disclosure())) end)
it("requires adopted disclosure policy", function() local p = disclosure(); p.approved = false; assert.is_nil(intent.validate_disclosure({ x = leaf("read") }, p)) end)
it("rejects nested credentials", function() local p = disclosure(); p.allowed_classes.credential = true; assert.is_nil(intent.validate_disclosure({ tool = { arguments = leaf("bytes", "credential") } }, p)) end)
it("inspects nested serialized value", function() assert.is_nil(intent.validate_disclosure({ definition = leaf({ source = "SECRET" }) }, disclosure())) end)
it("rejects filtered required evidence", function() local l = leaf("removed"); l.filtered = true; assert.is_nil(intent.validate_disclosure({ fact = l }, disclosure())) end)
it("rejects unknown sensitivity", function() local p = disclosure(); p.allowed_classes.unknown = true; assert.is_nil(intent.validate_disclosure({ x = leaf("text", "unknown") }, p)) end)
it("rejects unlabeled scalar", function() assert.is_nil(intent.validate_disclosure({ source = "text" }, disclosure())) end)
it("rejects unapproved confidential class", function() assert.is_nil(intent.validate_disclosure({ source = leaf("text", "confidential") }, disclosure())) end)
it("rejects failed credential inspection", function() local p = disclosure(); p.inspect = function() error("unavailable") end; assert.is_nil(intent.validate_disclosure({ x = leaf("text") }, p)) end)
it("rejects credential bytes in payload keys", function() assert.is_nil(intent.validate_disclosure({ SECRET = leaf("text") }, disclosure())) end)
it("rejects nonfinite synthesis threshold", function() assert.is_nil(intent.validate_synthesis(fixture(), sources, checks(), { defect_threshold = 0/0 })) end)
it("rejects unassessed credential inspection", function() local p = disclosure(); p.inspect = function() return "unknown" end; assert.is_nil(intent.validate_disclosure({ x = leaf("text") }, p)) end)
