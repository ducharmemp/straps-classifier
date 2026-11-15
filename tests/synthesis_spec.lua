local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(vim.fn.fnamemodify(here, ":p"), ":h:h")
vim.opt.rtp:prepend(root)
local core = vim.fn.fnamemodify(os.getenv("STRAPS_ROOT") or "../straps", ":p")
vim.opt.rtp:prepend(core)
package.path = root .. "/lua/?.lua;" .. core .. "/lua/?.lua;" .. package.path

local mutations = {
  density = { "for index = 1, count do if rawget(value, index) == nil then return false end end", "" },
  completion = { "result.metadata.complete ~= true", "false" },
  refusal = { "result.metadata.refused ~= false", "false" },
  incomplete = { "result.metadata.incomplete ~= false", "false" },
  tool_output = { "result.metadata.tool_output ~= false", "false" },
  route = { "intent.serialize(value, limits) ~= identity_json", "false" },
  task = { "spec.task_id ~= held.task_id or spec.instruction_revision ~= held.instruction_revision", "false" },
  disclosure = { "local ok, disclosure_err = intent.validate_disclosure(node, disclosure)", "local ok, disclosure_err = true, nil" },
  schema = { "local valid, schema_err = intent.validate(spec, held.sources)", "local valid, schema_err = true, nil" },
  task_arrays = { "intent.serialize_task(spec, held.sources, limits)", "intent.serialize(spec, limits)" },
  defects = { "valid, schema_err = intent.validate_synthesis(spec, held.sources, checks, { defect_threshold = frozen.defect_threshold })", "valid, schema_err = true, nil" },
  bootstrap = { "if not require(\"straps.registry\").trusted_setup_allowed()", "if false" },
  cancel = { "not ok or cancelled ~= false", "false" },
  sources = { "type(id) ~= \"string\" or held.payload.sources[id] == nil", "false" },
  final_validation = { "ready, reason = current(ctx)\n    if not ready then return nil, reason end\n    local sent", "ready, reason = true, nil\n    if not ready then return nil, reason end\n    local sent" },
  validation_yield = { 'coroutine.status(validation) ~= "dead"', "false" },
  defect_map = { "defects[id] = false", "defects[id] = true" },
  resolver_order = { "local resolved, value = pcall(frozen.resolve_identity)\n      local ok, cancelled = pcall(ctx.cancelled)", "local ok, cancelled = pcall(ctx.cancelled)\n      local resolved, value = pcall(frozen.resolve_identity)" },
}
local mutation = mutations[os.getenv("SYNTHESIS_MUTATION")]
if mutation then
  local module = os.getenv("SYNTHESIS_MUTATION") == "density" and "intent"
    or (({ task = true, schema = true, task_arrays = true, defects = true, sources = true, defect_map = true, bootstrap = true })[os.getenv("SYNTHESIS_MUTATION")] and "synthesis" or "request")
  local source = table.concat(vim.fn.readfile(root .. "/lua/straps_classifier/" .. module .. ".lua"), "\n")
  local start, finish = source:find(mutation[1], 1, true)
  assert(start, "mutation target missing")
  source = source:sub(1, start - 1) .. mutation[2] .. source:sub(finish + 1)
  package.loaded["straps_classifier." .. module] = assert(loadstring(source))()
end
local synthesis = require("straps_classifier.synthesis")
local questions = require("straps_classifier.contextual_questions")
local assertion_index = 0
teardown(function() print("SYNTHESIS_ASSERTIONS=" .. assertion_index) end)
local function check(value, message)
  assertion_index = assertion_index + 1
  assert(value, "assertion " .. assertion_index .. ": " .. message)
end
local function leaf(value, sensitivity)
  return { value = value, sensitivity = sensitivity or "public", required = true, filtered = false }
end
local function fixture()
  local identity = { provider_id = "offline", model = "fixed", backend = "mock", backend_definition = "definition:1",
    endpoint = "offline://route", config = "config:1", account = "account:1", credentials = "credential-resolution:1",
    transport = "transport:1", disclosure_revision = "disclosure:1" }
  local ticket = { task_id = "task:1", instruction_revision = 2, sources = { s1 = { trusted = true, revoked = false } },
    payload = { sources = { s1 = leaf("Implement task in approved files") }, tool = { source = leaf("tool source"),
      metadata = { description = leaf("tool description") } }, evidence = leaf("observed fact") } }
  local spec = { schema_version = 1, task_id = "task:1", instruction_revision = 2 }
  for _, field in ipairs({ "outcome", "mode", "targets", "effects", "constraints", "reserved_decisions", "latitude", "unresolved_scope" }) do
    spec[field] = { value = {}, sources = { "s1" } }
  end
  spec.outcome.value, spec.mode.value = "Implement task", "implementation"
  local checks = {}
  for _, id in ipairs(questions.synthesis_ids()) do
    checks[id] = { score = 0, explanation = "No defect in this routing fixture", sources = { "s1" }, field = "constraints" }
  end
  local calls, results = {}, {}
  local function result(value)
    return { text = vim.json.encode(value), metadata = { complete = true, refused = false, incomplete = false,
      tool_output = false, stop_reason = "end_turn" } }
  end
  results[1], results[2] = result(spec), result(checks)
  local ctx = { cancelled = function() return false end }
  local cfg = { identity = vim.deepcopy(identity), resolve_identity = function() return vim.deepcopy(identity) end,
    limits = { max_bytes = 65536, max_depth = 20, max_items = 2000 },
    defect_threshold = 0.5, disclosure = { approved = true, provider_id = "offline", revision = "disclosure:1",
      allowed_classes = { public = true }, inspect = function(bytes)
        return bytes:find("SECRET_BYTES", 1, true) and "reject" or "clear"
      end }, transport = function(request)
        calls[#calls + 1] = vim.deepcopy(request)
        return results[#calls]
      end }
  return { cfg = cfg, ctx = ctx, ticket = ticket, spec = spec, checks = checks, calls = calls, results = results, identity = identity, result = result }
end
local function reject(f, reason, count)
  local adapter, setup_err = synthesis.new(f.cfg)
  check(type(adapter) == "function", "valid trusted setup: " .. tostring(setup_err))
  local spec, err = adapter(f.ticket, f.ctx)
  check(spec == nil and type(err) == "string" and err:find(reason, 1, true), "expected rejection: " .. reason .. ", got " .. tostring(err))
  check(#f.calls == count, "expected transport call count")
end

it("uses isolated fixed routing and a separate defect request", function()
  local f = fixture()
  local adapter = synthesis.new(f.cfg)
  f.cfg.model, f.cfg.identity.model = "attacker", "attacker"
  f.cfg.transport = function() error("replacement callback") end
  local spec, defects = adapter(f.ticket, f.ctx)
  check(spec and spec.outcome.value == f.spec.outcome.value, "returns validated task")
  local expected = {}
  for _, id in ipairs(questions.synthesis_ids()) do expected[id] = false end
  check(vim.deep_equal(defects, expected), "returns exact validated boolean defect map")
  check(#f.calls == 2, "two independent requests")
  for i, request in ipairs(f.calls) do
    check(request.model == "fixed" and request.provider_id == "offline", "frozen provider/model")
    check(vim.deep_equal(request.route, f.identity), "frozen transitive route")
    check(next(request.tools) == nil and #request.messages == 1 and request.messages[1].role == "user", "isolated tool-free context")
    check(request.system == nil and request.bufnr == nil and request.pin == nil and request.transcript == nil, "no session state")
    local payload = vim.json.decode(request.messages[1].content)
    check(payload.operation == (i == 1 and "extract_task" or "check_synthesis"), "separate extraction and check operations")
  end
  local battery = vim.json.decode(f.calls[2].messages[1].content)
  check(#battery.questions == #questions.synthesis_ids() and vim.json.decode(battery.proposal_json).task_id == "task:1", "complete independent defect battery")
  check(battery.proposal_json:find('"constraints":{"sources":["s1"],"value":[]}', 1, true), "empty task lists preserve JSON array shape")
end)

it("requires trusted bootstrap and explicit approved setup", function()
  local registry = require("straps.registry")
  local original = registry.trusted_setup_allowed
  registry.trusted_setup_allowed = function() return false end
  local adapter, err = synthesis.new(fixture().cfg)
  registry.trusted_setup_allowed = original
  check(adapter == nil and err == "trusted bootstrap required", "tool-time setup rejected")
  for _, field in ipairs({ "identity", "transport", "resolve_identity", "disclosure", "limits", "defect_threshold" }) do
    local f = fixture()
    f.cfg[field] = nil
    local value = synthesis.new(f.cfg)
    check(value == nil, "missing trusted configuration: " .. field)
  end
  for _, field in ipairs({ "approved", "provider_id", "revision" }) do
    local f = fixture()
    f.cfg.disclosure[field] = false
    check(synthesis.new(f.cfg) == nil, "unapproved disclosure: " .. field)
  end
end)

it("rejects changes to every transitive route component", function()
  for key in pairs(fixture().identity) do
    local f = fixture()
    local adapter = synthesis.new(f.cfg)
    f.identity[key] = "changed"
    local spec, err = adapter(f.ticket, f.ctx)
    check(spec == nil and err == "provider resolution changed", "changed route: " .. key)
    check(#f.calls == 0, "no send after route change")
  end
end)

it("rejects late route changes and cancellation", function()
  local f = fixture()
  local transport = f.cfg.transport
  f.cfg.transport = function(request)
    local result = transport(request)
    f.identity.account = "changed"
    return result
  end
  reject(f, "provider resolution changed", 1)
  f = fixture()
  f.ctx.cancelled = function() return true end
  reject(f, "synthesis cancelled", 0)
  f = fixture()
  transport = f.cfg.transport
  local cancelled = false
  f.ctx.cancelled = function() return cancelled end
  f.cfg.transport = function(request) cancelled = true; return transport(request) end
  reject(f, "synthesis cancelled", 1)
end)

for _, stage in ipairs({ "complete_request", "complete_transport_request" }) do
  for _, change in ipairs({ "cancellation", "route" }) do
    it("rejects " .. change .. " during " .. stage .. " before dispatch", function()
      local f = fixture()
      local cancelled = false
      f.ctx.cancelled = function() return cancelled end
      f.cfg.disclosure.inspect = function(_, location)
        if location == stage then
          if change == "cancellation" then cancelled = true else f.identity.account = "changed" end
        end
        return "clear"
      end
      reject(f, change == "cancellation" and "synthesis cancelled" or "provider resolution changed", 0)
    end)
  end
end

it("checks cancellation after identity resolution", function()
  local f = fixture()
  local cancelled = false
  f.ctx.cancelled = function() return cancelled end
  f.cfg.resolve_identity = function() cancelled = true; return vim.deepcopy(f.identity) end
  reject(f, "synthesis cancelled", 0)
end)

for _, change in ipairs({ "route", "cancellation" }) do
  it("rejects " .. change .. " during final identity resolution before dispatch", function()
    local f = fixture()
    local cancelled, calls = false, 0
    f.ctx.cancelled = function() return cancelled end
    f.cfg.resolve_identity = function()
      calls = calls + 1
      if calls == 2 then
        if change == "route" then f.identity.endpoint = "changed" else cancelled = true end
      end
      return vim.deepcopy(f.identity)
    end
    reject(f, change == "route" and "provider resolution changed" or "synthesis cancelled", 0)
  end)
end

for _, callback in ipairs({ "resolve_identity", "cancelled" }) do
  it("refuses yielding final " .. callback .. " validation", function()
    local f = fixture()
    local calls = 0
    local owner = callback == "cancelled" and f.ctx or f.cfg
    local original = owner[callback]
    owner[callback] = function()
      calls = calls + 1
      if calls == 2 then coroutine.yield(true) end
      return original()
    end
    reject(f, "provider validation yielded", 0)
  end)
end

it("requires explicit successful completion metadata on both responses", function()
  for response = 1, 2 do
    for _, field in ipairs({ "complete", "refused", "incomplete", "tool_output", "stop_reason" }) do
      local f = fixture()
      f.results[response].metadata[field] = nil
      reject(f, "unassessed provider result", response)
      f = fixture()
      f.results[response].metadata[field] = field == "stop_reason" and "max_tokens" or field ~= "complete"
      reject(f, "unassessed provider result", response)
    end
    local f = fixture()
    f.results[response].metadata = nil
    reject(f, "unassessed provider result", response)
  end
end)

it("rejects malformed, oversized, tool-bearing and failed results", function()
  for response = 1, 2 do
    local f = fixture()
    f.results[response].text = "not JSON"
    reject(f, "malformed synthesis JSON", response)
    f = fixture()
    f.results[response].text = string.rep("x", 65537)
    reject(f, "unassessed provider result", response)
    f = fixture()
    f.results[response].tool_calls = {}
    reject(f, "unassessed provider result", response)
  end
  local f = fixture()
  f.cfg.transport = function() error("SECRET_BYTES") end
  reject(f, "transport unavailable", 0)
end)

it("checks disclosure in source evidence, tool source, metadata, values and keys", function()
  for _, location in ipairs({ "source", "tool_source", "metadata", "evidence", "key" }) do
    local f = fixture()
    if location == "source" then f.ticket.payload.sources.s1.value = "SECRET_BYTES"
    elseif location == "tool_source" then f.ticket.payload.tool.source.value = "SECRET_BYTES"
    elseif location == "metadata" then f.ticket.payload.tool.metadata.description.value = "SECRET_BYTES"
    elseif location == "evidence" then f.ticket.payload.evidence.value = "SECRET_BYTES"
    else f.ticket.payload.SECRET_BYTES = leaf("public") end
    reject(f, "credential inspection", 0)
  end
  for _, sensitivity in ipairs({ "credential", "unknown", "confidential" }) do
    local f = fixture()
    f.ticket.payload.evidence.sensitivity = sensitivity
    reject(f, sensitivity == "credential" and "credential material" or "unapproved sensitivity", 0)
  end
  local f = fixture()
  f.ticket.payload.evidence.filtered = true
  reject(f, "required evidence filtered", 0)
  f = fixture()
  f.ticket.payload.evidence.value = { nested = "unclassified" }
  reject(f, "disclosure leaves must be scalar", 0)
  f = fixture()
  f.cfg.disclosure.inspect = function() return "unknown" end
  reject(f, "credential inspection", 0)
end)

it("rejects sparse local ticket evidence before transport", function()
  local f = fixture()
  local evidence = { leaf("preserve files"), leaf("preserve files"), leaf("preserve files"), leaf("never dispatch") }
  evidence[2] = nil
  f.ticket.payload.sources.s1 = evidence
  local adapter = synthesis.new(f.cfg)
  adapter(f.ticket, f.ctx)
  check(#f.calls == 0, "sparse local ticket must not dispatch transport")
end)

it("rejects unsupported evidence and incomplete task schemas", function()
  local f = fixture()
  f.ticket.payload.sources.s1 = nil
  reject(f, "source evidence missing", 0)
  f = fixture()
  f.ticket.payload.sources.other = leaf("forged")
  reject(f, "unknown source evidence", 0)
  f = fixture()
  f.ticket.payload.evidence.value = string.rep("x", 65537)
  reject(f, "unbounded synthesis ticket", 0)
  f = fixture()
  f.ticket.sources.s1.revoked = true
  reject(f, "invalid sources", 1)
  for _, field in ipairs({ "schema_version", "task_id", "instruction_revision", "outcome", "mode", "targets", "effects", "constraints", "reserved_decisions", "latitude", "unresolved_scope" }) do
    f = fixture()
    f.spec[field] = nil
    f.results[1] = f.result(f.spec)
    reject(f, "invalid task schema", 1)
  end
  f = fixture()
  f.spec.task_id = "other"
  f.results[1] = f.result(f.spec)
  reject(f, "task identity mismatch", 1)
  f = fixture()
  f.spec.constraints.sources = { "forged" }
  f.results[1] = f.result(f.spec)
  reject(f, "invalid sources", 1)
end)

it("rejects every synthesis defect and missing check", function()
  for _, id in ipairs(questions.synthesis_ids()) do
    local f = fixture()
    f.checks[id].score = 0.5
    f.results[2] = f.result(f.checks)
    reject(f, "synthesis defects: " .. id, 2)
    f = fixture()
    f.checks[id] = nil
    f.results[2] = f.result(f.checks)
    reject(f, "incomplete synthesis battery", 2)
  end
end)
