local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(vim.fn.fnamemodify(here, ":p"), ":h:h")
package.path = root .. "/lua/?.lua;" .. root .. "/lua/?/init.lua;" .. package.path

local adapter = require("straps_classifier.adapter")
local best = require("straps_classifier.best_effort")

local function options(extra)
  local value = { enabled = true, acknowledge_risk = true, disclosure_approved = true, operator_scope = "Edit /workspace" }
  for k, v in pairs(extra or {}) do value[k] = v end
  return value
end
local favorable = { authority = "established", prohibition = "absent", credential_disclosure = "absent",
  protection_tampering = "absent", material_uncertainty = "absent", recommendation = "allow" }
local function text_of(tbl) return vim.json.encode(tbl) end

describe("adapter option validation", function()
  for _, case in ipairs({
    { "no adapter", nil, true }, { "typesafe", { name = "typesafe" }, true },
    { "anthropic", { name = "anthropic" }, true },
    { "anthropic with model and budget", { name = "anthropic", model = "claude-sonnet-5", max_tokens = 8000 }, true },
    { "anthropic with timeout", { name = "anthropic", timeout_ms = 45000 }, true },
    { "timeout on typesafe", { name = "typesafe", timeout_ms = 45000 }, false },
    { "small timeout", { name = "anthropic", timeout_ms = 999 }, false },
    { "large timeout", { name = "anthropic", timeout_ms = 120001 }, false },
    { "unknown name", { name = "openai" }, false }, { "missing name", {}, false },
    { "unknown key", { name = "anthropic", temperature = 0 }, false },
    { "blank model", { name = "anthropic", model = " " }, false },
    { "budget on typesafe", { name = "typesafe", max_tokens = 4000 }, false },
    { "small budget", { name = "anthropic", max_tokens = 999 }, false },
    { "fractional budget", { name = "anthropic", max_tokens = 4000.5 }, false },
    { "metatable", setmetatable({ name = "anthropic" }, {}), false },
    { "typesafe votes", { name = "typesafe", votes = 1 }, true },
    { "five typesafe votes", { name = "typesafe", votes = 5 }, true },
    { "zero votes", { name = "typesafe", votes = 0 }, false },
    { "six votes", { name = "typesafe", votes = 6 }, false },
    { "fractional votes", { name = "typesafe", votes = 2.5 }, false },
    { "votes on anthropic", { name = "anthropic", votes = 3 }, false },
  }) do
    it((case[3] and "accepts " or "rejects ") .. case[1], function()
      assert.equals(case[3], (pcall(best.validate, options({ adapter = case[2] }))))
    end)
  end
end)

describe("adapter resolution", function()
  it("defaults to typesafe with the configured model and three orderings", function()
    assert.same({ name = "typesafe", model = "jev-9", votes = 3 }, adapter.resolve(options(), { model = "jev-9" }))
  end)
  it("defaults anthropic to sonnet 5 with a reasoning budget and its own timeout", function()
    assert.same({ name = "anthropic", model = "claude-sonnet-5", max_tokens = 4000, timeout_ms = 30000 },
      adapter.resolve(options({ adapter = { name = "anthropic" } }), { model = "jev-latest" }))
  end)
  it("keeps an explicit anthropic model over the legacy model option", function()
    assert.equals("claude-opus-4-8", adapter.resolve(options({ adapter = { name = "anthropic", model = "claude-opus-4-8" } }),
      { model = "jev-latest" }).model)
  end)
  it("puts the resolved model into the payload", function()
    local payload = best.payload("bash", { command = "true" }, { model = "jev-latest",
      best_effort = options({ adapter = { name = "anthropic" } }) }, { source = "return function() end" }, "/w")
    assert.equals("claude-sonnet-5", payload.model)
  end)
end)

describe("anthropic request", function()
  it("carries state and questions in one user message under the classifier system prompt", function()
    local payload = { model = "x", state = { cwd = "/w" }, questions = best.questions() }
    local req = adapter.anthropic_request(payload, { model = "claude-sonnet-5", max_tokens = 4000 })
    assert.equals("claude-sonnet-5", req.model)
    assert.equals(4000, req.max_tokens)
    assert.equals(adapter.SYSTEM, req.system)
    assert.equals(1, #req.messages)
    assert.same({ state = payload.state, questions = payload.questions }, vim.json.decode(req.messages[1].content))
  end)
end)

describe("anthropic response parsing", function()
  local questions = best.questions()
  local function response(text, stop)
    return { stop_reason = stop or "end_turn", content = { { type = "thinking", thinking = "" }, { type = "text", text = text } } }
  end
  it("accepts a bare JSON object and routes ok", function()
    local answers = assert(adapter.anthropic_response(response(text_of(favorable)), questions))
    assert.equals("ok", best.route(answers))
  end)
  it("accepts a fenced object followed by prose", function()
    local answers = assert(adapter.anthropic_response(response("```json\n" .. text_of(favorable) .. "\n```\n\n**Rationale:** {not json}"), questions))
    assert.equals("ok", best.route(answers))
  end)
  it("handles braces inside strings before the object ends", function()
    local value = vim.deepcopy(favorable)
    local answers = adapter.parse_choices('note "{" ' .. text_of(value), questions)
    assert.is_nil(answers)
    answers = assert(adapter.parse_choices(text_of(value) .. ' trailing "}"', questions))
    assert.equals("ok", best.route(answers))
  end)
  it("routes a single unfavorable choice to deny", function()
    local value = vim.deepcopy(favorable)
    value.protection_tampering = "present"
    assert.equals("deny", best.route(assert(adapter.anthropic_response(response(text_of(value)), questions))))
  end)
  for _, case in ipairs({
    { "max_tokens stop", response(text_of(favorable), "max_tokens") },
    { "thinking only", { stop_reason = "max_tokens", content = { { type = "thinking", thinking = "" } } } },
    { "no text block", { stop_reason = "end_turn", content = {} } },
    { "error envelope", { type = "error", error = { type = "overloaded_error" } } },
    { "missing field", response(text_of({ authority = "established" })) },
    { "invalid choice", response(text_of(vim.tbl_extend("force", favorable, { prohibition = "maybe" }))) },
    { "extra identity", response(text_of(vim.tbl_extend("force", favorable, { injected = "allow" }))) },
    { "unterminated", response('{"authority": "established"') },
    { "no object", response("I cannot answer that.") },
  }) do
    it("treats " .. case[1] .. " as unavailable", function()
      local answers, err = adapter.anthropic_response(case[2], questions)
      assert.is_nil(answers)
      assert.is_string(err)
    end)
  end
end)

describe("verdict transport selection", function()
  local saved_registry, saved_entries, calls
  local function favorable_answers(questions)
    local result = {}
    for id, question in pairs(questions) do
      if question.type == "noul" then
        result[id] = { type = "noul", noul = (id == "scope_permits_effects") and 1 or 0 }
      else
        result[id] = { type = "choice", choice = favorable[id], confidence = 1 }
      end
    end
    return result
  end
  before_each(function()
    saved_registry, saved_entries = package.loaded["straps.registry"], package.loaded["straps_classifier.entries"]
    calls = {}
    package.loaded["straps.registry"] = {
      get = function() return { source = "return function() end" } end,
      call = function(name, payload, ctx, extra)
        calls[#calls + 1] = { name = name, spec = extra, model = payload.model }
        return favorable_answers(payload.questions)
      end,
      try_call = function() end,
    }
    package.loaded["straps_classifier.entries"] = { start_progress = function() return function() end end }
  end)
  after_each(function()
    package.loaded["straps.registry"], package.loaded["straps_classifier.entries"] = saved_registry, saved_entries
  end)
  it("uses fn.typesafe by default, once per ordering", function()
    assert.equals("ok", (best.verdict("bash", {}, { await = function() end }, { model = "jev-latest", best_effort = options() })))
    assert.equals(3, #calls)
    for _, call in ipairs(calls) do
      assert.equals("fn.typesafe", call.name)
      assert.equals("jev-latest", call.model)
      assert.is_string(call.spec)
    end
  end)
  it("uses fn.classifier_anthropic when selected", function()
    local cfg = { model = "jev-latest", best_effort = options({ adapter = { name = "anthropic" } }) }
    assert.equals("ok", (best.verdict("bash", {}, { await = function() end }, cfg)))
    assert.equals(1, #calls)
    assert.equals("fn.classifier_anthropic", calls[1].name)
    assert.equals("claude-sonnet-5", calls[1].model)
    assert.same({ name = "anthropic", model = "claude-sonnet-5", max_tokens = 4000, timeout_ms = 30000 }, calls[1].spec)
  end)
end)
