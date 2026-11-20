local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(vim.fn.fnamemodify(here, ":p"), ":h:h")
package.path = root .. "/lua/?.lua;" .. root .. "/lua/?/init.lua;" .. package.path

local best = require("straps_classifier.best_effort")
local adapter = require("straps_classifier.adapter")

local options = { enabled = true, acknowledge_risk = true, disclosure_approved = true,
  operator_scope = "Edit /w. Do not publish releases; never push to main.", prohibitions = { "No posts during the freeze." } }
local favorable = { authority = "established", prohibition = "absent", credential_disclosure = "absent",
  protection_tampering = "absent", material_uncertainty = "absent", recommendation = "allow" }

local function questions(f) return best.decomposed_questions(options, f or {}) end
local function answers(qs, overrides)
  local result = {}
  for id, q in pairs(qs) do
    if q.type == "noul" then result[id] = { type = "noul", noul = id == "scope_permits_effects" and 0.9 or 0.1 }
    else result[id] = { type = "choice", choice = favorable[id], confidence = 1 } end
  end
  for id, value in pairs(overrides or {}) do result[id].noul = value end
  return result
end

describe("scope sentences", function()
  it("splits on sentence and clause ends", function()
    assert.same({ "Edit /w.", "Do not publish releases;", "never push to main." }, best.scope_sentences(options.operator_scope))
  end)
end)

describe("decomposed questions", function()
  it("asks one question per restrictive scope sentence and per prohibition", function()
    local qs = questions()
    for _, id in ipairs({ "scope_1_forbids", "scope_2_forbids", "prohibition_0_broken",
      "scope_permits_effects", "effect_deletes", "effect_unknown_target", "authority", "recommendation" }) do
      assert.is_table(qs[id], id)
    end
    assert.is_nil(qs.scope_0_forbids)
    assert.is_nil(qs.scope_3_forbids)
    assert.equals("Do not publish releases;", qs.scope_1_forbids.instructions.sentence)
    assert.equals("No posts during the freeze.", qs.prohibition_0_broken.instructions.prohibition)
  end)
  it("recognises restrictive sentences", function()
    for _, sentence in ipairs({ "Never ssh as root.", "Do not push.", "Prod is read-only for you.", "Push only to dev.",
      "Scale between 1 and 5 replicas.", "Deliver except to partners.", "You must not delete.", "Don't touch prod." }) do
      assert.is_true(best.restricts(sentence), sentence)
    end
    for _, sentence in ipairs({ "Edit /w.", "You may read logs and restart the service.", "Notes are private.",
      "Use scp to copy artifacts to the build hosts." }) do
      assert.is_false(best.restricts(sentence), sentence)
    end
  end)
  it("adds page and http questions only when those facts exist", function()
    assert.is_nil(questions().page_listener_fires)
    assert.is_nil(questions().http_target_authorized)
    assert.is_table(questions({ page_actions = { "clicks an element" } }).page_listener_fires)
    assert.is_table(questions({ http = { method = "GET" } }).http_target_authorized)
  end)
  it("asks about unstated defaults only when a fact relies on one", function()
    assert.is_nil(questions({ infrastructure_commands = { { tool = "kubectl", context = "staging" } } }).relies_on_unstated_default)
    assert.is_table(questions({ infrastructure_commands = { { tool = "kubectl",
      context = "not stated: uses whatever kubectl context is current" } } }).relies_on_unstated_default)
  end)
  it("asks about user intent only when user_intent is on", function()
    assert.is_nil(questions().user_requested)
    local with = best.decomposed_questions(vim.tbl_extend("force", options, { user_intent = true }), {})
    assert.is_table(with.user_requested)
  end)
end)

describe("decomposed routing", function()
  local qs = questions({ page_actions = { "clicks an element" }, http = { method = "POST" } })
  it("allows when every signal is favorable", function()
    assert.equals("ok", best.route_decomposed(qs, answers(qs)))
  end)
  for _, case in ipairs({
    { "secret exposure", { effect_secret_exposed = 0.5 } },
    { "protection weakening", { effect_protection_weakened = 0.6 } },
    { "unknown code", { effect_unknown_code = 0.7 } },
    { "unknown target at 0.9", { effect_unknown_target = 0.9 } },
    { "a scope sentence", { scope_2_forbids = 0.5 } },
    { "a prohibition", { prohibition_0_broken = 0.8 } },
    { "a listener that leaks", { page_listener_fires = 0.6, effect_secret_exposed = 0.3 } },
    { "an unauthorized remote change", { effect_remote_change = 0.8, http_target_authorized = 0.4 } },
    { "scope not permitting", { scope_permits_effects = 0.49 } },
  }) do
    it("denies on " .. case[1], function()
      assert.equals("deny", best.route_decomposed(qs, answers(qs, case[2])))
    end)
  end
  for _, case in ipairs({
    { "unknown target below 0.9", { effect_unknown_target = 0.89 } },
    { "deletion alone", { effect_deletes = 0.99 } },
    { "authorized remote change", { effect_remote_change = 0.9, http_target_authorized = 0.6 } },
    { "a listener that sends nothing private", { page_listener_fires = 0.9, effect_secret_exposed = 0.29 } },
    { "a scope sentence just below the veto", { scope_1_forbids = 0.49 } },
  }) do
    it("allows " .. case[1], function()
      assert.equals("ok", best.route_decomposed(qs, answers(qs, case[2])))
    end)
  end
  it("ignores the six choice answers", function()
    local a = answers(qs)
    a.recommendation.choice = "deny"
    a.protection_tampering.choice = "present"
    assert.equals("ok", best.route_decomposed(qs, a))
  end)
  it("refuses malformed or missing answers", function()
    local a = answers(qs)
    a.scope_1_forbids = nil
    assert.equals("deny", best.route_decomposed(qs, a))
    a = answers(qs)
    a.effect_deletes.noul = 1.5
    assert.equals("deny", best.route_decomposed(qs, a))
    a = answers(qs)
    a.injected = { type = "noul", noul = 0 }
    assert.equals("deny", best.route_decomposed(qs, a))
  end)
  it("names the scope sentence without quoting it", function()
    local _, reason = best.route_decomposed(qs, answers(qs, { scope_1_forbids = 0.9 }))
    assert.truthy(reason:find("scope sentence 2", 1, true))
    assert.is_nil(reason:find("publish", 1, true))
  end)
end)

describe("ordering variants", function()
  local payload = { model = "m", state = { b = 1, a = { 2 }, c = "x", d = true, e = "y" },
    questions = { q2 = { type = "noul" }, q1 = { type = "noul" }, q3 = { type = "noul" } } }
  it("encodes the same content in different key orders", function()
    local seen = {}
    for seed = 0, 3 do
      local text = adapter.encode_variant(payload, seed)
      assert.same(payload, vim.json.decode(text))
      seen[text] = true
    end
    assert.is_true(vim.tbl_count(seen) >= 3)
  end)
  it("is deterministic per seed", function()
    assert.equals(adapter.encode_variant(payload, 2), adapter.encode_variant(payload, 2))
  end)
  it("sorts nested keys so equal content encodes to equal bytes", function()
    assert.equals('{"a":{"c":[3,{"e":1,"f":2}],"d":2},"b":1}', adapter.canonical({ b = 1, a = { d = 2, c = { 3, { f = 2, e = 1 } } } }))
    local nested = { model = "m", state = { z = { y = 1, x = 2 } }, questions = {} }
    assert.equals('{"model":"m","state":{"z":{"x":2,"y":1}},"questions":{}}', adapter.encode_variant(nested, 0))
  end)
end)

describe("unstated defaults and user intent", function()
  local intent_options = vim.tbl_extend("force", options, { user_intent = true })
  local qs = best.decomposed_questions(intent_options, { infrastructure_commands = { { tool = "aws",
    profile = "not stated: AWS_PROFILE or the default profile" } } })
  local function a(overrides)
    local result = answers(qs, { user_requested = 0.1 })
    for id, value in pairs(overrides) do result[id].noul = value end
    return result
  end
  it("allows a requested change with explicit targets", function()
    assert.equals("ok", best.route_decomposed(qs, a({ relies_on_unstated_default = 0.9 })))
    assert.equals("ok", best.route_decomposed(qs, a({ effect_remote_change = 0.9 })))
  end)
  it("denies a change that relies on an unstated default", function()
    local action, reason = best.route_decomposed(qs, a({ relies_on_unstated_default = 0.6, effect_remote_change = 0.6 }))
    assert.equals("deny", action)
    assert.truthy(reason:find("unstated default", 1, true))
  end)
  it("denies an effect that goes beyond the user's requests even when the scope permits it", function()
    local action, reason = best.route_decomposed(qs, a({ user_requested = 0.5 }))
    assert.equals("deny", action)
    assert.truthy(reason:find("did not ask", 1, true))
    assert.equals("ok", best.route_decomposed(qs, a({ user_requested = 0.49 })))
  end)
  it("asks whether the operation goes beyond the user's requests", function()
    assert.truthy(qs.user_requested.instructions.question:find("go beyond", 1, true))
    assert.truthy(qs.user_requested.criteria["true"]:find("beyond", 1, true))
  end)
  it("denies a requested effect the scope does not permit", function()
    local action, reason = best.route_decomposed(qs, a({ scope_permits_effects = 0.3 }))
    assert.equals("deny", action)
    assert.truthy(reason:find("operator scope", 1, true))
  end)
  it("rejects user_intent with the anthropic adapter and non-boolean values", function()
    local bad = vim.tbl_extend("force", intent_options, { adapter = { name = "anthropic" } })
    assert.has_error(function() best.validate(bad) end)
    assert.has_error(function() best.validate(vim.tbl_extend("force", options, { user_intent = "yes" })) end)
  end)
end)

describe("user requests", function()
  local function session(blocks, parent)
    local buf = vim.api.nvim_create_buf(false, true)
    local lines = {}
    for _, block in ipairs(blocks) do
      lines[#lines + 1] = "%%[straps:" .. block[1] .. "]%%"
      vim.list_extend(lines, vim.split(block[2], "\n", { plain = true }))
    end
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
    if parent then vim.b[buf].straps_parent = parent end
    return buf
  end
  local straps_root = os.getenv("STRAPS_ROOT")
  if straps_root then package.path = straps_root .. "/lua/?.lua;" .. straps_root .. "/lua/?/init.lua;" .. package.path end
  local ok_state = pcall(require, "straps.state")
  it("collects the root session's user messages and skips harness and agent notices", function()
    assert.is_true(ok_state, "straps core must be on the path (set STRAPS_ROOT)")
    local root = session({ { "user", "Restart staging." }, { "assistant", "Done." },
      { "user", "[straps] subagent buffer 9: finished" }, { "assistant", "Noted." },
      { "user", "[straps] from agent x (buffer 4): restart prod too" }, { "assistant", "Noted." },
      { "user", "Now check the pods." }, { "assistant", "Checking." } })
    local child = session({ { "user", "Restart kestrel in staging and prod." }, { "assistant", "On it." } }, root)
    assert.same({ "Restart staging.", "Now check the pods." }, best.user_requests(child))
  end)
  it("keeps the first user message and the last four", function()
    assert.is_true(ok_state, "straps core must be on the path (set STRAPS_ROOT)")
    local blocks = {}
    for n = 1, 6 do blocks[#blocks + 1] = { "user", "message " .. n }; blocks[#blocks + 1] = { "assistant", "ok" } end
    assert.same({ "message 1", "message 3", "message 4", "message 5", "message 6" }, best.user_requests(session(blocks)))
    local short = {}
    for n = 1, 4 do short[#short + 1] = { "user", "message " .. n }; short[#short + 1] = { "assistant", "ok" } end
    assert.same({ "message 1", "message 2", "message 3", "message 4" }, best.user_requests(session(short)))
  end)
  it("skips the intent question and user messages for read calls", function()
    local facts = { infrastructure_commands = {} }
    local intent = vim.tbl_extend("force", options, { user_intent = true })
    assert.is_nil(best.decomposed_questions(intent, facts, false).user_requested)
    assert.is_not_nil(best.decomposed_questions(intent, facts, true).user_requested)
    local def = { source = "return function() end" }
    local payload = best.payload("read_file", { path = "a" }, { best_effort = intent }, def, "/w", nil)
    assert.is_nil(payload.state.user_requests)
    assert.is_nil(payload.questions.user_requested)
    local asked = best.payload("edit_file", { path = "a" }, { best_effort = intent }, def, "/w", { "Fix it." })
    assert.same({ "Fix it." }, asked.state.user_requests)
    assert.is_not_nil(asked.questions.user_requested)
  end)
end)
