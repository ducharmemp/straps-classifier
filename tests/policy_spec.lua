-- tests/policy_spec.lua — policy.route: every threshold boundary.
--   busted tests/policy_spec.lua
-- No network, no straps: policy.lua and questions.lua are pure Lua.

local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(vim.fn.fnamemodify(here, ":p"), ":h:h")
vim.opt.rtp:prepend(root)
package.path = root .. "/lua/?.lua;" .. root .. "/lua/?/init.lua;" .. package.path

local questions = require("straps_classifier.questions")
local policy = require("straps_classifier.policy")

local CFG = {
  deny_threshold = 0.85,
  damage_deny = 2.5,
  opaque_action = "deny",
}

-- A well-formed answer set with every noul at `p` and damage at `score`.
local function answers(p, score, conf)
  local out = {}
  for _, id in ipairs(questions.ids()) do
    out[id] = { type = "noul", noul = p }
  end
  local legend = {}
  for i, text in ipairs(questions.DAMAGE_LEVELS) do
    legend[tostring(i - 1)] = text
  end
  out.damage = {
    type = "score",
    score = score or 0,
    legend = legend,
    confidence = conf == nil and 0.9 or conf,
  }
  return out
end

it("a quiet battery is ok", function()
  local action, reason = policy.route(answers(0.02, 0.1), CFG)
  assert(action == "ok", "want ok, got " .. action .. ": " .. reason)
end)

it("a hazard at the threshold denies", function()
  local a = answers(0.1, 0.1)
  a.writes_outside_root.noul = 0.85
  local action, reason = policy.route(a, CFG)
  assert(action == "deny", "0.85 should deny")
  assert(reason:find("writes_outside_root=0.85", 1, true), "reason should carry id and probability: " .. reason)
end)

it("a hazard just below the threshold does not deny", function()
  local a = answers(0.1, 0.1)
  a.writes_outside_root.noul = 0.84
  local action = policy.route(a, CFG)
  assert(action == "ok", "0.84 should not deny")
end)

it("the reason names the highest hazard", function()
  local a = answers(0.1, 0.1)
  a.reads_credentials.noul = 0.93
  a.sends_message.noul = 0.90
  local action, reason = policy.route(a, CFG)
  assert(action == "deny", "want deny")
  assert(reason:find("reads_credentials", 1, true), "reason should name reads_credentials: " .. reason)
end)

it("the signal alone never denies as a hazard", function()
  local a = answers(0.1, 0.1)
  a.runs_script_outside_root.noul = 0.99
  local action, reason = policy.route(a, { deny_threshold = 0.85, damage_deny = 2.5, opaque_action = "log" })
  assert(action == "ok", "signal with opaque_action=log must not deny: " .. reason)
  assert(reason:find("opaque", 1, true), "reason should log the signal: " .. reason)
end)

it("the signal denies when opaque_action is deny", function()
  local a = answers(0.1, 0.1)
  a.runs_script_outside_root.noul = 0.99
  local action, reason = policy.route(a, CFG)
  assert(action == "deny", "opaque_action=deny must deny")
  assert(reason:find("opaque", 1, true), "reason should say opaque: " .. reason)
end)

it("opaque_action defaults to deny", function()
  local a = answers(0.1, 0.1)
  a.runs_script_outside_root.noul = 0.99
  local action = policy.route(a, { deny_threshold = 0.85, damage_deny = 2.5 })
  assert(action == "deny", "the default must be deny")
end)

it("a hazard deny outranks the opaque signal in the reason", function()
  local a = answers(0.1, 0.1)
  a.runs_script_outside_root.noul = 0.99
  a.transmits_local_data.noul = 0.95
  local _, reason = policy.route(a, CFG)
  assert(reason:find("transmits_local_data", 1, true), "hazard should decide: " .. reason)
end)

it("damage at the threshold denies on its own", function()
  local action, reason = policy.route(answers(0.05, 2.5), CFG)
  assert(action == "deny", "damage 2.5 should deny")
  assert(reason:find("damage", 1, true), "reason should name damage: " .. reason)
end)

it("low damage confidence does not downgrade a deny", function()
  local action = policy.route(answers(0.05, 2.9, 0.1), CFG)
  assert(action == "deny", "confidence must not open the gate")
end)

it("redefines_protected is ignored for an edit-capability tool", function()
  local a = answers(0.05, 0.1)
  a.redefines_protected.noul = 0.99
  local action = policy.route(a, CFG, "edit")
  assert(action == "ok", "an edit tool's redefines_protected must not deny")
  local action2 = policy.route(a, CFG, "lua")
  assert(action2 == "deny", "a lua tool's redefines_protected must deny")
  local action3 = policy.route(a, CFG, nil)
  assert(action3 == "deny", "an unknown capability must not skip anything")
end)

it("a mismatched damage legend denies", function()
  local a = answers(0.01, 0.0)
  a.damage.legend["2"] = "something else entirely"
  local action, reason = policy.route(a, CFG)
  assert(action == "deny", "a moved legend must deny")
  assert(reason:find("legend", 1, true), "reason should name the legend: " .. reason)
end)

it("a missing hazard answer denies", function()
  local a = answers(0.01, 0.0)
  a.reads_credentials = nil
  local action, reason = policy.route(a, CFG)
  assert(action == "deny", "a missing answer must deny")
  assert(reason:find("reads_credentials", 1, true), "reason should name it: " .. reason)
end)

it("a missing signal answer denies", function()
  local a = answers(0.01, 0.0)
  a.runs_script_outside_root = nil
  local action = policy.route(a, CFG)
  assert(action == "deny", "a missing signal must deny")
end)

it("a missing damage answer denies", function()
  local a = answers(0.01, 0.0)
  a.damage = nil
  local action = policy.route(a, CFG)
  assert(action == "deny", "a missing damage answer must deny")
end)

it("nil answers deny", function()
  local action = policy.route(nil, CFG)
  assert(action == "deny", "nil must deny")
end)

it("unreachable thresholds let nothing deny", function()
  local a = answers(0.99, 3.0)
  a.runs_script_outside_root.noul = 0.99
  local action, reason = policy.route(a, { deny_threshold = 1.1, damage_deny = 99, opaque_action = "deny" })
  assert(action == "ok", "1.1 is unreachable for every probability, signal included: " .. reason)
end)

it("cutoffs override one command hazard at a time", function()
  local cut, deny_at = policy.cutoffs(CFG)
  assert(deny_at == 0.85, "threshold from deny_threshold")
  for _, id in ipairs(questions.ids()) do
    assert(cut[id] == 0.85, id .. " defaults to deny_threshold")
  end
  local a = answers(0.05, 0.1)
  a.pushes_or_publishes.noul = 0.96
  assert(policy.route(a, CFG) == "deny", "0.96 denies at the default")
  local relaxed = vim.tbl_extend("force", CFG, { cutoffs = { pushes_or_publishes = 1.1 } })
  local action, reason = policy.route(a, relaxed)
  assert(action == "ok", "a cutoff above 1 disables that hazard alone: " .. reason)
  a.writes_outside_root.noul = 0.9
  local action2, reason2 = policy.route(a, relaxed)
  assert(action2 == "deny" and reason2:find("writes_outside_root=0.90", 1, true), "other hazards keep the threshold: " .. reason2)
  local tight = vim.tbl_extend("force", CFG, { cutoffs = { sends_message = 0.3 } })
  local b = answers(0.05, 0.1)
  b.sends_message.noul = 0.35
  b.reads_credentials.noul = 0.8
  local action3, reason3 = policy.route(b, tight)
  assert(action3 == "deny" and reason3:find("sends_message=0.35 (>= 0.30)", 1, true),
    "the hazard furthest over its own cutoff decides: " .. reason3)
  local c = answers(0.05, 0.1)
  c.runs_script_outside_root.noul = 0.9
  local off = vim.tbl_extend("force", CFG, { cutoffs = { runs_script_outside_root = 1.1 } })
  assert(policy.route(c, off) == "ok", "the signal has a cutoff too")
  local edit = answers(0.05, 0.1)
  edit.redefines_protected.noul = 0.99
  assert(policy.route(edit, vim.tbl_extend("force", CFG, { cutoffs = { redefines_protected = 0.1 } }), "edit") == "ok",
    "a cutoff does not un-skip redefines_protected for edit tools")
end)

it("the battery has the documented shape", function()
  assert(#questions.DAMAGE_LEVELS == 4, "want 4 levels")
  local hazards = questions.ids("hazard")
  local signals = questions.ids("signal")
  assert(#hazards == 11, "want 11 noul hazards, got " .. #hazards)
  assert(#signals == 1 and signals[1] == "runs_script_outside_root", "want one signal")
  local battery = questions.battery()
  for _, id in ipairs(questions.ids()) do
    assert(battery[id].type == "noul", id .. " should be a noul")
    assert(type(battery[id].instructions) == "table", id .. " should use object instructions")
    assert(battery[id].criteria["true"] and battery[id].criteria["false"], id .. " needs both criteria")
  end
  assert(battery.damage.type == "score", "damage should be a score")
  assert(battery.damage.criteria == questions.DAMAGE_LEVELS, "damage uses the pinned levels")
end)

it("state refuses an over-cap exec input and elides prose for edit tools", function()
  local big = ("x"):rep(5000)
  local cfg = { max_state_bytes = 4000 }
  local s, err = questions.state("bash", { command = big }, nil, cfg, { latest_user_request = "r", child = false })
  assert(s == nil and err:find("over"), "exec input over cap must refuse: " .. tostring(err))
  local s2 = questions.state("write_file", { path = "a/very/specific/path.lua", content = big }, nil, cfg,
    { latest_user_request = "r", child = false, capability = "edit" })
  assert(s2 ~= nil, "edit input over cap must render")
  assert(s2.tool_input:find("a/very/specific/path.lua", 1, true), "path survives elision")
  assert(s2.tool_input:find("elided", 1, true), "content is elided with a marker")
  assert(#s2.tool_input <= 4400, "rendered input near the cap: " .. #s2.tool_input)
  local s3 = questions.state("write_file", { path = "p", content = big }, nil, cfg,
    { latest_user_request = "r", child = false })
  assert(s3 == nil, "without a known capability, an over-cap input is refused")
end)

it("state names the request field by session kind", function()
  local cfg = { max_state_bytes = 4000 }
  local parent = questions.state("bash", { command = "ls" }, nil, cfg, { latest_user_request = "r", child = false })
  assert(parent.latest_user_request == "r" and parent.parent_agent_task == nil, "parent field")
  local child = questions.state("bash", { command = "ls" }, nil, cfg, { latest_user_request = "t", child = true })
  assert(child.parent_agent_task == "t" and child.latest_user_request == nil, "child field")
  assert(type(parent.project_root_parent) == "string", "parent dir present")
  assert(type(parent.temp_dirs) == "table" and #parent.temp_dirs > 0, "temp dirs present")
  assert(type(parent.resolved_paths) == "nil", "a command has no structured paths")
end)

it("state resolves structured paths against the root", function()
  local cfg = { max_state_bytes = 4000 }
  local s = questions.state("read_file", { path = "README.md" }, nil, cfg, { latest_user_request = "r", child = false })
  local r = s.resolved_paths["README.md"]
  assert(r and r.within == "project_root", "in-root path resolves to project_root: " .. vim.inspect(r))
  local s2 = questions.state("delete_files", { paths = { "README.md", "/etc/hosts" } }, nil, cfg,
    { latest_user_request = "r", child = false })
  assert(s2.resolved_paths["/etc/hosts"].within == "outside", "/etc is outside")
end)

it("dependency_roots lists the sibling straps checkout alongside STRAPS_ROOT", function()
  local root = vim.fn.getcwd()
  local sibling = vim.fn.fnamemodify(root, ":h") .. "/straps"
  local saved = vim.env.STRAPS_ROOT
  vim.env.STRAPS_ROOT = "/nix/store/abc-source"
  local deps = questions.dependency_roots(root)
  vim.env.STRAPS_ROOT = saved
  assert(deps[1] == "STRAPS_ROOT=/nix/store/abc-source", "STRAPS_ROOT leads: " .. vim.inspect(deps))
  assert(deps[#deps] == "/nix/store", "/nix/store last")
  local has_sibling = vim.tbl_contains(deps, sibling)
  assert(has_sibling == (vim.fn.isdirectory(sibling) == 1), "the sibling is listed iff it exists: " .. vim.inspect(deps))
  vim.env.STRAPS_ROOT = sibling
  local same = questions.dependency_roots(root)
  vim.env.STRAPS_ROOT = saved
  assert(same[1] == "STRAPS_ROOT=" .. sibling and same[2] == "/nix/store", "no duplicate when STRAPS_ROOT is the sibling: " .. vim.inspect(same))
end)

local function ask_answers(p, over)
  local out = {}
  for _, id in ipairs(questions.ids("hazard", "ask")) do
    out[id] = { type = "noul", noul = p }
  end
  out.marked_recommended = { type = "noul", noul = 0.05 }
  out.states_deciding_factor = { type = "noul", noul = 0.9 }
  for k, v in pairs(over or {}) do
    out[k].noul = v
  end
  return out
end

local LABELS = { "Add an index", "Rewrite in Rust", "Do nothing" }

local function signal_answers(p, over)
  local out = ask_answers(p)
  for i = 1, #LABELS do
    out["viable_" .. i] = { type = "noul", noul = 0.9 }
    out["disfavored_" .. i] = { type = "noul", noul = 0.1 }
  end
  out.asymmetric_detail = { type = "noul", noul = 0.1 }
  out.decoy_present = { type = "noul", noul = 0.1 }
  out.steer = { type = "choice", choice = "none", confidence = 0.9 }
  local legend = {}
  for i, text in ipairs(questions.FAIRNESS_LEVELS) do legend[tostring(i - 1)] = text end
  out.fairness = { type = "score", score = 0.3, legend = legend }
  for k, v in pairs(over or {}) do
    if type(v) == "number" then
      out[k].noul = v
    else
      out[k] = vim.tbl_extend("force", out[k], v)
    end
  end
  return out
end

it("a quiet ask battery is ok and needs no damage answer", function()
  local action, reason = policy.route(ask_answers(0.05), CFG, "read", "ask")
  assert(action == "ok", "want ok, got " .. action .. ": " .. reason)
end)

it("each ask noul at the threshold denies with its id and fix", function()
  for _, id in ipairs(questions.ids("hazard", "ask")) do
    local a = ask_answers(0.05)
    a[id].noul = 0.85
    local action, reason = policy.route(a, CFG, "read", "ask")
    assert(action == "deny", id .. " at 0.85 should deny")
    assert(reason:find(id .. "=0.85", 1, true), "reason should name " .. id .. ": " .. reason)
    assert(reason:find(questions.fix(id), 1, true), "reason should carry the fix: " .. reason)
    if policy.DO_NOT_ASK[id] then
      assert(reason:sub(1, 12) == "do not ask (", "do-not-ask prefix: " .. reason)
      assert(not reason:find("Ask again", 1, true), "no rework suffix when told not to ask: " .. reason)
    else
      assert(reason:sub(1, 23) == "question needs rework (", "rework prefix: " .. reason)
      assert(reason:find("Ask again with the reworked question.", 1, true), "rework suffix: " .. reason)
    end
  end
end)

it("an ask noul just below the threshold does not deny", function()
  local a = ask_answers(0.05)
  a.loaded_premise.noul = 0.84
  local action = policy.route(a, CFG, "read", "ask")
  assert(action == "ok", "0.84 should not deny")
end)

it("a missing ask answer denies", function()
  local a = ask_answers(0.05)
  a.vague_option = nil
  local action, reason = policy.route(a, CFG, "read", "ask")
  assert(action == "deny", "a missing ask answer must deny")
  assert(reason:find("vague_option", 1, true), "reason should name it: " .. reason)
end)

it("a NaN or out-of-range ask answer denies", function()
  for _, bad in ipairs({ 0 / 0, math.huge, -0.1, 1.5 }) do
    local a = ask_answers(0.05)
    a.package_deal.noul = bad
    local action, reason = policy.route(a, CFG, "read", "ask")
    assert(action == "deny", tostring(bad) .. " must deny")
    assert(reason:find("package_deal", 1, true), "reason should name it: " .. reason)
  end
end)

it("the hazard kind still needs damage", function()
  local a = answers(0.01, 0.0)
  a.damage = nil
  assert(policy.route(a, CFG, "read", "hazard") == "deny", "hazard kind without damage must deny")
end)

it("an unknown kind routes as the hazard battery", function()
  local action = policy.route(ask_answers(0.05), CFG, "read", "Ask")
  assert(action == "deny", "ask answers under an unknown kind must fail the hazard checks")
  assert(policy.route(answers(0.02, 0.1), CFG, "read", "Ask") == "ok", "hazard answers pass")
end)

it("ask_deny_threshold overrides and falls back to deny_threshold", function()
  local a = ask_answers(0.05)
  a.loaded_premise.noul = 0.7
  assert(policy.route(a, CFG, "read", "ask") == "ok", "0.7 is under the default")
  local cfg = { deny_threshold = 0.85, ask_deny_threshold = 0.6 }
  assert(policy.route(a, cfg, "read", "ask") == "deny", "ask_deny_threshold 0.6 should deny 0.7")
  local watch = { deny_threshold = 1.1 }
  local b = ask_answers(0.99)
  assert(policy.route(b, watch, "read", "ask") == "ok", "watch mode stops ask denies")
end)

it("the ask battery has the documented shape", function()
  local ids = questions.ids("hazard", "ask")
  assert(#ids == 8, "want 8 fixed ask hazards, got " .. #ids)
  assert(ids[1] == "vague_option", "vague_option leads")
  local battery = questions.battery("ask")
  assert(battery.damage == nil, "no damage in the ask battery")
  local roles = {}
  for _, q in ipairs(questions.questions_for("ask", 3)) do roles[q.id] = q.role end
  local n = 0
  for id, q in pairs(battery) do
    n = n + 1
    assert(q.type == "noul", id .. " should be a noul")
    assert(q.instructions.judge_by == questions.ASK_JUDGE_BY, id .. " should judge prose")
    assert(q.criteria["true"] and q.criteria["false"], id .. " needs both criteria")
    assert(q.fix == nil, id .. " must not send its fix")
    if roles[id] == "hazard" then
      assert(type(questions.fix(id)) == "string", id .. " needs fix text")
    else
      assert(questions.fix(id) == nil, id .. " is a signal and carries no fix")
    end
  end
  assert(n == 10, "with fewer than two options: 8 hazards and 2 fixed signals, got " .. n)
  assert(battery.marked_recommended and battery.states_deciding_factor, "fixed signals are always sent")
  local b3 = questions.battery("ask", 3)
  local m = 0
  for _ in pairs(b3) do m = m + 1 end
  assert(m == 20, "three options: 10 fixed plus viable and disfavored per option plus four set signals, got " .. m)
  assert(b3.viable_3.instructions.question:find("option 3", 1, true), "each viability question names its option")
  assert(b3.disfavored_3.instructions.question:find("Option 3", 1, true), "each disfavored question names its option")
  assert(b3.is_hobsons == nil and b3.strawman_alternative == nil and b3.unsupported_recommendation == nil
    and b3.false_dilemma == nil and b3.competent_1 == nil, "removed questions stay removed")
  assert(b3.steer.type == "choice" and b3.steer.criteria["3"] and b3.steer.criteria.none, "steer lists each option")
  assert(b3.fairness.type == "score" and b3.fairness.criteria == questions.FAIRNESS_LEVELS, "fairness uses the pinned levels")
  assert(b3.viable_4 == nil, "no question for an option that does not exist")
  assert(#questions.ids("hazard") == 11 and #questions.ids("signal") == 1, "hazard ids unchanged")
end)

it("a Hobson's choice denies and names the non-options", function()
  local a = signal_answers(0.05, { viable_2 = 0.07, viable_3 = 0.16 })
  local action, reason = policy.route(a, CFG, "read", "ask", LABELS)
  assert(action == "deny", "want deny: " .. reason)
  assert(reason:sub(1, 17) == "Hobson's choice (", "reason starts with the verdict: " .. reason)
  assert(reason:find('only option 1 "Add an index" is a real choice', 1, true), "reason names the real option: " .. reason)
  assert(reason:find('2 "Rewrite in Rust" (viable=0.07)', 1, true), "reason names each non-option: " .. reason)
  assert(reason:find("propose two or more genuinely different approaches", 1, true), "reason says what to do: " .. reason)
  assert(reason:find("single recommendation", 1, true), "reason offers the single-recommendation route: " .. reason)
  assert(reason:find("describe it as a competent engineer would build it", 1, true), "reason carries the strawman clause: " .. reason)
end)

it("a Hobson's choice with no viable option says so", function()
  local a = signal_answers(0.05, { viable_1 = 0.1, viable_2 = 0.07, viable_3 = 0.16 })
  local action, reason = policy.route(a, CFG, "read", "ask", LABELS)
  assert(action == "deny", "want deny")
  assert(reason:find("none of the options is a real choice", 1, true), "zero viable options: " .. reason)
  assert(not reason:find("single recommendation", 1, true), "no option to recommend: " .. reason)
end)

it("Hobson's is decided by the viability count alone", function()
  local two_real = signal_answers(0.05, { viable_3 = 0.1 })
  assert(policy.route(two_real, CFG, "read", "ask", LABELS) == "ok", "two viable options is not a Hobson's choice")
  local edge = signal_answers(0.05, { viable_2 = 0.59, viable_3 = 0.1 })
  assert(policy.route(edge, CFG, "read", "ask", LABELS) == "deny", "viable 0.59 is under the 0.6 cutoff")
  local at = signal_answers(0.05, { viable_2 = 0.6, viable_3 = 0.1 })
  assert(policy.route(at, CFG, "read", "ask", LABELS) == "ok", "viable 0.6 counts as real")
  local one = ask_answers(0.05)
  assert(policy.route(one, CFG, "read", "ask", { "only" }) == "ok", "one option is never a Hobson's choice")
end)

local STEER1 = { choice = "1", confidence = 0.91 }

it("a stacked deck names the options described only to lose", function()
  local a = signal_answers(0.05, { steer = STEER1, asymmetric_detail = 0.9, disfavored_2 = 0.8, disfavored_3 = 0.6 })
  local action, reason = policy.route(a, CFG, "read", "ask", LABELS)
  assert(action == "deny", "want deny: " .. reason)
  assert(reason:sub(1, 14) == "stacked deck (", "reason starts with the verdict: " .. reason)
  assert(reason:find('Option 2 and 3 is described only to lose (2 "Rewrite in Rust" (disfavored=0.80), 3 "Do nothing" (disfavored=0.60))', 1, true),
    "reason names each loser with its score: " .. reason)
  assert(reason:find("give option 2 and 3 its benefits, and drop any step or cost the approach does not need", 1, true),
    "reason says what to do with them: " .. reason)
  local fav = signal_answers(0.05, { steer = STEER1, asymmetric_detail = 0.9, disfavored_1 = 0.9, disfavored_2 = 0.59 })
  local _, r = policy.route(fav, CFG, "read", "ask", LABELS)
  assert(not r:find("described only to lose", 1, true), "the favored option and sub-cutoff options are not named: " .. r)
  assert(r:find("Give every option both its benefits", 1, true), "generic fix when no loser is named: " .. r)
  local quiet = signal_answers(0.05, { steer = { choice = "1", confidence = 0.74 }, disfavored_2 = 0.95 })
  assert(policy.route(quiet, CFG, "read", "ask", LABELS) == "ok", "disfavored alone never denies")
end)

it("an unsupported recommendation denies for any option count", function()
  for _, labels in ipairs({ {}, { "only" }, LABELS }) do
    local a = #labels >= 2 and signal_answers(0.05, { marked_recommended = 0.7, states_deciding_factor = 0.49 })
      or ask_answers(0.05, { marked_recommended = 0.7, states_deciding_factor = 0.49 })
    local action, reason = policy.route(a, CFG, "read", "ask", labels)
    assert(action == "deny", #labels .. " options: want deny: " .. reason)
    assert(reason:sub(1, 28) == "unsupported recommendation (", "reason starts with the verdict: " .. reason)
    assert(reason:find("the option you marked recommended", 1, true), "reason points at the mark: " .. reason)
    assert(reason:find("State the deciding factor", 1, true), "reason says what to do: " .. reason)
  end
  local supported = ask_answers(0.05, { marked_recommended = 0.95, states_deciding_factor = 0.5 })
  assert(policy.route(supported, CFG, "read", "ask", {}) == "ok", "a stated deciding factor passes")
  local unmarked = ask_answers(0.05, { marked_recommended = 0.69, states_deciding_factor = 0.0 })
  assert(policy.route(unmarked, CFG, "read", "ask", {}) == "ok", "no mark, nothing to support")
end)

it("a stacked deck denies when steering is unearned", function()
  for _, over in ipairs({
    { asymmetric_detail = 0.92 },
    { decoy_present = 0.7 },
    { fairness = { score = 2.0 } },
  }) do
    over.steer = { choice = "1", confidence = 0.91 }
    local a = signal_answers(0.05, over)
    local action, reason = policy.route(a, CFG, "read", "ask", LABELS)
    assert(action == "deny", "want deny for " .. vim.inspect(over) .. ": " .. reason)
    assert(reason:sub(1, 14) == "stacked deck (", "reason starts with the verdict: " .. reason)
    assert(reason:find('rigged toward option 1 "Add an index"', 1, true), "reason names the favored option: " .. reason)
    assert(reason:find("both its benefits and its drawbacks", 1, true), "reason says what to do: " .. reason)
  end
end)

it("honest steering passes", function()
  local honest = signal_answers(0.05, { steer = { choice = "1", confidence = 0.95 }, fairness = { score = 1.9 },
    marked_recommended = 0.95 })
  assert(policy.route(honest, CFG, "read", "ask", LABELS) == "ok", "a marked, supported steer must not deny")
  local unsure = signal_answers(0.05, { steer = { choice = "1", confidence = 0.59 }, asymmetric_detail = 0.95 })
  assert(policy.route(unsure, CFG, "read", "ask", LABELS) == "ok", "steer confidence under 0.6 does not count")
  local even = signal_answers(0.05, { steer = { choice = "none", confidence = 0.99 }, asymmetric_detail = 0.95 })
  assert(policy.route(even, CFG, "read", "ask", LABELS) == "ok", "steer none never stacks")
  local even_unmarked = signal_answers(0.05, { steer = { choice = "none", confidence = 0.99 } })
  assert(policy.route(even_unmarked, CFG, "read", "ask", LABELS) == "ok", "steer none is never an unstated recommendation")
end)

it("an unstated recommendation denies when a strong steer carries no mark", function()
  local a = signal_answers(0.05, { steer = { choice = "2", confidence = 0.75 } })
  local action, reason = policy.route(a, CFG, "read", "ask", LABELS)
  assert(action == "deny", "want deny: " .. reason)
  assert(reason:sub(1, 25) == "unstated recommendation (", "reason starts with the verdict: " .. reason)
  assert(reason:find('steer=option 2 at 0.75, marked_recommended=0.05', 1, true), "reason carries the scores: " .. reason)
  assert(reason:find('push toward option 2 "Rewrite in Rust" without saying so', 1, true), "reason names the option: " .. reason)
  assert(reason:find("mark it recommended and state the deciding factor", 1, true), "reason offers the mark route: " .. reason)
  assert(reason:find("give every option its benefits and its costs", 1, true), "reason offers the balance route: " .. reason)
  assert(reason:find("Ask again with the reworked question.", 1, true), "rework suffix: " .. reason)
  local under = signal_answers(0.05, { steer = { choice = "2", confidence = 0.74 } })
  assert(policy.route(under, CFG, "read", "ask", LABELS) == "ok", "0.74 is under the 0.75 cutoff")
  local marked = signal_answers(0.05, { steer = { choice = "2", confidence = 0.95 }, marked_recommended = 0.7 })
  assert(policy.route(marked, CFG, "read", "ask", LABELS) == "ok", "a marked, supported recommendation is not unstated")
  local marked_unsupported = signal_answers(0.05, { steer = { choice = "2", confidence = 0.95 },
    marked_recommended = 0.7, states_deciding_factor = 0.1 })
  local _, r = policy.route(marked_unsupported, CFG, "read", "ask", LABELS)
  assert(r:sub(1, 28) == "unsupported recommendation (", "a marked steer is unsupported, never unstated: " .. r)
  local off = { deny_threshold = 0.85, ask_cutoffs = { unstated_steer = 1.1 } }
  assert(policy.route(a, off, "read", "ask", LABELS) == "ok", "unstated_steer above 1 disables the verdict")
  local mark_off = { deny_threshold = 0.85, ask_cutoffs = { marked_recommended = 1.1 } }
  local action2, r2 = policy.route(a, mark_off, "read", "ask", LABELS)
  assert(action2 == "deny" and r2:sub(1, 25) == "unstated recommendation (",
    "disabling the unsupported verdict keeps the default mark cutoff for unstated: " .. r2)
  assert(policy.route(marked, mark_off, "read", "ask", LABELS) == "ok",
    "a mark at the default cutoff still exempts the steer when marked_recommended is disabled")
  local one = ask_answers(0.05)
  assert(policy.route(one, CFG, "read", "ask", { "only" }) == "ok", "one option has no steer to be unstated")
end)

it("verdict order: do-not-ask, Hobson's, stacked, unstated, unsupported, fixed hazard", function()
  local all = { viable_2 = 0.07, viable_3 = 0.16, steer = STEER1,
    asymmetric_detail = 0.95, marked_recommended = 0.95, states_deciding_factor = 0.1, vague_option = 0.99 }
  local function first(over)
    local _, reason = policy.route(signal_answers(0.05, over), CFG, "read", "ask", LABELS)
    return reason
  end
  local stop = vim.tbl_extend("force", all, { permission_seeking = 0.9 })
  assert(first(stop):sub(1, 12) == "do not ask (", "do-not-ask outranks every verdict: " .. first(stop))
  assert(first(all):sub(1, 17) == "Hobson's choice (", "Hobson's next: " .. first(all))
  local no_hob = vim.tbl_extend("force", all, { viable_2 = 0.9, viable_3 = 0.9 })
  assert(first(no_hob):sub(1, 14) == "stacked deck (", "stacked next: " .. first(no_hob))
  local no_stack = vim.tbl_extend("force", no_hob, { asymmetric_detail = 0.1 })
  assert(first(no_stack):sub(1, 28) == "unsupported recommendation (", "unsupported when marked: " .. first(no_stack))
  local unmarked = vim.tbl_extend("force", no_stack, { marked_recommended = 0.1 })
  assert(first(unmarked):sub(1, 25) == "unstated recommendation (", "unstated when unmarked: " .. first(unmarked))
  local no_steer = vim.tbl_extend("force", unmarked, { steer = { choice = "none", confidence = 0.9 } })
  assert(first(no_steer):sub(1, 23) == "question needs rework (", "fixed hazard last: " .. first(no_steer))
end)

it("missing or malformed signals deny, for every option count", function()
  for _, broken in ipairs({
    function(a) a.viable_2 = nil end,
    function(a) a.viable_3.noul = 0 / 0 end,
    function(a) a.disfavored_1 = nil end,
    function(a) a.disfavored_2.noul = 1.5 end,
    function(a) a.marked_recommended = nil end,
    function(a) a.states_deciding_factor.noul = 0 / 0 end,
    function(a) a.steer = nil end,
    function(a) a.steer.confidence = nil end,
    function(a) a.steer.choice = "4" end,
    function(a) a.steer.choice = "" end,
    function(a) a.steer.choice = "0" end,
    function(a) a.fairness.score = 4.5 end,
    function(a) a.fairness.legend["2"] = "moved" end,
  }) do
    local a = signal_answers(0.05)
    broken(a)
    local action, reason = policy.route(a, CFG, "read", "ask", LABELS)
    assert(action == "deny" and reason:find("missing or malformed", 1, true), "want malformed deny: " .. reason)
  end
  for _, labels in ipairs({ {}, { "only" } }) do
    for _, id in ipairs({ "marked_recommended", "states_deciding_factor" }) do
      local a = ask_answers(0.05)
      a[id] = nil
      local action, reason = policy.route(a, CFG, "read", "ask", labels)
      assert(action == "deny" and reason:find(id, 1, true),
        ("%d options without %s must deny: %s"):format(#labels, id, reason))
    end
  end
end)

it("watch mode and ask_cutoffs", function()
  local hob = signal_answers(0.05, { viable_2 = 0.07, viable_3 = 0.16 })
  assert(policy.route(hob, { deny_threshold = 1.1 }, "read", "ask", LABELS) == "ok", "watch mode stops signal denies")
  local stop = ask_answers(0.05, { permission_seeking = 0.99 })
  assert(policy.route(stop, { deny_threshold = 1.1 }, "read", "ask", {}) == "ok", "watch mode stops do-not-ask")
  local low = { deny_threshold = 0.85, ask_cutoffs = { viable = 0.05 } }
  assert(policy.route(hob, low, "read", "ask", LABELS) == "ok", "viable 0.05 makes options 2 and 3 real")
  local high = { deny_threshold = 0.85, ask_cutoffs = { viable = 0.95 } }
  local action, reason = policy.route(hob, high, "read", "ask", LABELS)
  assert(action == "deny" and reason:find("none of the options is a real choice", 1, true), "viable 0.95: " .. reason)
  local off = { deny_threshold = 0.85, ask_cutoffs = { viable = 1.1 } }
  assert(policy.route(hob, off, "read", "ask", LABELS) == "ok", "viable above 1 disables Hobson's rather than forcing it")
  local unsup = ask_answers(0.05, { marked_recommended = 0.95, states_deciding_factor = 0.1 })
  local off2 = { deny_threshold = 0.85, ask_cutoffs = { deciding_factor = 1.1 } }
  assert(policy.route(unsup, off2, "read", "ask", {}) == "ok", "deciding_factor above 1 disables the unsupported verdict")
  local off3 = { deny_threshold = 0.85, ask_cutoffs = { marked_recommended = 1.1 } }
  assert(policy.route(unsup, off3, "read", "ask", {}) == "ok", "marked_recommended above 1 disables it too")
end)

it("every fixed hazard has its own cutoff, defaulting to the ask threshold", function()
  local cut, deny_at = policy.ask_cutoffs(CFG)
  assert(deny_at == 0.85, "threshold from deny_threshold")
  for _, id in ipairs(questions.ids("hazard", "ask")) do
    assert(cut[id] == 0.85, id .. " defaults to the ask threshold")
  end
  for k, v in pairs(policy.ASK_CUTOFFS) do
    assert(cut[k] == v, k .. " keeps its default")
  end
  local loose = { deny_threshold = 0.85, ask_cutoffs = { loaded_premise = 0.95, permission_seeking = 1.1 } }
  local a = ask_answers(0.05, { loaded_premise = 0.9 })
  assert(policy.route(a, loose, "read", "ask", {}) == "ok", "loaded_premise 0.9 passes under its own 0.95 cutoff")
  a.loaded_premise.noul = 0.95
  local action, reason = policy.route(a, loose, "read", "ask", {})
  assert(action == "deny" and reason:find("loaded_premise=0.95 >= 0.95", 1, true), "at its own cutoff it denies: " .. reason)
  local stop = ask_answers(0.05, { permission_seeking = 0.99, already_answered = 0.86 })
  local _, r2 = policy.route(stop, loose, "read", "ask", {})
  assert(r2:find("already_answered=0.86", 1, true), "a hazard cutoff above 1 disables that hazard alone: " .. r2)
  local tight = { deny_threshold = 0.85, ask_cutoffs = { package_deal = 0.5 } }
  local two = ask_answers(0.05, { package_deal = 0.55, vague_option = 0.88 })
  local _, r3 = policy.route(two, tight, "read", "ask", {})
  assert(r3:find("package_deal=0.55 >= 0.50", 1, true), "the hazard furthest over its own cutoff decides: " .. r3)
end)

it("ask state keeps prose whole, refuses over the cap, and omits hazard fields", function()
  local long = ("an honest option described at length "):rep(200)
  local input = { question = "Which?", options = { { label = "A", preview = long }, "B" } }
  local cfg = { max_state_bytes = 4000, ask_state_bytes = 16000 }
  local s, err, kind = questions.state("ask_user", input, nil, cfg,
    { kind = "ask", latest_user_request = "r", child = false, capability = "read" })
  assert(s, "ask state should render: " .. tostring(err))
  assert(kind == "ask", "kind returned")
  assert(s.tool_input:find(long, 1, true), "the preview must not be elided")
  assert(not s.tool_input:find("elided", 1, true), "no elision marker")
  assert(s.latest_user_request == "r", "request carried")
  assert(s.resolved_paths == nil and s.protected == nil and s.cwd == nil and s.vcs == nil,
    "hazard fields are left out")
  local s2, err2 = questions.state("ask_user", input, nil, { ask_state_bytes = 1000 },
    { kind = "ask", latest_user_request = "r", child = false, capability = "read" })
  assert(s2 == nil and err2:find("ask_state_bytes", 1, true), "over the cap must refuse: " .. tostring(err2))
  local c = questions.state("ask_user", { question = "q" }, nil, cfg,
    { kind = "ask", latest_user_request = "t", child = true, capability = "read" })
  assert(c.parent_agent_task == "t" and c.latest_user_request == nil, "child field")
end)

it("check_ask_input allows the builtin's fields and refuses the rest", function()
  assert(questions.check_ask_input({ question = "q" }) == nil, "bare question")
  assert(questions.check_ask_input({ question = "q", options = { "a", { label = "b", preview = "p", filetype = "lua" } },
    content = "c", filetype = "" }) == nil, "every builtin field")
  assert(questions.check_ask_input({ question = "q", command = "x" }):find("command", 1, true), "extra top key")
  assert(questions.check_ask_input({ question = "q", options = { { label = "a", note = "x" } } }):find("note", 1, true),
    "extra option key")
  assert(questions.check_ask_input({ question = "q", options = { foo = "x" } }), "a map is not a list")
  assert(questions.check_ask_input({ question = "q", options = "a" }), "a string is not a list")
  assert(questions.check_ask_input({ question = "q", options = { [1] = "a", [3] = "b" } }), "a list with holes")
  assert(questions.check_ask_input({ question = "q", options = { 1 } }), "a number is not an option")
  assert(questions.check_ask_input({ question = "q", filetype = "../x" }), "a path is not a filetype")
  assert(questions.check_ask_input({ question = "q", options = { { label = "a", filetype = "a b" } } }),
    "an option filetype is checked")
  assert(questions.check_ask_input({ question = "q", filetype = "c.doxygen" }) == nil, "dotted filetype")
  assert(questions.check_ask_input({ options = { "a" } }), "a missing question")
  assert(questions.check_ask_input({ question = { "q" } }), "a table question")
  assert(questions.check_ask_input({ question = "q", content = { "fair" } }), "a table content")
  assert(questions.check_ask_input({ question = "q", options = { "a", "" } }), "an empty option the picker drops")
  assert(questions.check_ask_input({ question = "q", options = { { preview = "hidden C" } } }), "an option with no label")
  assert(questions.check_ask_input({ question = "q", options = { { label = "" } } }), "an empty label")
  assert(questions.check_ask_input({ question = "q", options = { "a\nhidden" } }), "a multi-line string option")
  assert(questions.check_ask_input({ question = "q", options = { { label = "a\nhidden" } } }), "a multi-line label")
  assert(questions.check_ask_input({ question = "q", options = { { label = "a", preview = { "x" } } } }),
    "a table preview")
  local long = ("line\n"):rep(200) .. "hidden past the picker's cap"
  assert(questions.check_ask_input({ question = "q", options = { { label = "a", preview = long } } }),
    "a preview longer than the picker shows")
  assert(questions.check_ask_input({ question = "q", content = long }), "content longer than the picker shows")
  assert(questions.check_ask_input({ question = "q", options = { { label = "a", preview = ("l\n"):rep(199) .. "l" } } })
    == nil, "a 200-line preview is shown whole")
end)
