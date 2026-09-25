-- tests/run_policy.lua — policy.route: every threshold boundary.
--   nvim --headless -l tests/run_policy.lua
-- No network, no straps: policy.lua and questions.lua are pure Lua.

local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(vim.fn.fnamemodify(here, ":p"), ":h:h")
vim.opt.rtp:prepend(root)
package.path = root .. "/lua/?.lua;" .. root .. "/lua/?/init.lua;" .. package.path

local failed = false
local function case(name, fn)
  local ok, err = pcall(fn)
  if ok then
    print("PASS  " .. name)
  else
    failed = true
    print("FAIL  " .. name .. ": " .. tostring(err))
  end
end

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

case("a quiet battery is ok", function()
  local action, reason = policy.route(answers(0.02, 0.1), CFG)
  assert(action == "ok", "want ok, got " .. action .. ": " .. reason)
end)

case("a hazard at the threshold denies", function()
  local a = answers(0.1, 0.1)
  a.writes_outside_root.noul = 0.85
  local action, reason = policy.route(a, CFG)
  assert(action == "deny", "0.85 should deny")
  assert(reason:find("writes_outside_root=0.85", 1, true), "reason should carry id and probability: " .. reason)
end)

case("a hazard just below the threshold does not deny", function()
  local a = answers(0.1, 0.1)
  a.writes_outside_root.noul = 0.84
  local action = policy.route(a, CFG)
  assert(action == "ok", "0.84 should not deny")
end)

case("the reason names the highest hazard", function()
  local a = answers(0.1, 0.1)
  a.reads_credentials.noul = 0.93
  a.sends_message.noul = 0.90
  local action, reason = policy.route(a, CFG)
  assert(action == "deny", "want deny")
  assert(reason:find("reads_credentials", 1, true), "reason should name reads_credentials: " .. reason)
end)

case("the signal alone never denies as a hazard", function()
  local a = answers(0.1, 0.1)
  a.runs_script_outside_root.noul = 0.99
  local action, reason = policy.route(a, { deny_threshold = 0.85, damage_deny = 2.5, opaque_action = "log" })
  assert(action == "ok", "signal with opaque_action=log must not deny: " .. reason)
  assert(reason:find("opaque", 1, true), "reason should log the signal: " .. reason)
end)

case("the signal denies when opaque_action is deny", function()
  local a = answers(0.1, 0.1)
  a.runs_script_outside_root.noul = 0.99
  local action, reason = policy.route(a, CFG)
  assert(action == "deny", "opaque_action=deny must deny")
  assert(reason:find("opaque", 1, true), "reason should say opaque: " .. reason)
end)

case("opaque_action defaults to deny", function()
  local a = answers(0.1, 0.1)
  a.runs_script_outside_root.noul = 0.99
  local action = policy.route(a, { deny_threshold = 0.85, damage_deny = 2.5 })
  assert(action == "deny", "the default must be deny")
end)

case("a hazard deny outranks the opaque signal in the reason", function()
  local a = answers(0.1, 0.1)
  a.runs_script_outside_root.noul = 0.99
  a.transmits_local_data.noul = 0.95
  local _, reason = policy.route(a, CFG)
  assert(reason:find("transmits_local_data", 1, true), "hazard should decide: " .. reason)
end)

case("damage at the threshold denies on its own", function()
  local action, reason = policy.route(answers(0.05, 2.5), CFG)
  assert(action == "deny", "damage 2.5 should deny")
  assert(reason:find("damage", 1, true), "reason should name damage: " .. reason)
end)

case("low damage confidence does not downgrade a deny", function()
  local action = policy.route(answers(0.05, 2.9, 0.1), CFG)
  assert(action == "deny", "confidence must not open the gate")
end)

case("redefines_protected is ignored for an edit-capability tool", function()
  local a = answers(0.05, 0.1)
  a.redefines_protected.noul = 0.99
  local action = policy.route(a, CFG, "edit")
  assert(action == "ok", "an edit tool's redefines_protected must not deny")
  local action2 = policy.route(a, CFG, "lua")
  assert(action2 == "deny", "a lua tool's redefines_protected must deny")
  local action3 = policy.route(a, CFG, nil)
  assert(action3 == "deny", "an unknown capability must not skip anything")
end)

case("a mismatched damage legend denies", function()
  local a = answers(0.01, 0.0)
  a.damage.legend["2"] = "something else entirely"
  local action, reason = policy.route(a, CFG)
  assert(action == "deny", "a moved legend must deny")
  assert(reason:find("legend", 1, true), "reason should name the legend: " .. reason)
end)

case("a missing hazard answer denies", function()
  local a = answers(0.01, 0.0)
  a.reads_credentials = nil
  local action, reason = policy.route(a, CFG)
  assert(action == "deny", "a missing answer must deny")
  assert(reason:find("reads_credentials", 1, true), "reason should name it: " .. reason)
end)

case("a missing signal answer denies", function()
  local a = answers(0.01, 0.0)
  a.runs_script_outside_root = nil
  local action = policy.route(a, CFG)
  assert(action == "deny", "a missing signal must deny")
end)

case("a missing damage answer denies", function()
  local a = answers(0.01, 0.0)
  a.damage = nil
  local action = policy.route(a, CFG)
  assert(action == "deny", "a missing damage answer must deny")
end)

case("nil answers deny", function()
  local action = policy.route(nil, CFG)
  assert(action == "deny", "nil must deny")
end)

case("unreachable thresholds let nothing deny", function()
  local a = answers(0.99, 3.0)
  a.runs_script_outside_root.noul = 0.99
  local action, reason = policy.route(a, { deny_threshold = 1.1, damage_deny = 99, opaque_action = "deny" })
  assert(action == "ok", "1.1 is unreachable for every probability, signal included: " .. reason)
end)

case("the battery has the documented shape", function()
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

case("state refuses an over-cap exec input and elides prose for edit tools", function()
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

case("state names the request field by session kind", function()
  local cfg = { max_state_bytes = 4000 }
  local parent = questions.state("bash", { command = "ls" }, nil, cfg, { latest_user_request = "r", child = false })
  assert(parent.latest_user_request == "r" and parent.parent_agent_task == nil, "parent field")
  local child = questions.state("bash", { command = "ls" }, nil, cfg, { latest_user_request = "t", child = true })
  assert(child.parent_agent_task == "t" and child.latest_user_request == nil, "child field")
  assert(type(parent.project_root_parent) == "string", "parent dir present")
  assert(type(parent.temp_dirs) == "table" and #parent.temp_dirs > 0, "temp dirs present")
  assert(type(parent.resolved_paths) == "nil", "a command has no structured paths")
end)

case("state resolves structured paths against the root", function()
  local cfg = { max_state_bytes = 4000 }
  local s = questions.state("read_file", { path = "README.md" }, nil, cfg, { latest_user_request = "r", child = false })
  local r = s.resolved_paths["README.md"]
  assert(r and r.within == "project_root", "in-root path resolves to project_root: " .. vim.inspect(r))
  local s2 = questions.state("delete_files", { paths = { "README.md", "/etc/hosts" } }, nil, cfg,
    { latest_user_request = "r", child = false })
  assert(s2.resolved_paths["/etc/hosts"].within == "outside", "/etc is outside")
end)

print(failed and "FAILED" or "ALL PASS")
os.exit(failed and 1 or 0)
