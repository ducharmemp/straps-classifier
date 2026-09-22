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
  min_confidence = 0.5,
}

-- A well-formed answer set with every hazard at `p` and damage at `score`.
local function answers(p, score, conf)
  local out = {}
  for _, id in ipairs(questions.HAZARDS) do
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
  local action, reason = policy.route(answers(0.85, 0.1), CFG)
  assert(action == "deny", "0.85 should deny")
  assert(reason:find("0.85", 1, true), "reason should carry the probability: " .. reason)
end)

case("a hazard just below the threshold does not deny", function()
  local action = policy.route(answers(0.84, 0.1), CFG)
  assert(action == "ok", "0.84 should not deny")
end)

case("the reason names the highest hazard", function()
  local a = answers(0.1, 0.1)
  a.secrets.noul = 0.93
  local action, reason = policy.route(a, CFG)
  assert(action == "deny", "want deny")
  assert(reason:find("secrets", 1, true), "reason should name secrets: " .. reason)
end)

case("damage at the threshold denies on its own", function()
  local action, reason = policy.route(answers(0.05, 2.5), CFG)
  assert(action == "deny", "damage 2.5 should deny")
  assert(reason:find("damage", 1, true), "reason should name damage: " .. reason)
end)

case("a low-confidence damage deny is downgraded to ok", function()
  local action, reason = policy.route(answers(0.05, 2.9, 0.31), CFG)
  assert(action == "ok", "low confidence should downgrade: " .. reason)
  assert(reason:find("confidence", 1, true), "reason should explain: " .. reason)
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
  a.secrets = nil
  local action, reason = policy.route(a, CFG)
  assert(action == "deny", "a missing answer must deny")
  assert(reason:find("secrets", 1, true), "reason should name it: " .. reason)
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

case("the never-block configuration blocks nothing", function()
  local watch = { deny_threshold = 1.1, damage_deny = 99, min_confidence = 0.5 }
  local action = policy.route(answers(0.99, 3.0), watch)
  assert(action == "ok", "unreachable thresholds should never deny")
end)

case("the damage legend has four ordered levels", function()
  assert(#questions.DAMAGE_LEVELS == 4, "want 4 levels")
  assert(#questions.HAZARDS == 5, "want 5 hazards")
  local battery = questions.battery()
  for _, id in ipairs(questions.HAZARDS) do
    assert(battery[id].type == "noul", id .. " should be a noul")
  end
  assert(battery.damage.type == "score", "damage should be a score")
end)

print(failed and "FAILED" or "ALL PASS")
os.exit(failed and 1 or 0)
