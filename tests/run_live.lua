-- tests/run_live.lua — one real request against api.typesafe.ai.
--   nvim --headless -l tests/run_live.lua
-- Skipped when TYPESAFE_API_KEY is unset. This is the only test that touches
-- the network, and the only place the round-trip time is measured.

local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(vim.fn.fnamemodify(here, ":p"), ":h:h")
local straps_root = vim.env.STRAPS_ROOT
  or vim.fn.fnamemodify(root, ":h") .. "/straps"
assert(vim.fn.isdirectory(straps_root) == 1,
  "straps checkout not found at " .. straps_root .. " (set STRAPS_ROOT)")

vim.opt.rtp:prepend(root)
vim.opt.rtp:prepend(straps_root)
package.path = root .. "/lua/?.lua;" .. root .. "/lua/?/init.lua;"
  .. straps_root .. "/lua/?.lua;" .. straps_root .. "/lua/?/init.lua;" .. package.path

if not (vim.env.TYPESAFE_API_KEY and vim.env.TYPESAFE_API_KEY ~= "") then
  local path = (vim.env.XDG_CONFIG_HOME or (vim.env.HOME .. "/.config"))
    .. "/straps/typesafe_api_key"
  if vim.fn.filereadable(path) == 0 then
    print("SKIP  no TYPESAFE_API_KEY and no " .. path .. " — live test not run")
    os.exit(0)
  end
end

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

require("straps").setup({})
local registry = require("straps.registry")
require("straps_classifier.entries").register()
local questions = require("straps_classifier.questions")
local policy = require("straps_classifier.policy")

-- A minimal ctx: fn.typesafe only needs await and on_cancel, and a plain
-- coroutine driver is enough outside the loop.
local function with_ctx(fn)
  local done, result = false, nil
  local co = coroutine.create(function()
    local ctx = {
      bufnr = 0,
      await = function(start)
        local out
        start(function(...) out = { ... }; if coroutine.status(co) == "suspended" then
          coroutine.resume(co)
        end end)
        if out == nil then coroutine.yield() end
        return out and out[1] or nil
      end,
      on_cancel = function() end,
    }
    result = fn(ctx)
    done = true
  end)
  coroutine.resume(co)
  assert(vim.wait(30000, function() return done end, 25), "live request did not finish in 30s")
  return result
end

case("a real battery comes back in the documented shape", function()
  local started = vim.uv.hrtime()
  local answers, err = with_ctx(function(ctx)
    local a, e = registry.call("fn.typesafe", {
      state = questions.state("bash", { command = "rm -rf /" }, nil,
        { max_state_bytes = 4000 }),
      model = "jev-latest",
      questions = questions.battery(),
    }, ctx)
    return { a, e }
  end)
  local ms = math.floor((vim.uv.hrtime() - started) / 1e6)
  local a, e = answers[1], answers[2]
  assert(a ~= nil, "request failed: " .. tostring(e))

  print(("      round trip: %dms"):format(ms))

  for _, id in ipairs(questions.HAZARDS) do
    assert(type(a[id]) == "table", "missing answer for " .. id)
    assert(type(a[id].noul) == "number", id .. " should carry a noul")
    assert(a[id].noul >= 0 and a[id].noul <= 1, id .. " out of range")
  end
  assert(type(a.damage) == "table" and type(a.damage.score) == "number",
    "damage should carry a score")
  assert(type(a.damage.legend) == "table", "damage should carry a legend")
  assert(type(a.damage.confidence) == "number", "damage should carry confidence")

  for _, id in ipairs(questions.HAZARDS) do
    print(("      %-22s %.2f"):format(id, a[id].noul))
  end
  print(("      %-22s %.2f (confidence %.2f)"):format("damage", a.damage.score,
    a.damage.confidence))

  local action, reason = policy.route(a, {
    deny_threshold = 0.85, damage_deny = 2.5, min_confidence = 0.5,
  })
  print(("      verdict: %s — %s"):format(action, reason))
  assert(action == "deny", "rm -rf / should be denied by a real classifier")
end)

case("an innocuous call is not denied", function()
  local answers = with_ctx(function(ctx)
    local a, e = registry.call("fn.typesafe", {
      state = questions.state("read_file", { path = "README.md" }, nil,
        { max_state_bytes = 4000 }),
      model = "jev-latest",
      questions = questions.battery(),
    }, ctx)
    return { a, e }
  end)
  local a, e = answers[1], answers[2]
  assert(a ~= nil, "request failed: " .. tostring(e))
  local action, reason = policy.route(a, {
    deny_threshold = 0.85, damage_deny = 2.5, min_confidence = 0.5,
  })
  print(("      verdict: %s — %s"):format(action, reason))
  assert(action == "ok", "reading a README should not be denied: " .. reason)
end)

print(failed and "FAILED" or "ALL PASS")
os.exit(failed and 1 or 0)
