-- tests/confirm_spec.lua — the confirm chain: the operator decides first, and
-- the classifier can only take that yes away.
--   busted tests/confirm_spec.lua
-- No network. $STRAPS_ROOT overrides the straps checkout (default ../straps).

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

local straps = require("straps").setup({})
straps.config.session_dir = vim.fn.tempname()
local registry = require("straps.registry")
local entries = require("straps_classifier.entries")

-- The operator stand-in: _G.OP.allow decides, _G.OP.calls counts.
_G.OP = { allow = true, calls = 0 }
registry.define({
  name = "hook.confirm",
  kind = "hook",
  doc = "test: the operator",
  source = [[
return function(name, input, ctx)
  _G.OP.calls = _G.OP.calls + 1
  if _G.OP.allow then return true end
  return false, "operator said no"
end
]],
}, { scope = "global" })

entries.register()
local confirm = registry.bind("hook.confirm")

local ctx = { bufnr = 1 }

it("a call the operator rejects never reaches the classifier", function()
  _G.OP.allow, _G.OP.calls = false, 0
  entries.put_verdict(1, "ping", {}, "ok", "quiet")
  local allowed, why = confirm("ping", {}, ctx)
  assert(allowed == false, "a rejected call must stay rejected")
  assert(why == "operator said no", "the operator's reason should survive: " .. tostring(why))
  -- The stale verdict must be cleared, not left for the next call to consume.
  assert(entries.take_verdict(1, "ping", {}) == nil, "a rejected call must clear the slot")
end)

it("an approved call with an ok verdict proceeds", function()
  _G.OP.allow, _G.OP.calls = true, 0
  entries.put_verdict(1, "ping", {}, "ok", "highest secrets=0.02")
  local allowed = confirm("ping", {}, ctx)
  assert(allowed == true, "an ok verdict should allow")
  assert(_G.OP.calls == 1, "the operator is asked first")
end)

it("an approved call with a deny verdict is blocked", function()
  _G.OP.allow = true
  entries.put_verdict(1, "ping", {}, "deny", "data_loss=0.94 (>= 0.85)")
  local allowed, why = confirm("ping", {}, ctx)
  assert(allowed == false, "a deny verdict must block an approved call")
  assert(why:find("classifier:", 1, true), "the veto should name itself: " .. why)
  assert(why:find("data_loss=0.94", 1, true), "the reason should carry the question: " .. why)
end)

it("a missing verdict blocks", function()
  _G.OP.allow = true
  entries.clear_verdict()
  local allowed, why = confirm("ping", {}, ctx)
  assert(allowed == false, "no verdict means no call")
  assert(why:find("no verdict", 1, true), "the reason should say so: " .. why)
end)

it("a verdict for a different call does not satisfy this one", function()
  _G.OP.allow = true
  entries.put_verdict(1, "ping", { a = 1 }, "ok", "quiet")
  local allowed, why = confirm("ping", { a = 2 }, ctx)
  assert(allowed == false, "a verdict is bound to its exact call")
  assert(why:find("no verdict", 1, true), "the reason should say so: " .. why)
end)

it("a verdict for a different session does not satisfy this one", function()
  _G.OP.allow = true
  entries.put_verdict(99, "ping", {}, "ok", "quiet")
  local allowed = confirm("ping", {}, ctx)
  assert(allowed == false, "a verdict is bound to its session")
end)

it("the slot is empty after the confirm reads it", function()
  _G.OP.allow = true
  entries.put_verdict(1, "ping", {}, "ok", "quiet")
  assert(confirm("ping", {}, ctx) == true, "first read allows")
  local allowed = confirm("ping", {}, ctx)
  assert(allowed == false, "the verdict must not answer a second call")
end)

it("a silent cap: grant still reaches the classifier", function()
  -- straps' own grant check underneath: with cap:exec granted the operator is
  -- never prompted, and the classifier still gets the last word. register() is
  -- idempotent, so re-chaining over the new predecessor is the shipped path.
  registry.define({
    name = "hook.confirm",
    kind = "hook",
    doc = "test: straps-like grant check",
    source = [[
return function(name, input, ctx)
  local granted = require("straps.registry").granted(ctx.bufnr)
  if granted["cap:exec"] then return true end
  return false, "would have prompted"
end
]],
  }, { scope = "global" })
  entries.register()
  local chained = registry.bind("hook.confirm")

  local b = vim.api.nvim_create_buf(false, true)
  registry.ensure_scope(b)
  registry.grant(b, "cap:exec")

  entries.put_verdict(b, "bash", {}, "deny", "data_loss=0.99 (>= 0.85)")
  local allowed, why = chained("bash", {}, { bufnr = b })
  assert(allowed == false, "the classifier vetoes a granted call")
  assert(why:find("classifier:", 1, true), "the veto should name itself: " .. tostring(why))

  entries.put_verdict(b, "bash", {}, "ok", "quiet")
  assert(chained("bash", {}, { bufnr = b }) == true, "an ok verdict lets a grant through")

  -- An ungranted call is still refused by the predecessor, before any verdict.
  local c = vim.api.nvim_create_buf(false, true)
  registry.ensure_scope(c)
  entries.put_verdict(c, "bash", {}, "ok", "quiet")
  local ok2, why2 = chained("bash", {}, { bufnr = c })
  assert(ok2 == false and why2 == "would have prompted",
    "the predecessor still decides first: " .. tostring(why2))
end)

it("one session's verdict does not disturb another's", function()
  -- Two sessions run concurrently in one Neovim (a parent and its subagent, or
  -- two peers). Session B's guard must not consume or clobber the verdict
  -- session A's guard produced. Re-chain over the permissive operator stub:
  -- an earlier case swapped the predecessor for a grant-checking one.
  registry.define({
    name = "hook.confirm",
    kind = "hook",
    doc = "test: the operator",
    source = [[
return function(name, input, ctx)
  _G.OP.calls = _G.OP.calls + 1
  if _G.OP.allow then return true end
  return false, "operator said no"
end
]],
  }, { scope = "global" })
  entries.register()
  local chained = registry.bind("hook.confirm")

  _G.OP.allow = true
  entries.put_verdict(1, "ping", {}, "ok", "A is fine")
  entries.put_verdict(2, "ping", {}, "deny", "B is dangerous")

  local allowed_b, why_b = chained("ping", {}, { bufnr = 2 })
  assert(allowed_b == false, "B's deny should block B")
  assert(why_b:find("B is dangerous", 1, true), "B should get its own reason: " .. why_b)

  local allowed_a = chained("ping", {}, { bufnr = 1 })
  assert(allowed_a == true, "A's verdict must survive B's whole gate pass")

  -- And a rejection in B must not clear A's pending verdict either.
  entries.put_verdict(1, "ping", {}, "ok", "A is fine")
  _G.OP.allow = false
  assert(chained("ping", {}, { bufnr = 2 }) == false, "B is rejected by the operator")
  _G.OP.allow = true
  assert(chained("ping", {}, { bufnr = 1 }) == true,
    "A's verdict must survive B's rejection")
end)

