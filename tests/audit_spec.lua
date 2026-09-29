-- tests/audit_spec.lua — the classification record and its buffer view.
--   busted tests/audit_spec.lua
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
local state = require("straps.state")
local plugin = require("straps_classifier")
local audit = require("straps_classifier.audit")

require("straps_classifier.entries").register()

local function fresh_session()
  return state.new_session()
end

it("a record lands in the ring", function()
  audit.clear()
  local b = fresh_session()
  audit.record(b, { tool = "ping", capability = "other", action = "ok", reason = "quiet" })
  local all = audit.all()
  assert(#all == 1, "want one session, got " .. #all)
  assert(#all[1].entries == 1, "want one entry")
  assert(all[1].entries[1].tool == "ping", "the tool should be recorded")
  assert(type(all[1].entries[1].at) == "number", "a timestamp should be stamped")
  assert(all[1].entries[1].seq == 1, "entries are sequenced")
end)

it("every verdict keeps the state it was judged on", function()
  audit.clear()
  registry.define({
    name = "fn.typesafe", kind = "fn", doc = "test stub: quiet battery",
    source = [[
return function(payload, ctx)
  if not (ctx and ctx.await) then return nil, "no ctx to await on" end
  _G.AUDIT_PAYLOAD = payload
  local out = {}
  for id, q in pairs(payload.questions) do
    if q.type == "noul" then
      local p = 0.01
      if id:match("^viable_") or id == "states_deciding_factor" then
        p = 0.9
      end
      out[id] = { type = "noul", noul = p }
    elseif q.type == "score" then
      local legend = {}
      for i, text in ipairs(q.criteria) do legend[tostring(i - 1)] = text end
      out[id] = { type = "score", score = 0.1, legend = legend, confidence = 0.9 }
    elseif q.type == "choice" then
      out[id] = { type = "choice", choice = "none", confidence = 0.9 }
    end
  end
  return out, nil, { input_tokens = 123 }
end
]],
  }, { scope = "global" })
  local b = fresh_session()
  local ctx = { bufnr = b, await = function(_) return nil end }
  local action = registry.call("fn.risk_verdict", "ping", { x = 1 }, ctx)
  assert(action == "ok", "the quiet battery should allow")
  local rec = audit.all()[1].entries[1]
  assert(rec.state ~= nil and rec.state.tool == "ping", "an allow keeps the state sent")
  assert(rec.answers ~= nil, "an allow keeps its answers")
  assert(rec.usage and rec.usage.input_tokens == 123, "token usage is recorded")
  local lines = audit.answer_lines({ a = { noul = 0.2 }, b = { noul = 0.9 }, damage = { score = 1.5 }, odd = {} })
  assert(lines[1]:find("^b"), "strongest noul first: " .. lines[1])
  assert(lines[2]:find("^damage"), "score sorted by legend position: " .. lines[2])
  assert(lines[#lines]:find("^odd"), "shapeless answers sort last")
end)

it("an ask_user verdict records its battery and shows it in the record", function()
  audit.clear()
  local b = fresh_session()
  local ctx = { bufnr = b, await = function(_) return nil end }
  local prev = registry.set_active_scope(b)
  local action = registry.call("fn.risk_verdict", "ask_user", { question = "Which?", options = { "a", "b" } }, ctx)
  registry.set_active_scope(prev)
  assert(action == "ok", "the quiet ask battery should allow")
  assert(_G.AUDIT_PAYLOAD.questions.damage == nil, "no damage sent for ask_user")
  assert(_G.AUDIT_PAYLOAD.questions.vague_option ~= nil, "the ask battery was sent")
  local rec = audit.all()[1].entries[1]
  assert(rec.kind == "ask", "the record should carry kind=ask, got " .. tostring(rec.kind))
  registry.call("fn.risk_verdict", "ping", { x = 1 }, ctx)
  assert(audit.all()[1].entries[2].kind == "hazard", "other tools record kind=hazard")
end)

it("last_user_text skips harness notices", function()
  local questions = require("straps_classifier.questions")
  local b = fresh_session()
  state.append(b, "user", nil, "pick the parser")
  state.append(b, "user", nil, "[straps] another agent is running in this Neovim")
  local text = questions.last_user_text(b, 500)
  assert(text == "pick the parser", "the notice should be skipped, got " .. vim.inspect(text))
  local long = ("x"):rep(50) .. "DECIDE"
  state.append(b, "user", nil, long)
  local tail = questions.last_user_text(b, 10, "tail")
  assert(tail:find("DECIDE", 1, true), "tail keeps the end: " .. tail)
  local head = questions.last_user_text(b, 10)
  assert(not head:find("DECIDE", 1, true), "head keeps the start: " .. head)
end)

it("the ring caps at audit_limit and drops the oldest", function()
  audit.clear()
  plugin.config.audit_limit = 5
  local b = fresh_session()
  for i = 1, 12 do
    audit.record(b, { tool = "ping" .. i, action = "ok", reason = "quiet" })
  end
  local entries = audit.all()[1].entries
  assert(#entries == 5, "want 5 entries, got " .. #entries)
  assert(entries[1].tool == "ping8", "oldest should be dropped, first is " .. entries[1].tool)
  assert(entries[5].tool == "ping12", "newest should be kept")
  plugin.config.audit_limit = 500
end)

it("counts report allows, denies, and causes", function()
  audit.clear()
  local b = fresh_session()
  audit.record(b, { tool = "a", action = "ok", reason = "quiet" })
  audit.record(b, { tool = "b", action = "deny", reason = "HTTP 500", failure = "HTTP 500" })
  audit.record(b, { tool = "c", action = "deny", reason = "timeout", failure = "timeout" })
  local total, causes = audit.counts()
  assert(total.allow == 1 and total.deny == 2,
    ("want 1 allow / 2 denies, got %d / %d"):format(total.allow, total.deny))
  assert(causes["HTTP 500"] == 1 and causes["timeout"] == 1, "causes should be tallied")
end)

it("a child's entries carry its parent and depth", function()
  audit.clear()
  local parent = fresh_session()
  local child = fresh_session()
  vim.b[child].straps_parent = parent
  vim.b[child].straps_spawn_depth = 1
  audit.record(child, { tool = "ping", action = "ok", reason = "quiet" })
  local rec = audit.all()[1]
  assert(rec.parent == parent, "the parent bufnr should be recorded")
  assert(rec.depth == 1, "the depth should be recorded")
end)

it("a session's path is kept so a closed session stays identifiable", function()
  audit.clear()
  local b = fresh_session()
  local name = vim.api.nvim_buf_get_name(b)
  audit.record(b, { tool = "ping", action = "ok", reason = "quiet" })
  local rec = audit.all()[1]
  if name ~= "" then
    assert(rec.path ~= nil, "a file-backed session should record its path")
  end
  vim.api.nvim_buf_delete(b, { force = true })
  local after = audit.all()[1]
  assert(after ~= nil, "the audit should survive the buffer")
  assert(after.alive == false, "a closed session should be marked closed")
  assert(#after.entries == 1, "its entries should still be there")
end)

it("children sort under their parent", function()
  audit.clear()
  local parent = fresh_session()
  local child = fresh_session()
  vim.b[child].straps_parent = parent
  audit.record(child, { tool = "c", action = "ok", reason = "q" })
  audit.record(parent, { tool = "p", action = "ok", reason = "q" })
  local all = audit.all()
  assert(#all == 2, "two sessions")
  assert(all[1].key == parent, "the parent sorts first")
  assert(all[2].key == child, "the child follows it")
end)

it("the buffer renders every session and marks denies", function()
  audit.clear()
  local b = fresh_session()
  audit.record(b, { tool = "bash", action = "deny", reason = "data_loss=0.91" })
  audit.record(b, { tool = "read_file", action = "ok", reason = "quiet" })
  local buf = vim.api.nvim_create_buf(false, true)
  audit.render(buf)
  local text = table.concat(vim.api.nvim_buf_get_lines(buf, 0, -1, false), "\n")
  assert(text:find("DENY", 1, true), "a deny should be marked:\n" .. text)
  assert(text:find("bash", 1, true), "the tool should appear")
  assert(text:find("read_file", 1, true), "the allow should appear too")
  assert(text:find("data_loss=0.91", 1, true), "the reason should appear")
  assert(not vim.bo[buf].modifiable, "the view should be read-only")
end)

it("an empty audit renders without error", function()
  audit.clear()
  local buf = vim.api.nvim_create_buf(false, true)
  audit.render(buf)
  local text = table.concat(vim.api.nvim_buf_get_lines(buf, 0, -1, false), "\n")
  assert(text:find("no classifications", 1, true), "should say so:\n" .. text)
end)

it("clearing one session leaves the others", function()
  audit.clear()
  local a, b = fresh_session(), fresh_session()
  audit.record(a, { tool = "x", action = "ok", reason = "q" })
  audit.record(b, { tool = "y", action = "ok", reason = "q" })
  audit.clear(a)
  local all = audit.all()
  assert(#all == 1 and all[1].key == b, "only the cleared session should go")
end)

it("audit_limit below 1 is refused by setup", function()
  local ok, err = pcall(plugin.setup, { audit_limit = 0 })
  assert(not ok, "audit_limit = 0 must be refused")
  assert(tostring(err):find("audit_limit", 1, true), "the error should name it: " .. tostring(err))
end)

it("fn.classifier_audit records through the registry", function()
  audit.clear()
  local b = fresh_session()
  registry.call("fn.classifier_audit", b, { tool = "via_registry", action = "ok", reason = "q" })
  assert(audit.all()[1].entries[1].tool == "via_registry", "the fn should be the writer")
end)

it("fn.log receives one classify event per verdict", function()
  audit.clear()
  _G.LOGGED = {}
  registry.define({
    name = "fn.log", kind = "fn", doc = "test capture",
    source = "return function(ev) table.insert(_G.LOGGED, ev) end",
  }, { scope = "global" })
  registry.define({
    name = "fn.typesafe", kind = "fn", doc = "test stub",
    source = [[
return function(payload, ctx)
  if not (ctx and ctx.await) then return nil, "no ctx to await on" end
  return nil, "HTTP 500"
end
]],
  }, { scope = "global" })
  local b = fresh_session()
  local ctx = { bufnr = b, await = function(_) return nil end }
  registry.call("fn.risk_verdict", "ping", {}, ctx)
  local seen = false
  for _, ev in ipairs(_G.LOGGED) do
    if ev.ev == "classify" then
      seen = true
      assert(ev.tool == "ping", "the event should name the tool")
      assert(ev.action == "deny", "a failed classification is a deny")
    end
  end
  assert(seen, "no classify event was logged")
end)

