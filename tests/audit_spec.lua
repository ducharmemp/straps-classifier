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

local function capture_notify(fn)
  local seen = {}
  local orig = vim.notify
  vim.notify = function(msg, level) seen[#seen + 1] = { msg = msg, level = level } end
  local ok, err = pcall(fn)
  vim.notify = orig
  assert(ok, tostring(err))
  return seen
end

it("audit_limit below 1 is refused by setup with an ERROR notify and ignored", function()
  local seen = capture_notify(function() plugin.setup({ audit_limit = 0 }) end)
  local hit
  for _, n in ipairs(seen) do
    if n.msg:find("audit_limit", 1, true) then hit = n end
  end
  assert(hit, "setup should notify about audit_limit: " .. vim.inspect(seen))
  assert(hit.msg:find("^straps_classifier: audit_limit must be at least 1"), "prefix and wording: " .. hit.msg)
  assert(hit.level == vim.log.levels.ERROR, "level should be ERROR, got " .. tostring(hit.level))
  assert(plugin.effective().audit_limit == 500, "the bad value is ignored, got " .. tostring(plugin.effective().audit_limit))
end)

it("setup keeps a user's fn.classifier_audit and fn.typesafe_api_key redefinitions", function()
  registry.define({ name = "fn.classifier_audit", kind = "fn", doc = "user sink",
    source = "return function(b, rec) _G.USER_SINK = rec.tool; return rec end" }, { scope = "global" })
  registry.define({ name = "fn.classifier_audit_render", kind = "fn", doc = "user render",
    source = "return function() _G.USER_RENDER = true end" }, { scope = "global" })
  registry.define({ name = "fn.typesafe_api_key", kind = "fn", doc = "user key",
    source = "return function() return 'user-key' end" }, { scope = "global" })
  local before = registry.get("fn.typesafe").version
  require("straps_classifier.entries").register()
  assert(registry.get("fn.classifier_audit").doc == "user sink", "the audit sink must survive register()")
  assert(registry.get("fn.classifier_audit_render").doc == "user render", "the render fn must survive register()")
  assert(registry.call("fn.typesafe_api_key") == "user-key", "the key fn must survive register()")
  assert(registry.get("fn.typesafe").version == before + 1, "fn.typesafe is always redefined")
  registry.call("fn.classifier_audit", 0, { tool = "sinked" })
  assert(_G.USER_SINK == "sinked", "the user sink should receive records")
  registry.define({ name = "fn.classifier_audit", kind = "fn", doc = "restore",
    source = "return function(b, rec) return require('straps_classifier.audit').record(b, rec) end" },
    { scope = "global" })
  registry.define({ name = "fn.classifier_audit_render", kind = "fn", doc = "restore",
    source = "return function(b) return require('straps_classifier.audit').render(b) end" }, { scope = "global" })
end)

it("status without setup says tool calls are not classified", function()
  package.loaded["straps_classifier"] = nil
  local fresh = require("straps_classifier")
  local lines, level, s = fresh.status_report()
  assert(s.setup_ran == false, "setup_ran should be false")
  assert(lines[1] == "straps_classifier: setup() has not run; tool calls are NOT classified", lines[1])
  assert(level == vim.log.levels.WARN, "level should be WARN")
  package.loaded["straps_classifier"] = plugin
end)

it("status carries the key error and warns", function()
  registry.define({ name = "fn.typesafe_api_key", kind = "fn", doc = "no key",
    source = "return function() error('straps_classifier: no TypeSafe API key. test reason', 0) end" },
    { scope = "global" })
  plugin.setup_ran, plugin.installed = true, true
  local lines, level, s = plugin.status_report()
  assert(s.api_key == false, "api_key should be false")
  assert(s.api_key_error == "straps_classifier: no TypeSafe API key. test reason", tostring(s.api_key_error))
  assert(table.concat(lines, "\n"):find("test reason", 1, true), "the reason should be in the report")
  assert(level == vim.log.levels.WARN, "level should be WARN, got " .. tostring(level))
  plugin.installed, plugin.install_error = false, "frozen"
  local _, level2 = plugin.status_report()
  assert(level2 == vim.log.levels.ERROR, "an install failure is ERROR")
  registry.define({ name = "fn.typesafe_api_key", kind = "fn", doc = "key",
    source = "return function() return 'k' end" }, { scope = "global" })
  plugin.installed, plugin.install_error = true, nil
  local _, level3 = plugin.status_report()
  assert(level3 == vim.log.levels.INFO, "a working install is INFO")
end)

it(":StrapsClassifierStatus notifies at the report's level", function()
  vim.g.loaded_straps_classifier = nil
  vim.cmd("source " .. vim.fn.fnameescape(root .. "/plugin/straps_classifier.lua"))
  plugin.installed, plugin.install_error = false, "frozen"
  local seen = capture_notify(function() vim.cmd("StrapsClassifierStatus") end)
  assert(#seen == 1 and seen[1].level == vim.log.levels.ERROR, vim.inspect(seen))
  plugin.installed, plugin.install_error = true, nil
end)

it("checkhealth reports install, key and counts", function()
  audit.clear()
  audit.record(0, { tool = "a", action = "deny", reason = "x", failure = "timeout" })
  vim.cmd("checkhealth straps_classifier")
  local text = table.concat(vim.api.nvim_buf_get_lines(0, 0, -1, false), "\n")
  assert(text:find("guard installed", 1, true), text)
  assert(text:find("fn.typesafe_api_key resolves", 1, true), text)
  assert(text:find("allows: 0, denies: 1", 1, true), text)
  assert(text:find("failure timeout: 1", 1, true), text)
  vim.cmd("bwipeout!")
end)

it("the record view reuses one named nofile window and the audit command reuses its window", function()
  audit.clear()
  local b = fresh_session()
  audit.record(b, { tool = "one", action = "ok", reason = "q" })
  audit.record(b, { tool = "two", action = "ok", reason = "q" })
  local abuf = audit.open()
  local wins = #vim.api.nvim_list_wins()
  audit.open()
  assert(#vim.api.nvim_list_wins() == wins, "a second open should focus the existing window")
  audit.render(abuf)
  local rows = {}
  for i, l in ipairs(vim.api.nvim_buf_get_lines(abuf, 0, -1, false)) do
    if l:find("  ok  ", 1, true) then rows[#rows + 1] = i end
  end
  assert(#rows == 2, "two rows rendered")
  vim.api.nvim_win_set_cursor(0, { rows[1], 0 })
  audit._open_record()
  local rec_buf = vim.api.nvim_get_current_buf()
  assert(vim.api.nvim_buf_get_name(rec_buf):match("^straps://classifier/record/%d+$"), vim.api.nvim_buf_get_name(rec_buf))
  assert(vim.bo[rec_buf].buftype == "nofile", "record buffer is nofile")
  local after_first = #vim.api.nvim_list_wins()
  vim.api.nvim_set_current_win(vim.fn.bufwinid(abuf))
  vim.api.nvim_win_set_cursor(0, { rows[2], 0 })
  audit._open_record()
  assert(#vim.api.nvim_list_wins() == after_first, "a second record reuses the record window")
  assert(vim.api.nvim_get_current_buf() ~= rec_buf, "the second record shows a different buffer")
end)

it("x asks before clearing and notifies after", function()
  audit.clear()
  local b = fresh_session()
  audit.record(b, { tool = "one", action = "ok", reason = "q" })
  local abuf = audit.open()
  audit.render(abuf)
  local row
  for i, l in ipairs(vim.api.nvim_buf_get_lines(abuf, 0, -1, false)) do
    if l:find("  ok  ", 1, true) then row = i end
  end
  vim.api.nvim_set_current_win(vim.fn.bufwinid(abuf))
  vim.api.nvim_win_set_cursor(0, { row, 0 })
  local orig_confirm = vim.fn.confirm
  vim.fn.confirm = function() return 2 end
  local seen = capture_notify(function() audit._clear_at_cursor() end)
  assert(#audit.all() == 1, "a No keeps the records")
  assert(#seen == 0, "no notice on No")
  vim.fn.confirm = function() return 1 end
  seen = capture_notify(function() audit._clear_at_cursor() end)
  vim.fn.confirm = orig_confirm
  assert(#audit.all() == 0, "a Yes clears the records")
  assert(#seen == 1 and seen[1].msg:find("^straps_classifier: cleared 1 records"), vim.inspect(seen))
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

