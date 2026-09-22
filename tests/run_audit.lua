-- tests/run_audit.lua — the classification record and its buffer view.
--   nvim --headless -l tests/run_audit.lua
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

case("a record lands in the ring", function()
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

case("a deny keeps the state it was judged on; an allow does not", function()
  audit.clear()
  local b = fresh_session()
  audit.record(b, { tool = "bash", action = "deny", reason = "data_loss=0.9",
    state = { tool = "bash" }, answers = { data_loss = { noul = 0.9 } } })
  audit.record(b, { tool = "ping", action = "ok", reason = "quiet" })
  local entries = audit.all()[1].entries
  local deny, allow = entries[1], entries[2]
  assert(deny.state ~= nil, "a deny should keep the state sent")
  assert(allow.state == nil, "an allow should not carry state")
end)

case("the ring caps at audit_limit and drops the oldest", function()
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

case("counts report allows, denies, and causes", function()
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

case("a child's entries carry its parent and depth", function()
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

case("a session's path is kept so a closed session stays identifiable", function()
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

case("children sort under their parent", function()
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

case("the buffer renders every session and marks denies", function()
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

case("an empty audit renders without error", function()
  audit.clear()
  local buf = vim.api.nvim_create_buf(false, true)
  audit.render(buf)
  local text = table.concat(vim.api.nvim_buf_get_lines(buf, 0, -1, false), "\n")
  assert(text:find("no classifications", 1, true), "should say so:\n" .. text)
end)

case("clearing one session leaves the others", function()
  audit.clear()
  local a, b = fresh_session(), fresh_session()
  audit.record(a, { tool = "x", action = "ok", reason = "q" })
  audit.record(b, { tool = "y", action = "ok", reason = "q" })
  audit.clear(a)
  local all = audit.all()
  assert(#all == 1 and all[1].key == b, "only the cleared session should go")
end)

case("audit_limit below 1 is refused by setup", function()
  local ok, err = pcall(plugin.setup, { audit_limit = 0 })
  assert(not ok, "audit_limit = 0 must be refused")
  assert(tostring(err):find("audit_limit", 1, true), "the error should name it: " .. tostring(err))
end)

case("fn.classifier_audit records through the registry", function()
  audit.clear()
  local b = fresh_session()
  registry.call("fn.classifier_audit", b, { tool = "via_registry", action = "ok", reason = "q" })
  assert(audit.all()[1].entries[1].tool == "via_registry", "the fn should be the writer")
end)

case("fn.log receives one classify event per verdict", function()
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

print(failed and "FAILED" or "ALL PASS")
os.exit(failed and 1 or 0)
