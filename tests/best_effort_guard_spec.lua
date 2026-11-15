local root = vim.fn.fnamemodify(debug.getinfo(1, "S").source:sub(2), ":p:h:h")
local core = vim.fn.fnamemodify(os.getenv("STRAPS_ROOT") or "../straps", ":p")
vim.opt.rtp:prepend(core)
package.path = root .. "/lua/?.lua;" .. root .. "/lua/?/init.lua;" .. core .. "/lua/?.lua;" .. core .. "/lua/?/init.lua;" .. package.path
local straps = require("straps").setup({})
straps.config.session_dir = vim.fn.tempname()
local registry = require("straps.registry")
local state = require("straps.state")
local entries = require("straps_classifier.entries")
local best_effort = require("straps_classifier.best_effort")
local original_verdict = best_effort.verdict
local fixture, buf, buffers
local checks = 0
local function expect(actual, expected)
  checks = checks + 1
  if tonumber(vim.env.BEST_EFFORT_COUNTERFACTUAL) == checks then assert.are_not.same(expected, actual)
  else assert.same(expected, actual) end
end
local function define(name, source, capability, scope)
  return registry.define({ name = name, kind = name:match("^([^.]+)"), source = source, capability = capability }, scope)
end
local confirm_source = "return function() _G.best_guard.confirms = _G.best_guard.confirms + 1; return not _G.best_guard.refuse, 'operator refused' end"
define("hook.confirm", confirm_source)
require("straps_classifier").setup({ best_effort = { enabled = true, acknowledge_risk = true, disclosure_approved = true,
  operator_scope = "Edit and test the local fixture" } })
local chained_confirm = registry.get("hook.confirm").source
local function context(b)
  return { bufnr = b, cancelled = function() return false end, await = function(start)
    local done, result = false, nil
    start(function(value) done, result = true, value end)
    assert(vim.wait(2000, function() return done end, 1), "await timed out")
    return result
  end }
end
local function invoke(name, input, b)
  local ctx = context(b or buf)
  local allowed, reason, run = registry.gate_tool(name or "best_probe", input or {}, ctx,
    { confirm = function(...) return registry.call("hook.confirm", ...) end })
  if not allowed then return false, reason end
  return run(ctx)
end
before_each(function()
  fixture = { calls = 0, bodies = 0, confirms = 0, action = "ok", records = {} }
  _G.best_guard = fixture
  buffers = {}
  buf = state.new_session()
  buffers[#buffers + 1] = buf
  registry.ensure_scope(buf)
  define("hook.confirm", chained_confirm)
  define("tool.best_probe", "return function(input) _G.best_guard.bodies = _G.best_guard.bodies + 1; return input.value or 'ran' end", "exec")
  define("fn.classifier_audit", "return function(_, rec) table.insert(_G.best_guard.records, rec) end")
  best_effort.verdict = function(name, input, ctx, cfg)
    fixture.calls = fixture.calls + 1
    fixture.name, fixture.input, fixture.cfg = name, vim.deepcopy(input), cfg
    ctx.await(function(done)
      vim.schedule(function()
        if fixture.mutate then coroutine.wrap(fixture.mutate)() end
        done(true)
      end)
    end)
    return fixture.action, "fixed verdict"
  end
end)
after_each(function()
  registry.set_active_scope(nil)
  for _, b in ipairs(buffers) do if vim.api.nvim_buf_is_valid(b) then vim.api.nvim_buf_delete(b, { force = true }) end end
end)
teardown(function()
  best_effort.verdict = original_verdict
  vim.fn.delete(straps.config.session_dir, "rf")
  _G.best_guard = nil
  print("BEST_EFFORT_ASSERTIONS=" .. checks)
end)
it("routes before legacy rules and preserves native confirmation", function()
  local ok, result = invoke(nil, { command = "sudo routine", value = "passed" })
  expect(ok, true)
  expect(result, "passed")
  expect(fixture.calls, 1)
  expect(fixture.confirms, 1)
  expect(fixture.bodies, 1)
  expect(fixture.cfg.best_effort.operator_scope, "Edit and test the local fixture")
end)
it("retains root operator refusal", function()
  fixture.refuse = true
  local ok, reason = invoke()
  expect(ok, false)
  expect(tostring(reason):find("operator refused", 1, true) ~= nil, true)
  expect(fixture.calls, 1)
  expect(fixture.confirms, 1)
  expect(fixture.bodies, 0)
  expect(entries.take_verdict(buf, "best_probe", {}), nil)
end)
it("keeps a classifier denial after replacement confirmation", function()
  define("hook.confirm", "return function() return true end", nil, { scope = buf })
  fixture.action = "deny"
  expect(invoke(), false)
  expect(fixture.calls, 1)
  expect(fixture.bodies, 0)
end)
it("keeps child ceilings despite scoped replacement confirmation", function()
  local child = vim.api.nvim_create_buf(false, true)
  buffers[#buffers + 1] = child
  registry.ensure_scope(child, buf)
  registry.grant(child, "spawn:gated")
  define("hook.confirm", "return function() return true end", nil, { scope = child })
  expect(invoke(nil, {}, child), false)
  expect(fixture.calls, 0)
  expect(fixture.bodies, 0)
  registry.grant(child, "cap:exec")
  expect(invoke(nil, {}, child), true)
  expect(fixture.calls, 1)
  expect(fixture.bodies, 1)
end)
it("denies without context and records no raw input", function()
  local ok, reason = pcall(registry.call, "tool.best_probe", { secret = "PRIVATE_INPUT", command = "sudo routine" })
  expect(ok, false)
  expect(tostring(reason):find("best-effort classification requires an await context", 1, true) ~= nil, true)
  expect(fixture.calls, 0)
  expect(fixture.bodies, 0)
  expect(fixture.records, { { tool = "best_probe", action = "deny",
    reason = "best-effort classification requires an await context", ms = 0 } })
end)
it("rejects definition changes during awaited classification", function()
  fixture.mutate = function() define("tool.best_probe", "return function() _G.best_guard.bodies = 100 end", "exec") end
  local ok, reason = invoke()
  expect(ok, false)
  expect(tostring(reason):find("tool definition changed", 1, true) ~= nil, true)
  expect(fixture.bodies, 0)
end)
it("rejects directory changes during awaited classification", function()
  local cwd = vim.fn.getcwd()
  fixture.mutate = function() vim.cmd("cd " .. vim.fn.fnameescape(core)) end
  local ok, reason = invoke()
  vim.cmd("cd " .. vim.fn.fnameescape(cwd))
  expect(ok, false)
  expect(tostring(reason):find("execution directory changed", 1, true) ~= nil, true)
  expect(fixture.bodies, 0)
end)
it("rechecks child grants after awaited classification", function()
  registry.grant(buf, "spawn:gated")
  registry.grant(buf, "cap:exec")
  fixture.mutate = function() registry.clear_grants(buf, "cap:exec") end
  expect(invoke(), false)
  expect(fixture.calls, 1)
  expect(fixture.bodies, 0)
end)
it("executes the frozen input when the caller mutates its original", function()
  local input = { value = "original" }
  fixture.mutate = function() input.value = "changed" end
  local ok, value = invoke(nil, input)
  expect(ok, true)
  expect(value, "original")
  expect(fixture.input.value, "original")
end)
it("retains native edit buffer undo and after-write hook", function()
  local path = vim.fn.tempname()
  vim.fn.writefile({ "before" }, path)
  local filebuf = vim.fn.bufadd(path)
  vim.fn.bufload(filebuf)
  define("hook.after_write", "return function() _G.best_guard.writes = (_G.best_guard.writes or 0) + 1 end")
  local ok, result = invoke("edit_file", { path = path, old_string = "before", new_string = "after" })
  local lines = vim.api.nvim_buf_get_lines(filebuf, 0, -1, false)
  vim.api.nvim_buf_call(filebuf, function() vim.cmd("undo") end)
  local undone = vim.api.nvim_buf_get_lines(filebuf, 0, -1, false)
  vim.api.nvim_buf_delete(filebuf, { force = true })
  vim.fn.delete(path)
  expect(ok, true)
  expect(type(result), "string")
  expect(lines, { "after" })
  expect(undone, { "before" })
  expect(fixture.writes, 1)
end)
