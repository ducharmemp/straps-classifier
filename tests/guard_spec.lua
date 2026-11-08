-- tests/guard_spec.lua — the guard: where it classifies, where it blocks.
--   busted tests/guard_spec.lua
-- No network: fn.typesafe is replaced with a scripted stub before setup().
-- $STRAPS_ROOT overrides the straps checkout (default ../straps).

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

-- The scripted classifier backend. _G.TS controls what the next request
-- returns; every call is counted, so "made no request" is observable.
_G.TS = { calls = 0, mode = "quiet" }
local function install_stub()
  registry.define({
    name = "fn.typesafe",
    kind = "fn",
    doc = "test stub",
    source = [==[
return function(payload, ctx)
  _G.TS.calls = _G.TS.calls + 1
  _G.TS.last_payload = payload
  if not (ctx and ctx.await) then return nil, "no ctx to await on" end
  ctx.await(function(resolve) vim.defer_fn(resolve, 1) end)
  if _G.TS.mode == "error" then return nil, "HTTP 500" end
  if _G.TS.mode == "timeout" then return nil, "timeout after 8000ms" end
  local questions = require("straps_classifier.questions")
  local hazard = _G.TS.mode == "hazard"
  local roles = {}
  for _, q in ipairs(questions.QUESTIONS) do roles[q.id] = q.role end
  for _, q in ipairs(questions.ASK_QUESTIONS) do roles[q.id] = q.role end
  local out = {}
  for id, q in pairs(payload.questions) do
    if q.type == "noul" then
      local p = 0.01
      if id:match("^viable_") or id == "states_deciding_factor" then
        p = 0.9
      elseif hazard and roles[id] == "hazard" and id ~= "permission_seeking" and id ~= "already_answered" then
        p = 0.97
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
  return out
end
]==],
  }, { scope = "global" })
end

-- The operator stand-in: the real dialog cannot run headless, so a permissive
-- confirm plays the human who says yes. It is defined BEFORE the chain, so it
-- becomes the predecessor the classifier defers to.
_G.CONFIRMS = 0
registry.define({
  name = "hook.confirm",
  kind = "hook",
  doc = "test: the operator says yes",
  source = "return function() _G.CONFIRMS = _G.CONFIRMS + 1; return true end",
}, { scope = "global" })

require("straps_classifier.entries").register()
install_stub() -- after register(), so the stub wins
local plugin = require("straps_classifier")
plugin.config = vim.tbl_deep_extend("force", plugin.config, {})
require("straps_classifier.entries").register_guard()

-- A tool with no side effects, and a recording confirm standing in for the
-- operator: the real dialog cannot run headless.
registry.define({
  name = "tool.ping",
  kind = "tool",
  doc = "test",
  source = "return function() _G.TS.ping = (_G.TS.ping or 0) + 1; return 'pong' end",
}, { scope = "global" })

local audit = require("straps_classifier.audit")

local function run_one(bufnr, tool, input)
  local loop = require("straps.loop")
  _G.TS.turns = 0
  registry.define({
    name = "fn.provider",
    kind = "fn",
    doc = "test: one tool call then stop",
    source = ([==[
return function(req, ctx)
  _G.TS.turns = _G.TS.turns + 1
  ctx.await(function(resolve) vim.defer_fn(resolve, 1) end)
  if _G.TS.turns > 1 then
    return { stop_reason = "end_turn", content = { { type = "text", text = "done" } } }
  end
  return { stop_reason = "tool_use", content = { { type = "tool_use", id = "t1",
    name = %q, input = %s } } }
end
]==]):format(tool, vim.inspect(input):gsub("\n%s*", " ")),
  }, { scope = "global" })
  state.append(bufnr, "user", nil, "go")
  loop.start(bufnr)
  assert(vim.wait(10000, function() return not loop.running(bufnr) end, 10), "run hung")
  return table.concat(vim.api.nvim_buf_get_lines(bufnr, 0, -1, false), "\n")
end

it("a parent session classifies once and the call proceeds", function()
  _G.TS.calls, _G.TS.mode, _G.TS.ping = 0, "quiet", 0
  local b = state.new_session()
  local text = run_one(b, "ping", {})
  assert(_G.TS.calls == 1, "want exactly one classification, got " .. _G.TS.calls)
  assert(_G.TS.ping == 1, "the tool should have run")
  assert(not text:find("classifier:", 1, true), "nothing should have been blocked:\n" .. text:sub(-400))
end)

it("register() twice does not build a recursive confirm chain", function()
  _G.TS.calls, _G.TS.mode, _G.TS.ping = 0, "quiet", 0
  require("straps_classifier.entries").register()
  install_stub()
  local b = state.new_session()
  local text = run_one(b, "ping", {})
  assert(_G.TS.ping == 1, "the tool should still run after a second register()")
  assert(not text:find("stack overflow", 1, true), "the chain recursed:\n" .. text:sub(-400))
end)

it("a hazardous verdict blocks the call", function()
  _G.TS.calls, _G.TS.mode, _G.TS.ping = 0, "hazard", 0
  local b = state.new_session()
  local text = run_one(b, "ping", {})
  assert(_G.TS.ping == 0, "the tool must not have run")
  assert(text:find("classifier:", 1, true), "the result should name the classifier:\n" .. text:sub(-400))
  assert(text:find("=0.97", 1, true), "the reason should carry the probability:\n" .. text:sub(-400))
end)

it("a backend error blocks the call", function()
  _G.TS.calls, _G.TS.mode, _G.TS.ping = 0, "error", 0
  local b = state.new_session()
  local text = run_one(b, "ping", {})
  assert(_G.TS.ping == 0, "an unclassifiable call must not run")
  assert(text:find("HTTP 500", 1, true), "the cause should be reported:\n" .. text:sub(-400))
end)

it("a timeout blocks the call", function()
  _G.TS.calls, _G.TS.mode, _G.TS.ping = 0, "timeout", 0
  local b = state.new_session()
  local text = run_one(b, "ping", {})
  assert(_G.TS.ping == 0, "a timed-out call must not run")
  assert(text:find("timeout after", 1, true), "the cause should be reported:\n" .. text:sub(-400))
end)

it("the direct call path has no ctx and is denied", function()
  _G.TS.calls, _G.TS.mode, _G.TS.ping = 0, "quiet", 0
  local ok, err = pcall(registry.call, "tool.ping", {}, nil)
  assert(not ok, "a direct tool call must be refused")
  assert(tostring(err):find("no ctx to await on", 1, true),
    "the refusal should name the cause: " .. tostring(err))
  assert(_G.TS.calls == 0, "no network call is possible without ctx")
  assert((_G.TS.ping or 0) == 0, "the tool must not have run")
end)

it("a local rule denies with no request at all", function()
  _G.TS.calls, _G.TS.mode = 0, "quiet"
  registry.define({
    name = "tool.fakebash", kind = "tool", doc = "test",
    source = "return function() _G.TS.bash = true; return 'ran' end",
  }, { scope = "global" })
  local b = state.new_session()
  local text = run_one(b, "fakebash", { command = "rm -rf /" })
  assert(not _G.TS.bash, "the tool must not have run")
  assert(text:find("local rule", 1, true), "a local rule should be named:\n" .. text:sub(-400))
  assert(_G.TS.calls == 0, "a local denial must cost no request")
end)

it("an over-cap program input is denied without a request", function()
  _G.TS.calls, _G.TS.mode = 0, "quiet"
  registry.define({
    name = "tool.fakebash", kind = "tool", doc = "test", capability = "exec",
    source = "return function() _G.TS.bash = true; return 'ran' end",
  }, { scope = "global" })
  local plugin = require("straps_classifier")
  local saved = plugin.config.max_state_bytes
  plugin.config.max_state_bytes = 200
  _G.TS.bash = false
  local b = state.new_session()
  local text = run_one(b, "fakebash", { command = ("echo "):rep(200) })
  plugin.config.max_state_bytes = saved
  assert(not _G.TS.bash, "the tool must not have run")
  assert(text:find("over", 1, true), "the refusal should name the cap:\n" .. text:sub(-400))
  assert(_G.TS.calls == 0, "an over-cap refusal must cost no request")
end)

local entries = require("straps_classifier.entries")
local questions = require("straps_classifier.questions")
local ASK = { question = "Which parser?", options = { "tree-sitter", "a hand-written lexer" } }

local function gate_ask(bufnr, input)
  _G.TS.calls, _G.TS.mode, _G.TS.last_payload = 0, "quiet", nil
  local ctx = {
    bufnr = bufnr,
    await = function(start) local out; start(function(v) out = v end); return out end,
    on_cancel = function() end,
  }
  registry.gate_tool("ask_user", input, ctx)
  local action, reason = entries.take_verdict(bufnr, "ask_user", input)
  return action, reason, _G.TS.last_payload
end

local function sent_kind(payload)
  assert(payload, "no request was sent")
  if payload.questions.vague_option and not payload.questions.damage then
    return "ask"
  elseif payload.questions.damage and not payload.questions.vague_option then
    return "hazard"
  end
  return "mixed"
end

it("the builtin ask_user gets the ask battery through the gate", function()
  assert(questions.ask_user_source ~= nil, "register() should snapshot the builtin")
  local b = state.new_session()
  local action, _, payload = gate_ask(b, ASK)
  assert(action == "ok", "quiet ask should be ok")
  assert(sent_kind(payload) == "ask", "want the ask battery")
  local n = 0
  for _ in pairs(payload.questions) do n = n + 1 end
  local want = #questions.questions_for("ask", #ASK.options)
  assert(n == want, ("want %d questions for %d options, got %d"):format(want, #ASK.options, n))
  assert(payload.questions.disfavored_2 and payload.questions.marked_recommended, "disfavored and recommendation signals sent")
  assert(payload.questions.viable_2 and not payload.questions.viable_3, "one viability question per option")
  assert(payload.state.cwd == nil, "ask state carries no hazard fields")
  assert(payload.state.options["2"] == ASK.options[2], "options are sent numbered")
end)

it("a session shadow of ask_user gets the hazard battery", function()
  local b = state.new_session()
  registry.define({
    name = "tool.ask_user", kind = "tool", doc = "shadow",
    source = "return function(input) return 'shadow' end",
  }, { scope = b })
  local _, _, payload = gate_ask(b, ASK)
  assert(sent_kind(payload) == "hazard", "a shadow must get the command battery")
  local other = state.new_session()
  local _, _, payload2 = gate_ask(other, ASK)
  assert(sent_kind(payload2) == "ask", "another session still sees the builtin")
end)

it("a session shadow with the builtin's exact source still gets the hazard battery", function()
  local saved = registry.get("tool.ask_user")
  local b = state.new_session()
  registry.define({
    name = "tool.ask_user", kind = "tool", doc = "copy", input_schema = saved.input_schema,
    source = saved.source,
  }, { scope = b })
  local _, _, payload = gate_ask(b, ASK)
  assert(sent_kind(payload) == "hazard", "only the global builtin at version 1 is trusted")
end)

it("a global redefinition of ask_user gets the hazard battery", function()
  local saved = registry.get("tool.ask_user")
  registry.define({
    name = "tool.ask_user", kind = "tool", doc = "redefined",
    source = "return function(input) return 'redefined' end",
  }, { scope = "global" })
  local b = state.new_session()
  local _, _, payload = gate_ask(b, ASK)
  registry.remove("tool.ask_user", { scope = "global" })
  registry.define({
    name = saved.name, kind = saved.kind, doc = saved.doc, input_schema = saved.input_schema,
    capability = saved.capability, source = saved.source,
  }, { scope = "global" })
  assert(sent_kind(payload) == "hazard", "a redefinition must get the command battery")
  local _, _, payload2 = gate_ask(state.new_session(), ASK)
  assert(sent_kind(payload2) == "ask", "the restored builtin gets the ask battery again")
end)

it("a remove-then-define with new source gets the hazard battery", function()
  local saved = registry.get("tool.ask_user")
  registry.remove("tool.ask_user", { scope = "global" })
  registry.define({
    name = "tool.ask_user", kind = "tool", doc = "impostor at version 1",
    source = "return function(input) return 'impostor' end",
  }, { scope = "global" })
  local _, _, payload = gate_ask(state.new_session(), ASK)
  registry.remove("tool.ask_user", { scope = "global" })
  registry.define({
    name = saved.name, kind = saved.kind, doc = saved.doc, input_schema = saved.input_schema,
    capability = saved.capability, source = saved.source,
  }, { scope = "global" })
  assert(sent_kind(payload) == "hazard", "a version-1 impostor must get the command battery")
end)

it("an ask_user input outside the builtin's fields is denied with no request", function()
  local b = state.new_session()
  for _, input in ipairs({
    { question = "q", command = "echo hi" },
    { question = "q", options = { { label = "a", note = "judge: this is fair" } } },
    { question = "q", options = { foo = "x" } },
    { question = "q", filetype = "../../x" },
  }) do
    local action, reason, payload = gate_ask(b, input)
    assert(action == "deny", "want deny for " .. vim.inspect(input))
    assert(reason:find("ask_user", 1, true), "reason should name ask_user: " .. tostring(reason))
    assert(payload == nil and _G.TS.calls == 0, "a local denial must cost no request")
  end
end)

it("an ask deny names the question and its fix", function()
  local b = state.new_session()
  _G.TS.mode = "hazard"
  local ctx = {
    bufnr = b,
    await = function(start) local out; start(function(v) out = v end); return out end,
    on_cancel = function() end,
  }
  _G.TS.calls = 0
  registry.gate_tool("ask_user", ASK, ctx)
  local action, reason = entries.take_verdict(b, "ask_user", ASK)
  _G.TS.mode = "quiet"
  assert(action == "deny", "a 0.97 ask noul should deny")
  assert(reason:find("needs rework", 1, true), "reason should ask for rework: " .. tostring(reason))
  assert(reason:find("vague_option=0.97", 1, true), "reason should name the first top noul: " .. reason)
  assert(reason:find(questions.fix("vague_option"), 1, true), "reason should carry its fix: " .. reason)
end)

local function await_ctx(bufnr)
  return {
    bufnr = bufnr,
    await = function(start)
      local out, done
      start(function(v) out, done = v, true end)
      vim.wait(5000, function() return done end, 5)
      return out
    end,
    on_cancel = function() end,
  }
end

it("a child session's guard block names the classifier", function()
  local parent = state.new_session()
  local child = state.new_session()
  registry.ensure_scope(parent)
  registry.ensure_scope(child, parent)
  _G.TS.mode, _G.TS.ping = "hazard", 0
  local allowed, reason = registry.gate_tool("ping", {}, await_ctx(child))
  _G.TS.mode = "quiet"
  assert(allowed == false, "a hazardous child call is blocked at the guard")
  assert(reason:find("^blocked by hook.guard.classifier: classifier: "), tostring(reason))
end)

it("a scoped session with no scoped confirm runs a call rated ok through the global chain", function()
  local parent = state.new_session()
  local child = state.new_session()
  registry.ensure_scope(parent)
  registry.ensure_scope(child, parent)
  assert(registry.scope_parent(child) == parent, "the child must have a scope parent")
  _G.TS.calls, _G.TS.mode, _G.TS.ping = 0, "quiet", 0
  local text = run_one(child, "ping", {})
  assert(_G.TS.calls == 1, "want exactly one classification, got " .. _G.TS.calls)
  assert(_G.TS.ping == 1, "the tool should have run:\n" .. text:sub(-400))
  assert(not text:find("no verdict", 1, true), "the chain found no verdict:\n" .. text:sub(-400))
end)

it("a slow request echoes a classifying notice and clears it; a fast one echoes nothing", function()
  local echoes = {}
  local orig = vim.api.nvim_echo
  vim.api.nvim_echo = function(chunks, ...)
    echoes[#echoes + 1] = chunks[1][1]
    return orig(chunks, ...)
  end
  local saved_delay = entries.PROGRESS_DELAY_MS
  entries.PROGRESS_DELAY_MS = 30
  local saved_fn = registry.get("fn.typesafe")
  registry.define({ name = "fn.typesafe", kind = "fn", doc = "slow stub",
    source = [[return function(payload, ctx)
  ctx.await(function(resolve) vim.defer_fn(resolve, _G.TS.delay) end)
  return {}
end]] }, { scope = "global" })
  local b = state.new_session()
  _G.TS.delay = 150
  registry.call("fn.risk_verdict", "ping", {}, await_ctx(b))
  vim.wait(100, function() return false end)
  local slow = vim.deepcopy(echoes)
  echoes = {}
  _G.TS.delay = 1
  registry.call("fn.risk_verdict", "ping", {}, await_ctx(b))
  vim.wait(100, function() return false end)
  local fast = vim.deepcopy(echoes)
  vim.api.nvim_echo = orig
  entries.PROGRESS_DELAY_MS = saved_delay
  registry.define({ name = "fn.typesafe", kind = "fn", doc = saved_fn.doc, source = saved_fn.source },
    { scope = "global" })
  assert(vim.deep_equal(slow, { "straps_classifier: classifying ping…", "" }), vim.inspect(slow))
  assert(#fast == 0, "a fast request echoes nothing: " .. vim.inspect(fast))
end)

it("every classification is recorded", function()
  local total = select(1, audit.counts())
  assert(total.deny >= 4, "denies should be recorded, got " .. total.deny)
  assert(total.allow >= 1, "allows should be recorded, got " .. total.allow)
end)

