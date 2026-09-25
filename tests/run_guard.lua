-- tests/run_guard.lua — the guard: where it classifies, where it blocks.
--   nvim --headless -l tests/run_guard.lua
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
  local out = {}
  for _, q in ipairs(questions.QUESTIONS) do
    if q.type == "noul" then
      out[q.id] = { type = "noul", noul = (hazard and q.role == "hazard") and 0.97 or 0.01 }
    end
  end
  local legend = {}
  for i, text in ipairs(questions.DAMAGE_LEVELS) do legend[tostring(i - 1)] = text end
  out.damage = { type = "score", score = 0.1, legend = legend, confidence = 0.9 }
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

case("a parent session classifies once and the call proceeds", function()
  _G.TS.calls, _G.TS.mode, _G.TS.ping = 0, "quiet", 0
  local b = state.new_session()
  local text = run_one(b, "ping", {})
  assert(_G.TS.calls == 1, "want exactly one classification, got " .. _G.TS.calls)
  assert(_G.TS.ping == 1, "the tool should have run")
  assert(not text:find("classifier:", 1, true), "nothing should have been blocked:\n" .. text:sub(-400))
end)

case("register() twice does not build a recursive confirm chain", function()
  _G.TS.calls, _G.TS.mode, _G.TS.ping = 0, "quiet", 0
  require("straps_classifier.entries").register()
  install_stub()
  local b = state.new_session()
  local text = run_one(b, "ping", {})
  assert(_G.TS.ping == 1, "the tool should still run after a second register()")
  assert(not text:find("stack overflow", 1, true), "the chain recursed:\n" .. text:sub(-400))
end)

case("a hazardous verdict blocks the call", function()
  _G.TS.calls, _G.TS.mode, _G.TS.ping = 0, "hazard", 0
  local b = state.new_session()
  local text = run_one(b, "ping", {})
  assert(_G.TS.ping == 0, "the tool must not have run")
  assert(text:find("classifier:", 1, true), "the result should name the classifier:\n" .. text:sub(-400))
  assert(text:find("=0.97", 1, true), "the reason should carry the probability:\n" .. text:sub(-400))
end)

case("a backend error blocks the call", function()
  _G.TS.calls, _G.TS.mode, _G.TS.ping = 0, "error", 0
  local b = state.new_session()
  local text = run_one(b, "ping", {})
  assert(_G.TS.ping == 0, "an unclassifiable call must not run")
  assert(text:find("HTTP 500", 1, true), "the cause should be reported:\n" .. text:sub(-400))
end)

case("a timeout blocks the call", function()
  _G.TS.calls, _G.TS.mode, _G.TS.ping = 0, "timeout", 0
  local b = state.new_session()
  local text = run_one(b, "ping", {})
  assert(_G.TS.ping == 0, "a timed-out call must not run")
  assert(text:find("timeout after", 1, true), "the cause should be reported:\n" .. text:sub(-400))
end)

case("the direct call path has no ctx and is denied", function()
  _G.TS.calls, _G.TS.mode, _G.TS.ping = 0, "quiet", 0
  local ok, err = pcall(registry.call, "tool.ping", {}, nil)
  assert(not ok, "a direct tool call must be refused")
  assert(tostring(err):find("no ctx to await on", 1, true),
    "the refusal should name the cause: " .. tostring(err))
  assert(_G.TS.calls == 0, "no network call is possible without ctx")
  assert((_G.TS.ping or 0) == 0, "the tool must not have run")
end)

case("a local rule denies with no request at all", function()
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

case("an over-cap program input is denied without a request", function()
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

case("every classification is recorded", function()
  local total = select(1, audit.counts())
  assert(total.deny >= 4, "denies should be recorded, got " .. total.deny)
  assert(total.allow >= 1, "allows should be recorded, got " .. total.allow)
end)

print(failed and "FAILED" or "ALL PASS")
os.exit(failed and 1 or 0)
