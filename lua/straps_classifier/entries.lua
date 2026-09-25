-- The registry entries. Every source is a Lua chunk returning a function;
-- bodies require() the plugin's real modules rather than carrying logic as
-- string literals, so the tests exercise the same code the entries run.

local M = {}

-- ── the verdict slot ────────────────────────────────────────────────────────
-- The guard classifies; the confirm chain enforces. They are two halves of one
-- gate_tool pass, microseconds apart, and the slot carries the verdict between
-- them. One entry per session, keyed to the exact call, cleared on read. Not a
-- cache: it answers no future call.
--
-- Per session, not one global slot: sessions run concurrently in one Neovim (a
-- parent and its subagent, or two peers), and a single slot lets one session's
-- guard overwrite another's verdict between that session's guard and its
-- confirm. The key check would catch it and deny, but the denial would be
-- spurious -- legitimate work blocked by a neighbour's timing.
local slots = {}

local function slot_key(name, input)
  local ok, encoded = pcall(vim.json.encode, input)
  return tostring(name) .. "\0" .. (ok and encoded or tostring(input))
end

function M.put_verdict(bufnr, name, input, action, reason)
  slots[bufnr or 0] = { key = slot_key(name, input), action = action, reason = reason }
end

function M.take_verdict(bufnr, name, input)
  local slot = slots[bufnr or 0]
  if not slot or slot.key ~= slot_key(name, input) then
    return nil
  end
  slots[bufnr or 0] = nil
  return slot.action, slot.reason
end

--- Drop a session's pending verdict. Called when a confirm refuses, so a
--- verdict produced for a rejected call cannot linger.
function M.clear_verdict(bufnr)
  if bufnr == nil then
    slots = {}
  else
    slots[bufnr] = nil
  end
end

function M.register()
  local registry = require("straps.registry")

  -- ── fn.typesafe_api_key ───────────────────────────────────────────────────
  registry.define({
    name = "fn.typesafe_api_key",
    kind = "fn",
    doc = "Return the TypeSafe API key ($TYPESAFE_API_KEY, then"
      .. " $XDG_CONFIG_HOME/straps/typesafe_api_key; the file must be chmod 600).",
    source = [==[
return function()
  local key = vim.env.TYPESAFE_API_KEY
  if key and key ~= "" then
    return key
  end
  local config_home = vim.env.XDG_CONFIG_HOME
  if not config_home or config_home == "" then
    local home = vim.env.HOME
    config_home = (home and home ~= "") and (home .. "/.config") or nil
  end
  local path = config_home and (config_home .. "/straps/typesafe_api_key")
  local st = path and vim.uv.fs_stat(path)
  if st and st.type == "file" then
    if st.mode % 64 ~= 0 then
      error(("straps_classifier: %s is accessible by group/other (mode %03o); run chmod 600 on it.")
        :format(path, st.mode % 4096))
    end
    local f, open_err = io.open(path, "r")
    if not f then
      error("straps_classifier: " .. path .. " exists but could not be read ("
        .. tostring(open_err) .. ").")
    end
    key = f:read("*l")
    f:close()
    key = key and vim.trim(key) or ""
    if key ~= "" then
      return key
    end
  end
  error("straps_classifier: no TypeSafe API key. Export TYPESAFE_API_KEY, or write it to "
    .. (path or "$XDG_CONFIG_HOME/straps/typesafe_api_key")
    .. ", or redefine fn.typesafe_api_key.")
end
]==],
  }, { scope = "global" })

  -- ── fn.typesafe ───────────────────────────────────────────────────────────
  -- POST one battery. curl through vim.system inside ctx.await: never
  -- vim.system():wait(), which would freeze the editor on the tool path.
  registry.define({
    name = "fn.typesafe",
    kind = "fn",
    doc = "POST a System One request to TypeSafe. (payload, ctx) -> answers |"
      .. " nil, err. Requires ctx (it awaits); one retry on 429/529/connection"
      .. " failure.",
    source = [==[
return function(payload, ctx)
  if not (ctx and ctx.await) then
    return nil, "no ctx to await on"
  end
  local ok_cfg, plugin = pcall(require, "straps_classifier")
  local cfg = (ok_cfg and type(plugin.effective) == "function" and plugin.effective())
    or (ok_cfg and plugin.config) or {}
  local timeout_ms = tonumber(cfg.timeout_ms) or 8000
  local retries = tonumber(cfg.retry) or 1
  local url = cfg.endpoint or "https://api.typesafe.ai/v1/systemone"

  local ok_key, key = pcall(require("straps.registry").call, "fn.typesafe_api_key")
  if not ok_key or type(key) ~= "string" or key == "" then
    return nil, "no API key"
  end

  local ok_body, body = pcall(vim.json.encode, payload)
  if not ok_body then
    return nil, "could not encode the request"
  end

  local function attempt()
    local proc
    local res = ctx.await(function(resolve)
      proc = vim.system({
        "curl", "-sS", "--fail-with-body",
        "-X", "POST", url,
        "-H", "Authorization: Bearer " .. key,
        "-H", "Content-Type: application/json",
        "-w", "\n%{http_code}",
        "--max-time", tostring(math.ceil(timeout_ms / 1000)),
        "--data-binary", "@-",
      }, { text = true, stdin = body, timeout = timeout_ms }, function(out) resolve(out) end)
      if ctx.on_cancel then
        ctx.on_cancel(function() pcall(function() proc:kill(9) end) end)
      end
    end)
    if type(res) ~= "table" then
      return nil, "classifier request produced no response"
    end
    local out = res.stdout or ""
    local status = out:match("\n(%d%d%d)%s*$")
    local payload_text = status and out:sub(1, #out - #status - 1) or out
    if res.code ~= 0 and not status then
      if res.signal == 15 or (res.stderr or ""):find("timed out") or res.code == 28 then
        return nil, ("timeout after %dms"):format(timeout_ms), true
      end
      return nil, ("curl exited %s: %s"):format(tostring(res.code),
        vim.trim(tostring(res.stderr or "")):sub(1, 200)), true
    end
    status = tonumber(status) or 0
    if status == 429 or status == 529 or status >= 500 then
      return nil, ("HTTP %d"):format(status), true
    end
    if status < 200 or status >= 300 then
      return nil, ("HTTP %d: %s"):format(status, vim.trim(payload_text):sub(1, 200))
    end
    local ok_decode, decoded = pcall(vim.json.decode, payload_text)
    if not ok_decode or type(decoded) ~= "table" or type(decoded.answers) ~= "table" then
      return nil, "unparseable response"
    end
    return decoded.answers, nil, false, decoded.usage
  end

  local answers, err, retryable, usage = attempt()
  local tries = 0
  while answers == nil and retryable and tries < retries do
    tries = tries + 1
    answers, err, retryable, usage = attempt()
  end
  if answers == nil then
    return nil, err
  end
  return answers, nil, usage
end
]==],
  }, { scope = "global" })

  -- ── fn.classifier_audit ───────────────────────────────────────────────────
  registry.define({
    name = "fn.classifier_audit",
    kind = "fn",
    doc = "Record one classification: (bufnr, record) -> record. The single"
      .. " writer of the per-session audit ring behind straps://classifier."
      .. " Redefine to send records somewhere else.",
    source = [==[
return function(bufnr, rec)
  return require("straps_classifier.audit").record(bufnr, rec)
end
]==],
  }, { scope = "global" })

  registry.define({
    name = "fn.classifier_audit_render",
    kind = "fn",
    doc = "Render the straps://classifier buffer from the audit rings. (bufnr).",
    source = [==[
return function(bufnr)
  return require("straps_classifier.audit").render(bufnr)
end
]==],
  }, { scope = "global" })

  -- ── fn.risk_verdict ───────────────────────────────────────────────────────
  -- Local rules, then one TypeSafe request, then policy. Fails closed: every
  -- path that cannot produce an answer returns "deny" with the cause.
  registry.define({
    name = "fn.risk_verdict",
    kind = "fn",
    doc = "Classify one tool call. (name, input, ctx) -> action ('deny'|'ok'),"
      .. " reason. Fails closed: no key, HTTP error, timeout, unparseable"
      .. " response, or no ctx to await on all return 'deny'.",
    source = [==[
return function(name, input, ctx)
  local plugin = require("straps_classifier")
  local cfg = plugin.effective and plugin.effective() or plugin.config
  local questions = require("straps_classifier.questions")
  local policy = require("straps_classifier.policy")
  local local_rules = require("straps_classifier.local_rules")
  local registry = require("straps.registry")

  local bufnr = ctx and ctx.bufnr or nil
  local started = vim.uv.hrtime()

  local function finish(action, reason, extra)
    local rec = vim.tbl_extend("force", {
      tool = tostring(name),
      capability = (registry.try_call("fn.capability", name, input)) or "unknown",
      action = action,
      reason = reason,
      digest = vim.inspect(input):sub(1, 400),
      ms = math.floor((vim.uv.hrtime() - started) / 1e6),
    }, extra or {})
    pcall(registry.try_call, "fn.classifier_audit", bufnr or 0, rec)
    pcall(registry.try_call, "fn.log", {
      ev = "classify", session = bufnr, tool = rec.tool, cap = rec.capability,
      action = action, reason = reason, ms = rec.ms,
    })
    if type(cfg.on_verdict) == "function" then
      local snapshot = vim.deepcopy(rec)
      vim.schedule(function() pcall(cfg.on_verdict, snapshot) end)
    end
    return action, reason
  end

  local denied, why = local_rules.check(name, input, cfg)
  if denied then
    return finish("deny", why, { failure = "local rule" })
  end

  local state, state_err = questions.state(name, input, ctx, cfg)
  if not state then
    return finish("deny", tostring(state_err), { failure = tostring(state_err) })
  end
  local answers, err, usage = registry.call("fn.typesafe", {
    state = state,
    model = cfg.model or "jev-latest",
    questions = questions.battery(),
  }, ctx)

  if not answers then
    return finish("deny", tostring(err), { failure = tostring(err), state = state })
  end

  local action, reason = policy.route(answers, cfg, state.capability)
  return finish(action, reason, { answers = answers, state = state, usage = usage })
end
]==],
  }, { scope = "global" })

  -- ── hook.confirm (chained) ────────────────────────────────────────────────
  -- The previous definition is captured BEFORE the redefinition and reached
  -- from the entry body through previous_confirm(); an entry chunk takes no
  -- arguments, so it cannot be closed over directly. The operator decides
  -- first, and the classifier can only take that yes away.
  --
  -- Idempotent on purpose: a second register() that re-captured OUR OWN
  -- definition as `prev` would make the chain call itself forever. When the
  -- live confirm is already ours, the original predecessor is kept.
  local live = registry.bind("hook.confirm")
  if live ~= M._our_confirm then
    M._prev_confirm = live
  end
  registry.define({
    name = "hook.confirm",
    kind = "hook",
    doc = "straps_classifier: the operator decides first (dialog or cap: grant);"
      .. " on a yes, the classifier verdict from this gate pass is enforced."
      .. " Never approves a call the previous confirm refused. Fails closed:"
      .. " a missing verdict denies.",
    source = [==[
return function(name, input, ctx)
  local entries = require("straps_classifier.entries")
  local prev = entries.previous_confirm()
  local allowed, why
  if prev then
    allowed, why = prev(name, input, ctx)
  else
    allowed = true
  end
  if not allowed then
    entries.clear_verdict(ctx and ctx.bufnr or 0)
    return false, why
  end
  local action, reason = entries.take_verdict(ctx and ctx.bufnr, name, input)
  if action == nil then
    return false, "classifier: no verdict was produced for this call"
  end
  if action == "deny" then
    return false, "classifier: " .. tostring(reason)
  end
  return true
end
]==],
  }, { scope = "global" })

  -- Remember our own compiled body, so a later register() can tell "the live
  -- confirm is mine" from "someone else redefined it after me".
  M._our_confirm = registry.bind("hook.confirm")
end

--- The confirm definition that was live before this plugin chained itself.
function M.previous_confirm()
  return M._prev_confirm
end

--- The guard. Installed separately from register(), because guards must be
--- defined before the chain freezes and refuse a scope argument.
function M.register_guard()
  require("straps.registry").define({
    name = "hook.guard.classifier",
    kind = "hook",
    doc = "straps_classifier: classify every tool call. In a parent session the"
      .. " verdict is stored for the confirm chain to enforce after the operator"
      .. " decides; in a child session (no operator) it blocks here; on the"
      .. " direct call path there is no ctx to await on, so it blocks.",
    source = [==[
return function(op, name, input, ctx, info)
  if op ~= "before" then
    return
  end
  local ok_plugin, plugin = pcall(require, "straps_classifier")
  if not ok_plugin or not plugin.config then
    return false, "straps_classifier: plugin not configured"
  end
  local entries = require("straps_classifier.entries")
  local registry = require("straps.registry")

  local bufnr = ctx and ctx.bufnr or nil

  -- No ctx means nothing can await, so nothing can be classified. This is the
  -- direct registry.call("tool.*") path, which carries no confirm either.
  if not (ctx and ctx.await) then
    local local_rules = require("straps_classifier.local_rules")
    local denied, why = local_rules.check(name, input,
      plugin.effective and plugin.effective() or plugin.config)
    local reason = denied and why or "no ctx to await on"
    pcall(registry.try_call, "fn.classifier_audit", bufnr or 0, {
      tool = tostring(name), capability = "unknown", action = "deny",
      reason = reason, failure = denied and "local rule" or "no ctx",
      digest = vim.inspect(input):sub(1, 400), ms = 0,
    })
    return false, reason
  end

  local action, reason = registry.call("fn.risk_verdict", name, input, ctx)

  -- A child session has no operator behind it and its own hook.confirm shadow
  -- replaces our chain, so the guard is the only position that reaches it.
  local parent = select(1, registry.scope_parent(bufnr))
  if parent ~= nil then
    if action == "deny" then
      return false, reason
    end
    return
  end

  entries.put_verdict(bufnr, name, input, action, reason)
  return
end
]==],
  })
end

return M
