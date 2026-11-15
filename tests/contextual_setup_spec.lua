local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(here, ":p:h:h")
local core = vim.fn.fnamemodify(os.getenv("STRAPS_ROOT") or "../straps", ":p")
package.path = root .. "/lua/?.lua;" .. root .. "/lua/?/init.lua;" .. core .. "/lua/?.lua;" .. package.path
vim.opt.rtp:prepend(core)
local plugin, registry, adapters, captured, requests, provider_calls, setup_config, confirms, guard_calls
local snapshot, route_seen
local fields = { "outcome", "mode", "targets", "effects", "constraints", "reserved_decisions", "latitude", "unresolved_scope" }
local function specification()
  local result = { schema_version = 1, task_id = "task", instruction_revision = 1 }
  for _, key in ipairs(fields) do result[key] = { value = {}, sources = { "event" } } end
  result.outcome.value, result.mode.value = "project read", "investigation"
  return result
end
local function options()
  return { contextual = { enabled = true, route = { provider_config = { provider = "configured", model = "chosen" },
    max_output_tokens = 1000, max_response_bytes = 65536, timeout_ms = 1000 },
    limits = { max_bytes = 131072, max_depth = 40, max_items = 10000 }, defect_threshold = 0.8,
    thresholds = { positive_threshold = 0.9, conflict_threshold = 0.8 },
    disclosure = { approved = true, provider_id = "configured", revision = "adopted",
      allowed_classes = { public = true, project = true, unknown = true }, inspect = function() return "clear" end } } }
end
local function boot(real)
  if not real then
    package.loaded["straps.contextual"] = { setup = function(config)
      setup_config = config
      config.install_assessor(function(factory) captured = factory end)
      for name, install in pairs(config.install) do install({ name = name }) end
      return true
    end }
  end
  return plugin.setup(options())
end
before_each(function()
  for _, name in ipairs({ "straps_classifier", "straps_classifier.bootstrap", "straps_classifier.entries", "straps.registry", "straps.context_ui", "straps.contextual",
      "straps.authorization", "straps.consent", "straps_classifier.request", "straps_classifier.synthesis", "straps_classifier.assessment" }) do package.loaded[name] = nil end
  registry = require("straps.registry")
  adapters, requests, provider_calls, confirms, guard_calls = {}, {}, 0, 0, 0
  captured, setup_config, route_seen = nil, nil, nil
  package.loaded["straps.loop"] = {
    install_contextual = function(adapter) adapters.loop = adapter end,
    install_human_operations = function(consumer) consumer(function(_, fn) fn({ cancelled = function() return false end }) end, function() end) end,
  }
  package.loaded["straps.provider"] = { install_prompt_receipts = function(consumer)
    consumer({ identity = function() return "receipt" end, validate = function() return true end })
  end }
  package.loaded["straps.questions"] = { install_contextual = function(adapter) adapters.questions = adapter end }
  package.loaded["straps.contextual_human"] = { install = function(adapter) adapters.human = adapter end }
  package.loaded["straps.contextual_children"] = { install = function(adapter) adapters.children = adapter end }
  package.loaded["straps.contextual_targets"] = { resolve = function() return { known = {}, unresolved = {}, checks = {} } end,
    validate = function() return true end }
  package.loaded["straps.contextual_provider"] = { install = function(consumer)
    consumer(function(route)
      provider_calls, route_seen = provider_calls + 1, route
      local identity = {}
      for _, key in ipairs({ "provider_id", "model", "backend", "backend_definition", "endpoint", "config", "account", "credentials", "transport", "disclosure_revision" }) do identity[key] = key end
      identity.provider_id, identity.disclosure_revision = "configured", "adopted"
      return { identity = identity, resolve_identity = function() return vim.deepcopy(identity) end, transport = function(request)
        local payload = vim.json.decode(request.messages[1].content)
        requests[#requests + 1] = payload
        local output
        if payload.operation == "extract_task" then output = specification()
        elseif payload.operation == "check_synthesis" then
          output = {}
          for _, id in ipairs(require("straps_classifier.contextual_questions").synthesis_ids()) do
            output[id] = { score = 0, explanation = id, sources = { "event" }, field = "mode" }
          end
        else
          output = { checks = {}, effects = { { id = "read", target = "project", kind = "read", coverage = { score = 1, explanation = "covered", source_ids = { "event" } } } } }
          for _, id in ipairs(require("straps_classifier.contextual_questions").authorization_ids()) do
            output.checks[id] = { score = 0, explanation = id, source_ids = { "event" } }
          end
          output.checks.task_connection.score, output.checks.authorization_coverage.score = 1, 1
        end
        return { text = vim.json.encode(output), metadata = { complete = true, refused = false, incomplete = false, tool_output = false, stop_reason = "end_turn" } }
      end }
    end)
    return true
  end }
  snapshot = { task_id = "task", epoch = 1, adopted = { "event" }, events = { { id = "event", payload = { text = "project read" } },
    { id = "unadopted", payload = { text = "untrusted historical role" } } },
    standing = { sources = { { id = "standing", text = "project rules" } } }, spec = specification() }
  plugin = require("straps_classifier")
  local mutation = vim.env.BOOTSTRAP_MUTATION
  if mutation and mutation ~= "" then
    local substitutions = {
      disclosure = { 'local function factory(disclosure)', 'local function factory(disclosure)\n    if disclosure and disclosure.approved == true then disclosure = copy(held.disclosure) end' },
      assessment_original = { 'payload = { sources = payload, spec = labeled(snapshot.spec, "project")', 'payload = { sources = {}, spec = labeled(snapshot.spec, "project")' },
      adoption = { 'if adopted[event.id] then', 'if true then' },
      sensitivity = { 'call = labeled(binding, "unknown")', 'call = labeled(binding, "project")' },
      revision = { 'instruction_revision = snapshot.epoch', 'instruction_revision = snapshot.epoch + 1' },
      discovery = { 'discover = require("straps.instructions").discover,', '' },
      limits = { 'limits = copy(held.limits), disclosure = copy(held.disclosure)', 'limits = nil, disclosure = copy(held.disclosure)' },
    }
    local change = assert(substitutions[mutation])
    local text = table.concat(vim.fn.readfile(root .. "/lua/straps_classifier/bootstrap.lua"), "\n")
    local first, last = assert(text:find(change[1], 1, true))
    package.loaded["straps_classifier.bootstrap"] = assert(loadstring(text:sub(1, first - 1) .. change[2] .. text:sub(last + 1)))()
  end
end)
it("defaults to legacy and rejects mode switching", function()
  local calls = 0
  package.loaded["straps_classifier.entries"] = { register = function() calls = calls + 1 end, register_guard = function() end }
  plugin.setup()
  assert.equals(false, plugin.effective().contextual)
  assert.equals(1, calls)
  assert.has_error(function() plugin.setup(options()) end)
end)
it("installs private adapters without replacing ordinary confirmation or another guard", function()
  registry.define({ name = "hook.confirm", kind = "hook", source = "return function() return false, 'ordinary confirmation' end" })
  registry.define({ name = "hook.guard.other", kind = "hook", source = "return function() return false, 'other guard' end" })
  local confirm, guard = registry.get("hook.confirm"), registry.get("hook.guard.other")
  boot()
  assert.same(options().contextual.limits, setup_config.limits)
  assert.same(confirm, registry.get("hook.confirm"))
  assert.same(guard, registry.get("hook.guard.other"))
  assert.is_nil(registry.get("hook.guard.classifier"))
  assert.is_nil(registry.get("fn.typesafe"))
  assert.equals("human", adapters.human.name)
  assert.equals("questions", adapters.questions.name)
  assert.equals("loop", adapters.loop.name)
  assert.equals("children", adapters.children.name)
  assert.has_error(function() plugin.setup({ contextual = false }) end)
  assert.equals(plugin, plugin.setup({ contextual = vim.deepcopy(plugin.effective().contextual) }))
end)
it("refuses late installation before modifying confirmation", function()
  registry.define({ name = "tool.sample", kind = "tool", source = "return function() end" })
  registry.freeze_guards()
  assert.has_error(function() plugin.setup(options()) end)
  assert.is_nil(registry.get("hook.guard.classifier"))
end)
it("requires disclosure before constructing a provider and status never reads TypeSafe credentials", function()
  boot()
  assert.is_nil(captured({ approved = false, provider_id = "configured", revision = "adopted" }))
  assert.equals(0, provider_calls)
  registry.define({ name = "fn.typesafe_api_key", kind = "fn", source = "return function() error('credential read') end" })
  assert.is_table(plugin.status().contextual)
  assert.equals(0, #requests)
end)
it("rejects incomplete approved disclosure before provider construction or credential reads", function()
  local credential_reads = 0
  package.loaded["straps.contextual_provider"] = { install = function(consumer)
    consumer(function()
      provider_calls = provider_calls + 1
      credential_reads = credential_reads + 1
      return nil, "credential unavailable"
    end)
    return true
  end }
  boot()
  local invalid = {
    { approved = true },
    vim.tbl_extend("force", options().contextual.disclosure, { provider_id = "other" }),
    vim.tbl_extend("force", options().contextual.disclosure, { revision = " " }),
    vim.tbl_extend("force", options().contextual.disclosure, { revision = "different" }),
    vim.tbl_extend("force", options().contextual.disclosure, { allowed_classes = { project = "yes" } }),
    vim.tbl_extend("force", options().contextual.disclosure, { allowed_classes = false }),
    vim.tbl_extend("force", options().contextual.disclosure, { inspect = false }),
  }
  for _, disclosure in ipairs(invalid) do
    assert.is_nil(captured(disclosure))
    assert.equals(0, credential_reads)
    assert.equals(0, provider_calls)
  end
end)
it("maps adopted snapshot sources and exact binding into real synthesis and assessment tickets", function()
  boot()
  local adapter = assert(captured(options().contextual.disclosure))
  local ctx = { cancelled = function() return false end }
  local spec, checks = adapter.synthesize(snapshot, ctx)
  assert.is_truthy(spec, tostring(checks))
  assert.same(specification(), spec)
  assert.is_false(checks.unsupported_authority)
  assert.equals("chosen", route_seen.provider_config.model)
  assert.is_nil(requests[1].evidence.sources.unadopted)
  assert.equals("project rules", requests[1].evidence.sources.standing.text)
  local decision = adapter.assess({ input = { path = "project" }, definition = { source = "exact source" } }, snapshot, ctx, { known = {} })
  assert.equals("deny", decision.decision)
  assert.equals("unassessed", decision.reasons[1].code)
  assert.equals(2, #requests)
end)
it("captures adopted and standing originals in production assessment payloads", function()
  boot()
  local adapter = assert(captured(options().contextual.disclosure))
  snapshot.events[1].payload.text = "  project read\nNever publish.\n"
  snapshot.standing.sources[1].text = "\nproject rules  \n"
  local decision = adapter.assess({}, snapshot, { cancelled = function() return false end }, {})
  assert.equals("allow", decision.decision)
  assert.equals(1, #requests)
  local originals = requests[1].evidence.sources
  assert.same(snapshot.events[1], originals.event)
  assert.same(snapshot.standing.sources[1], originals.standing)
  assert.is_nil(originals.unadopted)
end)
it("keeps unknown call content unassessed despite project disclosure", function()
  boot()
  local adapter = assert(captured(options().contextual.disclosure))
  local decision = adapter.assess({ input = "unknown material" }, snapshot, { cancelled = function() return false end }, {})
  assert.equals("deny", decision.decision)
  assert.equals("unassessed", decision.reasons[1].code)
  assert.equals(0, #requests)
end)
it("retains a deny gate when a lifecycle installer throws", function()
  package.loaded["straps.contextual_human"] = { install = function() error("installer unavailable") end }
  local opts = options()
  opts.contextual.disclosure = nil
  plugin.setup(opts)
  local status = plugin.status().contextual
  assert.is_true(status.installed)
  assert.is_false(status.dependencies_ready)
  assert.is_true(table.concat(status.missing):find("installer unavailable", 1, true) ~= nil)
  registry.define({ name = "tool.sample", kind = "tool", source = "return function() error('body executed') end" })
  assert.is_false(registry.gate_tool("sample", {}, { bufnr = 1 }, { confirm = false }))
end)
local function production_override_fixture(ceiling)
  vim.cmd("only")
  for _, name in ipairs({ "straps", "straps.state", "straps.ui", "straps.agents", "straps.loop", "straps.provider",
      "straps.questions", "straps.contextual_human", "straps.contextual_children", "straps.contextual_targets",
      "straps.contextual_provider", "straps.contextual", "straps.authorization", "straps.consent" }) do package.loaded[name] = nil end
  local workflow_mutant = vim.env.BOOTSTRAP_WORKFLOW_MUTANT
  if workflow_mutant == "guard" or workflow_mutant == "confirm" or workflow_mutant == "ceiling" then
    local source = table.concat(vim.fn.readfile(core .. "/lua/straps/registry.lua"), "\n")
    local changes = {
      guard = { 'if block then return true, block end', 'if false then return true, block end' },
      confirm = { 'if not allowed then\n        local prefix', 'if false then\n        local prefix' },
      ceiling = { 'if not ceiling_ok then return false, why end', 'if false then return false, why end' },
    }
    local change = changes[workflow_mutant]
    local first, last = assert(source:find(change[1], 1, true))
    package.loaded["straps.registry"] = assert(loadstring(source:sub(1, first - 1) .. change[2] .. source:sub(last + 1)))()
    registry = require("straps.registry")
  end
  require("straps").setup({ session_dir = vim.fn.tempname(), layers = { editor = false } })
  local human = require("straps.contextual_human")
  if vim.env.BOOTSTRAP_WORKFLOW_MUTANT == "refusal" then
    local source = table.concat(vim.fn.readfile(core .. "/lua/straps/contextual_human.lua"), "\n")
    local old = 'if ok == false then vim.notify("straps: " .. tostring(reason or "authorization replay refused"), vim.log.levels.WARN) end'
    local first, last = assert(source:find(old, 1, true))
    human = assert(loadstring(source:sub(1, first - 1) .. source:sub(last + 1)))()
    package.loaded["straps.contextual_human"] = human
  end
  local install = human.install
  human.install = function(adapter, install_options)
    local create = adapter.create
    adapter.create = function(buf, create_options)
      if ceiling then create_options.ceiling = ceiling end
      return create(buf, create_options)
    end
    return install(adapter, install_options)
  end
  local attach, callbacks = human.attach
  human.attach = function(surface, consumer)
    return attach(surface, function(value)
      if surface == "plugin" then callbacks = value end
      return consumer(value)
    end)
  end
  vim.g.loaded_straps = nil
  vim.cmd("source " .. vim.fn.fnameescape(core .. "/plugin/straps.lua"))
  local opts = options()
  opts.contextual.disclosure = nil
  plugin.setup(opts)
  assert.is_true(plugin.status().contextual.dependencies_ready)
  local fixture = { actor_calls = 0, bodies = 0, confirms = 0, results = {}, notifications = {} }
  local loop, state = require("straps.loop"), require("straps.state")
  fixture.loop, fixture.state = loop, state
  function fixture.refresh_results()
    fixture.results = {}
    for _, block in ipairs(state.list_blocks(fixture.buf)) do
      if block.kind == "tool_result" then
        fixture.results[#fixture.results + 1] = table.concat(vim.api.nvim_buf_get_lines(fixture.buf, block.first_lnum - 1, block.last_lnum, false), "\n")
      end
    end
    return #fixture.results
  end
  _G.bootstrap_override_actor = function(_, ctx)
    fixture.actor_calls = fixture.actor_calls + 1
    if fixture.busy then return ctx.await(function(resolve) fixture.release = resolve end) end
    if fixture.actor_calls == 1 then
      return { content = { { type = "tool_use", id = "denied-path-info", name = ceiling and "write_file" or "path_info",
        input = ceiling and { path = vim.fn.tempname(), content = "must not execute" } or { paths = { core } } } }, stop_reason = "tool_use", complete = true }
    end
    ctx.emit({ type = "text_delta", text = "done" })
    return { content = { { type = "text", text = "done" } }, stop_reason = "end_turn", complete = true }
  end
  _G.bootstrap_override_confirm = function() fixture.confirms = fixture.confirms + 1; return not fixture.confirm_refusal, "ordinary confirmation refused" end
  _G.bootstrap_override_before = function() fixture.bodies = fixture.bodies + 1 end
  _G.bootstrap_override_result = function(_, _, result) fixture.results[#fixture.results + 1] = result end
  _G.bootstrap_override_guard = function() return not fixture.guard_refusal, "independent guard refused" end
  registry.define({ name = "fn.openai_api_key", kind = "fn", source = "return function() error('credential read before disclosure') end" })
  registry.define({ name = "fn.provider", kind = "fn", source = "return function(...) return _G.bootstrap_override_actor(...) end" })
  registry.define({ name = "hook.confirm", kind = "hook", source = "return function(...) return _G.bootstrap_override_confirm(...) end" })
  registry.define({ name = "hook.before_tool", kind = "hook", source = "return function(...) return _G.bootstrap_override_before(...) end" })
  registry.define({ name = "hook.after_tool", kind = "hook", source = "return function(...) return _G.bootstrap_override_result(...) end" })
  registry.define({ name = "hook.guard.workflow", kind = "hook", source = "return function(...) return _G.bootstrap_override_guard(...) end" })
  fixture.buf = callbacks.construct()
  callbacks.steer(fixture.buf, "Inspect the local project", function() end)
  assert.is_true(vim.wait(3000, function() return type(vim.fn.maparg("y", "n", false, true).callback) == "function" end, 5))
  vim.fn.maparg("y", "n", false, true).callback()
  assert.is_true(vim.wait(3000, function()
    local value = require("straps.authorization").snapshot(fixture.buf)
    return value and #value.adopted > 0
  end, 5))
  state.seed_user(fixture.buf, "Inspect the local project")
  loop.start(fixture.buf)
  assert.is_true(vim.wait(3000, function() return fixture.refresh_results() == 1 and not loop.running(fixture.buf) end, 5),
    "initial denial must finish: " .. vim.inspect(fixture.results))
  assert.equals(0, fixture.bodies)
  assert.equals(0, fixture.confirms)
  if ceiling then return fixture end
  assert.is_truthy(fixture.results[1]:find(":StrapsAuthorization 1", 1, true))
  fixture.callbacks = callbacks
  return fixture
end

local function request_override(fixture)
  require("straps.ui").show_session(fixture.buf, "none")
  vim.cmd("StrapsAuthorization! 1")
end

local function accept_override(fixture)
  assert.is_true(vim.wait(3000, function()
    local lines = vim.api.nvim_buf_get_lines(0, 0, 1, false)
    return lines[1] == "Consent: inspect the complete request before choosing."
      and type(vim.fn.maparg("y", "n", false, true).callback) == "function"
  end, 5), "exact consent display must appear")
  vim.fn.maparg("y", "n", false, true).callback()
  assert.is_true(vim.wait(3000, function() return fixture.refresh_results() == 2 end, 5), "fresh replay must finish")
end

it("replays a shipped denial through command bang and actual consent while authority remains pending", function()
  local fixture = production_override_fixture()
  request_override(fixture)
  accept_override(fixture)
  assert.equals(1, fixture.bodies)
  assert.equals(1, fixture.confirms)
  local snapshot = require("straps.authorization").snapshot(fixture.buf)
  assert.equals("pending", snapshot.status)
  assert.is_nil(snapshot.spec)
  assert.is_truthy(fixture.results[2]:find(core, 1, true))
  assert.equals(2, fixture.actor_calls)
end)

for _, refusal in ipairs({ "guard", "confirm" }) do
  it("retains the independent " .. refusal .. " refusal on the actual command replay", function()
    local fixture = production_override_fixture()
    fixture[refusal .. "_refusal"] = true
    request_override(fixture)
    if refusal == "confirm" then
      accept_override(fixture)
    else
      assert.is_true(vim.wait(3000, function()
        if fixture.refresh_results() == 2 then return true end
        local lines = vim.api.nvim_buf_get_lines(0, 0, 1, false)
        if lines[1] == "Consent: inspect the complete request before choosing." then
          vim.fn.maparg("y", "n", false, true).callback()
        end
        return fixture.refresh_results() == 2
      end, 5))
    end
    assert.equals(0, fixture.bodies)
    assert.equals(refusal == "confirm" and 1 or 0, fixture.confirms)
    assert.is_truthy(fixture.results[2]:find(refusal == "confirm" and "ordinary confirmation refused" or "independent guard refused", 1, true))
  end)
end

it("retains the actual capability ceiling without opening override consent", function()
  local fixture = production_override_fixture({ allow = {} })
  assert.is_truthy(fixture.results[1]:find("ceiling", 1, true), fixture.results[1])
  local notify = vim.notify
  vim.notify = function(message) fixture.notifications[#fixture.notifications + 1] = message end
  request_override(fixture)
  vim.notify = notify
  assert.equals("straps: no authorization decision for this session", fixture.notifications[#fixture.notifications])
  assert.equals(0, fixture.bodies)
  assert.equals(0, fixture.confirms)
  assert.equals(1, fixture.refresh_results())
end)

it("reports busy replay refusal and permits the same decision after the actor becomes idle", function()
  local fixture = production_override_fixture()
  fixture.busy = true
  fixture.state.append(fixture.buf, "user", nil, "Continue inspection")
  fixture.loop.start(fixture.buf)
  assert.is_true(vim.wait(3000, function() return type(fixture.release) == "function" end, 5))
  local notify = vim.notify
  vim.notify = function(message) fixture.notifications[#fixture.notifications + 1] = message end
  request_override(fixture)
  vim.notify = notify
  local reported = false
  for _, message in ipairs(fixture.notifications) do if message:find("replay requires an idle actor", 1, true) then reported = true end end
  fixture.busy = false
  fixture.release({ content = { { type = "text", text = "done" } }, stop_reason = "end_turn", complete = true })
  assert.is_true(vim.wait(3000, function() return not fixture.loop.running(fixture.buf) end, 5))
  request_override(fixture)
  accept_override(fixture)
  assert.equals(1, fixture.bodies)
  assert.is_true(reported, "command bang must report an idle-actor refusal")
end)

it("denies a trusted adopted production family for unapproved disclosure before provider or credentials", function()
  for _, name in ipairs({ "straps", "straps.state", "straps.ui", "straps.agents", "straps.loop", "straps.provider",
      "straps.questions", "straps.contextual_human", "straps.contextual_children", "straps.contextual_targets",
      "straps.contextual_provider", "straps.contextual", "straps.authorization", "straps.consent" }) do package.loaded[name] = nil end
    local authorization_mutation = vim.env.BOOTSTRAP_CONTEXT_MUTATION
    if authorization_mutation == "pending" then
      local text = table.concat(vim.fn.readfile(core .. "/lua/straps/contextual.lua"), "\n")
      local before = 'return authorization.validate_context_stamp(bufnr, stamp)'
      local first, last = assert(text:find(before, 1, true))
      package.loaded["straps.contextual"] = assert(loadstring(text:sub(1, first - 1)
        .. 'return authorization.validate_stamp(bufnr, stamp)' .. text:sub(last + 1)))()
    end
  require("straps").setup({ session_dir = vim.fn.tempname(), layers = { editor = false } })
  local callbacks
  require("straps.contextual_human").attach("plugin", function(value) callbacks = value end)
  local factory_calls, credential_reads, actor_calls, result = 0, 0, 0
  local actual = require("straps.contextual_provider")
  local install = actual.install
  actual.install = function(consumer)
    return install(function(factory)
      consumer(function(...) factory_calls = factory_calls + 1; return factory(...) end)
    end)
  end
  local actual_provider = require("straps.provider")
  local receipt_install = actual_provider.install_prompt_receipts
  actual_provider.install_prompt_receipts = function(consumer)
    return receipt_install(function(receipts)
      local construct = receipts.construct
      receipts.construct = function(...)
        local buf, token = construct(...)
        assert(buf, tostring(token))
        return buf, token
      end
      consumer(receipts)
    end)
  end
  local opts = options()
  opts.contextual.disclosure = nil
  plugin.setup(opts)
  assert.is_true(plugin.status().contextual.dependencies_ready)
  _G.bootstrap_credential = function() credential_reads = credential_reads + 1; return "not-a-real-key" end
  _G.bootstrap_actor = function()
    actor_calls = actor_calls + 1
    return { blocks = {}, stop_reason = "end_turn", complete = true }
  end
  registry.define({ name = "fn.openai_api_key", kind = "fn", source = "return function() return _G.bootstrap_credential() end" })
  registry.define({ name = "fn.provider", kind = "fn", source = "return function() return _G.bootstrap_actor() end" })
  registry.define({ name = "hook.confirm", kind = "hook", source = "return function() return true end" })
  registry.define({ name = "tool.sample", kind = "tool", source = "return function() error('body executed') end" })
  local loop = require("straps.loop")
  _G.bootstrap_gate = function(ctx)
    result = { registry.gate_tool("sample", {}, ctx, { confirm = function() return registry.call("hook.confirm") end }) }
    loop.stop(ctx.bufnr)
  end
  registry.define({ name = "hook.on_run_start", kind = "hook", source = "return function(ctx) _G.bootstrap_gate(ctx) end" })
  local buf = callbacks.construct()
  callbacks.steer(buf, "Inspect the local project", function() end)
  assert.is_true(vim.wait(3000, function()
    return type(vim.fn.maparg("y", "n", false, true).callback) == "function"
  end, 5))
  vim.fn.maparg("y", "n", false, true).callback()
  assert.is_true(vim.wait(3000, function()
    local value = require("straps.authorization").snapshot(buf)
    return value and #value.adopted > 0
  end, 5))
  assert.is_true(registry.call("hook.confirm"))
  require("straps.state").seed_user(buf, "Inspect the local project")
  loop.start(buf)
  assert.is_true(vim.wait(3000, function() return result ~= nil and not loop.running(buf) end, 5))
  assert.is_false(result[1])
  assert.equals("contextual authorization denied; inspect with :StrapsAuthorization 1", result[2])
  callbacks.authorization(buf, 1, false)
  local description = table.concat(vim.api.nvim_buf_get_lines(vim.api.nvim_get_current_buf(), 0, -1, false), "\n")
  assert.is_truthy(description:find('failure = "provider disclosure unapproved"', 1, true))
  assert.equals(0, factory_calls)
  assert.equals(0, credential_reads)
  assert.equals(1, actor_calls)
  actual.install = install
  _G.bootstrap_credential, _G.bootstrap_actor, _G.bootstrap_gate = nil, nil, nil
end)
it("adopts configured extra instructions with the production prompt discovery snapshot", function()
  for _, name in ipairs({ "straps", "straps.state", "straps.ui", "straps.agents", "straps.loop", "straps.provider",
      "straps.questions", "straps.contextual_human", "straps.contextual_children", "straps.contextual_targets",
      "straps.contextual_provider", "straps.contextual", "straps.authorization", "straps.consent" }) do package.loaded[name] = nil end
  local extra = vim.fn.tempname()
  local text = "Configured extra instruction from disk"
  vim.fn.writefile({ text }, extra)
  local disk_text = text .. "\n"
  local unsaved = vim.fn.bufadd(extra)
  vim.fn.bufload(unsaved)
  vim.api.nvim_buf_set_lines(unsaved, 0, -1, false, { "Unsaved instruction must not become authority" })
  local buf
  local ok, failure = xpcall(function()
    require("straps").setup({ session_dir = vim.fn.tempname(), layers = { editor = false }, instructions_files = { extra } })
    local callbacks
    require("straps.contextual_human").attach("plugin", function(value) callbacks = value end)
    local opts = options()
    opts.contextual.disclosure = nil
    plugin.setup(opts)
    assert.is_true(plugin.status().contextual.dependencies_ready)
    buf = callbacks.construct()
    assert.is_truthy(require("straps.state").parse(buf).system:find(text, 1, true))
    local expected = require("straps.instructions").discover()
    local source = expected.sources[#expected.sources]
    assert.equals(extra, source.path)
    assert.equals(disk_text, source.text)
    callbacks.steer(buf, "Inspect the configured project rules", function() end)
    assert.is_true(vim.wait(3000, function()
      return type(vim.fn.maparg("y", "n", false, true).callback) == "function"
    end, 5))
    local displayed = table.concat(vim.api.nvim_buf_get_lines(vim.api.nvim_get_current_buf(), 0, -1, false), "\n")
    assert.is_truthy(displayed:find(extra, 1, true))
    assert.is_truthy(displayed:find(text, 1, true))
    assert.is_nil(displayed:find("Unsaved instruction must not become authority", 1, true))
    vim.fn.maparg("y", "n", false, true).callback()
    assert.is_true(vim.wait(3000, function()
      local value = require("straps.authorization").snapshot(buf)
      return value and #value.adopted == 1
    end, 5), "production adoption must accept the same configured instructions as the prompt")
    local adopted = require("straps.authorization").snapshot(buf)
    assert.same(expected, adopted.standing)
    assert.equals("pending", adopted.status)
    assert.is_nil(adopted.spec)
    assert.is_true(require("straps.provider").contextual_validate_prompt(buf, adopted.standing))
  end, debug.traceback)
  if buf and vim.api.nvim_buf_is_valid(buf) then vim.api.nvim_buf_delete(buf, { force = true }) end
  vim.bo[unsaved].modified = false
  vim.fn.delete(extra)
  assert.is_true(ok, failure)
end)
it("installs the actual deny gate without disclosure even when lifecycle dependencies are missing", function()
  package.loaded["straps.contextual_human"] = {}
  package.loaded["straps.provider"] = {}
  local opts = options()
  opts.contextual.disclosure = nil
  plugin.setup(opts)
  local status = plugin.status().contextual
  assert.is_true(status.installed)
  assert.is_true(vim.tbl_contains(status.missing, "straps.contextual_human.install"))
  assert.equals(0, provider_calls)
  registry.define({ name = "tool.sample", kind = "tool", source = "return function() error('body executed') end" })
  assert.is_false(registry.gate_tool("sample", {}, { bufnr = 1 }, { confirm = false }))
end)
