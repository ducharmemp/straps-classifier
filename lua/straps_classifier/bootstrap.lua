local M = {}
local installed = false
local report
local copy = vim.deepcopy

local function labeled(value, sensitivity)
  if type(value) ~= "table" then return { value = value, sensitivity = sensitivity, required = true, filtered = false } end
  local result = {}
  for key, child in pairs(value) do result[key] = labeled(child, sensitivity) end
  return result
end

local function sources(snapshot)
  local trusted, payload, adopted = {}, {}, {}
  for _, id in ipairs(snapshot.adopted or {}) do adopted[id] = true end
  for _, event in ipairs(snapshot.events or {}) do
    if adopted[event.id] then
      trusted[event.id] = { trusted = true, revoked = false, original = copy(event) }
      payload[event.id] = labeled(event, "project")
      adopted[event.id] = nil
    end
  end
  if next(adopted) then return nil, "adopted event unavailable" end
  for _, source in ipairs(snapshot.standing and snapshot.standing.sources or {}) do
    if trusted[source.id] then return nil, "duplicate authority source" end
    trusted[source.id] = { trusted = true, revoked = false, original = copy(source) }
    payload[source.id] = labeled(source, "project")
  end
  if next(trusted) == nil then return nil, "adopted sources unavailable" end
  return trusted, payload
end

local function deny(reason)
  return { decision = "deny", failure = reason, reasons = { { code = "unassessed", detail = reason, source_ids = {} } }, effects = {}, source_ids = {} }
end

function M.validate(options)
  assert(type(options.limits) == "table", "explicit contextual input limits required")
  for _, name in ipairs({ "max_bytes", "max_depth", "max_items" }) do
    local value = options.limits[name]
    assert(type(value) == "number" and value > 0 and value < math.huge and value % 1 == 0,
      "invalid contextual input limit: " .. name)
  end
end

function M.setup(options)
  M.validate(options)
  local registry = require("straps.registry")
  assert(not installed and registry.trusted_setup_allowed(), "contextual bootstrap must precede sessions and guard freeze")
  installed = true
  local held = copy(options)
  report = { installed = false, missing = {} }
  local function missing(name)
    report.missing[#report.missing + 1] = name
  end
  local function dependency(name, member)
    local ok, module = pcall(require, name)
    if not ok or type(module) ~= "table" or type(module[member]) ~= "function" then
      missing(name .. "." .. member)
      return nil
    end
    return module[member]
  end
  local function invoke(name, fn, ...)
    local ok, result, reason = pcall(fn, ...)
    if not ok or result == false then missing(name .. ": " .. tostring(reason or result)); return false end
    return true
  end
  local run_human, replay, receipts, resolve_targets, validate_targets
  local operations = dependency("straps.loop", "install_human_operations")
  if operations then invoke("straps.loop.install_human_operations", operations, function(run, retry) run_human, replay = run, retry end) end
  local receipt_install = dependency("straps.provider", "install_prompt_receipts")
  if receipt_install then invoke("straps.provider.install_prompt_receipts", receipt_install, function(value) receipts = value end) end
  if type(run_human) ~= "function" or type(replay) ~= "function" then
    missing("straps.loop human operation callbacks")
    run_human, replay = nil, nil
  end
  if type(receipts) ~= "table" or type(receipts.identity) ~= "function" or type(receipts.validate) ~= "function" then
    missing("straps.provider prompt receipt callbacks")
    receipts = nil
  end
  resolve_targets = dependency("straps.contextual_targets", "resolve")
  validate_targets = dependency("straps.contextual_targets", "validate")
  local installers = {}
  local loop_install = dependency("straps.loop", "install_contextual")
  if loop_install then installers.loop = loop_install end
  local questions_install = dependency("straps.questions", "install_contextual")
  if questions_install then installers.questions = questions_install end
  local human_install = dependency("straps.contextual_human", "install")
  if human_install and receipts then installers.human = function(adapter) human_install(adapter, { receipts = receipts, run_human = run_human }) end end
  local children_install = dependency("straps.contextual_children", "install")
  if children_install and receipts then installers.children = function(adapter) children_install(adapter, { receipts = receipts }) end end
  for name, installer in pairs(installers) do
    local key, fn = name, installer
    installers[key] = function(adapter) invoke(key .. ".install", fn, adapter) end
  end
  local factories = {}
  for key, module in pairs({ provider = "straps.contextual_provider", synthesis = "straps_classifier.synthesis", assessment = "straps_classifier.assessment" }) do
    local install = dependency(module, "install")
    if install then
      local ok, reason = pcall(install, function(factory) factories[key] = factory end)
      if not ok or type(factories[key]) ~= "function" then missing(module .. ".install: " .. tostring(reason)) end
    end
  end
  local function factory(disclosure)
    if type(disclosure) ~= "table" or getmetatable(disclosure) ~= nil or disclosure.approved ~= true
        or type(disclosure.provider_id) ~= "string" or not disclosure.provider_id:find("%S")
        or type(disclosure.revision) ~= "string" or not disclosure.revision:find("%S")
        or type(disclosure.allowed_classes) ~= "table" or getmetatable(disclosure.allowed_classes) ~= nil
        or type(disclosure.inspect) ~= "function" then return nil end
    for class, allowed in pairs(disclosure.allowed_classes) do
      if type(class) ~= "string" or not class:find("%S") or type(allowed) ~= "boolean" then return nil end
    end
    if type(held.route) ~= "table" or type(held.route.provider_config) ~= "table"
        or held.route.provider_config.provider ~= disclosure.provider_id
        or type(held.disclosure) ~= "table" or held.disclosure.provider_id ~= disclosure.provider_id
        or held.disclosure.revision ~= disclosure.revision
        or (held.route.disclosure_revision ~= nil and held.route.disclosure_revision ~= disclosure.revision) then return nil end
    if #report.missing > 0 or not factories.provider or not factories.synthesis or not factories.assessment
        or type(held.route) ~= "table" or type(held.route.provider_config) ~= "table"
        or type(held.limits) ~= "table" or type(held.thresholds) ~= "table"
        or type(held.defect_threshold) ~= "number" then return nil end
    local route = copy(held.route)
    route.disclosure_revision = disclosure.revision
    route.disclosure_approved = function() return disclosure.approved == true end
    local provider, why = factories.provider(route)
    if not provider then report.unavailable = why; return nil end
    local config = { identity = provider.identity, resolve_identity = provider.resolve_identity, transport = provider.transport,
      disclosure = copy(disclosure), limits = copy(held.limits) }
    local synthesis_config = copy(config)
    synthesis_config.defect_threshold = held.defect_threshold
    local synthesize, synthesis_error = factories.synthesis(synthesis_config)
    local assess, assessment_error = factories.assessment(config, copy(held.thresholds))
    if not synthesize or not assess then report.unavailable = synthesis_error or assessment_error; return nil end
    return {
      synthesize = function(snapshot, ctx)
        local trusted, payload = sources(snapshot)
        if not trusted then return nil, payload end
        return synthesize({ task_id = snapshot.task_id, instruction_revision = snapshot.epoch, sources = trusted,
          payload = { sources = payload } }, ctx)
      end,
      assess = function(binding, snapshot, ctx, facts)
        local trusted, payload = sources(snapshot)
        if not trusted or type(snapshot.spec) ~= "table" then return deny(payload or "task specification unavailable") end
        return assess({ spec = copy(snapshot.spec), sources = trusted,
          payload = { sources = payload, spec = labeled(snapshot.spec, "project"), call = labeled(binding, "unknown"), evidence = labeled(facts, "unknown") } }, ctx)
      end,
    }
  end
  require("straps.contextual").setup({ enabled = true, limits = copy(held.limits), disclosure = copy(held.disclosure), install = installers,
    discover = require("straps.instructions").discover,
    run_human = run_human or function() return false, "human scheduler unavailable" end,
    receipts = receipts, replay = replay, resolve_targets = resolve_targets, validate_targets = validate_targets,
    composition_identity = receipts and receipts.identity, validate_prompt = receipts and receipts.validate,
    install_assessor = function(consumer) consumer(factory) end,
  })
  report.installed = true
  report.dependencies_ready = #report.missing == 0
  report.disclosure_approved = type(held.disclosure) == "table" and held.disclosure.approved == true
  return copy(report)
end

function M.status() return copy(report) end

return M
