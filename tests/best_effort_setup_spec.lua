local root = vim.fn.fnamemodify(debug.getinfo(1, "S").source:sub(2), ":p:h:h")
local core = vim.fn.fnamemodify(os.getenv("STRAPS_ROOT") or "../straps", ":p")
package.path = root .. "/lua/?.lua;" .. root .. "/lua/?/init.lua;" .. core .. "/lua/?.lua;" .. core .. "/lua/?/init.lua;" .. package.path
local plugin, registry
local checks = 0
local function expect(actual, expected)
  checks = checks + 1
  if tonumber(vim.env.BEST_EFFORT_COUNTERFACTUAL) == checks then assert.are_not.same(expected, actual)
  else assert.same(expected, actual) end
end
local function options()
  return { best_effort = { enabled = true, acknowledge_risk = true, disclosure_approved = true,
    operator_scope = "Read and edit this local project", prohibitions = { "Do not publish" } } }
end
before_each(function()
  for _, name in ipairs({ "straps_classifier", "straps_classifier.entries", "straps.registry" }) do package.loaded[name] = nil end
  registry = require("straps.registry")
  plugin = require("straps_classifier")
end)
teardown(function() print("BEST_EFFORT_ASSERTIONS=" .. checks) end)
it("defaults to legacy and refuses later opt-in", function()
  plugin.setup()
  expect(plugin.effective().best_effort, false)
  expect(plugin.installed, true)
  expect(pcall(plugin.setup, options()), false)
end)
it("requires explicit startup options despite public config mutation before setup", function()
  registry.ensure_scope(12345)
  plugin.config.best_effort = options().best_effort
  plugin.setup()
  expect(plugin.effective().best_effort, false)
end)
it("does not adopt authority from mutated legacy public config or effective copies", function()
  plugin.setup()
  registry.ensure_scope(12345)
  plugin.config.best_effort = options().best_effort
  plugin.setup()
  expect(plugin.effective().best_effort, false)
  local copy = plugin.effective()
  copy.best_effort = options().best_effort
  expect(plugin.effective().best_effort, false)
end)
it("validates explicit risk disclosure scope and exact option types before installation", function()
  local invalid = { true, {}, { enabled = false }, { enabled = true } }
  for _, key in ipairs({ "enabled", "acknowledge_risk", "disclosure_approved", "operator_scope" }) do
    local value = options().best_effort
    value[key] = nil
    invalid[#invalid + 1] = value
  end
  for _, pair in ipairs({ { "operator_scope", " " }, { "operator_scope", 1 }, { "prohibitions", { false } },
    { "prohibitions", "no" }, { "max_request_bytes", 0 }, { "max_request_bytes", 1.5 },
    { "max_request_bytes", math.huge }, { "max_request_bytes", false }, { "max_request_bytes", "65536" }, { "unknown", true } }) do
    local value = options().best_effort
    value[pair[1]] = pair[2]
    invalid[#invalid + 1] = value
  end
  for _, value in ipairs(invalid) do
    expect(pcall(plugin.setup, { best_effort = value }), false)
    expect(registry.get("hook.guard.classifier"), nil)
  end
end)
it("rejects coexistence before installing either mode", function()
  local opts = options()
  opts.contextual = { enabled = true }
  expect(pcall(plugin.setup, opts), false)
  expect(registry.get("hook.guard.classifier"), nil)
end)
it("requires trusted startup before scopes or guard freezing", function()
  registry.ensure_scope(12345)
  expect(pcall(plugin.setup, options()), false)
  expect(registry.get("fn.risk_verdict"), nil)
end)
it("refuses setup after guard freeze", function()
  registry.freeze_guards()
  expect(pcall(plugin.setup, options()), false)
  expect(registry.get("fn.risk_verdict"), nil)
end)
it("freezes input public config and every effective result", function()
  local opts = options()
  plugin.setup(opts)
  expect(plugin.installed, true)
  expect(plugin.effective().best_effort.max_request_bytes, 65536)
  opts.best_effort.operator_scope = "publish"
  plugin.config.best_effort.operator_scope = "publish"
  local copy = plugin.effective()
  copy.best_effort.prohibitions[1] = "publish"
  copy.best_effort.operator_scope = "publish"
  copy.retry = 100
  expect(plugin.effective().best_effort.operator_scope, "Read and edit this local project")
  expect(plugin.effective().best_effort.prohibitions, { "Do not publish" })
  expect(plugin.effective().retry, 1)
  expect(plugin.setup(), plugin)
  expect(plugin.setup(options()), plugin)
  expect(pcall(plugin.setup, { best_effort = false }), false)
  expect(pcall(plugin.setup, { retry = 10 }), false)
  local narrowed = options()
  narrowed.best_effort.prohibitions = {}
  expect(pcall(plugin.setup, narrowed), false)
  expect(pcall(plugin.setup, { best_effort = { enabled = true, acknowledge_risk = true,
    disclosure_approved = true, operator_scope = "publish" } }), false)
end)
it("forces one TypeSafe attempt regardless of legacy retry option", function()
  local opts = options()
  opts.retry = 8
  plugin.setup(opts)
  registry.define({ name = "fn.typesafe_api_key", kind = "fn", source = "return function() return 'fake' end" })
  local calls, system = 0, vim.system
  vim.system = function(_, _, done)
    calls = calls + 1
    done({ code = 0, stdout = "unavailable\n529", stderr = "" })
    return { kill = function() end }
  end
  local ok, answer = pcall(registry.call, "fn.typesafe", { questions = {} }, {
    await = function(start) local out; start(function(value) out = value end); return out end,
  })
  vim.system = system
  expect(ok, true)
  expect(answer, nil)
  expect(calls, 1)
end)
