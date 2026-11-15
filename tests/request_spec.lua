local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(vim.fn.fnamemodify(here, ":p"), ":h:h")
local core = vim.fn.fnamemodify(os.getenv("STRAPS_ROOT") or "../straps", ":p")
package.path = root .. "/lua/?.lua;" .. core .. "/lua/?.lua;" .. package.path
vim.opt.rtp:prepend(core)
local request = require("straps_classifier.request")
local function fixture()
  local identity = {}
  for _, key in ipairs({ "provider_id", "model", "backend", "backend_definition", "endpoint", "config", "account", "credentials", "transport", "disclosure_revision" }) do identity[key] = key end
  local calls = {}
  local ctx = { cancelled = function() return false end }
  local config = { identity = identity, resolve_identity = function() return vim.deepcopy(identity) end,
    limits = { max_bytes = 65536, max_depth = 20, max_items = 2000 },
    disclosure = { approved = true, provider_id = identity.provider_id, revision = identity.disclosure_revision,
      allowed_classes = { public = true }, inspect = function() return "clear" end },
    transport = function(req, invocation)
      calls[#calls + 1] = { req, invocation }
      return { text = '{"ok":true}', metadata = { complete = true, refused = false, incomplete = false, tool_output = false, stop_reason = "end_turn" } }
    end }
  return config, ctx, calls
end
it("uses each invocation cancellation and forwards its context", function()
  local config, ctx, calls = fixture()
  local send = assert(request.new(config))
  local payload = { value = "data", sensitivity = "public", required = true, filtered = false }
  assert.same({ ok = true }, send(payload, ctx))
  assert.equals(ctx, calls[1][2])
  assert.is_nil(send(payload, { cancelled = function() return true end }))
  assert.equals(1, #calls)
  assert.is_nil(send(payload, {}))
end)
it("captures private factories during setup and checks config after setup", function()
  local factory
  assert.is_true(request.install(function(value) factory = value end))
  local registry = require("straps.registry")
  local original = registry.trusted_setup_allowed
  registry.trusted_setup_allowed = function() return false end
  local config = fixture()
  local public = request.new(config)
  local private = factory(config)
  config.disclosure.approved = false
  local denied = factory(config)
  registry.trusted_setup_allowed = original
  assert.is_nil(public)
  assert.is_function(private)
  assert.is_nil(denied)
end)
