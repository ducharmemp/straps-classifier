local intent = require("straps_classifier.intent")
local M = {}
local identity_keys = { "provider_id", "model", "backend", "backend_definition", "endpoint", "config", "account", "credentials", "transport", "disclosure_revision" }

local function exact(value, keys)
  if type(value) ~= "table" or getmetatable(value) ~= nil then return false end
  local allowed = {}
  for _, key in ipairs(keys) do allowed[key] = true; if value[key] == nil then return false end end
  for key in pairs(value) do if not allowed[key] then return false end end
  return true
end

local function construct(config)
  if not exact(config, { "identity", "resolve_identity", "transport", "disclosure", "limits" })
    or not exact(config.identity, identity_keys) or type(config.resolve_identity) ~= "function"
    or type(config.transport) ~= "function" then return nil, "trusted setup required" end
  for _, key in ipairs(identity_keys) do
    if type(config.identity[key]) ~= "string" or not config.identity[key]:find("%S") then return nil, "resolution identity required" end
  end
  local frozen = vim.deepcopy(config)
  local identity, limits, disclosure = frozen.identity, frozen.limits, frozen.disclosure
  if type(disclosure) ~= "table" or disclosure.provider_id ~= identity.provider_id
    or disclosure.revision ~= identity.disclosure_revision or disclosure.approved ~= true then return nil, "disclosure approval required" end
  local identity_json, err = intent.serialize(identity, limits)
  if not identity_json then return nil, err end
  disclosure.limits = vim.deepcopy(limits)

  local function current(ctx)
    local validation = coroutine.create(function()
      local resolved, value = pcall(frozen.resolve_identity)
      local ok, cancelled = pcall(ctx.cancelled)
      if not ok or cancelled ~= false then return nil, "synthesis cancelled" end
      if not resolved or not exact(value, identity_keys) or intent.serialize(value, limits) ~= identity_json then
        return nil, "provider resolution changed"
      end
      return true
    end)
    local resumed, ready, reason = coroutine.resume(validation)
    if not resumed then return nil, "provider validation failed" end
    if coroutine.status(validation) ~= "dead" then return nil, "provider validation yielded" end
    return ready, reason
  end

  local function disclose(node)
    local encoded, encode_err = intent.serialize(node, limits)
    if not encoded then return nil, encode_err end
    local ok, disclosure_err = intent.validate_disclosure(node, disclosure)
    if not ok then return nil, (tostring(disclosure_err):match("^[^:]+") or "disclosure unassessed") end
    local function unwrap(value)
      if value.sensitivity ~= nil then
        if type(value.value) == "table" then return nil, "disclosure leaves must be scalar" end
        if value.filtered then return nil, "filtered evidence is unassessed" end
        return value.value
      end
      local out = {}
      for key, child in pairs(value) do
        local result, child_err = unwrap(child)
        if child_err then return nil, child_err end
        out[key] = result
      end
      return out
    end
    local result, unwrap_err = unwrap(node)
    if unwrap_err then return nil, unwrap_err end
    local plain, plain_err = intent.serialize(result, limits)
    if not plain then return nil, plain_err end
    local inspected, verdict = pcall(disclosure.inspect, plain, "complete_payload")
    if not inspected or verdict ~= "clear" then return nil, "disclosure unassessed" end
    return result
  end

  return function(payload, ctx)
    if type(ctx) ~= "table" or type(ctx.cancelled) ~= "function" then return nil, "invocation cancellation required" end
    local ready, reason = current(ctx)
    if not ready then return nil, reason end
    local plain, disclosure_err = disclose(payload)
    if not plain then return nil, disclosure_err end
    local content, serialization_err = intent.serialize(plain, limits)
    if not content then return nil, serialization_err end
    local inspected, verdict = pcall(disclosure.inspect, content, "complete_request")
    if not inspected or verdict ~= "clear" then return nil, "disclosure unassessed" end
    local transport_request = {
      provider_id = identity.provider_id, model = identity.model, route = vim.deepcopy(identity),
      messages = { { role = "user", content = content } }, tools = {},
    }
    local wire = intent.serialize(transport_request, limits)
    if not wire then return nil, "unbounded transport request" end
    inspected, verdict = pcall(disclosure.inspect, wire, "complete_transport_request")
    if not inspected or verdict ~= "clear" then return nil, "disclosure unassessed" end
    ready, reason = current(ctx)
    if not ready then return nil, reason end
    local sent, result = pcall(frozen.transport, transport_request, ctx)
    ready, reason = current(ctx)
    if not ready then return nil, reason end
    if not sent then return nil, "transport unavailable" end
    if not exact(result, { "text", "metadata" }) or type(result.text) ~= "string" or #result.text > limits.max_bytes
      or not exact(result.metadata, { "complete", "refused", "incomplete", "tool_output", "stop_reason" })
      or result.metadata.complete ~= true or result.metadata.refused ~= false or result.metadata.incomplete ~= false
      or result.metadata.tool_output ~= false or result.metadata.stop_reason ~= "end_turn" then return nil, "unassessed provider result" end
    local decoded, value = pcall(vim.json.decode, result.text)
    if not decoded then return nil, "malformed synthesis JSON" end
    local bounded = intent.serialize(value, limits)
    if not bounded then return nil, "unbounded synthesis result" end
    return value
  end
end

function M.new(config)
  if not require("straps.registry").trusted_setup_allowed() then return nil, "trusted bootstrap required" end
  return construct(config)
end

function M.install(consumer)
  if not require("straps.registry").trusted_setup_allowed() or type(consumer) ~= "function" then return nil, "trusted bootstrap required" end
  local thread = coroutine.create(function() consumer(construct) end)
  local ok = coroutine.resume(thread)
  if not ok or coroutine.status(thread) ~= "dead" then return nil, "factory installation failed" end
  return true
end

return M
