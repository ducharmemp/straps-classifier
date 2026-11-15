local questions = require("straps_classifier.contextual_questions")
local M = {}
local fields = { "outcome", "mode", "targets", "effects", "constraints", "reserved_decisions", "latitude", "unresolved_scope" }
local modes = { discussion = true, investigation = true, planning = true, implementation = true }

local function text(value) return type(value) == "string" and value:find("%S") ~= nil end
local function integer(value) return type(value) == "number" and value >= 1 and value % 1 == 0 and value < math.huge end
local function object(value) return type(value) == "table" and getmetatable(value) == nil end
local function exact(value, keys)
  if not object(value) then return false end
  local allowed = {}
  for _, key in ipairs(keys) do allowed[key] = true; if value[key] == nil then return false end end
  for key in pairs(value) do if not allowed[key] then return false end end
  return true
end
local function array(value, remaining)
  if not object(value) then return false end
  local count = 0
  for key in pairs(value) do
    count = count + 1
    if remaining and count > remaining then error("serialization structural overflow", 0) end
    if not integer(key) then return false end
  end
  for index = 1, count do if rawget(value, index) == nil then return false end end
  return true
end
local function sources_valid(ids, sources)
  if not array(ids) or #ids == 0 then return false end
  local seen = {}
  for _, id in ipairs(ids) do
    local source = sources[id]
    if not text(id) or seen[id] or not object(source) or source.trusted ~= true or source.revoked ~= false then return false end
    seen[id] = true
  end
  return true
end

function M.validate(spec, sources)
  local keys = { "schema_version", "task_id", "instruction_revision" }
  for _, field in ipairs(fields) do keys[#keys + 1] = field end
  if not exact(spec, keys) or spec.schema_version ~= 1 or not text(spec.task_id) or not integer(spec.instruction_revision)
    or not object(sources) then return nil, "invalid task schema or identity" end
  for _, field in ipairs(fields) do
    local entry = spec[field]
    if not exact(entry, { "value", "sources" }) or not sources_valid(entry.sources, sources) then return nil, "invalid sources: " .. field end
    if field == "outcome" or field == "mode" then
      if not text(entry.value) then return nil, "invalid value: " .. field end
    else
      if not array(entry.value) then return nil, "invalid value: " .. field end
      for _, value in ipairs(entry.value) do if not text(value) then return nil, "invalid value: " .. field end end
    end
  end
  if not modes[spec.mode.value] then return nil, "invalid work mode" end
  return true
end

function M.validate_synthesis(spec, sources, checks, config)
  local ok, err = M.validate(spec, sources)
  if not ok then return nil, err end
  if not object(config) or type(config.defect_threshold) ~= "number" or config.defect_threshold <= 0
    or config.defect_threshold ~= config.defect_threshold or config.defect_threshold > 1 then return nil, "explicit defect threshold required" end
  if not exact(checks, questions.synthesis_ids()) then return nil, "incomplete synthesis battery" end
  local defects = {}
  for _, id in ipairs(questions.synthesis_ids()) do
    local check = checks[id]
    if not exact(check, { "score", "explanation", "sources", "field" }) or type(check.score) ~= "number"
      or check.score ~= check.score or check.score < 0 or check.score > 1 or not text(check.explanation)
      or not sources_valid(check.sources, sources) then return nil, "invalid synthesis check: " .. id end
    local found = false
    for _, field in ipairs(fields) do if check.field == field then found = true end end
    if not found then return nil, "invalid affected field: " .. id end
    if check.score >= config.defect_threshold then defects[#defects + 1] = id end
  end
  if #defects > 0 then return nil, "synthesis defects: " .. table.concat(defects, ",") end
  return true
end

local function quote(value)
  return '"' .. value:gsub('[%z\1-\31\\"]', function(char)
    if char == '"' then return '\\"' end
    if char == '\\' then return '\\\\' end
    return string.format("\\u%04x", char:byte())
  end) .. '"'
end

local function serialize(value, limits, arrays)
  if not object(limits) or not integer(limits.max_bytes) or not integer(limits.max_depth) or not integer(limits.max_items) then
    return nil, "explicit serialization bounds required"
  end
  local chunks, bytes, items, active = {}, 0, 0, {}
  local function emit(chunk)
    bytes = bytes + #chunk
    if bytes > limits.max_bytes then error("serialization byte overflow", 0) end
    chunks[#chunks + 1] = chunk
  end
  local function encode(item, depth)
    items = items + 1
    if items > limits.max_items or depth > limits.max_depth then error("serialization structural overflow", 0) end
    local kind = type(item)
    if kind == "string" then
      if #item > limits.max_bytes then error("serialization byte overflow", 0) end
      emit(quote(item))
    elseif kind == "boolean" then emit(tostring(item))
    elseif kind == "number" and item == item and item ~= math.huge and item ~= -math.huge then emit(string.format("%.17g", item))
    elseif object(item) then
      if active[item] then error("cyclic data", 0) end
      active[item] = true
      if array(item, limits.max_items - items) and (#item > 0 or arrays and arrays[item]) then
        emit("[")
        for i, child in ipairs(item) do if i > 1 then emit(",") end; encode(child, depth + 1) end
        emit("]")
      else
        local keys = {}
        for key in pairs(item) do
          if type(key) ~= "string" then error("non-string object key", 0) end
          keys[#keys + 1] = key
          if #keys > limits.max_items - items then error("serialization structural overflow", 0) end
        end
        table.sort(keys)
        emit("{")
        for i, key in ipairs(keys) do
          if i > 1 then emit(",") end
          if #key > limits.max_bytes then error("serialization byte overflow", 0) end
          emit(quote(key)); emit(":"); encode(item[key], depth + 1)
        end
        emit("}")
      end
      active[item] = nil
    else error("unsupported data", 0) end
  end
  local ok, err = pcall(encode, value, 1)
  if not ok then return nil, err end
  return table.concat(chunks)
end

function M.serialize(value, limits) return serialize(value, limits) end

function M.serialize_task(spec, sources, limits)
  local ok, err = M.validate(spec, sources)
  if not ok then return nil, err end
  local arrays = {}
  for _, field in ipairs(fields) do
    arrays[spec[field].sources] = true
    if field ~= "outcome" and field ~= "mode" then arrays[spec[field].value] = true end
  end
  return serialize(spec, limits, arrays)
end

function M.validate_disclosure(payload, policy)
  if not object(policy) or policy.approved ~= true or not text(policy.provider_id) or not text(policy.revision)
    or not object(policy.allowed_classes) or type(policy.inspect) ~= "function" then return nil, "disclosure policy required" end
  local encoded, encode_error = M.serialize(payload, policy.limits)
  if not encoded then return nil, encode_error end
  local active = {}
  local function visit(node, path)
    if not object(node) or active[node] then return nil, "invalid disclosure node: " .. path end
    active[node] = true
    if node.sensitivity ~= nil then
      if not exact(node, { "value", "sensitivity", "required", "filtered" }) or type(node.required) ~= "boolean"
        or type(node.filtered) ~= "boolean" then return nil, "invalid disclosure leaf: " .. path end
      if node.filtered and node.required then return nil, "required evidence filtered: " .. path end
      if node.sensitivity == "credential" then return nil, "credential material: " .. path end
      if node.sensitivity == "unknown" or policy.allowed_classes[node.sensitivity] ~= true then return nil, "unapproved sensitivity: " .. path end
      local encoded, err = M.serialize(node.value, policy.limits)
      if not encoded then return nil, err end
      local ok, verdict = pcall(policy.inspect, encoded, path)
      if not ok or verdict ~= "clear" then return nil, "credential inspection unassessed or rejected: " .. path end
    else
      for key, child in pairs(node) do
        if type(key) ~= "string" and type(key) ~= "number" then return nil, "invalid disclosure path" end
        local ok, err = visit(child, path .. "/" .. tostring(key))
        if not ok then return nil, err end
      end
    end
    active[node] = nil
    return true
  end
  local ok, err = visit(payload, "payload")
  if not ok then return nil, err end
  local inspected, verdict = pcall(policy.inspect, encoded, "payload")
  if not inspected or verdict ~= "clear" then return nil, "credential inspection unassessed or rejected: payload" end
  return true
end

return M
