-- Pattern rules that need no network, no API key, and no ctx. They run on
-- every path, including the direct registry.call("tool.*") path where nothing
-- can await. They can only deny.

local M = {}

-- Every string value anywhere in the tool input, plus the tool name. A deny
-- pattern should match a dangerous command whether it arrived as `command`,
-- `path`, or an element of `paths`.
local function strings_in(value, out, depth)
  depth = depth or 0
  if depth > 6 then
    return out
  end
  if type(value) == "string" then
    out[#out + 1] = value
  elseif type(value) == "table" then
    for _, v in pairs(value) do
      strings_in(v, out, depth + 1)
    end
  end
  return out
end

--- check(name, input, cfg) -> "deny", reason | nil
--- Lua patterns, matched case-sensitively against each string in the input.
function M.check(name, input, cfg)
  local patterns = cfg.always_deny_patterns
  if type(patterns) ~= "table" or #patterns == 0 then
    return nil
  end
  local haystack = strings_in(input, { tostring(name) })
  for _, pattern in ipairs(patterns) do
    for _, text in ipairs(haystack) do
      local ok, found = pcall(string.find, text, pattern)
      if ok and found then
        return "deny", ("local rule %q matched %q"):format(pattern, text:sub(1, 120))
      end
    end
  end
  return nil
end

return M
