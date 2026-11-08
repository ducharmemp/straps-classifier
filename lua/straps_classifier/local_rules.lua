-- Pattern rules that need no network, no API key, and no ctx. They run on
-- every path, including the direct registry.call("tool.*") path where nothing
-- can await. They can only deny.

local M = {}

-- Fields that hold prose or file content. A pattern in a README paragraph, a
-- test fixture, or a subagent's task text is a mention, not a command, so
-- these fields are never searched. Sourced from questions.PROSE_KEYS so the
-- rules and the state renderer agree on what counts as prose. `pattern` and
-- `input_schema` are added here (a grep pattern or a JSON schema is not a
-- command); `replacement` is deliberately NOT prose (a :s replacement runs
-- code via \=).
local PROSE_KEYS = vim.tbl_extend("force",
  require("straps_classifier.questions").PROSE_KEYS,
  { pattern = true, input_schema = true })

-- Every string value anywhere in the tool input except prose fields, plus the
-- tool name. A deny pattern should match a dangerous command whether it arrived
-- as `command`, `code`, `path`, or an element of `paths`.
local function strings_in(value, out, depth)
  depth = depth or 0
  if depth > 6 then
    return out
  end
  if type(value) == "string" then
    out[#out + 1] = value
  elseif type(value) == "table" then
    for k, v in pairs(value) do
      if not (type(k) == "string" and PROSE_KEYS[k]) then
        strings_in(v, out, depth + 1)
      end
    end
  end
  return out
end

--- check(name, input, cfg) -> "deny", reason | nil
--- Each rule is a Lua pattern string, or { pattern = "...", label = "..." }.
--- Patterns match case-sensitively against each command-like string in the
--- input; the reason names the label when the rule has one.
function M.check(name, input, cfg)
  local patterns = cfg.always_deny_patterns
  if type(patterns) ~= "table" or #patterns == 0 then
    return nil
  end
  local haystack = strings_in(input, { tostring(name) })
  for _, rule in ipairs(patterns) do
    local pattern, label = rule, nil
    if type(rule) == "table" then
      pattern, label = rule.pattern or rule[1], rule.label
    end
    if type(pattern) == "string" then
      for _, text in ipairs(haystack) do
        local ok, found = pcall(string.find, text, pattern)
        if ok and found then
          local shown = type(label) == "string" and label ~= "" and label or pattern
          return "deny", ("local rule %q matched %q"):format(shown, text:sub(1, 120))
        end
      end
    end
  end
  return nil
end

return M
