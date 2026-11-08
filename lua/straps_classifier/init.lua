-- straps-classifier: every tool call is rated by TypeSafe's Jev, and a call
-- rated dangerous is blocked once the operator approves it. The classifier
-- can veto and cannot approve. No verdict means no call.

local M = {}

M.config = {
  model = "jev-latest",
  endpoint = "https://api.typesafe.ai/v1/systemone",
  timeout_ms = 8000,
  retry = 1,
  deny_threshold = 0.85,
  damage_deny = 2.5,
  opaque_action = "deny",
  cutoffs = nil,
  ask_deny_threshold = nil,
  ask_cutoffs = nil,
  always_deny_patterns = {
    "rm%s+%-rf%s+/",
    "%.ssh/id_",
    "%.aws/credentials",
    "^sudo%s",
    "%ssudo%s",
    "^doas%s",
    "%sdoas%s",
    "%-%-remote%-",
    "%-%-server%s",
    "%$NVIM%f[%W]",
    "NVIM_LISTEN_ADDRESS",
  },
  max_state_bytes = 4000,
  ask_state_bytes = 16000,
  audit_limit = 500,
  on_verdict = nil,
}

M.installed = false
M.install_error = nil

-- Frozen at setup(). Every entry reads config through effective(), so a later
-- assignment to M.config (from eval_lua, say) changes nothing the classifier
-- does. Before setup() runs there is nothing to freeze and M.config is used.
local snapshot = nil

function M.effective()
  return snapshot or M.config
end

--- Install the guard and the confirm chain. Call this EAGERLY — from
--- init.lua after require("straps").setup{}, or from
--- stdpath("config")/straps/init.lua. Guards freeze when the first session
--- opens, so a lazy load that fires on :Straps is too late and the session
--- runs unclassified.
local DEFAULT_AUDIT_LIMIT = M.config.audit_limit

function M.setup(opts)
  assert(opts == nil or type(opts) == "table", "straps_classifier: setup options must be a table")
  opts = vim.deepcopy(opts or {})
  local optional = { cutoffs = "table", ask_cutoffs = "table", ask_deny_threshold = "number", on_verdict = "function" }
  for key, value in pairs(opts) do
    local expected = optional[key] or (M.config[key] ~= nil and type(M.config[key]))
    assert(expected, "straps_classifier: unknown option " .. tostring(key))
    assert(type(value) == expected, "straps_classifier: invalid type for " .. key)
    if expected == "number" then
      assert(value == value and math.abs(value) < math.huge and value >= 0,
        "straps_classifier: " .. key .. " must be finite and nonnegative")
    elseif expected == "string" then
      assert(value ~= "", "straps_classifier: " .. key .. " must be nonempty")
    end
  end
  for _, key in ipairs({ "timeout_ms", "retry", "max_state_bytes", "ask_state_bytes", "audit_limit" }) do
    local value = opts[key]
    if value ~= nil then
      assert(value % 1 == 0 and (key == "retry" or key == "audit_limit" or value > 0),
        "straps_classifier: " .. key .. " must be an integer in range")
    end
  end
  assert(opts.opaque_action == nil or opts.opaque_action == "deny" or opts.opaque_action == "log",
    "straps_classifier: opaque_action must be deny or log")
  for _, key in ipairs({ "cutoffs", "ask_cutoffs" }) do
    for name, value in pairs(opts[key] or {}) do
      assert(type(name) == "string" and type(value) == "number" and value == value and math.abs(value) < math.huge and value >= 0,
        "straps_classifier: " .. key .. " requires string keys and finite nonnegative numbers")
    end
  end
  if opts.always_deny_patterns then
    assert(vim.islist(opts.always_deny_patterns), "straps_classifier: always_deny_patterns must be a list")
    for index, rule in ipairs(opts.always_deny_patterns) do
      local path = "straps_classifier: always_deny_patterns[" .. index .. "]"
      assert(type(rule) == "string" or type(rule) == "table", path .. " must be a string or a rule table")
      local pattern, label = rule, nil
      if type(rule) == "table" then
        pattern, label = rule.pattern or rule[1], rule.label
      end
      assert(type(pattern) == "string", path .. ".pattern must be a string (use pattern or [1])")
      assert(label == nil or type(label) == "string", path .. ".label must be a string")
      local ok, err = pcall(string.find, "", pattern)
      assert(ok, path .. ".pattern must be a valid Lua pattern: " .. tostring(err))
    end
  end
  if tonumber(opts.audit_limit) and tonumber(opts.audit_limit) < 1 then
    vim.notify(("straps_classifier: audit_limit must be at least 1 (got %s); using %d")
      :format(tostring(opts.audit_limit), DEFAULT_AUDIT_LIMIT), vim.log.levels.ERROR)
    opts.audit_limit = nil
  end
  M.config = vim.tbl_deep_extend("force", M.config, opts)
  M.setup_ran = true
  snapshot = vim.deepcopy(M.config)

  local registry = require("straps.registry")
  local entries = require("straps_classifier.entries")

  entries.register()

  if registry.guards_frozen() then
    M.installed = false
    M.install_error = "the guard chain was already frozen when setup() ran"
    vim.notify(
      "straps_classifier: the guard chain froze before setup() ran, so"
        .. " tool calls in this Neovim are NOT classified. Install eagerly from"
        .. " stdpath('config')/straps/init.lua, then restart.",
      vim.log.levels.ERROR)
    return M
  end

  local ok, err = pcall(entries.register_guard)
  if not ok then
    M.installed = false
    M.install_error = tostring(err)
    vim.notify("straps_classifier: guard install failed: " .. tostring(err),
      vim.log.levels.ERROR)
    return M
  end

  M.installed = true
  M.install_error = nil
  return M
end

--- Whether the classifier is actually in front of tool calls right now, for a
--- statusline or a quick :lua check.
function M.status()
  local key_ok, key_err = pcall(function()
    return require("straps.registry").call("fn.typesafe_api_key")
  end)
  if key_ok and (type(key_err) ~= "string" or key_err == "") then
    key_ok, key_err = false, "fn.typesafe_api_key returned no key"
  end
  return {
    setup_ran = M.setup_ran == true,
    installed = M.installed,
    install_error = M.install_error,
    api_key = key_ok,
    api_key_error = not key_ok and tostring(key_err) or nil,
  }
end

--- status() as lines plus the vim.log.levels value they warrant.
function M.status_report()
  local s = M.status()
  local lines, level = {}, vim.log.levels.INFO
  if not s.setup_ran then
    lines[#lines + 1] = "straps_classifier: setup() has not run; tool calls are NOT classified"
    return lines, vim.log.levels.WARN, s
  end
  lines[#lines + 1] = "straps_classifier: installed: " .. tostring(s.installed)
  if s.install_error then
    lines[#lines + 1] = "error:     " .. s.install_error .. "; tool calls are NOT classified"
    level = vim.log.levels.ERROR
  end
  if s.api_key then
    lines[#lines + 1] = "api key:   resolves"
  else
    lines[#lines + 1] = "api key:   MISSING; every tool call is denied: " .. s.api_key_error
    level = math.max(level, vim.log.levels.WARN)
  end
  return lines, level, s
end

--- Open the audit buffer (straps://classifier).
function M.audit()
  return require("straps_classifier.audit").open()
end

return M
