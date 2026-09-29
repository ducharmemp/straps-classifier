-- straps-classifier: every tool call is rated by TypeSafe's Jev after the
-- operator approves it, and a call rated dangerous is blocked. The classifier
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
function M.setup(opts)
  M.config = vim.tbl_deep_extend("force", M.config, opts or {})
  if tonumber(M.config.audit_limit) and tonumber(M.config.audit_limit) < 1 then
    error("straps_classifier: audit_limit must be at least 1 — a classifier that"
      .. " blocks work without saying why is worse than no classifier")
  end
  snapshot = vim.deepcopy(M.config)

  local registry = require("straps.registry")
  local entries = require("straps_classifier.entries")

  entries.register()

  if registry.guards_frozen() then
    M.installed = false
    M.install_error = "the guard chain was already frozen when setup() ran"
    vim.notify(
      "straps_classifier: TOO LATE — the guard chain froze before setup() ran, so"
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
  local key_ok = pcall(function()
    return require("straps.registry").call("fn.typesafe_api_key")
  end)
  return {
    installed = M.installed,
    install_error = M.install_error,
    api_key = key_ok,
  }
end

--- Open the audit buffer (straps://classifier).
function M.audit()
  return require("straps_classifier.audit").open()
end

return M
