-- The classification record and its buffer view (straps://classifier).
-- Shaped after straps' own agents buffer: one ordinary buffer, rendered from
-- live state by a redefinable registry fn, a module-level line map, a
-- debounced refresh.

local M = {}

local BUFNAME = "straps://classifier"
local WIDTH = 76
local KEYS = "<CR> record   o session   d denies   R refresh   x clear"
local ns = vim.api.nvim_create_namespace("straps_classifier_audit")

-- session key -> { label, path, parent, depth, entries = ring }
-- The key is the bufnr while the buffer lives. Each record also carries the
-- session's file path, so a closed session's audit is still identifiable.
local sessions = {}
local seq = 0

-- lnum -> entry, for the rendered buffer. Module-level, like agents_lines:
-- vim.b cannot hold a sparse integer-keyed table.
local lines_map = {}
local timer = nil
local filter_denies = false

local function cfg()
  local ok, plugin = pcall(require, "straps_classifier")
  if not (ok and type(plugin) == "table") then
    return {}
  end
  return (plugin.effective and plugin.effective()) or plugin.config or {}
end

local function session_meta(bufnr)
  local label, path, parent, depth = "buffer " .. tostring(bufnr), nil, nil, 0
  pcall(function()
    label = require("straps.ui").session_label(bufnr) or label
  end)
  pcall(function()
    local name = vim.api.nvim_buf_get_name(bufnr)
    if name ~= "" then
      path = vim.fn.fnamemodify(name, ":p")
    end
  end)
  pcall(function()
    local p = vim.b[bufnr].straps_parent
    if type(p) == "number" and vim.api.nvim_buf_is_valid(p) then
      parent = p
    end
    depth = tonumber(vim.b[bufnr].straps_spawn_depth) or 0
  end)
  return label, path, parent, depth
end

--- Record one classification. `rec` carries everything the plan lists; every
--- verdict keeps the state it was judged on and the answers it got, so an
--- allow that looks wrong can be read back the same way a deny can.
function M.record(bufnr, rec)
  local limit = tonumber(cfg().audit_limit) or 500
  if limit < 1 then
    limit = 500
  end
  local key = type(bufnr) == "number" and bufnr or 0
  local s = sessions[key]
  if not s then
    local label, path, parent, depth = session_meta(key)
    s = { label = label, path = path, parent = parent, depth = depth, entries = {} }
    sessions[key] = s
  else
    -- Refresh the label/parent each time: a session gets renamed, and a child's
    -- parent stamp lands after its first tool call in some orders.
    local label, path, parent, depth = session_meta(key)
    s.label, s.parent, s.depth = label, parent, depth
    s.path = path or s.path
  end

  seq = seq + 1
  rec.seq = seq
  rec.at = os.time()
  rec.at_ms = math.floor((vim.uv.hrtime() / 1e6) % 1000)
  s.entries[#s.entries + 1] = rec
  while #s.entries > limit do
    table.remove(s.entries, 1)
  end

  M.refresh()
  return rec
end

--- Every recorded session, newest activity first. Read-only copies.
function M.all()
  local out = {}
  for key, s in pairs(sessions) do
    out[#out + 1] = {
      key = key,
      label = s.label,
      path = s.path,
      parent = s.parent,
      depth = s.depth,
      alive = type(key) == "number" and key > 0 and vim.api.nvim_buf_is_valid(key),
      entries = s.entries,
    }
  end
  table.sort(out, function(a, b)
    local la = a.entries[#a.entries]
    local lb = b.entries[#b.entries]
    -- Children sort under their parent: compare by the parent's key when set.
    local ka = a.parent or a.key
    local kb = b.parent or b.key
    if ka ~= kb then
      return ka < kb
    end
    if a.key ~= b.key then
      return a.key < b.key
    end
    return (la and la.seq or 0) > (lb and lb.seq or 0)
  end)
  return out
end

--- Counts for :checkhealth: allows, denies, and failures by cause.
function M.counts()
  local total = { allow = 0, deny = 0 }
  local causes = {}
  for _, s in pairs(sessions) do
    for _, e in ipairs(s.entries) do
      if e.action == "deny" then
        total.deny = total.deny + 1
        if e.failure then
          causes[e.failure] = (causes[e.failure] or 0) + 1
        end
      else
        total.allow = total.allow + 1
      end
    end
  end
  return total, causes
end

function M.clear(key)
  if key == nil then
    sessions = {}
  else
    sessions[key] = nil
  end
  M.refresh()
end

-- ── the buffer ──────────────────────────────────────────────────────────────

local function find_buf()
  for _, b in ipairs(vim.api.nvim_list_bufs()) do
    if vim.api.nvim_buf_is_valid(b) and vim.api.nvim_buf_get_name(b):sub(-#BUFNAME) == BUFNAME then
      return b
    end
  end
  return nil
end

local function rule(name)
  local trailing = WIDTH - 3 - #name - 1
  return ("━━ %s %s"):format(name, string.rep("━", math.max(1, trailing)))
end

local function fit(text, width)
  if width < 1 then
    return ""
  end
  text = tostring(text):gsub("%s+", " ")
  if vim.fn.strdisplaywidth(text) <= width then
    return text
  end
  local n = math.min(vim.fn.strchars(text), width)
  while n > 0 and vim.fn.strdisplaywidth(vim.fn.strcharpart(text, 0, n)) > width - 1 do
    n = n - 1
  end
  return vim.fn.strcharpart(text, 0, n) .. "…"
end

-- A noul is its probability; a score is its position on the legend scale; an
-- answer with neither sorts last. Keyed on field presence, not `type`, so
-- hand-built records without a type still render.
local function strength(a)
  if type(a) ~= "table" then
    return -1
  end
  if type(a.noul) == "number" then
    return a.noul
  end
  if type(a.score) == "number" then
    local levels = #require("straps_classifier.questions").DAMAGE_LEVELS
    return levels > 1 and a.score / (levels - 1) or a.score
  end
  return -1
end

--- One line per answer, strongest first, for the record view.
function M.answer_lines(answers)
  local ids = {}
  for id in pairs(answers) do
    ids[#ids + 1] = id
  end
  table.sort(ids, function(x, y)
    local sx, sy = strength(answers[x]), strength(answers[y])
    if sx ~= sy then
      return sx > sy
    end
    return x < y
  end)
  local out = {}
  for _, id in ipairs(ids) do
    local a = answers[id]
    if type(a) == "table" and type(a.noul) == "number" then
      out[#out + 1] = ("%-28s %.2f"):format(id, a.noul)
    elseif type(a) == "table" and type(a.score) == "number" then
      out[#out + 1] = ("%-28s %.2f  (score%s)"):format(id, a.score,
        type(a.confidence) == "number" and (", confidence %.2f"):format(a.confidence) or "")
    else
      out[#out + 1] = ("%-28s %s"):format(id, vim.inspect(a):gsub("%s+", " "))
    end
  end
  return out
end
--- Implementation of fn.classifier_audit_render.
function M.render(bufnr)
  if not vim.api.nvim_buf_is_valid(bufnr) then
    return
  end
  vim.bo[bufnr].modifiable = true
  local ok, err = pcall(function()
    local lines, map, hls = {}, {}, {}
    lines[#lines + 1] = KEYS .. (filter_denies and "   [denies only]" or "")
    hls[#hls + 1] = { 0, 0, -1, "Comment" }
    lines[#lines + 1] = ""

    local sets = M.all()
    if #sets == 0 then
      lines[#lines + 1] = "  no classifications recorded yet"
    end

    for _, s in ipairs(sets) do
      local title = s.label
      if s.parent then
        title = ("%s  (child of buffer %d, depth %d)"):format(title, s.parent, s.depth or 0)
      end
      if not s.alive then
        title = title .. "  [closed]"
      end
      lines[#lines + 1] = rule(title)
      hls[#hls + 1] = { #lines - 1, 0, -1, "StrapsRule" }
      if s.path then
        lines[#lines + 1] = "  " .. fit(vim.fn.fnamemodify(s.path, ":~"), WIDTH - 2)
        hls[#hls + 1] = { #lines - 1, 0, -1, "Comment" }
      end

      local shown = 0
      for i = #s.entries, 1, -1 do
        local e = s.entries[i]
        if not filter_denies or e.action == "deny" then
          local mark = e.action == "deny" and "DENY" or " ok "
          local row = ("  %s  %s  %-16s %s"):format(
            os.date("%H:%M:%S", e.at), mark, fit(e.tool, 16), fit(e.reason or "", 41))
          lines[#lines + 1] = row
          hls[#hls + 1] = { #lines - 1, 12, 18,
            e.action == "deny" and "DiagnosticError" or "DiagnosticOk" }
          map[#lines] = { session = s.key, seq = e.seq }
          shown = shown + 1
        end
      end
      if shown == 0 then
        lines[#lines + 1] = "  (nothing to show)"
        hls[#hls + 1] = { #lines - 1, 0, -1, "Comment" }
      end
      lines[#lines + 1] = ""
    end

    vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, lines)
    vim.api.nvim_buf_clear_namespace(bufnr, ns, 0, -1)
    for _, h in ipairs(hls) do
      pcall(vim.api.nvim_buf_set_extmark, bufnr, ns, h[1], h[2], {
        end_col = h[3] == -1 and nil or h[3],
        end_row = h[3] == -1 and h[1] + 1 or nil,
        hl_group = h[4],
      })
    end
    lines_map[bufnr] = map
  end)
  vim.bo[bufnr].modifiable = false
  vim.bo[bufnr].modified = false
  if not ok then
    pcall(vim.notify, "straps_classifier: audit render failed: " .. tostring(err),
      vim.log.levels.ERROR)
  end
end

--- Debounced re-render of the audit buffer, if one is open.
function M.refresh()
  local buf = find_buf()
  if not buf then
    return
  end
  if timer then
    pcall(function() timer:stop() end)
  end
  timer = vim.defer_fn(function()
    timer = nil
    local b = find_buf()
    if b then
      local reg_ok = pcall(function()
        require("straps.registry").call("fn.classifier_audit_render", b)
      end)
      if not reg_ok then
        M.render(b)
      end
    end
  end, 60)
end

local function entry_at_cursor()
  local buf = vim.api.nvim_get_current_buf()
  local lnum = vim.api.nvim_win_get_cursor(0)[1]
  local ref = (lines_map[buf] or {})[lnum]
  if not ref then
    return nil
  end
  local s = sessions[ref.session]
  if not s then
    return nil
  end
  for _, e in ipairs(s.entries) do
    if e.seq == ref.seq then
      return e, s
    end
  end
  return nil
end

local function window_with_filetype(ft)
  for _, w in ipairs(vim.api.nvim_tabpage_list_wins(0)) do
    if vim.bo[vim.api.nvim_win_get_buf(w)].filetype == ft then
      return w
    end
  end
  return nil
end

local function window_with_buf(b)
  for _, w in ipairs(vim.api.nvim_tabpage_list_wins(0)) do
    if vim.api.nvim_win_get_buf(w) == b then
      return w
    end
  end
  return nil
end

-- The full record for one row, in a scratch split.
local function open_record()
  local e, s = entry_at_cursor()
  if not e then
    return
  end
  local out = {
    "session:   " .. tostring(s.label),
    "tool:      " .. tostring(e.tool),
    "category:  " .. tostring(e.capability),
    "battery:   " .. tostring(e.kind or "hazard"),
    "action:    " .. tostring(e.action),
    "reason:    " .. tostring(e.reason),
    "latency:   " .. (e.ms and (e.ms .. "ms") or "n/a"),
  }
  if e.failure then
    out[#out + 1] = "failure:   " .. tostring(e.failure)
  end
  out[#out + 1] = ""
  out[#out + 1] = "input digest:"
  for _, l in ipairs(vim.split(tostring(e.digest or ""), "\n", { plain = true })) do
    out[#out + 1] = "  " .. l
  end
  if e.answers then
    out[#out + 1] = ""
    out[#out + 1] = "answers (strongest first):"
    for _, l in ipairs(M.answer_lines(e.answers)) do
      out[#out + 1] = "  " .. l
    end
  end
  if e.usage and e.usage.input_tokens then
    out[#out + 1] = "tokens:    " .. tostring(e.usage.input_tokens)
  end
  if e.state then
    out[#out + 1] = ""
    out[#out + 1] = "state sent to the classifier:"
    for _, l in ipairs(vim.split(vim.inspect(e.state), "\n", { plain = true })) do
      out[#out + 1] = "  " .. l
    end
  end
  local name = ("straps://classifier/record/%d"):format(e.seq)
  local b = vim.fn.bufnr("^" .. name .. "$")
  if b == -1 then
    b = vim.api.nvim_create_buf(false, true)
    vim.bo[b].buftype = "nofile"
    vim.bo[b].bufhidden = "wipe"
    vim.bo[b].swapfile = false
    vim.api.nvim_buf_set_name(b, name)
    vim.api.nvim_buf_set_lines(b, 0, -1, false, out)
    vim.bo[b].filetype = "straps_classifier_record"
    vim.bo[b].modifiable = false
  end
  local win = window_with_filetype("straps_classifier_record")
  if win then
    vim.api.nvim_set_current_win(win)
  else
    vim.cmd("botright vsplit")
  end
  vim.api.nvim_win_set_buf(0, b)
end

local function clear_at_cursor()
  local _, s = entry_at_cursor()
  if not s then
    return
  end
  local n = #s.entries
  local choice = vim.fn.confirm(("Clear %d classification records for %s?"):format(n, tostring(s.label)),
    "&Yes\n&No", 2)
  if choice ~= 1 then
    return
  end
  M.clear(s.key)
  M.render(vim.api.nvim_get_current_buf())
  vim.notify(("straps_classifier: cleared %d records for %s"):format(n, tostring(s.label)), vim.log.levels.INFO)
end

--- Open (or reuse) straps://classifier and render it.
function M.open()
  local bufnr = find_buf()
  if not bufnr then
    bufnr = vim.api.nvim_create_buf(true, true)
    vim.api.nvim_buf_set_name(bufnr, BUFNAME)
    vim.bo[bufnr].buftype = "nofile"
    vim.bo[bufnr].swapfile = false
    vim.bo[bufnr].filetype = "straps_classifier"
    local function map(lhs, fn)
      vim.keymap.set("n", lhs, fn, { buffer = bufnr, nowait = true, silent = true })
    end
    map("<CR>", open_record)
    map("o", function()
      local _, s = entry_at_cursor()
      if s and type(s.key) == "number" and vim.api.nvim_buf_is_valid(s.key) then
        vim.cmd("split")
        vim.api.nvim_win_set_buf(0, s.key)
      end
    end)
    map("d", function()
      filter_denies = not filter_denies
      M.render(vim.api.nvim_get_current_buf())
    end)
    map("R", function() M.render(vim.api.nvim_get_current_buf()) end)
    map("x", clear_at_cursor)
  end
  local win = window_with_buf(bufnr)
  if win then
    vim.api.nvim_set_current_win(win)
  else
    vim.cmd("split")
    vim.api.nvim_win_set_buf(0, bufnr)
  end
  M.render(bufnr)
  return bufnr
end

M._open_record = open_record
M._clear_at_cursor = clear_at_cursor

return M
