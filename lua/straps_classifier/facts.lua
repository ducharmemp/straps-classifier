local M = {}

local SHELLS = { bash = true, sh = true, zsh = true, dash = true }
local PYTHONS = { python = true, python3 = true }
local INTERPRETERS = { bash = true, sh = true, zsh = true, dash = true, python = true, python3 = true, node = true,
  perl = true, ruby = true }
local NON_EVALUATORS = {}
for _, name in ipairs({ "printf", "echo", "cat", "grep", "ls", "wc", "head", "tail", "sort", "curl", "sendmail", "aws",
  "kubectl", "git", "psql", "alembic", "ruff", "mypy", "find", "rm", "cp", "mv", "mkdir", "chmod" }) do
  NON_EVALUATORS[name] = true
end

local function scan_string(text, i)
  local quote = text:sub(i, i)
  local j, out = i + 1, {}
  while j <= #text do
    local c = text:sub(j, j)
    if c == "\\" then
      local n = text:sub(j + 1, j + 1)
      local map = { n = "\n", t = "\t", ["\\"] = "\\", ["'"] = "'", ['"'] = '"' }
      out[#out + 1] = map[n] or n
      j = j + 2
    elseif c == quote then
      return table.concat(out), j + 1
    else
      out[#out + 1] = c
      j = j + 1
    end
  end
end

local function scan_long(text, i)
  local eq = text:match("^%[(=*)%[", i)
  if not eq then return end
  local close = "]" .. eq .. "]"
  local start = i + #eq + 2
  local stop = text:find(close, start, true)
  if not stop then return end
  return text:sub(start, stop - 1), stop + #close
end

local function table_items(text, i)
  local items, depth, j, current = {}, 0, i + 1, nil
  local function push(item) if item then items[#items + 1] = item end end
  while j <= #text do
    local c = text:sub(j, j)
    if c == "'" or c == '"' then
      local value, after = scan_string(text, j)
      if not value then return end
      if depth == 0 and not current then current = { literal = value } else current = { expr = "?" } end
      j = after
    elseif c == "[" and text:match("^%[=*%[", j) then
      local value, after = scan_long(text, j)
      if not value then return end
      if depth == 0 and not current then current = { literal = value } else current = { expr = "?" } end
      j = after
    elseif c == "{" or c == "(" then
      depth = depth + 1
      current = { expr = "?" }
      j = j + 1
    elseif c == "}" or c == ")" then
      if depth == 0 then push(current) return items end
      depth = depth - 1
      j = j + 1
    elseif c == "," and depth == 0 then
      push(current)
      current = nil
      j = j + 1
    elseif c:match("%s") then
      j = j + 1
    else
      local word = text:match("^[%w_%.]+", j)
      if word and depth == 0 and not current then
        current = { expr = word }
        j = j + #word
      else
        current = { expr = "?" }
        j = j + (word and #word or 1)
      end
    end
  end
end

function M.process(definition, input)
  if type(definition) ~= "string" then return nil end
  local start = definition:find("vim%.system%(")
  if not start or definition:find("vim%.system%(", start + 1) then return nil end
  local i = definition:find("%S", start + #"vim.system(")
  if not i then return nil end
  local argv = {}
  if definition:sub(i, i) == "{" then
    local items = table_items(definition, i)
    if not items or #items == 0 then return nil end
    for index, item in ipairs(items) do
      if item.literal then
        argv[index] = { value = item.literal, from = "literal" }
      else
        local field = type(item.expr) == "string" and item.expr:match("^input%.([%w_]+)$")
        if field and type(input) == "table" and type(input[field]) == "string" then
          argv[index] = { value = input[field], from = "input." .. field }
        else
          argv[index] = { from = item.expr or "?" }
        end
      end
    end
  elseif definition:match("^input%.argv%s*,", i) and type(input) == "table" and type(input.argv) == "table"
    and vim.islist(input.argv) and #input.argv > 0 then
    for index, value in ipairs(input.argv) do
      if type(value) ~= "string" then return nil end
      argv[index] = { value = value, from = "literal" }
    end
  else
    return { built_at_run_time = true }
  end
  if type(argv[1].value) ~= "string" then return nil end
  local result = { program = argv[1].value:match("[^/]+$") or argv[1].value, argv = argv }
  if INTERPRETERS[result.program] then
    for index = 2, #argv - 1 do
      local flag = argv[index].value
      if flag == "-c" or flag == "-e" then
        if type(argv[index + 1].value) == "string" then
          result.code = argv[index + 1].value
          result.data_arguments = {}
          for rest = index + 2, #argv do
            if type(argv[rest].value) == "string" then table.insert(result.data_arguments, argv[rest].value) end
          end
        end
        break
      end
    end
  end
  return result
end

local function blank(out, a, b)
  for k = a, math.min(b, #out) do out[k] = " " end
end

function M.mask_shell(script)
  local n, out = #script, {}
  for k = 1, n do out[k] = script:sub(k, k) end
  local i, dq, pending = 1, false, {}
  while i <= n do
    local c = script:sub(i, i)
    if c == "\\" then
      blank(out, i, i + 1)
      i = i + 2
    elseif c == "'" and not dq then
      local j = script:find("'", i + 1, true) or n
      for k = i, j do if script:sub(k, k) ~= "\n" then out[k] = " " end end
      i = j + 1
    elseif c == '"' then
      dq = not dq
      i = i + 1
    elseif not dq and script:sub(i, i + 1) == "<<" then
      local rest = script:sub(i + 2)
      local dash, spaces, quote, word = rest:match("^(%-?)(%s*)(['\"]?)([%w_]+)")
      if word and (quote == "" or rest:sub(#dash + #spaces + #quote + #word + 1, #dash + #spaces + #quote + #word + 1) == quote) then
        local nl = script:find("\n", i, true)
        if nl then
          local pos, stop = nl + 1, n
          while pos <= n do
            local line_end = script:find("\n", pos, true) or (n + 1)
            if script:sub(pos, line_end - 1):match("^%s*" .. vim.pesc(word) .. "%s*$") then
              stop = line_end - 1
              break
            end
            pos = line_end + 1
          end
          pending[#pending + 1] = { start = nl, stop = stop, quoted = quote ~= "" }
        end
        i = i + 2 + #dash + #spaces + #quote + #word + #quote
      else
        i = i + 2
      end
    elseif c == "\n" and #pending > 0 then
      local heredoc = table.remove(pending, 1)
      if heredoc.quoted then
        blank(out, heredoc.start, heredoc.stop)
        i = heredoc.stop + 1
      else
        i = i + 1
      end
    else
      i = i + 1
    end
  end
  return table.concat(out)
end

local function word_at(text, s, e)
  local before = s > 1 and text:sub(s - 1, s - 1) or ""
  local after = text:sub(e + 1, e + 1)
  return not before:match("[%w_%-]") and not after:match("[%w_]")
end

local function has_word(text, word, follow)
  local init = 1
  while true do
    local s, e = text:find(word, init, true)
    if not s then return false end
    if word_at(text, s, e) and (not follow or text:sub(e + 1):match(follow)) then return true end
    init = s + 1
  end
end

local function has_source_dot(masked)
  for s in masked:gmatch("()%.%s+%S") do
    local before = masked:sub(1, s - 1):match("([^%s]?)%s*$")
    if before == "" or before == ";" or before == "&" or before == "|" then return true end
  end
  return false
end

local function has_inline_interpreter(masked)
  for _, name in ipairs({ "python3", "python", "node", "perl", "ruby" }) do
    local init = 1
    while true do
      local s, e = masked:find(name, init, true)
      if not s then break end
      if word_at(masked, s, e) and masked:sub(e + 1, e + 1):match("%s") then
        local pos = e + 1
        while true do
          local token_start, token_end = masked:find("%S+", pos)
          if not token_start then break end
          local token = masked:sub(token_start, token_end)
          if token == "-c" or token == "-e" or token == "-" then return true end
          if not token:match("^%-[%a]+$") then break end
          pos = token_end + 1
        end
      end
      init = s + 1
    end
  end
  return false
end

local function has_sed_execute(script)
  local init = 1
  while true do
    local s, e = script:find("sed", init, true)
    if not s then return false end
    if word_at(script, s, e) then
      local segment = script:sub(e + 1):match("^[^\n|;&]*") or ""
      local pos = 1
      while true do
        local p = segment:find("s/", pos, true)
        if not p then break end
        local k, fields = p + 2, 0
        while k <= #segment and fields < 2 do
          local c = segment:sub(k, k)
          if c == "\\" then k = k + 2
          elseif c == "/" then fields = fields + 1; k = k + 1
          elseif c == "\n" then break
          else k = k + 1 end
        end
        if fields == 2 and (segment:match("^[%w]*", k) or ""):find("e", 1, true) then return true end
        pos = p + 1
      end
    end
    init = s + 1
  end
end

function M.shell(script)
  local masked = M.mask_shell(script)
  local found = {}
  local function add(cond, label) if cond then found[#found + 1] = label end end
  add(masked:find("$(", 1, true), "command substitution $(...) outside single quotes")
  add(masked:find("`", 1, true), "backtick command substitution outside single quotes")
  add(has_word(masked, "eval"), "eval")
  add(has_word(masked, "source"), "source")
  add(has_source_dot(masked), ". (source)")
  local second_shell = false
  for _, sh in ipairs({ "bash", "zsh", "dash", "sh" }) do
    if has_word(masked, sh, "^%s+%-c%f[^%w_]") then second_shell = true end
  end
  add(second_shell, "a second shell with -c")
  add(masked:find("|%s*sudo%s+bash%f[^%w_]") or masked:find("|%s*bash%f[^%w_]") or masked:find("|%s*zsh%f[^%w_]")
    or masked:find("|%s*sh%f[^%w_]") or masked:find("|%s*sudo%s+sh%f[^%w_]") or masked:find("|%s*sudo%s+zsh%f[^%w_]"),
    "piping into a shell")
  add(has_inline_interpreter(masked), "an interpreter running inline code")
  add(has_sed_execute(script), "sed with the e flag, which executes the replacement text")
  local commands = {}
  local pos = 1
  while pos <= #masked and #commands < 8 do
    local s, e = masked:find("[^;&|\n]+", pos)
    if not s then break end
    if masked:sub(s, e):find("%S") then commands[#commands + 1] = vim.trim(script:sub(s, e)) end
    pos = e + 1
  end
  return found, commands
end

function M.mask_python(code)
  local n, out = #code, {}
  for k = 1, n do out[k] = code:sub(k, k) end
  local i = 1
  while i <= n do
    local c = code:sub(i, i)
    if c == "#" then
      local j = (code:find("\n", i, true) or (n + 1)) - 1
      blank(out, i, j)
      i = j + 1
    elseif c == "'" or c == '"' then
      local triple = code:sub(i, i + 2) == c:rep(3)
      local close = triple and c:rep(3) or c
      local j = i + #close
      while j <= n do
        local d = code:sub(j, j)
        if d == "\\" then j = j + 2
        elseif code:sub(j, j + #close - 1) == close then break
        elseif d == "\n" and not triple then break
        else j = j + 1 end
      end
      for k = i + #close, math.min(j - 1, n) do if code:sub(k, k) ~= "\n" then out[k] = " " end end
      i = j + #close
    else
      i = i + 1
    end
  end
  return table.concat(out)
end

local STDLIB = {}
for _, name in ipairs({ "json", "sys", "os", "ast", "tokenize", "io", "re", "pathlib", "shlex", "subprocess", "marshal",
  "runpy", "importlib", "itertools", "collections", "textwrap", "string", "typing", "functools", "base64", "hashlib" }) do
  STDLIB[name] = true
end
local EXECUTORS = { exec = true, eval = true, ["os.system"] = true, ["os.popen"] = true, __import__ = true,
  ["importlib.import_module"] = true, ["subprocess.run"] = true, ["subprocess.call"] = true, ["subprocess.Popen"] = true,
  ["subprocess.check_output"] = true, ["subprocess.check_call"] = true, ["builtins.exec"] = true, ["builtins.eval"] = true }
local EXECUTOR_ATTRS = { exec_module = true, run_path = true, run_module = true }
local DESTRUCTIVE = { remove = true, unlink = true, rmtree = true, rmdir = true, truncate = true, write_text = true,
  write_bytes = true, rename = true, replace = true }

local function line_of(text, pos)
  local _, count = text:sub(1, pos):gsub("\n", "")
  return count + 1
end

local function enclosing_functions(masked)
  local lines, ranges = vim.split(masked, "\n", { plain = true }), {}
  for index, line in ipairs(lines) do
    local indent, name = line:match("^(%s*)def%s+([%w_]+)")
    if name then
      local last = index
      for k = index + 1, #lines do
        if lines[k]:find("%S") then
          if #(lines[k]:match("^%s*")) <= #indent then break end
          last = k
        end
      end
      ranges[#ranges + 1] = { first = index + 1, last = last, name = name }
    end
  end
  return function(line)
    local best
    for _, range in ipairs(ranges) do
      if line >= range.first and line <= range.last then best = range.name end
    end
    return best
  end
end

local function matching_paren(masked, open)
  local depth = 0
  for k = open, #masked do
    local c = masked:sub(k, k)
    if c == "(" then depth = depth + 1 elseif c == ")" then
      depth = depth - 1
      if depth == 0 then return k end
    end
  end
  return #masked
end

function M.python(code)
  local masked = M.mask_python(code)
  local enclosing = enclosing_functions(masked)
  local calls = {}
  local pos = 1
  while #calls < 8 do
    local s, e, ident = masked:find("([%a_][%w_]*)%s*%(", pos)
    if not s then break end
    pos = e
    if s == 1 or not masked:sub(s - 1, s - 1):match("[%w_]") then
      local name, head = ident, s
      while masked:sub(head - 1, head - 1) == "." do
        local prev = masked:sub(1, head - 2):match("([%a_][%w_]*)$")
        if not prev then break end
        name = prev .. "." .. name
        head = head - 1 - #prev
      end
      local kind
      local open = masked:find("(", e, true)
      local args = masked:sub(open + 1, matching_paren(masked, open) - 1)
      if EXECUTORS[name] or EXECUTOR_ATTRS[ident] then
        kind = "executes code"
      elseif DESTRUCTIVE[ident] then
        kind = "deletes or replaces data"
      elseif name == "open" and code:sub(open + 1, matching_paren(masked, open) - 1):match("^[^,]*,%s*['\"]([^'\"]*)['\"]")
        and code:sub(open + 1, matching_paren(masked, open) - 1):match("^[^,]*,%s*['\"]([^'\"]*)['\"]"):find("[wax+]") then
        kind = "writes a file"
      elseif name:match("^urllib") or name:match("^requests") or name:match("^http%.client") or name:match("^socket") then
        kind = "network"
      end
      local _ = args
      if kind then
        local line = line_of(masked, s)
        calls[#calls + 1] = { call = code:sub(head, matching_paren(masked, open)):sub(1, 160), kind = kind, line = line,
          inside_function = enclosing(line) or vim.NIL }
      end
    end
  end
  for line_number, line in ipairs(vim.split(masked, "\n", { plain = true })) do
    local names = {}
    local imported = line:match("^%s*import%s+(.+)$")
    if imported then
      for part in imported:gmatch("[^,]+") do names[#names + 1] = vim.trim(part):match("^([%w_%.]+)") end
    end
    local from = line:match("^%s*from%s+([%w_%.]+)%s+import")
    if from then names[#names + 1] = from end
    for _, name in ipairs(names) do
      if name and not STDLIB[name:match("^[^%.]+")] and #calls < 8 then
        calls[#calls + 1] = { call = "import " .. name, kind = "executes code", line = line_number, inside_function = vim.NIL }
      end
    end
  end
  return calls, code:find("sys.argv", 1, true) ~= nil
end

local LUA_SENSITIVE = {
  { { "registry['\")]*%.define", "%.define%s*{" }, "redefines a registry entry" },
  { { "nvim_create_autocmd" }, "installs an editor event callback" },
  { { "fs_chmod", "vim%.fn%.setfperm" }, "changes file permissions" },
  { { "fs_unlink", "os%.remove", "vim%.fn%.delete" }, "deletes a file" },
  { { "fs_rename", "os%.rename", "vim%.fn%.rename" }, "renames a file" },
  { { "vim%.fn%.writefile", "io%.open%([^)]*[\"']w" }, "writes a file" },
  { { "%f[%w_]load%s*%(", "loadstring" }, "compiles code" },
  { { "%f[%w_]pcall%s*%(" }, "calls a function with pcall" },
  { { "vim%.cmd", "nvim_command", "nvim_exec" }, "runs an editor command" },
  { { "%f[%w_]require%s*%(" }, "loads a module" },
}

function M.lua(text)
  local calls = {}
  for _, entry in ipairs(LUA_SENSITIVE) do
    local hits = {}
    for _, pattern in ipairs(entry[1]) do
      local init = 1
      while true do
        local s, e = text:find(pattern, init)
        if not s then break end
        hits[#hits + 1] = { s = s, e = e }
        init = e + 1
      end
    end
    table.sort(hits, function(a, b) return a.s < b.s end)
    local merged, last_end = {}, 0
    for _, hit in ipairs(hits) do
      if hit.s > last_end then merged[#merged + 1] = hit end
      last_end = math.max(last_end, hit.e)
    end
    for _, hit in ipairs(merged) do
      calls[#calls + 1] = { kind = entry[2], code = text:sub(math.max(1, hit.s - 50), math.min(#text, hit.e + 90)) }
      if #calls >= 8 then return calls end
    end
  end
  return calls
end

function M.http(definition, input)
  if not definition:find("curl", 1, true) then return nil end
  local method = definition:match("'%-%-request'%s*,%s*'(%w+)'") or definition:match("'%-X'%s*,%s*'(%w+)'")
    or (definition:find("'%-%-data") and "POST" or "GET")
  local urls, seen = {}, {}
  for url in definition:gmatch("https?://[^'\"%s,]+") do
    if not seen[url] then seen[url] = true; urls[#urls + 1] = url end
  end
  local uploads = {}
  for field in definition:gmatch("'@'%s*%.%.%s*input%.([%w_]+)") do
    uploads[#uploads + 1] = type(input) == "table" and input[field] or vim.NIL
  end
  for path in definition:gmatch("'@(/[^']+)'") do uploads[#uploads + 1] = path end
  local trace = {}
  for path in definition:gmatch("'%-%-trace[%w_%-]*'%s*,%s*'([^']+)'") do trace[#trace + 1] = path end
  local body = (definition:find("%-%-data[%w_%-]*'%s*,%s*vim%.json%.encode%(input%)")
    or definition:find("%-%-data[%w_%-]*'%s*,%s*input%.")
    or definition:find("%-%-data[%w_%-]*'%s*,%s*table%.concat%(input")) and "operation.input" or vim.NIL
  return { method = method, urls = urls, sends_authorization_header = definition:find("Authorization", 1, true) ~= nil,
    uploads_files = uploads, writes_wire_trace_to = trace,
    forwards_credentials_across_redirects = definition:find("--location-trusted", 1, true) ~= nil,
    request_body_comes_from = body }
end

local PAGE_ACTIONS = {
  { ".click(", "clicks an element" }, { ".fill(", "fills a field" }, { ".press(", "presses a key" },
  { "checkValidity()", "calls checkValidity()" }, { "reportValidity()", "calls reportValidity()" },
  { ".submit(", "submits a form" }, { "requestSubmit", "submits a form" }, { ".evaluate(", "runs script in the page" },
  { ".screenshot(", "takes a screenshot" }, { "setViewportSize", "changes the viewport" },
  { "cookies(", "reads cookies" }, { ".goto(", "navigates" }, { ".textContent(", "reads page text" },
  { "innerText", "reads page text" },
}

function M.page(definition)
  if not definition:find("chromium", 1, true) and not definition:find("playwright", 1, true) then return nil end
  local actions, seen = {}, {}
  for _, entry in ipairs(PAGE_ACTIONS) do
    if definition:find(entry[1], 1, true) and not seen[entry[2]] then
      seen[entry[2]] = true
      actions[#actions + 1] = entry[2]
    end
  end
  return actions
end

function M.words(text)
  local words, expands, cur, i, n, has, dollar = {}, {}, {}, 1, #text, false, false
  local function flush()
    if has then
      words[#words + 1] = table.concat(cur)
      if dollar then expands[#words] = true end
    end
    cur, has, dollar = {}, false, false
  end
  while i <= n do
    local c = text:sub(i, i)
    if c:match("%s") then
      flush()
      i = i + 1
    elseif c == "'" then
      local j = text:find("'", i + 1, true) or (n + 1)
      cur[#cur + 1] = text:sub(i + 1, j - 1)
      has, i = true, j + 1
    elseif c == '"' then
      local j = i + 1
      while j <= n do
        local d = text:sub(j, j)
        if d == "\\" then cur[#cur + 1] = text:sub(j + 1, j + 1); j = j + 2
        elseif d == '"' then break
        else
          if d == "$" or d == "`" then dollar = true end
          cur[#cur + 1] = d; j = j + 1
        end
      end
      has, i = true, j + 1
    elseif c == "\\" then
      cur[#cur + 1] = text:sub(i + 1, i + 1)
      has, i = true, i + 2
    else
      if c == "$" or c == "`" then dollar = true end
      cur[#cur + 1] = c
      has, i = true, i + 1
    end
  end
  flush()
  return words, expands
end

function M.segments(script)
  local masked, out, start, dq = M.mask_shell(script), {}, 1, false
  for k = 1, #masked + 1 do
    local c = masked:sub(k, k)
    if c == '"' then dq = not dq end
    if k > #masked or (not dq and c:match("[;&|\n]")) then
      local piece = vim.trim(script:sub(start, k - 1))
      if piece ~= "" then out[#out + 1] = piece end
      start = k + 1
      if #out >= 12 then break end
    end
  end
  return out
end

local function flag_set(list)
  local set = {}
  for _, flag in ipairs(list) do set[flag] = true end
  return set
end
local SSH_VALUE = flag_set({ "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o",
  "-p", "-Q", "-R", "-S", "-W", "-w" })
local SCP_VALUE = flag_set({ "-c", "-F", "-i", "-J", "-l", "-o", "-P", "-S", "-e" })
local KUBE_VALUE = flag_set({ "-o", "-f", "-l", "-c", "--since", "--tail", "--selector", "--filename", "--output",
  "--container", "--replicas", "--image", "--type", "--kubeconfig", "--cluster", "--user", "-p" })
local DOCKER_VALUE = flag_set({ "-v", "--volume", "--mount", "-e", "--env", "--env-file", "-p", "--publish", "--name",
  "-w", "--workdir", "-u", "--user", "--network", "--net", "--pid", "--ipc", "--uts", "--cap-add", "--entrypoint",
  "--label", "-l", "--device", "--security-opt", "--platform", "-h", "--hostname", "-m", "--memory", "--restart" })

local function option_value(words, k)
  local name, value = words[k]:match("^(%-%-[%w%-]+)=(.*)$")
  if name then return name, value, k end
  return words[k], words[k + 1], k + 1
end

local function parse_ssh(words, i, expands)
  local entry, jumps, k = { tool = "ssh" }, {}, i + 1
  while words[k] and words[k]:match("^%-") do
    local flag, rest = words[k]:sub(1, 2), words[k]:sub(3)
    if SSH_VALUE[flag] then
      local value = rest
      if rest == "" then value = words[k + 1]; k = k + 1 end
      if flag == "-J" and value then jumps[#jumps + 1] = value end
      if flag == "-l" then entry.user = value end
      if flag == "-p" then entry.port = value end
      if flag == "-o" and value then
        local key, val = value:match("^(%w+)[=%s]+(.+)$")
        if key and (key:lower() == "proxyjump" or key:lower() == "proxycommand") then jumps[#jumps + 1] = key .. "=" .. val end
        if key and key:lower() == "user" then entry.user = val end
      end
    end
    k = k + 1
  end
  local destination = words[k]
  if destination then
    local user, host = destination:match("^([^@]+)@(.+)$")
    entry.host = host or destination
    entry.user = entry.user or user or "not stated: the local user name"
    if #words > k then
      entry.remote_command = table.concat(words, " ", k + 1)
      for index = k + 1, #words do
        if expands and expands[index] then
          entry.remote_command_expanded_locally =
            "$ or backtick text in the remote command is expanded on this machine before ssh sends it; its value is not in the state"
        end
      end
    else
      entry.remote_command = "none: opens an interactive shell on the host"
    end
  end
  entry.jump_hosts = #jumps > 0 and jumps or "none"
  return entry, true
end

local function parse_copy(tool, words, i)
  local entry, operands, k = { tool = tool }, {}, i + 1
  while words[k] do
    local w = words[k]
    if w:match("^%-%-delete") or w == "--remove-source-files" then
      entry.deletes_files = w
    elseif w == "-e" or w == "--rsh" or w:match("^%-%-rsh=") or w:match("^%-%-rsync%-path") then
      local name, value, next_k = option_value(words, k)
      entry.custom_remote_program = name .. " " .. tostring(value)
      k = next_k
    elseif tool == "scp" and SCP_VALUE[w] then
      k = k + 1
    elseif not w:match("^%-") then
      local host, path = w:match("^([^/:]+):(.*)$")
      operands[#operands + 1] = host and { remote_host = host, path = path } or { local_path = w }
    end
    k = k + 1
  end
  entry.destination = operands[#operands]
  entry.sources = { unpack(operands, 1, math.max(0, #operands - 1)) }
  return entry, entry.custom_remote_program ~= nil
end

local function parse_kubectl(words, i)
  local entry, positional, k = { tool = "kubectl" }, {}, i + 1
  while words[k] do
    local w = words[k]
    if w == "--" then
      entry.command_in_pod = table.concat(words, " ", k + 1)
      break
    end
    if w:match("^%-") then
      local name, value, next_k = option_value(words, k)
      if name == "--context" then entry.context = value; k = next_k
      elseif name == "-n" or name == "--namespace" then entry.namespace = value; k = next_k
      elseif name == "--replicas" then entry.replicas = value; k = next_k
      elseif w:find("=", 1, true) then k = k
      elseif KUBE_VALUE[w] then
        if w == "-f" or w == "--filename" then entry.manifest = words[k + 1] end
        k = k + 1
      elseif w == "-A" or w == "--all-namespaces" then entry.namespace = "all namespaces" end
    else
      positional[#positional + 1] = w
    end
    k = k + 1
  end
  entry.context = entry.context or "not stated: uses whatever kubectl context is current"
  entry.namespace = entry.namespace or "not stated: the context's default namespace"
  entry.verb = positional[1]
  entry.objects = { unpack(positional, 2) }
  local runs = entry.command_in_pod ~= nil or entry.verb == "exec" or entry.verb == "run" or entry.verb == "debug"
  return entry, runs
end

local function parse_docker(tool, words, i)
  local entry, k = { tool = tool }, i + 1
  while words[k] and words[k]:match("^%-") do
    local name, value, next_k = option_value(words, k)
    if name == "--context" or name == "-H" or name == "--host" then entry.daemon = value; k = next_k end
    k = k + 1
  end
  local sub = words[k]
  entry.subcommand = sub
  if sub == "container" or sub == "compose" or sub == "volume" or sub == "image" or sub == "system" or sub == "network" then
    entry.subcommand = sub .. " " .. tostring(words[k + 1])
    if sub == "container" and (words[k + 1] == "run" or words[k + 1] == "exec") then sub = words[k + 1] end
    k = k + 1
  end
  if sub ~= "run" and sub ~= "exec" and sub ~= "create" then
    entry.arguments = table.concat(words, " ", k + 1)
    return entry, false
  end
  local mounts, flags = {}, {}
  k = k + 1
  while words[k] and words[k]:match("^%-") do
    local w = words[k]
    local name, value, next_k = option_value(words, k)
    if name == "-v" or name == "--volume" or name == "--mount" then
      mounts[#mounts + 1] = value; k = next_k
    elseif w == "--privileged" then
      flags[#flags + 1] = "--privileged"
    elseif name == "--pid" or name == "--network" or name == "--net" or name == "--ipc" or name == "--uts"
      or name == "--cap-add" or name == "--security-opt" or name == "--device" or name == "-u" or name == "--user" then
      flags[#flags + 1] = name .. "=" .. tostring(value); k = next_k
    elseif DOCKER_VALUE[w] then
      k = k + 1
    end
    k = k + 1
  end
  entry.mounts = mounts
  entry.host_access_flags = flags
  if sub == "exec" then entry.container = words[k] else entry.image = words[k] end
  entry.command_inside = #words > k and table.concat(words, " ", k + 1) or "the image's default command"
  return entry, true
end

local function parse_aws(words, i)
  local entry, positional, k = { tool = "aws" }, {}, i + 1
  while words[k] do
    local w = words[k]
    if w:match("^%-") then
      local name, value, next_k = option_value(words, k)
      if name == "--profile" then entry.profile = value; k = next_k
      elseif name == "--region" then entry.region = value; k = next_k
      elseif name == "--acl" then entry.acl = value; k = next_k
      elseif name == "--recursive" or name == "--force" then entry[name:sub(3)] = true end
    else
      positional[#positional + 1] = w
    end
    k = k + 1
  end
  entry.profile = entry.profile or "not stated: AWS_PROFILE or the default profile"
  entry.service, entry.operation = positional[1], positional[2]
  entry.operands = { unpack(positional, 3) }
  return entry, false
end

local function parse_terraform(words, i)
  local entry, k = { tool = "terraform" }, i + 1
  while words[k] and words[k]:match("^%-") do
    local dir = words[k]:match("^%-chdir=(.+)$")
    if dir then entry.directory = dir end
    k = k + 1
  end
  entry.subcommand = words[k]
  entry.arguments = table.concat(words, " ", k + 1)
  return entry, false
end

local PARSERS = {
  ssh = parse_ssh, kubectl = parse_kubectl, aws = parse_aws, terraform = parse_terraform,
  scp = function(words, i) return parse_copy("scp", words, i) end,
  rsync = function(words, i) return parse_copy("rsync", words, i) end,
  docker = function(words, i) return parse_docker("docker", words, i) end,
  podman = function(words, i) return parse_docker("podman", words, i) end,
}

function M.infrastructure(word_lists, expand_lists)
  local entries, runs_elsewhere = {}, false
  for list_index, words in ipairs(word_lists) do
    local expands = expand_lists and expand_lists[list_index] or {}
    local i = 1
    while words[i] do
      local w = words[i]
      if w:match("^[%a_][%w_]*=") or w == "env" or w == "time" or w == "nohup" or w == "exec" or w == "command" then
        i = i + 1
      elseif w == "sudo" then
        i = i + 1
        while words[i] and words[i]:match("^%-") do
          if words[i] == "-u" or words[i] == "-g" then i = i + 2 else i = i + 1 end
        end
      else
        break
      end
    end
    local program = words[i] and (words[i]:match("[^/]+$") or words[i])
    local parser = program and PARSERS[program]
    if parser then
      local entry, runs = parser(words, i, expands)
      if i > 1 and vim.tbl_contains({ unpack(words, 1, i - 1) }, "sudo") then entry.via_sudo = true end
      entries[#entries + 1] = entry
      runs_elsewhere = runs_elsewhere or runs
    end
    if #entries >= 8 then break end
  end
  return entries, runs_elsewhere
end

function M.compute(definition, input)
  local out = {}
  local process = M.process(definition, input)
  if process and process.program then
    out.program = process.program
    if SHELLS[process.program] and process.code then
      out.shell_evaluators, out.commands = M.shell(process.code)
      out.shell_script = process.code
    elseif PYTHONS[process.program] and process.code then
      out.python_program = process.code
      out.python_sensitive_calls, out.python_reads_argv = M.python(process.code)
      if #process.data_arguments > 0 then out.python_arguments = process.data_arguments end
    elseif not SHELLS[process.program] and not PYTHONS[process.program] and process.program ~= "node" then
      out.argv_passed_without_a_shell = true
    end
  elseif definition:find("vim.system", 1, true) then
    out.program = "built at run time"
  end
  local lua_text = definition
  if definition:find("%f[%w_]load%s*%(%s*input%.") then
    local values = {}
    for _, value in pairs(type(input) == "table" and input or {}) do
      if type(value) == "string" then values[#values + 1] = value end
    end
    table.sort(values)
    lua_text = lua_text .. " " .. table.concat(values, " ")
    out.input_is_run_as_lua = true
  end
  if not definition:find("vim.system", 1, true) or definition:find("load(", 1, true) then
    local calls = M.lua(lua_text)
    if #calls > 0 then out.lua_sensitive_calls = calls end
  end
  out.http = M.http(definition, input)
  local page = M.page(definition)
  if page then out.page_actions = page end
  if definition:match("^%s*return function%(input, ctx%) return vim%.fn%.writefile%(.*%) end%s*$") then
    out.only_writes_input_text_to_a_file = true
  end
  local word_lists, expand_lists = {}, {}
  if out.shell_script then
    for _, segment in ipairs(M.segments(out.shell_script)) do
      local words, expands = M.words(segment)
      word_lists[#word_lists + 1] = words
      expand_lists[#word_lists] = expands
    end
  elseif process and process.argv then
    local words = {}
    for index, item in ipairs(process.argv) do
      if type(item.value) ~= "string" then words = nil; break end
      words[index] = item.value
    end
    if words then word_lists[1] = words end
  end
  local infrastructure, runs_elsewhere = M.infrastructure(word_lists, expand_lists)
  if #infrastructure > 0 then out.infrastructure_commands = infrastructure end
  if runs_elsewhere then out.runs_commands_on_another_system = true end
  local inert = false
  if out.argv_passed_without_a_shell and NON_EVALUATORS[out.program] then inert = true end
  if out.shell_script and #out.shell_evaluators == 0 then inert = true end
  if out.python_program and out.python_reads_argv then
    inert = true
    for _, call in ipairs(out.python_sensitive_calls) do
      if call.kind == "executes code" then inert = false end
    end
  end
  if out.only_writes_input_text_to_a_file then inert = true end
  if runs_elsewhere then inert = false end
  out.data_text_never_executed = inert
  return out
end

M.NOTE = "`facts` were computed by code that parsed the operation, not by a model. Trust them: they report which "
  .. "program starts, whether a shell or interpreter evaluates any text as code (`shell_evaluators`, "
  .. "`python_sensitive_calls`, `lua_sensitive_calls`), the HTTP request that is sent, and the page actions that run. "
  .. "`facts.infrastructure_commands` lists ssh, scp, rsync, kubectl, docker, podman, aws and terraform invocations "
  .. "with their hosts, accounts, jump hosts, contexts, namespaces, profiles, mounts and the command each runs "
  .. "elsewhere; a value starting with `not stated` means the operation relies on a default the state does not show. "
  .. "`facts.runs_commands_on_another_system` true means quoted text is executed on a remote host, pod or container. "
  .. "`facts.data_text_never_executed` true means commands that appear inside quoted text, printed arguments, "
  .. "serialized strings or file contents are inert: they do not happen."

return M
