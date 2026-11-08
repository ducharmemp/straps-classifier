-- tests/local_rules_spec.lua — the pattern rules that need no key and no ctx.
--   busted tests/local_rules_spec.lua

local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(vim.fn.fnamemodify(here, ":p"), ":h:h")
vim.opt.rtp:prepend(root)
package.path = root .. "/lua/?.lua;" .. root .. "/lua/?/init.lua;" .. package.path

local rules = require("straps_classifier.local_rules")

local CFG = {
  always_deny_patterns = { "rm%s+%-rf%s+/", "%.ssh/id_", "%.aws/credentials" },
}

it("a matching command denies", function()
  local action, reason = rules.check("bash", { command = "rm -rf /" }, CFG)
  assert(action == "deny", "rm -rf / must deny")
  assert(reason:find("local rule", 1, true), "reason should say so: " .. tostring(reason))
end)

it("a labelled rule names its label instead of the pattern", function()
  local cfg = { always_deny_patterns = { { pattern = "rm%s+%-rf%s+/", label = "recursive delete of /" }, "^sudo%s" } }
  local _, reason = rules.check("bash", { command = "rm -rf /" }, cfg)
  assert(reason == 'local rule "recursive delete of /" matched "rm -rf /"', tostring(reason))
  local _, plain = rules.check("bash", { command = "sudo ls" }, cfg)
  assert(plain == 'local rule "^sudo%s" matched "sudo ls"', tostring(plain))
  local _, nolabel = rules.check("bash", { command = "rm -rf /" }, { always_deny_patterns = { { pattern = "rm%s" } } })
  assert(nolabel == 'local rule "rm%s" matched "rm -rf /"', tostring(nolabel))
end)

it("an ordinary command passes", function()
  local action = rules.check("bash", { command = "ls -la" }, CFG)
  assert(action == nil, "ls should not match")
end)

it("a match is found in a nested field", function()
  local action = rules.check("delete_files", { paths = { "a.txt", "/home/x/.ssh/id_ed25519" } }, CFG)
  assert(action == "deny", "a nested path must be searched")
end)

it("a match is found in the tool name too", function()
  local action = rules.check("bash", { note = "harmless" },
    { always_deny_patterns = { "^bash$" } })
  assert(action == "deny", "the tool name is part of the haystack")
end)

it("no patterns configured means no local denial", function()
  local action = rules.check("bash", { command = "rm -rf /" }, { always_deny_patterns = {} })
  assert(action == nil, "an empty pattern list denies nothing")
end)

it("a malformed pattern does not raise", function()
  local action = rules.check("bash", { command = "x" }, { always_deny_patterns = { "%" } })
  assert(action == nil, "a bad pattern should be skipped, not thrown")
end)

it("deep nesting is bounded", function()
  local deep = { a = { b = { c = { d = { e = { f = { g = { command = "rm -rf /" } } } } } } } }
  local ok = pcall(rules.check, "bash", deep, CFG)
  assert(ok, "deep input must not blow the stack")
end)
local FULL = require("straps_classifier").config
local function joined(...) return table.concat({ ... }) end

it("prose fields are never searched", function()
  local dangerous = joined("rm -", "rf / && cat ~/.s", "sh/id_rsa && sudo --remote-expr $NVIM")
  assert(rules.check("write_file", { path = "README.md", content = dangerous }, FULL) == nil,
    "file content is a mention, not a command")
  assert(rules.check("edit_file", { path = "init.lua", old_string = dangerous, new_string = dangerous }, FULL) == nil,
    "edit strings are not commands")
  assert(rules.check("spawn", { task = dangerous }, FULL) == nil, "a subagent task is prose")
  assert(rules.check("ask_user", { question = dangerous }, FULL) == nil, "a question is prose")
end)

it("command fields are searched with the shipped patterns", function()
  assert(rules.check("bash", { command = "sudo rm x" }, FULL) == "deny", "sudo denies")
  assert(rules.check("bash", { command = "echo pseudo" }, FULL) == nil, "pseudo is not sudo")
  assert(rules.check("bash", { command = "git remote -v" }, FULL) == nil, "remote is not --remote")
  assert(rules.check("bash", { command = "nvim --server $NVIM --remote-expr 1" }, FULL) == "deny",
    "driving the host Neovim denies")
  assert(rules.check("bash", { command = "echo $NVIM" }, FULL) == "deny", "$NVIM denies")
  assert(rules.check("bash", { command = "echo $NVIMX" }, FULL) == nil, "$NVIMX is a different variable")
  assert(rules.check("eval_lua", { code = "os.getenv('NVIM_LISTEN_ADDRESS')" }, FULL) == "deny",
    "code fields are commands")
  assert(rules.check("delete_files", { paths = { "a", joined("/x/.s", "sh/id_rsa") } }, FULL) == "deny",
    "path lists are searched")
end)
