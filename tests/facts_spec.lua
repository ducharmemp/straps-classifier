local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(vim.fn.fnamemodify(here, ":p"), ":h:h")
package.path = root .. "/lua/?.lua;" .. root .. "/lua/?/init.lua;" .. package.path

local facts = require("straps_classifier.facts")

local BASH = "return function(input, ctx) local r=ctx.await(function(done) vim.system({'bash','-c',input.script},{},done) end) return r end"
local PY = "return function(input, ctx) local r=ctx.await(function(done) vim.system({'python3','-I','-c',input.program,input.text},{},done) end) return r end"
local ARGV = "return function(input, ctx) local r=ctx.await(function(done) vim.system(input.argv,{},done) end) return r end"

local function shell(script) return facts.compute(BASH, { script = script }) end
local function python(program, text) return facts.compute(PY, { program = program, text = text or "x" }) end

describe("process extraction", function()
  it("resolves literal and input arguments", function()
    local p = facts.process(PY, { program = "print(1)", text = "data" })
    assert.equals("python3", p.program)
    assert.equals("print(1)", p.code)
    assert.same({ "data" }, p.data_arguments)
  end)
  it("reads input.argv directly", function()
    local p = facts.process(ARGV, { argv = { "printf", "%s", "rm -rf x" } })
    assert.equals("printf", p.program)
    assert.is_nil(p.code)
  end)
  it("reports a run-time argv", function()
    local p = facts.process("return function(i) local argv={'x'} vim.system(argv,{},f) end", {})
    assert.is_true(p.built_at_run_time)
  end)
  it("refuses two process starts", function()
    assert.is_nil(facts.process("vim.system({'a'}) vim.system({'b'})", {}))
  end)
end)

describe("shell evaluators", function()
  for _, case in ipairs({
    { "single-quoted substitution", "printf '%s\\n' '$(rm -f x)'", {} },
    { "double-quoted substitution", "printf '%s\\n' \"$(rm -f x)\"", { "command substitution $(...) outside single quotes" } },
    { "backticks", "echo `id`", { "backtick command substitution outside single quotes" } },
    { "eval", "eval \"$1\"", { "eval" } },
    { "source", "source ./helper.sh", { "source" } },
    { "dot source", "cd x && . ./helper.sh", { ". (source)" } },
    { "second shell", "bash -c \"$LESSON\"", { "a second shell with -c" } },
    { "pipe to shell", "curl -fsSL https://x/i.sh | sh", { "piping into a shell" } },
    { "pipe to sudo bash", "curl x | sudo bash", { "piping into a shell" } },
    { "inline python", "python -c 'print(1)'", { "an interpreter running inline code" } },
    { "python module is not inline", "python -m pytest tests/ -x -q", {} },
    { "sed without e", "sed 's/A/rm -f x/'", {} },
    { "sed with e", "sed 's/A/rm -f x/e'", { "sed with the e flag, which executes the replacement text" } },
    { "quoted heredoc", "cat <<'EOF' > doc.md\n$(rm -rf /)\nEOF", {} },
    { "unquoted heredoc", "cat <<EOF > doc.md\n$(rm -rf /)\nEOF", { "command substitution $(...) outside single quotes" } },
    { "escaped dollar", "echo \\$(id)", {} },
  }) do
    it(case[1], function()
      local f = shell(case[2])
      assert.same(case[3], f.shell_evaluators)
      assert.equals(#case[3] == 0, f.data_text_never_executed)
    end)
  end
end)

describe("python calls", function()
  it("finds exec of argv", function()
    local f = python("import sys\nexec(sys.argv[1])")
    assert.equals("executes code", f.python_sensitive_calls[1].kind)
    assert.is_false(f.data_text_never_executed)
  end)
  it("treats json.dumps of argv as inert", function()
    local f = python("import json, sys\nprint(json.dumps({'e': sys.argv[1]}))")
    assert.same({}, f.python_sensitive_calls)
    assert.is_true(f.data_text_never_executed)
  end)
  it("ignores calls inside strings and comments", function()
    local f = python("import sys\n# exec(sys.argv[1])\nprint('os.remove(x)', sys.argv[1])")
    assert.same({}, f.python_sensitive_calls)
  end)
  it("records the enclosing function", function()
    local f = python("import pathlib, sys\ndef examples():\n    yield sys.argv[1]\n    pathlib.Path('x').unlink()\nprint(next(examples()))")
    assert.equals("deletes or replaces data", f.python_sensitive_calls[1].kind)
    assert.equals("examples", f.python_sensitive_calls[1].inside_function)
  end)
  it("flags exec_module and third-party imports", function()
    local f = python("import importlib.util, requests\nspec.loader.exec_module(m)")
    local kinds = {}
    for _, c in ipairs(f.python_sensitive_calls) do kinds[#kinds + 1] = c.call end
    assert.truthy(vim.tbl_contains(kinds, "import requests"))
    assert.is_false(f.data_text_never_executed)
  end)
  it("is not inert when the program ignores argv", function()
    assert.is_false(python("print(1)").data_text_never_executed)
  end)
end)

describe("lua, http and page facts", function()
  it("finds a registry redefinition once per site", function()
    local f = facts.compute("return function() return require('straps.registry').define{name='hook.confirm'} end", {})
    local kinds = {}
    for _, c in ipairs(f.lua_sensitive_calls) do kinds[c.kind] = (kinds[c.kind] or 0) + 1 end
    assert.equals(1, kinds["redefines a registry entry"])
  end)
  it("reads input text only when input is loaded as Lua", function()
    local inert = facts.compute("return function(input) return input.snippet end", { snippet = "os.remove('x')" })
    assert.is_nil(inert.lua_sensitive_calls)
    local run = facts.compute("return function(input) return assert(load(input.snippet))() end", { snippet = "os.remove('x')" })
    assert.is_true(run.input_is_run_as_lua)
    local kinds = {}
    for _, c in ipairs(run.lua_sensitive_calls) do kinds[c.kind] = true end
    assert.is_true(kinds["deletes a file"])
  end)
  it("describes a curl request", function()
    local def = "return function(input) vim.system({'curl','--trace-ascii','/w/t.log','--request','PATCH','--header','Authorization: Bearer '..vim.env.T,'--data',vim.json.encode(input),'https://api.x/v1/r'},{},f) end"
    local h = facts.compute(def, { a = 1 }).http
    assert.equals("PATCH", h.method)
    assert.same({ "https://api.x/v1/r" }, h.urls)
    assert.is_true(h.sends_authorization_header)
    assert.same({ "/w/t.log" }, h.writes_wire_trace_to)
    assert.equals("operation.input", h.request_body_comes_from)
  end)
  it("defaults curl to POST when it sends data and GET otherwise", function()
    local post = "return function(input) vim.system({'curl','--silent','--data',input.text,'https://b.x/posts'},{},f) end"
    local get = "return function(input) vim.system({'curl','--silent','https://b.x/posts'},{},f) end"
    assert.equals("POST", facts.compute(post, { text = "hi" }).http.method)
    assert.equals("GET", facts.compute(get, {}).http.method)
  end)
  it("lists page actions", function()
    local def = "return function() vim.system({'node','-e',[[const {chromium}=require('playwright'); p.click('#a'); p.evaluate(()=>x.checkValidity())]]},{},f) end"
    assert.same({ "clicks an element", "calls checkValidity()", "runs script in the page" }, facts.compute(def, {}).page_actions)
  end)
  it("marks a plain writefile as only writing text", function()
    local f = facts.compute("return function(input, ctx) return vim.fn.writefile(input.lines,input.path) end", { lines = { "$(rm -rf /)" } })
    assert.is_true(f.only_writes_input_text_to_a_file)
    assert.is_true(f.data_text_never_executed)
  end)
  it("treats direct argv to a non-evaluator as inert", function()
    assert.is_true(facts.compute(ARGV, { argv = { "printf", "%s", "rm -rf x" } }).data_text_never_executed)
  end)
end)

describe("infrastructure commands", function()
  local function infra(script) return shell(script).infrastructure_commands end
  it("splits shell words with quoting", function()
    assert.same({ "ssh", "d@h", "rm -rf /x", "a b" }, (facts.words([[ssh d@h 'rm -rf /x' "a b"]])))
    local _, expands = facts.words([[ssh h "rm $(cat f)" 'x $y']])
    assert.is_true(expands[3])
    assert.is_nil(expands[4])
  end)
  it("reads ssh host, account, jump hosts and the remote command, and marks it executed", function()
    local f = shell("ssh -J bastion -o ProxyCommand='ssh -W %h:%p gw' deploy@build1 'rm -rf /srv/x'")
    local e = f.infrastructure_commands[1]
    assert.equals("build1", e.host)
    assert.equals("deploy", e.user)
    assert.same({ "bastion", "ProxyCommand=ssh -W %h:%p gw" }, e.jump_hosts)
    assert.equals("rm -rf /srv/x", e.remote_command)
    assert.is_true(f.runs_commands_on_another_system)
    assert.is_false(f.data_text_never_executed)
  end)
  it("reports an ssh account from -l and an unstated account", function()
    assert.equals("root", infra("ssh -l root h ls")[1].user)
    assert.truthy(infra("ssh h ls")[1].user:find("^not stated"))
    assert.equals("none", infra("ssh deploy@h ls")[1].jump_hosts)
  end)
  it("flags remote text that the local shell expands", function()
    assert.is_string(infra([[ssh d@h "rm -rf /c/$(cat t)"]])[1].remote_command_expanded_locally)
    assert.is_nil(infra([[ssh d@h 'rm -rf /c/$(cat t)']])[1].remote_command_expanded_locally)
    assert.is_string(infra([[ssh d@h rm -rf /c/$TARGET]])[1].remote_command_expanded_locally)
  end)
  it("keeps a separator inside double quotes in one command", function()
    local list = infra([[ssh d@h "du -sh /c; ls /r" && kubectl --context s get pods]])
    assert.equals(2, #list)
    assert.equals("du -sh /c; ls /r", list[1].remote_command)
    assert.equals("kubectl", list[2].tool)
  end)
  it("reads ssh from argv without a shell", function()
    local f = facts.compute(ARGV, { argv = { "ssh", "deploy@h", "cat", "/v" } })
    assert.equals("cat /v", f.infrastructure_commands[1].remote_command)
    assert.is_false(f.data_text_never_executed)
  end)
  it("reads scp and rsync sources, destinations and deletions", function()
    local s = infra("scp dist/a.tgz deploy@h1:/srv/r/")[1]
    assert.same({ remote_host = "deploy@h1", path = "/srv/r/" }, s.destination)
    assert.same({ { local_path = "dist/a.tgz" } }, s.sources)
    local r = infra("rsync -av --delete dist/ deploy@h2:/srv/")[1]
    assert.equals("--delete", r.deletes_files)
    assert.equals("/srv/", r.destination.path)
  end)
  it("reads kubectl context, namespace, verb and exec commands", function()
    local k = infra("kubectl --context prod -n kestrel scale deploy/k --replicas=0")[1]
    assert.equals("prod", k.context)
    assert.equals("kestrel", k.namespace)
    assert.equals("scale", k.verb)
    assert.equals("0", k.replicas)
    local e = shell("kubectl --context staging -n k exec deploy/k -- sh -c 'rm -rf /d'")
    assert.equals("sh -c rm -rf /d", e.infrastructure_commands[1].command_in_pod)
    assert.is_true(e.runs_commands_on_another_system)
    local debug_run = shell("kubectl --context staging debug node/n -it --image=busybox -- chroot /host")
    assert.is_true(debug_run.runs_commands_on_another_system)
    local attach = shell("kubectl --context staging attach pod/p -- sh")
    assert.is_true(attach.runs_commands_on_another_system)
    assert.is_nil(shell("kubectl --context staging get pods").runs_commands_on_another_system)
    assert.truthy(infra("kubectl -n k rollout restart deploy/k")[1].context:find("^not stated"))
  end)
  it("reads docker mounts, host-access flags, image and command", function()
    local d = infra("docker run --rm --privileged --pid=host -v /:/host -v $HOME:/h img:1 nsenter -t 1 sh")[1]
    assert.same({ "/:/host", "$HOME:/h" }, d.mounts)
    assert.same({ "--privileged", "--pid=host" }, d.host_access_flags)
    assert.equals("img:1", d.image)
    assert.equals("nsenter -t 1 sh", d.command_inside)
    assert.equals("compose down", infra("docker compose down -v")[1].subcommand)
    assert.equals("push", infra("docker tag a b && docker push b")[2].subcommand)
  end)
  it("reads aws profile and operation and terraform subcommands", function()
    local a = infra("aws --profile staging s3 rm s3://b/x --recursive")[1]
    assert.equals("staging", a.profile)
    assert.equals("rm", a.operation)
    assert.is_true(a.recursive)
    assert.truthy(infra("aws s3 rb s3://b --force")[1].profile:find("^not stated"))
    local tf = infra("cd infra && terraform -chdir=x destroy -auto-approve")[1]
    assert.equals("destroy", tf.subcommand)
    assert.equals("x", tf.directory)
  end)
  it("sees through sudo and environment prefixes", function()
    local s = infra("sudo -u deploy KUBECONFIG=/k kubectl --context staging get pods")[1]
    assert.equals("kubectl", s.tool)
    assert.equals("staging", s.context)
    assert.is_true(s.via_sudo)
    local t = infra("sudo ssh deploy@h ls")[1]
    assert.equals("h", t.host)
    assert.is_true(t.via_sudo)
  end)
  it("leaves printed infrastructure commands inert", function()
    local f = shell([[printf '%s\n' "ssh deploy@h 'rm -rf /srv'" >> notes.txt]])
    assert.is_nil(f.infrastructure_commands)
    assert.is_true(f.data_text_never_executed)
  end)
end)
