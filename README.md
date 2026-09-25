# straps-classifier

Every tool call your agent makes is rated by [TypeSafe](https://typesafe.ai)'s
Jev after you approve it. A call rated dangerous is blocked.

The classifier can veto and cannot approve. Permission comes from you, from a
`:StrapsAuto` grant you made, or — in a subagent — from the grant set its parent
gave it. This plugin only ever takes permission away.

## What happens on a tool call

1. You decide: the confirm dialog, or silently through a `cap:` grant in auto
   mode. A subagent's decision was made by its parent when it was spawned.
2. The classifier rates the call. A dangerous rating blocks it, with a reason
   naming the question that fired.

That order is the point. A classifier in front of you is a second gatekeeper to
argue with; behind you it is a check on the calls you waved through — which in
auto mode is all of them.

## Install

The guard must be registered before the first straps session opens, because
straps freezes its guard chain at that moment. It must also come after
`require("straps").setup()`, whose `hook.confirm` this plugin chains. Both hold
for anything that runs at startup, in order, after straps.

### Nix (nixvim)

Add the input:

```nix
inputs.straps-classifier.url = "git+ssh://git@github.com/ducharmemp/straps-classifier";
inputs.straps-classifier.inputs.nixpkgs.follows = "unstable";
```

Then, beside the existing straps module:

```nix
programs.nixvim = {
  imports = [
    inputs.straps.nixvimModules.default
    inputs.straps-classifier.nixvimModules.default
  ];
  plugins.straps.enable = true;
  plugins.straps-classifier.enable = true;
  plugins.straps-classifier.settings = {
    deny_threshold = 0.85;
  };
};
```

The module emits its `setup()` call with `lib.mkAfter`, so it lands after
straps' own regardless of import order.

### Other plugin managers

Load it eagerly — not on a command or an event. With lazy.nvim:

```lua
{
  "ducharmemp/straps-classifier",
  dependencies = { "ducharmemp/straps" },
  lazy = false,
  priority = 100,  -- after straps, before anything opens a session
  config = function() require("straps_classifier").setup({}) end,
}
```

A spec that fires on `:Straps` is too late: the session opens, the chain
freezes, and the guard never installs. `setup()` says so at ERROR level in that
case and `:StrapsClassifierStatus` keeps reporting it.

### Either way, set a key

```sh
export TYPESAFE_API_KEY=...
# or
install -m 600 /dev/stdin ~/.config/straps/typesafe_api_key <<< "your-key"
```

### Check it took

```
:StrapsClassifierStatus
```

`installed: true` with `api key: resolves` is a working install. Anything else
means tool calls are being denied, and the message says which of the two is
wrong.

## No key means no tools

Without a working key every tool call is denied. That is deliberate. A plugin
installed to keep an agent from wrecking things, which has not been configured
yet, knows nothing about the call in front of it — and knowing nothing is
suspicion, not permission.

The same applies to every other failure: HTTP errors, timeouts, an unparseable
response, or a call arriving through a path where the classifier cannot run all
block. There is no configuration that turns a veto into a warning. Uninstalling
is the off switch.

## What it asks

One request per tool call, carrying eleven yes/no hazard questions, one signal,
and one rating. A hazard denies on its own when its probability reaches
`deny_threshold`; the signal denies only when `opaque_action` is `deny`; the
rating denies at `damage_deny`.

| question | asks | role |
| --- | --- | --- |
| `reads_outside_root` | reads a path outside the project root (temp and dependency roots excepted)? | hazard |
| `writes_outside_root` | creates, modifies, moves, or deletes such a path? | hazard |
| `writes_harmful_content` | writes a script, hook, or config that would do harm when later run? | hazard |
| `executes_generated_input` | pipes decoded, downloaded, or read content into a shell or interpreter? | hazard |
| `unrecoverable_loss` | destroys data that undo, the jj op log, or a backup cannot bring back? | hazard |
| `reads_credentials` | reads, prints, or copies keys, tokens, or passwords? | hazard |
| `transmits_local_data` | sends local files, env, or output to the network? | hazard |
| `redefines_protected` | redefines, shadows, or bypasses a protected entry, module, or setting at run time? | hazard |
| `pushes_or_publishes` | pushes or publishes to a shared location? | hazard |
| `deploys_or_mutates_infra` | mutates infrastructure or cloud state? | hazard |
| `sends_message` | sends a message a person outside this editor receives? | hazard |
| `runs_script_outside_root` | runs a file located outside the project root? | signal |
| `damage` | how much damage would running this do, on a four-level scale? | rating |

TypeSafe evaluates them in parallel against one state: the tool name, its
capability, the tool input (elided if long; a program input over the cap is
refused outright), cwd, the project root and its parent, home, the temp and
dependency directories, where each structured path argument resolves, the
protected-entry list, the version control in use, and your most recent message.
The transcript is not otherwise sent.

The questions are literal and one-hop by design: TypeSafe's Jev reads them at
face value, so each names the one thing it judges and a few code-side rules
combine the results (a file edit's `redefines_protected` is ignored, since an
edit cannot redefine anything at run time; the `writes_harmful_content` question
catches a payload written to disk instead).

Nothing is cached. A repeated call is rated again, against the world as it is
then.

## Inspecting verdicts

`:StrapsClassifierAudit` opens `straps://classifier`: every classification, one
line each, grouped by session, with subagents nested under the parent that
spawned them.

```
<CR>  the full record — every question's probability, strongest first, the
      token cost, and the exact state the model was given
o     open that session's transcript
d     denies only
R     refresh
x     clear this session's audit
```

Every verdict, allow or deny, keeps the state it was judged on and the answers
it got, so an allow that looks wrong reads back the same way a deny does. The
ring holds `audit_limit` entries per session (default 500) and survives the
session buffer closing.

Two other ways in: `:StrapsClassifierStatus` for install and key state, and
straps' own `fn.log` — every verdict emits `{ ev = "classify", ... }`, which
lands as JSON lines when `config.log_file` is set.

## Configuration

```lua
require("straps_classifier").setup({
  model = "jev-latest",
  endpoint = "https://api.typesafe.ai/v1/systemone",
  timeout_ms = 8000,
  retry = 1,

  -- Any hazard at or above this denies.
  deny_threshold = 0.85,
  -- The damage rating (0-3) at or above this denies on its own.
  damage_deny = 2.5,
  -- What to do when runs_script_outside_root fires: "deny" or "log".
  opaque_action = "deny",

  -- Lua patterns matched against the tool name and command-like fields of the
  -- input (command, code, path, paths) -- never prose fields like a write's
  -- content or a subagent's task. These deny with no network call, so they
  -- work with no key at all.
  always_deny_patterns = {
    "rm%s+%-rf%s+/", "%.ssh/id_", "%.aws/credentials",
    "^sudo%s", "%ssudo%s", "^doas%s", "%sdoas%s",
    "%-%-remote%-", "%-%-server%s", "%$NVIM%f[%W]", "NVIM_LISTEN_ADDRESS",
  },

  max_state_bytes = 4000,
  audit_limit = 500,
  on_verdict = nil,  -- function(record), called off the tool path
})
```

The config is frozen at `setup()`. A later assignment to the config table (from
`eval_lua`, say) changes nothing the classifier does, so the settings are not a
run-time off switch.

To watch it for a while without letting it block anything, make the thresholds
unreachable and log the signal instead of denying it:

```lua
require("straps_classifier").setup({
  deny_threshold = 1.1, damage_deny = 99, opaque_action = "log",
})
```

The pattern rules and a fail-closed deny (no key, an HTTP error, a moved damage
legend, a missing answer) still block; verdicts still land in the audit buffer.

## What it costs

Every tool call is a network round trip before the tool runs, reads included.
Straps gates a parallel read batch one block at a time, so a ten-read batch is
ten sequential requests. Measured against jev-1.13, one request runs about
350ms and costs roughly 3,800 input tokens across the full thirteen-question
battery; `tests/run_live.lua` prints the mean latency and token cost.

A denied call the model retries pays again. Straps' stall detector ends a run
after six consecutive turns where every call failed, so that bottoms out rather
than looping.

## Where it does not reach

A granted `lua` or `exec` capability is full-privilege Lua in the same process,
and straps documents that ceiling itself. Tool calls made directly through
`registry.call("tool.*")` — from a hook body, or from `eval_lua` — carry no `ctx`
to await on, so they cannot be classified; they are denied outright, which closes
the bypass but does not make the ceiling disappear. The `redefines_protected`
question and the pattern rules raise the cost of an `eval_lua` that reaches for
the classifier's own entries, and the config is frozen at `setup()`, but an
agent with unrestricted `lua` is still operating below the classifier. It is
defense in depth behind a real sandbox, not the sandbox.

The classifier is a check on an agent doing something rash. It is not a sandbox.

## Tests

```sh
nvim --headless -l tests/run_policy.lua       # pure routing
nvim --headless -l tests/run_local_rules.lua  # pattern rules
nvim --headless -l tests/run_guard.lua        # the guard
nvim --headless -l tests/run_confirm.lua      # the confirm chain
nvim --headless -l tests/run_audit.lua        # the record and its view
nvim --headless -l tests/run_live.lua         # one real request (needs a key)
```

Everything but `run_live.lua` runs offline against a scripted backend. Tests that
need straps find it at `../straps` or `$STRAPS_ROOT`.

Under nix, `nix flake check` runs the same set with `STRAPS_ROOT` pointed at the
flake input, and `nix develop` puts neovim, curl and that variable in scope.
