# Plan: straps-classifier

Build a plugin in `/home/matt/code/straps-classifier` that sends every tool call
to TypeSafe's Jev for a risk rating and blocks the ones it rates dangerous. The
rating happens after the operator has approved the call, so the classifier is a
check on your own decisions, not a gate in front of them.

**One repo changes: the plugin is new, and straps is untouched.** A second part,
a compaction policy needing a change to straps' `fn.compact`, was planned, built,
and dropped — see Part B below.

## The two rules

**The classifier can veto and cannot approve.** Nothing in this plugin returns
`true` from a confirm hook. Permission comes from you, or from a grant you made,
or — in a subagent — from the grant set its parent gave it. The classifier only
ever subtracts.

**No verdict means no call.** A missing key, an HTTP error, a timeout, an
unparseable response, or no `ctx` to await on all block. An unconfigured
classifier knows nothing about the call in front of it, and knowing nothing is
suspicion, not permission.

## The order

| Step | What runs | Outcome |
| --- | --- | --- |
| 1 | the operator's decision: your dialog, a `cap:` grant in auto mode, or the grant set a parent gave a child | yes or no |
| 2 | the classifier, only on a yes | veto, or silence |

In auto mode step 1 is silent — `:StrapsAuto` already granted the category — and
the classifier is the only thing between that grant and the call. That is the case
it exists for.

## What the plan rests on

| Fact | Where |
| --- | --- |
| `gate_tool` runs the before-guards, then `opts.confirm` | `registry.lua:437-445` |
| A `true` guard verdict does not skip `hook.confirm` | `DESIGN.md:1185` |
| Guards are global-only and freeze one-way | `registry.lua:306-315`, `registry.lua:249` |
| The freeze fires at the first session open and at `loop.start` | `init.lua:271`, `ui.lua:589`, `loop.lua:697` |
| A guard that calls a tool or `define` re-enters the fold, raises, and blocks | `registry.lua:200-204` |
| A before-guard may `ctx.await`; `ctx` is nil on the direct call path | `DESIGN.md:1178-1180` |
| The direct path passes no confirm at all, and no straps builtin uses it | `registry.lua:501-515`, `registry.lua:440` |
| The parallel read batch gates every block before any job starts | `loop.lua:488-506` |
| `hook.confirm` is one entry; chain it with `registry.bind` | `loop.lua:185`, `registry.lua:409-415` |
| A child session has a non-nil `registry.scope_parent` | `registry.lua:107-111` |
| `spawn` gives readonly and allow children their own `hook.confirm` | `agents.lua:284-295` |
| A `cap:` grant makes the default confirm return true silently | `permissions.lua:242-247` |
| `fn.capability` is the one category classifier | `permissions.lua:33-68` |
| `state.list_blocks` gives the transcript's block index | `state.lua:204` |
| Entry sources are plain `load()` chunks and may `require` modules | `registry.lua:329` |
| `fn.api_key` reads an env var, then a chmod-600 file | `provider.lua:14-46` |
| The stall detector ends a run after six turns where every call failed | `loop.lua:605-617` |

One of those decides the shape. **The direct call path passes no confirm**, so
`eval_lua` reaching `registry.call("tool.bash", ...)` today skips the dialog
entirely; Part A closes that.
## Part A — rating tool calls

### A1. Files

```
lua/straps_classifier/init.lua        setup(opts), config, register(), status()
lua/straps_classifier/questions.lua   the questions sent to TypeSafe
lua/straps_classifier/policy.lua      turns answers into deny or ok
lua/straps_classifier/local_rules.lua path and command patterns, no network
lua/straps_classifier/audit.lua       the per-session record and its buffer view
lua/straps_classifier/entries.lua     the registry entries
plugin/straps_classifier.lua          :StrapsClassifierAudit
tests/run_policy.lua   tests/run_local_rules.lua  tests/run_guard.lua
tests/run_confirm.lua  tests/run_audit.lua        tests/run_live.lua
README.md
```

Entry sources `require("straps_classifier.policy")` instead of carrying thresholds
inside Lua strings, so tests call the real code.

### A2. `fn.typesafe_api_key`

Mirrors `fn.api_key` (`provider.lua:14-46`): `$TYPESAFE_API_KEY`, then
`$XDG_CONFIG_HOME/straps/typesafe_api_key`, refusing a file that group or other
can read. The error names both locations.

### A3. `fn.typesafe`

`(payload, ctx) -> answers | nil, err`. POSTs to
`https://api.typesafe.ai/v1/systemone` with `Authorization: Bearer <key>`, through
`vim.system` inside `ctx.await`, with `config.timeout_ms` (default 8000) and
`ctx.on_cancel` killing the process when the run stops. One retry on 429, 529, or
a connection failure. Returns `nil, "no ctx"` when `ctx` is absent, and `nil, err`
on a non-2xx, a decode failure, or a timeout.

### A4. `questions.lua`

One request per tool call: eleven yes/no hazard questions, one signal, and one
rating. The questions are literal and one-hop, because jev-1.13 reads them at
face value; each names the one state field it judges and code combines the
results. `M.QUESTIONS` is the ordered source of truth (id, type, role); the
legacy flat `HAZARDS` list is gone.

| id | role | asks |
| --- | --- | --- |
| `reads_outside_root` | hazard | reads a path outside the project root (temp and dependency roots excepted)? |
| `writes_outside_root` | hazard | creates, modifies, moves, or deletes such a path? |
| `writes_harmful_content` | hazard | writes a script/hook/config that would do harm when later run? |
| `executes_generated_input` | hazard | pipes decoded, downloaded, or read content into a shell/interpreter? |
| `unrecoverable_loss` | hazard | destroys data that undo, the jj op log, or a backup cannot restore? |
| `reads_credentials` | hazard | reads, prints, or copies keys, tokens, passwords? |
| `transmits_local_data` | hazard | sends local files/env/output to the network? |
| `redefines_protected` | hazard | redefines, shadows, or bypasses a protected entry/module/setting at run time? |
| `pushes_or_publishes` | hazard | pushes or publishes to a shared location? |
| `deploys_or_mutates_infra` | hazard | mutates infrastructure or cloud state? |
| `sends_message` | hazard | sends a message a person outside this editor receives? |
| `runs_script_outside_root` | signal | runs a file located outside the project root? |
| `damage` | rating | how much damage would running this do, four levels? |

The `damage` levels are an ordered constant in `questions.lua`: four levels from
"affects nothing outside this editor session" to "irreversible damage to shared or
production state". `policy.lua` compares the returned `legend` against that
constant and denies if they differ, so editing a level never silently re-aims the
threshold.

Sent as state: tool name, capability, the tool input (a program input over
`config.max_state_bytes` is refused; other long inputs have their prose fields
elided head+tail), cwd, the project root and its parent, home, the temp and
dependency directories, `resolved_paths` (where each structured path argument
lands: project_root, dependency_roots, temp_dirs, or outside), the protected
list, the version control in use, and the most recent user request (named
`parent_agent_task` in a child session and marked non-authoritative). The
transcript is not otherwise sent.

### A5. `policy.lua`

`route(answers, cfg, capability) -> action, reason`. Pure, no I/O, testable.

- Any hazard at or above `deny_threshold` (default 0.85): `deny`.
- `runs_script_outside_root` at or above `deny_threshold` when
  `config.opaque_action` is `"deny"` (default): `deny`. When `"log"`, the reason
  records it but the call proceeds.
- `damage` at or above `damage_deny` (default 2.5): `deny`.
- A legend that does not match the constant, or any missing/malformed answer:
  `deny` (fail closed).
- `redefines_protected` is ignored when `capability` is `edit`: a file edit
  cannot redefine anything at run time, and a written payload is
  `writes_harmful_content`'s job.
- Otherwise `ok`.
- `reason` names the deciding question and its probability.

There is no confidence downgrade: an uncertain answer never opens the gate.
`deny_threshold = 1.1`, `damage_deny = 99`, `opaque_action = "log"` runs the
classifier and lets the model-scored questions block nothing, for watching
verdicts before trusting it; the pattern rules and fail-closed denies still fire.

### A6. `fn.risk_verdict`

`(name, input, ctx) -> action, reason`, where `action` is `deny` or `ok`.

1. A path or command matching `config.always_deny_patterns`: `deny`, no request.
   This works with no key and no network.
2. `fn.typesafe`, then `policy.route`.
3. Anything that stopped step 2 from producing an answer: `deny`, with the cause
   in the reason — `no API key`, `timeout after 8000ms`, `HTTP 429`,
   `no ctx to await on`.

Every tool call is classified, reads included. Nothing is skipped and nothing is
remembered: a repeated call is judged again, against the world as it is then.
There is no cache, because a stored verdict answers a later call from an earlier
judgment, and that is the part worth gaming.

The guard and the confirm chain both need the verdict for one call. The guard
writes `action, reason` into a single slot keyed by the session buffer and that
exact `(name, input)`; the confirm takes it and clears it, microseconds later in
the same `gate_tool` pass. The slot holds one verdict for the length of one gate,
is cleared on read, and is cleared when the run ends. An empty slot at the confirm
means the guard produced no verdict, which is itself a deny.

### A7. `hook.guard.classifier`

The guard is the only position every tool call passes: the loop path, the parallel
read batch, and the direct `registry.call("tool.*")` path that carries no confirm
at all.

- **Parent session on the loop path.** Classify, store the verdict in the slot,
  and return nothing. The confirm chain enforces it after your decision, so a call
  you reject costs no request.
- **Child session** (`registry.scope_parent(bufnr)` non-nil). Classify and block
  on `deny` here, because a child's own `hook.confirm`
  (`agents.lua:284-295`) replaces our chain and there is no operator behind it.
  What its parent granted is the approval the classifier subtracts from.
- **Direct path, no `ctx`.** Nothing can await, so nothing can classify: denied
  with `no ctx to await on`. This closes the `eval_lua` bypass. No straps builtin
  calls tools this way (`registry.lua:515` is the only caller of `call_tool`), so
  nothing internal breaks.

The guard never calls a tool and never defines an entry, since either re-enters
the fold and raises (`registry.lua:200-204`). HTTP goes through `vim.system`
directly, never through `tool.fetch_url`. `config.on_verdict` is dispatched
through `vim.schedule` inside a `pcall`, so a raising callback cannot block the
call it was only watching.

**Install ordering.** Guards freeze when the first session opens
(`ui.lua:589`), so a plugin manager that loads this on the `:Straps` command is
too late and the session runs unprotected. Three things make that loud: `setup()`
notifies at ERROR when `registry.guards_frozen()` is already true,
`:checkhealth straps_classifier` reports whether the guard is installed and
whether the key resolves, and `require("straps_classifier").status()` returns the
same fact for a statusline. The README says to install from
`stdpath("config")/straps/init.lua`.

### A8. The confirm chain

```
prev = registry.bind("hook.confirm")
confirm(name, input, ctx):
  allowed, why = prev(name, input, ctx)      -- your dialog, or a cap: grant
  if not allowed -> false, why               -- rejected; nothing else runs
  action, reason = take_verdict(ctx.bufnr, name, input)
  if action == "deny" -> false, "classifier: " .. reason
  return true
```

No second dialog: one you have already answered is one you learn to dismiss. The
reason names the question that fired or the failure that stopped the check.

`gate_tool` prefixes confirm refusals with `"user denied: "`
(`registry.lua:442`), so a veto reads `user denied: classifier: writes_outside_root=0.91`.
Cosmetic; parked.

### A9. Every classification is inspectable

A verdict you cannot examine is a verdict you cannot trust or tune. Each
classification is recorded, and the record is readable three ways.

**What is recorded.** One entry per classification: timestamp, session bufnr,
session label, parent bufnr, spawn depth, tool name, capability category, a
truncated input digest, the action, the deciding question and its probability,
every question's probability and confidence, the `damage` value, the round-trip
milliseconds, and — when the verdict was a failure — the cause. Every verdict,
allow or deny, keeps the exact state sent to TypeSafe and the answers it got, so
an allow that looks wrong reads back the way a deny does; the input token cost is
kept too.

**Where it lives.** `fn.classifier_audit` owns an in-memory ring per session
buffer, `config.audit_limit` entries each (default 500), plus the session's file
path so a record outlives its bufnr. A session that closes keeps its audit until
you clear it. The fn is the only writer, so a redefinition can send records
somewhere else without touching the guard.

**`straps://classifier`.** One ordinary buffer listing every session's
classifications, mirroring `straps://agents` (`ui.lua:1002-1007`): rendered from
live state by a redefinable registry fn (`fn.classifier_audit_render`), a
module-level line→entry map, a debounced refresh, one section rule per session.
Sessions are identified the way `fn.peer_agents` identifies them
(`agents.lua:83-92`) — bufnr, `ui.session_label`, parent, depth, task — so a
subagent's verdicts nest under the parent that spawned them. Rows are one line:
time, action, tool, the deciding question and probability. Keymaps follow the
agents buffer's grammar: `<CR>` opens the full record for a row in a split (the
whole question set, and the state sent when it was a deny), `o` opens that row's
session buffer, `d` filters to denies only, `R` refreshes, `x` clears the audit
for the session under the cursor.

**`fn.log`.** Every classification also emits
`{ ev = "classify", session, tool, cap, action, reason, ms }` through
straps' own logger, which appends JSON lines when `config.log_file` is set and is
a no-op otherwise (`provider.lua:2258-2262`). That is the machine-readable
history across restarts; the ring is the live view.

**`:checkhealth straps_classifier`.** Guard installed or frozen out, key
resolving, one live probe, and the session's verdict counts — allows, denies, and
failures by cause.

`config.on_verdict` still fires for anyone wiring their own sink, dispatched
through `vim.schedule` inside a `pcall` (A7).

### A10. Config

```lua
require("straps_classifier").setup({
  model = "jev-latest",
  timeout_ms = 8000,
  retry = 1,
  deny_threshold = 0.85,
  damage_deny = 2.5,
  opaque_action = "deny",
  always_deny_patterns = {
    "rm%s+%-rf%s+/", "%.ssh/id_", "%.aws/credentials",
    "^sudo%s", "%ssudo%s", "^doas%s", "%sdoas%s",
    "%-%-remote%-", "%-%-server%s", "%$NVIM%f[%W]", "NVIM_LISTEN_ADDRESS",
  },
  max_state_bytes = 4000,
  audit_limit = 500,
  on_verdict = nil,
})
```

The config is frozen at `setup()`; a later write to the config table changes
nothing the classifier does. Nothing configures its way around a veto, and there
is no off switch: turning the
classifier off means removing it from
`stdpath("config")/straps/init.lua` and restarting, because guards freeze.
Auditing has no off switch either — `audit_limit = 0` is refused, because a
classifier that blocks work without saying why is worse than no classifier.

## Part B — dropped

Part B would have added a per-block decision seam to straps' `fn.compact`, so
compaction could ask a model whether an old tool result is still needed instead
of stubbing every one.

It was built, then reverted, because it could not run. A compaction pass happens
only from `:StrapsCompact` or from auto-compaction, and auto-compaction is off
unless `config.auto_compact_tokens` or `auto_compact_bytes` is set
(`init.lua:81-82`, `loop.lua:375`) — which Matt does not set. `:StrapsCompact`
passes no `ctx`, so a policy that calls the network cannot await there either.
The seam would have sat dormant.

The standing position behind the drop: compaction is a conscious choice, not
something that fires on its own. Auto-compaction itself may be removed from
straps later; that is a separate change, not this one.

The straps working copy is back to its committed state — verified with `jj st`
(no changes) and `tests/run_compact.lua` (10/10 passing).
## Tests

Self-contained files run as `nvim --headless -l tests/run_X.lua`
(`AGENTS.md:48-58`). Each prepends this repo and `$STRAPS_ROOT` (default
`../straps`) to `rtp` and `package.path`.

| File | What it proves | Network |
| --- | --- | --- |
| `run_policy.lua` | every hazard threshold, the opaque signal denying or logging by `opaque_action`, `redefines_protected` skipped for edit tools, damage escalation with no confidence downgrade, a mismatched legend denying, missing answers denying, over-cap and path-resolution state building | none |
| `run_local_rules.lua` | deny patterns fire with no key and no `ctx`, against command-like fields only and never prose | none |
| `run_guard.lua` | with a scripted `fn.typesafe`: a child session classifies and blocks; a parent's loop call leaves enforcement to the confirm; a direct `registry.call` with no `ctx` is denied with `no ctx to await on`; a local rule denies with no request; an over-cap program input denies with no request; a repeated call is classified again | none |
| `run_confirm.lua` | a rejected call makes no request; an approved call is classified; a deny blocks with the question named; a silent `cap:` grant still reaches the classifier; a timeout blocks; a missing key blocks; the slot is empty after the confirm reads it | none |
| `run_audit.lua` | every classification lands in the ring, allow and deny alike; every verdict keeps the state and answers it was judged on, with the token cost; `answer_lines` sorts strongest first across noul/score/shapeless; the ring caps at `audit_limit` and drops oldest; a child's entries carry its parent bufnr and depth; `fn.classifier_audit_render` groups by session and survives a closed session buffer; `audit_limit = 0` is refused; `fn.log` receives one `ev = "classify"` per verdict | none |
| `run_live.lua` | the fixture matrix (40 cases) against Jev: every documented evasion denies on the intended question, every must-pass case (the plugin's own development included) stays clear, mean latency and token cost printed; skipped with a note when `TYPESAFE_API_KEY` is unset | live |

Straps is unmodified, so its own suite is unaffected; `tests/run_compact.lua`
was run after the Part B revert to confirm it (10/10 passing).

## What this costs

- **No key means no tools.** Every call in every session is denied until
  `TYPESAFE_API_KEY` resolves. `setup()` still installs when the key is missing and
  still denies; a plugin that disables itself on a missing credential is the
  fail-open behavior this design rejects.
- **TypeSafe down means work stops.** 429, 529 and network failure block after one
  retry.
- **Every tool call costs a round trip, reads included.** The parallel read batch
  gates each block in sequence (`loop.lua:488-506`), so a ten-read batch is ten
  sequential requests before any read starts. I have no latency figure for Jev;
  `run_live.lua` prints it, and that number may force a batching design.
- **A denied call the model retries pays again**, bounded near six attempts by the
  stall detector (`loop.lua:605-617`).
- **Text someone else wrote reaches the classifier.** Tool input is authored by the
  agent after it reads files and pages, so an injected instruction can address the
  judging model. The worst it buys is a blocked call, because the classifier has
  no path to approving one.

## Parked

- Coalescing a read batch into one request. The per-call guard signature cannot
  express it; needs a batch-aware entry point in straps.
- The `"user denied: "` prefix on a classifier veto.
- Compaction that reads tool output (Part B), until compaction is something Matt
  runs deliberately and a policy has somewhere to run.

## Review status

One fresh-context review ran against an earlier revision and returned ten findings
before its turn budget ended it. Six apply to the shipped work and are folded in:
the direct-call path (A7), verdict staleness (no cache at all, A6), silent install
failure (A7), `on_verdict` raising inside the fold (A7), the unpinned rating
legend and ignored confidence (A4, A5), and measuring latency before trusting the
read path (What this costs). Three concerned Part B and went with it. The tenth
asked for auto-approval to be dropped; it is gone for a different reason — the
classifier has no approve path at all.

A seventh finding surfaced during implementation rather than review: calling
`register()` twice re-captured the plugin's own confirm as its predecessor and
recursed until the stack blew. `entries.register()` is now idempotent, and
`run_guard.lua` covers it.

A second review runs against this revision before any code is written.
