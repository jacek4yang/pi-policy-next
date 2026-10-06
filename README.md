# pi-policy-next

Deterministic authorization policy for the [Pi](https://github.com/earendil-works/pi)
coding agent — the first Agent Body v2 productization plugin.

Policy classifies actions, protects resources, normalizes approval intents,
and **gates side effects before they execute**. Resource owners (filesystem,
git, GitHub, CI, runtime) execute only after a valid decision:

```
ALLOW              proceed silently
DENY               never allowed under current trust configuration
REQUIRE_APPROVAL   park the turn on a blocking dialog; resume on decision
```

## Enforcement model

- **`tool_call` gate** — every model-issued tool call passes through Pi's
  awaited `tool_call` event BEFORE execution. Policy-sensitive actions are
  blocked with `{ block: true, reason }` unless allowed or approved. If the
  extension handler fails, Pi itself blocks the call (fail-safe).
- **`user_bash` gate** — direct `!`-shell commands: destructive or
  unclassifiable commands get a confirm dialog; denial is by full
  replacement, so the command never executes.
- **Project trust integration** — policy consumes `ctx.isProjectTrusted()`.
  Trusted projects reduce friction for normal workspace edits and
  execution; trust NEVER lifts high-impact gates (recursive delete,
  destructive git, credentials, system changes).

## What policy owns

Action classification · authorization policy · protected resources ·
approval intent normalization · approval lifecycle · decisions · structured
events. It does NOT own filesystem/git/GitHub/CI/task execution, UI
semantics, session recovery, or credentials.

## Cacheability discipline

Policy state lives **outside** model context. Decisions are emitted as
`pinx.policy.request` / `pinx.policy.decision` EventBus events (UI/audit
only). The model sees a policy result only when a call is actually blocked
(a normal tool error, semantically necessary). Routine ALLOWs inject
nothing. Policy registers **zero tools** — no schema cost, no loadout churn.

## Default policy (balanced profile)

| Auto-allow                                  | Approval                                                                  | Deny (never allowed)            |
| ------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------- |
| reads, search, stat/list                    | recursive deletes                                                         | mutation of sealed resources    |
| safe git inspection (`status/log/diff/...`) | single deletes                                                            | deletion of home/workspace root |
| edits in a **trusted** workspace            | destructive git (`reset --hard`, `clean -fdx`, force push, branch delete) | credential changes              |
| execution in a **trusted** workspace        | edits outside the workspace / untrusted                                   |                                 |
| GitHub/CI **reads**                         | GitHub/CI writes, CI control, system changes                              |                                 |
|                                             | unknown/unclassifiable actions (fail toward approval)                     |                                 |

Sealed (always denied) by default: the Pi agent dir, `~/.ssh`, `~/.aws`,
`~/.gnupg`, plus operator-declared paths. Home and workspace are
**boundaries**: deleting their root is denied; their contents are normal
approval-gated work.

## Approval identity (material-action digest)

Approvals authorize the **exact material action**. A canonical intent
(action class, op, sorted canonical paths, recursive flag, git/GitHub/CI
ref, exact command, impact) is hashed with SHA-256. No timestamps, no UI
text, no request ids — identical actions share one digest; any material
change (path, recursive flag, PR head, merge method, repo) produces a new
digest and needs a fresh decision.

## Approval scopes

- **once** — exactly this execution; nothing recorded.
- **exact-action** — this digest for the session.
- **session-class** — all actions of one class this session; offered only
  as an explicit choice.

Denials and cancellations are never stored or interpreted as allow. There
is no persistent grant store: the ledger is bounded (128 entries),
in-memory, session-scoped; the event stream is the audit trail.

## Configuration (PINX namespace)

| Variable                | Meaning                                                                                                                                                                      |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PINX_POLICY_PROFILE`   | `safe` (approvals for edits+exec) / `balanced` (default) / `autonomous` (adds non-recursive in-workspace delete auto-allow — destructive git/credentials/system still gated) |
| `PINX_POLICY_PROTECTED` | Extra sealed paths, split on the platform path delimiter                                                                                                                     |
| `PINX_POLICY_DISABLE`   | `1` disables enforcement entirely — **no protection is claimed while set**                                                                                                   |

## Raw-shell detection honesty

Shell classification is conservative pattern detection, **not** a parser:
no variable expansion, alias resolution, or process-substitution analysis.
Nested shells (`bash -c`, `sh -c`, `cmd /c`, `powershell -Command`) are
unwrapped to a bounded depth; uncertainty escalates to approval. Cases
analyzed include `rm -rf`, `Remove-Item -Recurse`, `rd /s /q`, `git reset
--hard`, `git clean -fdx`, `git push --force`, `sudo`/`runas`, `chmod -R`,
service/system tools — with case variation, quoting, and mixed separators.

## Development

```bash
npm ci
npm run ci     # check:pi + typecheck + lint + format + test
npm test       # node:test via tsx
npm run bench  # policy latency overhead
```

Windows and Linux are both first-class; path semantics are platform-INJECTED,
so Windows behavior is tested on Linux CI and vice versa. Pi compatibility is
pinned exactly (`check:pi`) — see the meta repository
`docs/PI-COMPATIBILITY.md`.

## Invariants

Executable invariants (test-tagged, conformance-mapped in the meta repo):
**P1** no policy-sensitive side effect before a valid decision · **P2**
material identity change invalidates approval · **P3** expiry/denial never
become allow · **P4** unknown high-impact fails toward approval, never
silent allow · **P5** approval state never exposes protected secrets.
