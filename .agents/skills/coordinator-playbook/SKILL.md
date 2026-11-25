---
name: coordinator-playbook
description: How the coordinator plans, delegates and closes steps in this project, and the pitfalls met so far. Use when picking a step, briefing an agent or closing a step.
---

Rules are in `AGENTS.md` and `PLAN.md`. Format of this file: `AGENTS.md`, under "Skills".

## How to

- Check results by running them. For a background command, read the output: its exit code can come
  from its last, unrelated line.
- Before a real run, say what result you expect. When the result differs, say so plainly and find out
  why: an unexpected result is often the most useful finding of the run.
- Do not ask the user whether to go on to the next step or slice: go on, and ask only what the rules
  require (ambiguity, real effects, a requirement change).
- The version changes only at a release (W11): never bump it for a deploy. Two deploys differ
  by the build string (`v<version>-g<commit>`). At a release: tag the tested commit, push main
  and the tag, `gh release create` (with `--prerelease` for a 1.99.x) with the CHANGELOG section
  and the three .debs, install, then bump `Cargo.toml` and `cargo update -p bb-auth --offline`.
- Ask the user for real runs one at a time, with the exact command and the expected result.

### Who runs each role

The user chooses at every cold start (see the coordinator role): local subagents or Claude Code ones.

- Local: delegate tester, coder and docs work to the local model through OpenCode, as below; keep
  designer and architect as Claude subagents. The tester is local too: the user said so again on 2026-11-25
  ("usa l'agente locale, non sonnet"), after a run of Claude Sonnet testers.
- Claude Code: every role runs as a Claude subagent, and the OpenCode command below is not used.

The designer exists since 2026-11-24 (user's request); brief it before tester for any slice that
changes what a person sees or does, with `subagent_type: "designer"`, and have it review the
screenshots of the result before the slice closes. A role added mid-session is not an agent type
until the session restarts: until then run it as `general-purpose` with "read and follow
.opencode/agents/designer.md" at the top of the brief.

If a local coder run fails again on a slice already split, hand that part to a Claude `coder`
subagent with `model: "sonnet"` (the user's decision, 2026-11-24).

Every Claude Code subagent runs on Opus, whatever its role: pass
`model: "opus"` on each Agent tool call (for example `subagent_type: "architect"`, `model: "opus"`).
The coordinator itself is not bound to Opus: it runs on whatever model the session uses. The role
files carry no model, to stay readable by both harnesses.

Command, from the repo root (flags checked against `opencode run --help` on OpenCode 2.4.0; the roles
are the files in `.opencode/agents/`):

    opencode run --agent <tester|coder|docs> -m llama.cpp/Swift-Qwen3.8-Flash-Next \
      --auto --archived --title <task-name> "$(cat <prompt-file>)" > <task-name>.out 2>&1

Run it as a background command and read `<task-name>.out` when it ends. Keep the prompt and `.out`
files outside the repo.

1. `--auto` approves every tool permission, so the brief is the only limit. Start each brief with
   the hard limits: which files it may edit, "nothing in .agents/, put how-tos and pitfalls in the report",
   "do NOT commit". Testers put mutants in a scratch copy, never in the repo. Add what they report
   to the role's skill yourself.
2. The brief is all the context the agent gets: the goal, the exact files and line numbers,
   the spec lines to read, what is out of scope, the commands to run.
3. Ask for a final block whose first line is exactly REPORT, with a line limit, holding quoted
   output (the "Tests" line, the lint and format results), not a summary.
4. Do not trust the report alone. After every run check `git status --short` for writes outside
   the allowed paths and read the diff. The coder's first run wrote to a playbook against its
   brief; reverse only that hunk if it happens.
5. One small slice per run; a tester run and a coder run never edit at the same time.
6. If the local model cannot do a task, tell the user; do not fall back to Claude silently.
7. Repository content goes to the endpoint set in `~/.config/opencode/opencode.json`.

## Pitfalls

- A run that dies mid-task (an OpenCode update closed one) may have finished its edits: check the
  log, the tree and the tests before rerunning, and never take its missing REPORT as a failure of the work.

- Agents defined in a new `.claude/agents` directory appear only after a new session starts. If an agent
  type is missing, start one before doing its work yourself.
- OpenCode's first answer after a file changes can be stale: `opencode debug agents` gave `[]`, and
  `debug config` missed a new file. Query again before believing it.
- Headless Edge never finishes a `--screenshot` while a page waits on a host it cannot reach (an
  unreachable `ui.logo_url` hung it for good). Check the `<img>` with curl, and take the screenshot
  with that setting removed and under `timeout`.
- A local coder that starts its own server can end with exit 144 once its work is done. Check the tree
  and the tests before rerunning it, and tell it in the brief not to start servers or call `pkill`.
- Reach the test host as `rpi-01.bombicci.local`: its key is known under that name, and the bare
  `rpi-01` fails host key verification.
- aorus also runs the user's llama.cpp-framework work (its builds and its own opencode agents), and
  the local model serves both. Run one local agent at a time, no parallel cargo or e2e beside it,
  and never touch that project's processes.
- A local agent that exits 1 with no report may be the model server, not the agent: grep its
  output for `out of memory` (strata, the engine behind the local model, out of GPU memory when
  llama.cpp-framework work loads the cards) before rerunning the same brief.
- On rpi-01, root cannot overwrite a file a normal user created in /tmp (fs.protected_regular),
  so a `sudo` step must write its output to a root-owned `mktemp`, never to a path a dry run
  already created as you.
- A slice that touches more than a few functions overruns the local model's context: s8a ran 2h40
  with 19 compactions and left 8 compile errors. Split a coder brief so one part fits one context
  (add every K key the tests name in part 1, so the test module compiles and later parts go red one
  test at a time), and check `opencode session export <id>` for `compaction` entries when a run drags.
- Killing an `opencode run` client does NOT stop its session: it runs inside the shared
  `opencode serve --service` and keeps editing the tree (s8a-coder went on for 3 hours after its
  client was killed, and clobbered another agent's work). Check `opencode session export <id>`
  (`info.time.updated`) after stopping one. The HTTP routes need auth; stopping the service stops
  every project's agents, so ask the user and tell the llama.cpp-framework coordinator. **Never pass `--standalone`** (the
  user's rule, 2026-11-25): its private server writes the same `~/.local/share/opencode/opencode.db` as
  the service, the two collide (`database is locked`), and a run dies with "Failed to execute
  statement" (s8h-coder did). So a stopped client leaves its session running: stop one only by
  asking the user, and check the tree before relaunching. Server logs are in
  `~/.local/share/opencode/log/opencode.log`.
- To see or stop a run on the service (verified by IT-Admin on 2.4.1): `opencode api session.active`, then
  `opencode api session.get --param sessionID=<id>` (title, last update), then `opencode api
  session.interrupt --param sessionID=<id> --param resume=false`. A crashed run can leave a ghost
  that the service lists as `running`: interrupt ours by title, never another project's.
- cargo can keep a stale test binary after an agent's edit (a tester saw 191 green while the repo
  build kept failing on the old assertion). When an agent's green run and yours disagree on
  unchanged files, `touch` the edited source and rerun before sending the work back.
- Never `git commit -a` (or `-am`) while an agent may be editing: on 2026-11-25 a plan-only commit
  swept a running tester's half-written tests in with it. Name the files: `git commit PATH...`.
