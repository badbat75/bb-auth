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
- The version is the last released one plus one (W11). Bump it once, right after a release, never per
  commit: the patch in `Cargo.toml`, then `cargo check` to carry it into `Cargo.lock`, then the "Due
  out as" line of `CHANGELOG.md`. Find the last deployed number on the host (`bb-auth --version`, `/var/log/dpkg.log`), not only in
  the CHANGELOG lead, which can lag behind a deploy.
- Ask the user for real runs one at a time, with the exact command and the expected result.

### Who runs each role

The user chooses at every cold start (see the coordinator role): local subagents or Claude Code ones.

- Local: delegate tester, coder and docs work to the local model through OpenCode, as below; keep
  designer and architect as Claude subagents.
- Claude Code: every role runs as a Claude subagent, and the OpenCode command below is not used.

The designer exists since 2026-11-24 (user's request); brief it before tester for any slice that
changes what a person sees or does, with `subagent_type: "designer"`, and have it review the
screenshots of the result before the slice closes. A role added mid-session is not an agent type
until the session restarts: until then run it as `general-purpose` with "read and follow
.opencode/agents/designer.md" at the top of the brief.

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
