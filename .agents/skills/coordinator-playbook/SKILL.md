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
  out as" line of `CHANGELOG.md`. Check the CHANGELOG lead for the last deployed number first.
- Ask the user for real runs one at a time, with the exact command and the expected result.

### Who runs each role

The user chooses at every cold start (see the coordinator role): local subagents or Claude Code ones.

- Local: delegate tester, coder and docs work to the local model through OpenCode, as below; keep
  designer and architect as Claude subagents.
- Claude Code: every role runs as a Claude subagent, and the OpenCode command below is not used.

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
