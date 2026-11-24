---
name: docs-playbook
description: How the docs agent keeps the project docs accurate, and the pitfalls met so far. Use when editing README, AGENTS.md or docs/.
---

Rules are in `AGENTS.md`. Format of this file: `AGENTS.md`, under "Skills".

## How to

- For each fact, say whether it was measured here, read in a source, or reported by the user.
- When a measurement proves a note wrong, replace the note. Do not leave both.
- When a target is added, moved or deleted, grep for the **counts**, not only for the name:
  `grep -n "five targets\|four programs\|all three\|three programs\|three HTML" AGENTS.md
  README.md docs/ARCHITECTURE.md`. How many programs emit HTML, read the settings file, answer
  `--version`, and link the library are stated as numbers in prose in a dozen places, including
  the check table under "Commands", and none of them is pinned by a test.
- A prose count of code (`about 7,000 lines`, `nine that drive real HTTP`) is a measurement with
  no source in the file. Re-measure it (`wc -l`, the `cargo test` summary) before repeating it,
  and when the thing it counts moved between targets, drop the number rather than invent one.

## Pitfalls

- A source about something similar looks like a source, but is only a hint.
- `npx markdownlint-cli2 "**/*.md" "#target" "#dist" "#e2e/node_modules"` is **not clean**: it
  reports ~22 pre-existing MD041 and MD032 errors in the `.agents/`, `.claude/` and `.opencode/`
  skill and agent files, because MD041 fires on their YAML frontmatter. Judge the run by whether
  your own files appear in the list, not by the exit code, and do not "fix" the frontmatter.
- `docs/ARCHITECTURE.md` §13 is the architect's section: it is rewritten whole when the design
  moves, so a docs edit belongs in §2/§3 and in the stray counts outside it, not inside §13.
  Grep the line numbers before editing, since a §13 mention of an old name is the architect's
  record of the move, not rot.
