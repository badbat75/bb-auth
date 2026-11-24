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
- To check a `bb-auth-adm` recipe before documenting it, run it on a **scratch copy** under
  `/tmp/opencode` (`bb-auth-adm -f /tmp/opencode/…/access.json init`, then the recipe, then
  `can WHO URL` for the verdict the docs claim). Every write leaves an `access.json.bak` beside
  the file it wrote, so never point it at a tracked file such as `deploy/access.example.json`.
  `cargo build --bin bb-auth-adm` is instant when the tree is current.
- To check a startup rule before documenting an env var, **run the binary** on scratch files
  under `/tmp/opencode` and read its banner, which prints the value the process took
  (`workers=8`). `bb-auth-web` starts with a `{"version":1,…}` access file, a
  `{"version":3,"web":{"admins":[…]}}` settings file, `BB_AUTH_WEB_BASE_PATH=/admin` and a
  40-character `BB_AUTH_WEB_PROXY_SECRET`; run it with `timeout 3` and a spare
  `BB_AUTH_WEB_LISTEN=127.0.0.1:18091`. A unit test proves the parser; only the run proves the
  fatal path (exit 1, message naming the variable) and what the banner says.

## Pitfalls

- A source about something similar looks like a source, but is only a hint.
- A scope pattern must match its application's base **including the scheme**: `*://host/*` is
  refused as outside base `https://host`. So a documented catch-all is `https://host/*`, and a
  recipe that runs `scope add … --user X` needs `user add X` first, since a name not in the
  roster aborts that command.
- `npx markdownlint-cli2 "**/*.md" "#target" "#dist" "#e2e/node_modules"` is **not clean**: it
  reports ~22 pre-existing MD041 and MD032 errors in the `.agents/`, `.claude/` and `.opencode/`
  skill and agent files, because MD041 fires on their YAML frontmatter. Judge the run by whether
  your own files appear in the list, not by the exit code, and do not "fix" the frontmatter.
- The `N: ` prefix `read` prints makes an AGENTS.md bullet continuation look indented **three**
  spaces; it is **two**. An `edit` oldString copied from `read` fails to match. Check with
  `sed -n 'A,Bp' AGENTS.md | awk '{printf "[%s]\n", $0}'`.
- CHANGELOG.md has **no `## 1.99.8` heading** on purpose (an untagged candidate gets no section
  of its own): the `## Unreleased` section *is* 1.99.8, and its `###` sections run newest first,
  so a new entry goes directly above the first `###` after the "Nothing here changes the cookie
  format" paragraph.
- `docs/ARCHITECTURE.md` §13 is the architect's section: it is rewritten whole when the design
  moves, so a docs edit belongs in §2/§3 and in the stray counts outside it, not inside §13.
  Grep the line numbers before editing, since a §13 mention of an old name is the architect's
  record of the move, not rot.
