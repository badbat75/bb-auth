---
name: coder-playbook
description: How the coder implements and runs code in this project, and the pitfalls met so far. Use when changing production code.
---

Rules are in `AGENTS.md`. Format of this file: `AGENTS.md`, under "Skills".

## How to

- A library function that restates `decide` as a set must call the helpers `decide` calls
  (`vetoes_identifier`, `excludes_identifier`, `uuid_of`), never a copy of their logic.
- Run `cargo fmt` before `cargo fmt --check`: rustfmt splits long method chains.
- The tester's uncommitted test is already in the tree, so read `git diff` hunk by hunk to see your own change.
- To insert a large block at a known line, use the `shell` tool with a `python3` heredoc. Code Mode
  (`execute`) has no `fs` and no `shell` tool, so it cannot edit this repo at all.
- A check piped through `grep -c '^warning'` exits 1 when the count is 0, so read the number, not the
  exit code, when a command line ends in one.

## Pitfalls

- `pkill -f PATTERN` also matches the shell running it, and killed that shell. Use the task's own stop
  control, or a pattern that cannot match itself.
- `X-Auth-Email` holds every email of a roster row joined by a space: split it before comparing.
- A blank screenshot proves nothing about a GUI. Check that it really shows the window.
- maud emits attributes in the order written, and the tests here string-match markup like
  `<section id="keys"`. Put the `id` first, and keep headings bare (`<h2>`, no class), when a test
  extracts them; scope the styling rule to a parent class instead of adding an attribute.
