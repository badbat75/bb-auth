---
name: coder-playbook
description: How the coder implements and runs code in this project, and the pitfalls met so far. Use when changing production code.
---

Rules are in `AGENTS.md`. Format of this file: `AGENTS.md`, under "Skills".

## How to

- Run `cargo fmt` before `cargo fmt --check`: rustfmt splits long method chains.
- The tester's uncommitted test is already in the tree, so read `git diff` hunk by hunk to see your own change.

## Pitfalls

- `pkill -f PATTERN` also matches the shell running it, and killed that shell. Use the task's own stop
  control, or a pattern that cannot match itself.
- `X-Auth-Email` holds every email of a roster row joined by a space: split it before comparing.
- A blank screenshot proves nothing about a GUI. Check that it really shows the window.
