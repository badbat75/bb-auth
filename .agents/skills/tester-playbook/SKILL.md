---
name: tester-playbook
description: How the tester writes reliable tests in this project, and the pitfalls met so far. Use when writing or debugging tests.
---

Rules are in `AGENTS.md`. Format of this file: `AGENTS.md`, under "Skills".

## How to

- Give every wait a deadline, so a test fails instead of hanging.
- Check why each new test is red, and why any is already green. Tests that pass before the code exists
  (a check that something is absent or unchanged, or a validation of a field not there yet): list them
  and run them again once the code exists.
- Use one fixture per test.
- Fill fixtures with real names and values captured from the real system.
- In `bb-auth-web`, test a request end to end over a real socket: copy
  `serving_enforces_the_identity_header_and_the_admin_allowlist` (`scratch` with a unique name,
  `cfg_for`, `client()`, `IDENTITY_HEADER`, `cleanup`). The fixture's administrator is `admin@x.com`.
- Whole board: save each command's output to a file and give each one a `timeout`. On a Linux host
  the cfg(unix) tests run inside plain `cargo test`, with no WSL. `node e2e/run.js` builds and starts its
  own server and uses the system `microsoft-edge`; its `TOTAL` line is the verdict. For `cargo doc`,
  count the `^warning` lines.
- To show that an assertion after a red one already passes, move it ahead for one run, then
  restore the order: nothing after the first panic runs.

## Pitfalls

- A test polling a stub in another thread hung forever.
- An id taken from one temporary fixture does not match another, and the test fails with the wrong error.
- A fake holds whatever you write, while the real system can answer differently. A test passing on a
  fake proves nothing about the real thing.
