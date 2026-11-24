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
- A new library API makes the **whole lib test target** fail to compile, so no test can run and nothing
  else in the file is checked. Verify the parts that do not need the API from outside the test target:
  a new access-file fixture with `cargo run --bin bb-auth -- --check-access <file>`, and the expected
  `decide` answers with `cargo run --bin bb-auth-adm -- -f <file> can WHO URL --as api_key` (exit 0 =
  granted, and the verdict line names the scope that answered, which is how a probe table gets checked).
- To type-check tests for a missing API without touching production code: `rsync -a --exclude target
  --exclude .git` the tree to `/tmp/opencode/<name>`, add the stub **there**, run `cargo test --lib`
  there, then mutate the stub (drop a filter, sort the result) and confirm the new tests go red. A
  mutation that leaves them green is a test that asserts nothing.
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
- The e2e harness (`e2e/lib/server.js`) starts the GUI at `BB_AUTH_WEB_BASE_PATH=/admin` and leaves
  `BB_AUTH_WEB_ACCOUNT_PATH` at its `/account` default, so the two prefixes are siblings and
  `compile_account_path` accepts the suite as it stands. Its administrator is `admin@example.com`
  (the Rust fixture's is `admin@x.com`); a roster row that is **not** an administrator is
  `you@example.com`, which is the identity for the `/account` page.
- For the `/account` page's **empty states**, `account_scratch(name, ACCOUNT_SETTINGS)` is the
  fixture: bob has a roster row, no `api_keys`, and those settings name no `profile_claims`, so
  `keys` and `profile` both render their "none" line. `account_section(body, "keys")` cuts one
  section out, so a wording assertion cannot be satisfied by a neighbour section's word.
- To assert on **one** form among several in a section (the keys section carries a mint, a
  rotate and a remove per key), cut the `<form …>…</form>` blocks out (`account_forms`) and pick
  the one whose `action` and hidden `id` match (`account_form_for`), so an assertion about key A's
  rotate cannot be satisfied by key B's remove.
- A fixture key with `duration: "never"` is the right probe for "rotate leaves the window alone":
  the self-service page refuses to *mint* `never`, so a rotate that rewrote the window cannot hide
  behind a value the page would never have written.
- The `bb-auth-web` socket suite is **flaky under full-target parallelism**: every account test
  starts its own server and the client has a 5s global timeout, so a full `cargo test --bin
  bb-auth-web` can show `Timeout(Global)` on tests that pass alone. Run
  `cargo test --bin bb-auth-web -- --test-threads=1` before blaming an edit for a failure, and
  report a parallel-only failure as flakiness, not as a regression.
- `/account` dispatches a fixed allowlist of paths (the prefix, the page, `<prefix>/keys`), so a
  new mutation path is a `404` for every caller until the code lands. The console answers a
  mutation refusal (unknown id, not your row) with the `400` refusal page and has no `404` for a
  `POST`, so the account side's "not your key" is a `400` too.
- A scratch screenshot script can live outside the repo and `require()` `e2e/lib/server.js` by
  absolute path: `boot()` then gives the same server the suite starts, proxy secret included, with
  the working tree untouched.
- Over the account socket helpers: `account_serve(&path)` **starts** the server and returns its
  page URL, so derive every other URL under the prefix from that string (`format!("{base}keys")`).
  Calling `account_port` again on the same path starts a **second** server on a second port.
  ureq 3's `send_form` takes an `IntoIterator` of tuples, so a `&[(&str, &str)]` field list needs
  `.iter().copied()`.

## Pitfalls

- A test polling a stub in another thread hung forever.
- The mutation journal (`audit()`, `[bb-auth-web] <who>: <verb> <target>`) is `eprintln!` on the
  server's stderr, so no over-the-socket test can read it: a PLAN requirement that says "journal
  `<uuid> (self): key rotate <id>`" is not assertable from this suite, and has to be stated as the
  untested half rather than quietly dropped.
- An id taken from one temporary fixture does not match another, and the test fails with the wrong error.
- A fake holds whatever you write, while the real system can answer differently. A test passing on a
  fake proves nothing about the real thing.
- Renaming a test prefix with `sed` silently eats the palette: `ME_` is inside `THEME_` and `me_` is
  inside `THEME_CSS`, `scheme`, `machine`. Use `\b` on both sides and re-grep for the old prefix after.
