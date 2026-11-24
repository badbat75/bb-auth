---
name: coder-playbook
description: How the coder implements and runs code in this project, and the pitfalls met so far. Use when changing production code.
---

Rules are in `AGENTS.md`. Format of this file: `AGENTS.md`, under "Skills".

## How to

- A library function that restates `decide` as a set must ask what `decide` asks, never a copy of
  its logic. For an identifier that means the helpers (`vetoes_identifier`, `excludes_identifier`,
  `uuid_of`); for a uuid (a key's owner, as `key_scopes_for` takes) it means the raw fields the
  `Subject::Key` arm asks (`denied_users`, `excluded_users`, `credentials.api_key`, `members`),
  because the identifier helpers resolve an email and a uuid resolves to nothing.
- Run `cargo fmt` before `cargo fmt --check`: rustfmt splits long method chains.
- The tester's uncommitted test is already in the tree. It may be **staged**, where plain `git diff` is
  empty and says nothing: read `git diff --cached` (and `git status --porcelain`, where `MM` means both).
- To see a page the way an operator does, drive the real binary through `e2e/lib/server.js`'s `boot()`
  (it builds, starts and kills its own server) with `require('<repo>/e2e/node_modules/playwright')` and
  `chromium.launch({ channel: 'msedge' })`: Playwright's own browsers are not installed on this host.
  Sample the screenshot with PIL (`Image.getpixel` down a column) before editing CSS; a band you cannot
  measure is a band you will "fix" by guessing.
- The estate's ground is a glow: `--bg-grad` is a `radial-gradient(1200px 600px at 50% -10%, …)` that
  reaches its outer stop at 60% of the ellipse, so it goes flat about 240px down. A page that reads as a
  lit band over a flat field wants a flat ground, and the one rule for that is
  `body:has(.selfserve){background:var(--bg)}` in `admin.css` (`:has` because the ground is painted on
  the body and the page's own element is the `main` inside it).
- To insert a large block at a known line, use the `shell` tool with a `python3` heredoc. Code Mode
  (`execute`) has no `fs` and no `shell` tool, so it cannot edit this repo at all.
- A check piped through `grep -c '^warning'` exits 1 when the count is 0, so read the number, not the
  exit code, when a command line ends in one.
- `PAGE_SECURITY_HEADERS` already carries `Cache-Control: no-store`, so a page that reveals a secret
  needs no cache header of its own. A bearer cannot survive a redirect, so a mint answers `200`
  directly; the console's reveal page is then a re-submittable `POST`, which is the only reason
  `mutate` special-cases a stale `rev` there ("the key already exists"). A page whose way back is a
  `GET` link needs none of that.
- `rotate_api_key` mints a **new** secret on every call, so a rotate is exactly one call: keep the
  `SealedKey` it returns, commit, then `reveal(&written)`. A "check it exists, then rotate" pair
  mints two secrets and shows the second. The ownership check comes free: `key_mut` resolves the
  row from the caller's uuid first, so a key filed under another person is simply not found, and
  the self-service page answers every miss with one sentence so it is not an id-enumeration oracle.

## Pitfalls

- `pkill -f PATTERN` also matches the shell running it, and killed that shell. Use the task's own stop
  control, or a pattern that cannot match itself.
- A shade seam on a page is not the palette's doing: the two dark arms of `theme.css` are token-for-token
  identical, and an operator token file that defines only `:root` is outranked by
  `:root[data-theme=light|dark]`, so it changes nothing on a themed page. Look at `--bg-grad` first.
- `X-Auth-Email` holds every email of a roster row joined by a space: split it before comparing.
- A blank screenshot proves nothing about a GUI. Check that it really shows the window.
- maud emits attributes in the order written, and the tests here string-match markup like
  `<section id="keys"`. Put the `id` first, and keep headings bare (`<h2>`, no class), when a test
  extracts them; scope the styling rule to a parent class instead of adding an attribute.
- A clippy warning can land in the tester's test module (its `map.get(x).is_none()` assertion trips
  `unnecessary_get_then_check`), where a task's edit limit forbids touching it. Clippy exits 0 on a
  warning, so report the line and leave the test alone.
- The GUI suites' socket tests carry a 5s global ureq deadline (`account_client`, `client`), every
  write in the process serializes on `WRITE_LOCK`, and `write_atomically` fsyncs, so the POST-heavy
  tests intermittently fail at `.expect("a POST response")` with a timeout when the machine is busy
  (a full `cargo test` compiling the other three targets). Re-run before believing it, and prove it
  with `--test-threads=1`: the fix is never to shorten the handler's lock.
