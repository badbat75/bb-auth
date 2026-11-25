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
- When that stub copy gets **built more than once** (a red stub, then a green one, then the e2e
  suite against it), rsync the tree **with** `target/` instead: the copy is a few GB and takes
  minutes, the first build is 2 s instead of 10, and `cp -a e2e/node_modules` there lets
  `node <runner> <area>` run against the stubbed binary. Discard the copy afterwards.
- Assert anything about a **response** (CSP, `X-Frame-Options`, status line) over a real socket.
  The in-process `post(&cfg, Route, fields)` helper calls `mutate` and builds the `shell` itself, so
  its `Got` carries **no headers at all**: it cannot see a `Content-Security-Policy`, and a test
  written against it passes for the wrong reason.
- To run **one** e2e area, copy `e2e/run.js`'s per-area reset into a script outside the repo that
  `require()`s `e2e/lib/server.js` by absolute path: `fs.copyFileSync(FIXTURE, ctx.accessFile)`,
  rewrite `ctx.settingsFile` from `SETTINGS_FIXTURE`, `fs.rmSync(ctx.auditFile)`, then
  `require('.../e2e/tests/<area>').run(ctx, new Checker(area, null))`. `run.js` itself runs all nine.
- A clipboard assertion is possible headless: `context.grantPermissions(['clipboard-read',
  'clipboard-write'], { origin: ctx.origin })` succeeds for the loopback origin on the `msedge`
  channel, so `navigator.clipboard.readText()` can be compared byte for byte. Wrap the grant in
  `try/catch` and emit a passing "not verifiable" check when it throws, so a browser that refuses
  the permission fails the *behaviour* (the button's word) and not the harness.
- `K` carries no `PartialEq`, so a refusal is asserted through a helper that maps the variant to a
  `&'static str` name (`dur_answer`). Couple the assertion itself to the **English translation
  string** when the test reads a rendered page: that is what the operator sees, and it is the repo's
  style. Keep a literal tolerant where a sentence is brittle (`starts_with("Copy refused")`).
- The e2e fixture is `deploy/access.example.json`: `you@example.com` is the roster row with **no**
  `api_keys` (so an `/account` walk starts from an empty list), and the only other key owner is
  `bot@example.com`, with `laptop` (365d, narrowed to `mcp/api`) and `ci` (never). "A key on
  somebody else's row" is `laptop`, and the answer must not name `bot@example.com`.
- Before changing a control the console and `/account` **share** (`duration_choice`, `.pill`,
  `page_confirm`), grep the e2e suite for it: `grep -rn "name=duration" e2e/` finds four areas
  (`crud`, `conflict`, `validation`, `shots`) that drive the console's key form. A `page.fill` on a
  control that became a `select` throws, and the runner records the whole area as failed.
- An e2e **walk aborts at the first missing control** (a locator timeout ends the whole area, and
  the runner records it as one failure), so a red walk shows only its first gap. To prove the
  assertions after that gap are satisfiable rather than typos, copy the area's string helpers into
  a scratch script outside the repo and feed them the markup the design describes: every predicate
  that comes out `ok` is one the code can satisfy, and one that never can is a typo in the test.
- Page-shape checks in `e2e/tests/account.js` parse `page.content()` with string helpers
  (`sectionOf`, `all`, `words`, `anchors`), because that area runs with scripting off. Anything
  that needs the **layout** (a bounding box) goes in `nojs.js`, which runs with scripting on.
- Measure a target's size where it is **visible**: the copy button carries `hidden` until the
  reveal's script unhides it, and a hidden element's box is 0×0, so a 24-by-24 check on the served
  bytes measures nothing.
- `e2e/shots.js` runs every scene of a view in **one** browser context, so a scene that swaps
  `X-Auth-Email` (a `/account` scene needs a roster row who is not an administrator) must put
  `admin@example.com` back before it ends, or the next scene renders the console as a 403.
- Use one fixture per test.
- Fill fixtures with real names and values captured from the real system.
- In `bb-auth-web`, test a request end to end over a real socket: copy
  `serving_enforces_the_identity_header_and_the_admin_allowlist` (`scratch` with a unique name,
  `cfg_for`, `client()`, `IDENTITY_HEADER`, `cleanup`). The fixture's administrator is `admin@x.com`.
- A **concurrency** test in `bb-auth-web` needs its own server: the shared `serve` helper answers
  requests one at a time from one thread, and `account_post` holds `WRITE_PERMIT` across the request,
  so a pair of writers through those helpers is serialized by the harness and proves nothing. Bind a
  `Server`, wrap it in `Arc`, spawn N threads running `server.recv()` in a loop (the shape of `main`),
  post from N threads released by a `std::sync::Barrier`, and skip the permit.
  `account_two_concurrent_mints_against_one_rev_give_one_success_and_one_409` is that test.
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
- A **name contains the visible word** check (WCAG 2.5.3) reads the whole anchor: `visible_text` of
  `anchors_to(&keys, "/account/keys/rotate?id=")` is the word on the control, and the name is
  `attr(&a, "aria-label")` for a word control, falling back to `visible_text` of the first
  `elements(&a, "<span class=\"vh\"", "</span>")` for an icon one. Walk both `Lang::En` and
  `Lang::It` (`account_call_pref(.., Some("lang=it"), None)`, pinned by
  `account_html_tag(&g.body).contains(r#"lang="it""#)`): the pair that breaks is the one where the
  visible word and the label are **different keys** (`K::Rotate` "rigenera" vs `K::AccountKeyRotate`
  "Ruota la chiave"), and English passes, so a one-language test of this rule proves nothing.
- A fixture key with `duration: "never"` is the right probe for "rotate leaves the window alone":
  the self-service page refuses to *mint* `never`, so a rotate that rewrote the window cannot hide
  behind a value the page would never have written.
- The `bb-auth-web` write tests are **latency-bound by the disk, not by the code**: a mutation
  `POST` is answered only after `mutate` takes the process-wide `WRITE_LOCK` and
  `write_atomically` fsyncs the temp file and the directory, so one request's latency is one
  fsync (measured 0.1-4.2 s on a disk busy with another project's builds). The harness therefore
  serializes its own writers (`WRITE_PERMIT`, a `Mutex<()>` held across the request) and
  `ACCOUNT_DEADLINE_SECS` (60) is a **deadlock detector, not a latency budget**: never lower it to
  "fail fast", and never read a `Timeout(Global)` in this target as a hang before timing the disk
  (a 4 KB `write+fsync+rename+dir-fsync` in `tempfile.gettempdir()`). A suite wall time of 100 s
  at load 6 is the same floor, 39 writes x fsync, serialized by `WRITE_LOCK` with or without the
  permit; it is not a regression.
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
- When a field is added to `Config`, the whole `bb-auth-web` test target is red with E0063 from
  **one** place: `cfg_for` is the only `Config` literal in the test module (the other is production
  `from_env`). Fill it with the field's startup default (`DEFAULT_WORKERS`), not a test-specific
  value: a test that needs a different count builds its own server (`account_serve_with_workers`).

## Pitfalls

- `links_to` returns the **opening tag only**, so `visible_text` of it is always `""` and `elements(x,
  "<svg", "</svg>")` of it finds nothing: a test that reads a control's **name** from it passes on an
  unnamed icon. Use `anchors_to` (whole `<a …>…</a>`) for anything about what is *inside* a link, and
  keep `links_to` for an attribute.
- A "this refusal names nothing" check must run on `account_readable(&g.body)`, never on `g.body`:
  every page carries the inline stylesheets, and their comments say `phone` (the stacking rules) and
  `ci` (inside "decide" and "specificity"), so the bytes fail a page that names nothing.
- The document emits `href` and `action` as **paths** (`/account/keys/rotate?id=x`); the harness's
  `base` is `http://127.0.0.1:<port>/account/` and its port is the harness's, not the page's. Compare
  against `{ACCOUNT_PATH}/…`, never `{base}…`.
- `account_access_keys()` hands back the **expanded** document, so a later `.replace()` written
  against the `__BOB__` token is a silent no-op and the mutated case tests the file it started from.
  Write the pattern against `ACCOUNT_BOB`, and assert the fixture actually changed. When it does,
  assert the **specific** pattern is gone: the fixture names bob in three places, so "no longer
  contains bob" fails on a fixture that dropped exactly the one scope intended.
- A key's expiry cell answers *when*, so it carries `format_date(key_expiry(…))` plus a days-left
  figure, never the stored `duration`: an assertion on `365d` is a test that passes on one day a
  year, and within 30 days the cell switches to the `expires soon` arm. Assert the date and that the
  figure is digits.
- The duration is one `select[name=duration]` plus a `days` box on **both** surfaces (§13.16), so
  every e2e drive of it goes through `setDuration(page, value, scope)` in `e2e/lib/harness.js`.
  A `page.fill('input[name=duration]', …)` on a `select` throws after 30 s and the runner records
  the whole area as one failure, which hides the twenty checks behind it.

- A test polling a stub in another thread hung forever.
- The console's mint (`Route::KeyAdd`) refuses **only an empty `id`**: `0d`, `never` and a long
  window all mint a key, because the duration is the library's to judge. So a "bad field" probe
  aimed at the console writes a key, and the page's `rev` is stale for the next request, which
  answers `409` instead of the `400` under test. The account page is the strict one, and after
  §13.15 its refusals are an **empty `duration`** (`KeyDurationRequired`), `days` typed beside a
  preset (`KeyDaysWithoutCustom`), a custom box that is not a positive number, a bad `id`, a
  sub-day window: **`never` is no longer one of them**, it is a choice the page offers and mints
  (`a_self_service_key_may_never_expire` pins `200`).
- A "the icon control has no text" assertion is a claim about the **naming mechanism**, not about
  the icon: §13.17 names every `.pill.ico` with `span.vh` text **inside** the control, so an
  empty-`visible_text` check on the copy button is red on a correct control, and the green
  `the_copy_control_is_an_icon_with_a_name` pins that same text as `"Copy the key"`. Assert the
  control's words are absent from the block **outside** it (`body.replace(&element_containing(…),
  "")`), which is the property the old `aria-label` shape was really testing.
- A `400` writes nothing, so the `rev` on the page a `400` rendered is still current. A `409` test
  therefore needs a **real write first**: mint (200), then replay the same fields with the same
  `rev`. Replaying after a `400` is a second `400`, and the test passes for the wrong reason.
- A page scan for `on…=` attributes must strip `<script>` bodies **first**: a script's own source
  contains `on…` sequences (`addEventListener`, string literals), so the handler allowlist fails on
  a page that carries no handler attribute at all.
- The mutation journal (`audit()`, `[bb-auth-web] <who>: <verb> <target>`) is `eprintln!` on the
  server's stderr, so no over-the-socket test can read it: a PLAN requirement that says "journal
  `<uuid> (self): key rotate <id>`" is not assertable from this suite, and has to be stated as the
  untested half rather than quietly dropped.
- An id taken from one temporary fixture does not match another, and the test fails with the wrong error.
- A fake holds whatever you write, while the real system can answer differently. A test passing on a
  fake proves nothing about the real thing.
- Renaming a test prefix with `sed` silently eats the palette: `ME_` is inside `THEME_` and `me_` is
  inside `THEME_CSS`, `scheme`, `machine`. Use `\b` on both sides and re-grep for the old prefix after.
- The account page's mint and rotate answer the reveal page with a **`200`** (not a `303` PRG), so
  `page.reload()` on them **re-POSTs** and mints a second key. The reveal-once walk a person does is
  `page.goBack()` to the page, then `page.reload()` on *that*.
- In a `javaScriptEnabled: false` context every harness helper built on `page.evaluate`
  (`resubmit`, `formBytes`) throws. Read a hidden field with `locator('input[name=rev]').inputValue()`
  and navigate with `goBack()`/`reload()`.
- The account page's `#keys` section carries **two** `h2` (the section's "API keys" and the mint
  form's "Add a key"), so `locator('#keys').locator('h2')` is a Playwright strict-mode violation.
  Add `.first()`, and name the heading you mean.
- `key_expiry` answers an **absolute instant**, so "a year and a day is a year plus a day" is
  `Some(year + 86_400)`: adding `key_expiry(released, "1d")` to a 365d expiry adds the epoch
  seconds a one-day key expires at, and the expected value lands in 2084.
- A shared form assertion must know **which form** it is reading. §13.15's "no form preselects
  `never`" is a mint-form rule: an edit form of a key stored `never`, `0` or `-` marks `never`
  selected (§13.16), so a helper that asserts it unconditionally goes red on a correct edit form.
  Pass a `mint: bool` and gate the rule on it.
- `page.goto` refuses a root-relative href: every `href` and `action` these pages emit is a path
  (`/account/keys/new`), and the failure is `Cannot navigate to invalid URL`, which names neither
  the link nor the origin. Resolve it against the document that carried it:
  `new URL(href, page.url()).href`.
- A local `const words = []` inside `run` shadows the module's `words(s)` helper for the **whole**
  function body, so the call site 100 lines later dies as `words is not a function`. Name the
  local for what it holds (`labels`).
- The console's add control is `p.primary` **holding** `a.pill` (§13.16), so `primary` is the
  paragraph's class: an assertion that the `+ New key` **link** carries `primary` is red on the
  markup the design specifies, and `the_new_key_row_is_a_page_of_its_own` pins `class="pill"`.
- The console's table cells carry `data-label` (the phone stacking label) **beside** `class`, so a
  regex demanding `<td class="mono">` asserts the attribute order and is red on a correct cell.
  Read the class list.
- The reveal's copy icon is **two** glyphs (`.i-copy`, `.i-done`) that swap on `data-state`
  (§13.17), so `locator('#bearer-copy').locator('svg')` is a strict-mode violation. Address a
  glyph by class, or assert both, as the Rust suite does (`for glyph in ["i-copy", "i-done"]`).
- The same stylesheet trap as the Rust `account_readable` one, on the browser side: a "this refusal
  names nobody" check on `response.text()` fails on `ci`, because every page inlines the three
  stylesheets and their comments say `decide`, `specificity`, `opacity`. Strip the `<style>` and
  `<script>` bodies, then the tags.
- `rules_named(css, sel)` (lib.rs) matches **one** comma-part of a selector list, so passing a whole
  list (`"a,b"`) finds nothing: look each part up on its own. `the_rule` (bb-auth-web) swallows the
  first rule inside an `@media` block and returns the first match in file order, so a phone-block
  rule needs its own reader (`phone_rules`).
