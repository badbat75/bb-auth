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
- When the slice adds a **field to a struct the test module constructs** (`UserIdentity`), the repo's
  red is a compile error (E0560/E0609) and no test runs, so the assertions are unproven. In the stub
  copy apply a **red stub** first: the field exists, every construction site fills `None`, nothing
  reads it. The target compiles, so the new tests fail on their own assertions, and the same script
  then swaps in the green stub and each mutant. Keep the stub in a script that restores the repo's
  test sources first, so the repo's file is the only copy of the tests.
- `cargo test` stops at the first failing target, so a red lib target hides the gate's results:
  add `--no-fail-fast` when more than one target carries new tests.
- A fixture that must **verify** (a signed RS256 `id_token`) is generated with node `crypto` and
  checked with `crypto.verify` against the fixture JWK, printing the decoded payload, before the test
  is trusted: a bad signature is red as "token invalid", which reads exactly like the feature missing.
- To test what the **verifier** does with bytes the writer would never emit (a claims segment
  carrying a value `make_session` refuses to write), sign the cookie by hand:
  `format!("{COOKIE_VERSION}.{kid}.{exp}.{b64(email)}.{b64(claims)}.{sign(keys.active(), msg)}")`.
  Minting it through the API under test over-constrains the design, because it asserts the writer
  cannot produce the input.
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
- When the design (`docs/ARCHITECTURE.md`) carries a **`K` table** of new wording, spell its EN and IT
  strings **verbatim** in the test's local consts (the test module may not add `K` variants). A
  paraphrased const is red after the coder lands the table, and reads like a broken implementation.
  Pin **both** languages: a stub (or a coder) that paraphrases the Italian, "hai acceduto" for the
  design's "hai effettuato l'accesso", is caught only by the IT assert.
- To run **several** tests by name: `cargo test --bin bb-auth-web -- --test-threads=1 name1 name2`.
  Only one filter fits before `--`, and `--test-threads=1` keeps each failure's dump in its own block.
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
- The gate's sign-in page: each step id (`register-form`, `code-form`, `given_name`) appears in the
  markup **and** in the inline script's `getElementById` calls, and the markup is first, so
  `page.find(r#"id="X""#)` is the markup and one step's region is `find(id=FROM)..find(id=TO)`. Assert
  an element through its **opening tag** (back up to `<`, forward to `>`): the `I18N` table carries
  every translated word and sentence on every deployment, so a string search cannot show an element's
  absence, and the page's one `<style>` carries the word `content` too.
- A golden of `social_block`'s bytes: build it from an array of lines joined with `\n` (the provider
  with no icon leaves a whitespace-only line, and trailing whitespace inside a source literal is
  fragile), and use the **same provider order** as the page fixture, because file order is display
  order. The login page carries exactly one `<script>` and one `<style>`; a handler scan must require
  a space before `on…=`, since the template's `content="` matches `on[a-z]*=` without one.
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
- The e2e fake Cognito (`e2e/lib/cognito.js`, §13.24) is reset per area by `run.js` and per scene by
  `shots.js` (`ctx.cognito.reset()` clears calls and queued replies); a walk that scripts `'silent'`
  costs the binary's whole 5 s bound. A feature-gated cargo test (`#[cfg(feature = ...)]`) is not
  run by plain `cargo test`: add `--features e2e-fake-cognito`. To prove a feature-dependent harness,
  stub the production half in an rsync copy (`/tmp/opencode/...`) with `target/` left out is fine
  (first build ~1 min) and run `node e2e/run.js` there.

- A stylesheet check that must tell a rule **inside** an `@media` block from one at the top level uses
  `css_scoped` (`bb-auth-web`'s test module): it yields `(at-rule, selector, declarations)` with a
  selector's spaces **collapsed to one each** and a declaration body's whitespace **removed**. So
  write the selector the way the stylesheet spells it (`.brand img`, not `.brandimg`) and compare a
  declaration against the whitespace-free text (`max-width:16rem`).
- Look a rule up by a **comma-part**, never by whole-selector equality: `admin.css` spells a shared
  declaration as one rule with two names (`.bar .who svg,.menu svg`, `p.primary .pill,.actions .pill`),
  so a reader demanding the list equal `.menu svg` is red on the spelling the design asked for.
  `rule_named(scoped, at, sel)` does that; `the_rule(CSS, sel)` already does it and **keeps the
  whitespace**, which is the only way to read a multi-token shorthand (`flex:0 1 auto` reaches
  `css_scoped` as `01auto`, and `css_decl` on that answers `01auto`, a value nothing can assert).
- A bar-geometry check belongs beside `barStaysOneRow`, not inside it: that helper counts the
  vertical centres of `.bar`'s **children**, so a tab strip that wraps inside its own `nav` leaves
  all three children centred on one line and the wrap is invisible. Read the strip's own rows
  (`nav:not(.acct)` children) and `bar.getBoundingClientRect().height` (one row measures 36px, a
  wrapped strip measures 76).
- A long **given name** in the bar needs `gate.profile_claims: ['given_name']` written into the
  settings file: the header is read only where the deployment says the proxy fills it, so a walk
  that sends `X-Auth-Given-Name` alone measures the bar's easy case and passes on a broken layout.
- The `admin.css` **field-measure** assertions (`input.f-*` `max-width`) live in `src/lib.rs`'s test
  module (`the_header_shares_the_content_column`), not in `bb-auth-web`, because that test
  already reads the stylesheet. To prove a new arm satisfiable without touching the
  repo's stylesheet, compile a replica of `without_comments`/`flat_rules`/`rules_named` in
  `/tmp/opencode` and run it against a `sed`-mutated copy of the CSS: red on the repo's file, green on
  the mutated one, neighbours still green.

## Pitfalls

- A mutation harness that greps only `test tests::` lines reports a **compile failure as ALL GREEN**:
  print the compile status too. And prefer a statement-form mutation:
  `&f({ let mut v = two_buttons(); v.reverse(); &v })` compiled and left the assert green, while the
  same reversal as two statements went red.
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

- `validate_id_token` moves `c.email` at its top (`c.email.ok_or(…)`), so a new capture added to its
  `UserIdentity` literal borrows `c.identities` and `c.extra` **individually**, never `&c`: E0382
  "borrow of partially moved value", and it lands on the coder's stub, not on the tests.

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
- A markup helper that searches `"<h2>"` finds **no** heading once a heading carries an attribute:
  §13.26 gives every account `h2` `class="tight"`, and `account_heading` went red on a correct page.
  Search the tag **name** (`<h2`) and require the next character to be `>`, a space or a newline, so
  one name cannot match a longer one (`h1` versus `h1x`).
- `api(ctx, path, opts)` (e2e harness) fills `X-Auth-Email` with `admin@example.com` when
  `opts.email` is **omitted**, so a walk that means the roster person posts as the administrator and
  passes for the wrong reason. Pass `email: WHO` on every `api` call that is not an administrator's.
- A fake that **echoes** the request's `USERNAME` in its challenge makes "the pool answered for a
  different user" unrepresentable, so the test for that refusal cannot be written at all. Answer with
  fixed `ChallengeParameters` (`USERNAME`, `CODE_DELIVERY_DESTINATION`) and let a scene script the
  other username.
- `element_containing(body, "class=\"lede\"", "</p>")` reads the **first** lede of the document, and
  every account page carries one in the Preferences menu (the caller's name). A page whose own
  sentence is a bare `<p>` therefore answers a "the page says X" assert with `Bob · bob@x.com`,
  which reads like a broken helper. Assert the page's lede **carries** `class="lede"` first, and
  when a design changes that markup, say so in the test's comment.
- The Rust `FakeCognito` scripts replies by **action lookup**, not as a queue: every request for
  `InitiateAuth` gets the same scripted reply, so one fake answers the same `POST` in two languages
  and `fake.calls().len()` counts both. Assert the count you expect from the number of requests.
- A Node `Response` body is **single-use**: a second `(await res.text())` throws `Body is unusable`,
  and `run.js` records the whole area as one failure ("area completed without an unhandled error"),
  hiding every check behind it. Read it once into a `const`.
- The e2e `SETTINGS_FIXTURE` carries **no `ui` section** (every page falls back to the built-in
  brand), so `s.ui.brand_name = …` throws `Cannot set properties of undefined`, and `shots.js`
  records the scene as `SKIPPED` while `run.js` records the area as one failure. Create the section:
  `s.ui = { ...(s.ui || {}), brand_name: … }`.
- `ui.logo_url` goes through `compile_asset_url`, which accepts **absolute https or a root-relative
  path and nothing else**: a `data:` logo in an e2e fixture is a startup refusal, not a broken image.
  Use `/img/logo.png` — the 404 image is sized by its CSS box, which is the box the bar lays out, so
  the geometry a one-row check measures is real.
- Once the header's tab rows ride in the account panel, an unscoped `nav a.pill.on` or
  `nav a:not(.on)` is a **Playwright strict-mode violation** (the panel's rows are in the DOM while
  the panel is closed): scope the bar's strip as `header .bar > nav:not(.acct)`.
- A closed `details` keeps its fields in the DOM, so a `.menu select` **count** passes and every
  **click** on one times out after 30 s, which the runner records as one failed area. Open the box
  nested in the panel (`openPreferences`, `e2e/lib/harness.js`) before touching a control inside it,
  and **guard on its return value**: it answers `false` when a box is absent, and a
  `locator('details.prefs').evaluate(...)` on markup that does not exist waits the full 30 s and
  takes every later check in the area with it.
- An e2e area that imports a short-named helper (`text`, `count`, `attr`, `prop`) must check the area
  for an existing `const text = await mainText(page)`-style local: a `const` in the same function
  shadows the import for the **whole** function, so the failure is `TypeError: text is not a function`
  hundreds of lines away from the declaration, and the area dies mid-walk. Rename the local.
- A geometry helper that returns **absence** flags (`display === 'none'`) must have its expectations
  written in that same polarity: a pair spelled `[!inPanel, inPanel]` reads as the design and fails
  on a correct layout. Run one new geometry check against the layout of today and read the got/want
  line before trusting either half.
- Never wait with `while pgrep -f "<pattern>"; do sleep …; done` inside `bash -c`: the wrapper shell's own
  command line contains the pattern, so `pgrep -f` matches itself and the loop never ends (slice H lost 15
  minutes this way). Run the command in the foreground, or wait on its PID (`wait $!`, `tail --pid`).
- A CSS parser that decides "is this head an at-rule?" with `head.starts_with('@')` is reading the
  indentation: a rule inside a `@media` block arrives as `"  @media (max-width:800px)"`, so the prelude is
  kept as a **selector** and every nested rule is tagged with the prelude *with its space*, which no
  caller's key matches, and each media-block assert fails as an empty list. Test `head.trim_start()`.
- The console's user pages are keyed by the roster's **email** while the account fixture's subject is a
  **uuid**, so a walk over `every_route()` gets a `404` on `Route::User(BOB)`. A `404` renders the shell
  (bar, panel, a lede in `main`), so a "every page does X" loop must accept `200 || 404` and assert on the
  region it is about, not on the status.
- An element index found with `html.find(&el)` points at the element's **own start**, so
  `html[at..].contains("<a ")` is true of the element itself. Slice from `at + el.len()` to ask what
  follows it.
- Locating a panel row by its **visible word** answers for the wrong row: §13.28's "one name per
  place" makes the Settings tab in `div.menu-tabs` and the System settings row below it carry the
  same `K::Config` string, so `panel.find(t(lang, K::Config))` is the tab. Locate the row by
  `anchors_to(&panel, "{ADMIN_BASE}/config")` and measure the order from that, and pin "among the
  places" as `nested_block(&panel, "<div class=\"menu-places\">", "div").contains(&row)`.
- A test written against a `Result<_, String>` with `.err().expect(…)` trips clippy's `err_expect`
  the day the error becomes a `Debug` enum (step 12 S1). Write `.expect_err(…)` from the start;
  it compiles against both.
