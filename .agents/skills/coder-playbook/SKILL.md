---
name: coder-playbook
description: How the coder implements and runs code in this project, and the pitfalls met so far. Use when changing production code.
---

Rules are in `AGENTS.md`. Format of this file: `AGENTS.md`, under "Skills".

## How to

- A swept reference from `user_refs` is **marked**: a scope exclusion is `app/scope (excluded)`
  and the veto is `denied (excluded)`, both built from `EXCLUDED_REF`. `remove_user`
  **rewrites** an exclusion and the veto to the row's primary email (it drops them only for a
  row with no email), so a report that prints that list may not say "removed from" a marked
  entry: the veto is still in force, under the email. `user_rm_report` is the CLI's answer;
  the GUI's removal needs the same split.

- A settings refusal the **library** makes on the whole file is attributed to a field at the
  `SettingsWrite::prepare` call site in `mutate`: `From<String>` gives `field: None`, so the
  message is matched there and turned into `Refusal::on(field, ..)`, which is what marks the
  box `f-<name> invalid` and opens its group. `settings_group_of` sends every name it does not
  list to `signin`, so a new gate field needs no entry there.
- A library function that restates `decide` as a set must ask what `decide` asks, never a copy of
  its logic. For an identifier that means the helpers (`vetoes_identifier`, `excludes_identifier`,
  `uuid_of`); for a uuid (a key's owner, as `key_scopes_for` takes) it means the raw fields the
  `Subject::Key` arm asks (`denied_users`, `excluded_users`, `credentials.api_key`, `members`),
  because the identifier helpers resolve an email and a uuid resolves to nothing.
- Run `cargo fmt` before `cargo fmt --check`: rustfmt splits long method chains.
- A maud `(name)` **borrows**: `Render::render_to(&self)` (maud 0.27), so a `String` rendered inside
  one panel is still owned and can be passed by reference after the `html!`. No clone needed, and
  none of the `(expr)` sites move.
- A page's one primary action needs no CSS: `p.primary` and `p.primary .pill` are already rules in
  `admin.css`, so the markup is the whole change.
- A hot `ui` value the console's **shell** needs (the bar's brand, 8d-3): read it at the shell,
  fail-soft, from `cfg.settings_path` (`bar_brand`). Do not add a field to `Look` or `View` for
  one: the test module has exhaustive struct literals for both (`view()`'s `View { .. }` and
  `v.look = Look { .. }`), and a new field is an `E0063` that turns the whole suite red, which a
  task that forbids editing the test module cannot answer. The shell is the right place on the
  merits too: the `401` and the settings-file `500` render above the per-request read and pass
  `Look::default()`, so a value carried in would be missing on exactly the pages that need it.
- The tester's uncommitted test is already in the tree. It may be **staged**, where plain `git diff` is
  empty and says nothing: read `git diff --cached` (and `git status --porcelain`, where `MM` means both).
- To see a page the way an operator does, drive the real binary through `e2e/lib/server.js`'s `boot()`
  (it builds, starts and kills its own server) with `require('<repo>/e2e/node_modules/playwright')` and
  `chromium.launch({ channel: 'msedge' })`: Playwright's own browsers are not installed on this host.
  Sample the screenshot with PIL (`Image.getpixel` down a column) before editing CSS; a band you cannot
  measure is a band you will "fix" by guessing. `e2e/shots.js` writes at 2x, so divide by 2 for CSS px,
  and sample a column inside a box's own padding: a colour scan for `--chip` with a loose tolerance
  also matches the `--bg-grad` ground a few px below a panel, which reads as the box ending where the
  panel does.
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
- Adding a parameter to a widely-called function: let `cargo test`'s error list find the call sites.
  A scripted paren-walk inserts the argument before the closing `)`, which turns a multi-line call
  into `…,\n    , false);` and is invisible until the compiler complains.
- A `hidden` attribute is only a presentational hint, so a server-rendered "not shown" control needs
  a CSS rule of its own (`.secret button[hidden]{display:none}` in `admin.css`): the operator's
  stylesheet loads after ours and a plain `button{display:…}` there shows the dead button.
- The action word of an account key operation is `op.title()` (`AccountKeyOp::title`), already the
  refusal page's heading and the confirmation's shell `h1`/`<title>`: a page that needs the word
  reuses it, never re-matches the op, so the pill, the button, the heading and the refusal cannot
  drift. The account shell emits `h1 { (title) }` on **every** page under the prefix, so a card
  rendered inside it (`confirm_card`, the heading-less half of `page_confirm_at`) must carry no
  heading of its own and the caller passes the word as the title.
- `rotate_api_key` mints a **new** secret on every call, so a rotate is exactly one call: keep the
  `SealedKey` it returns, commit, then `reveal(&written)`. A "check it exists, then rotate" pair
  mints two secrets and shows the second. The ownership check comes free: `key_mut` resolves the
  row from the caller's uuid first, so a key filed under another person is simply not found, and
  the self-service page answers every miss with one sentence so it is not an id-enumeration oracle.

## Pitfalls

- A new `Config` field breaks the test module's `cfg_for` struct literal (the only one). Check the
  staged test first: when the staged test reads the new field it has usually added the line itself
  (8b-3's `account_logout_url`), and the task is clear. When it has not and the task forbids editing
  the test module, that one line (`workers: DEFAULT_WORKERS,`) is a blocker to report, not a licence
  to edit: production code is still checkable with `cargo check --bin bb-auth-web` and
  `cargo clippy --lib --bins`.
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
- The test module's `match mutate(...)` is exhaustive and read-only, so `Outcome` cannot gain a
  variant or a field without breaking it. When a task forbids editing tests, derive the fact at the
  one call site instead (the bearer reveal is `status == 200 && matches!(v.at, Route::KeyAdd(_) |
  Route::KeyRotate(..))`), and report the deviation from the design doc's suggested shape.
- A slice that changes markup breaks an **older** test that string-matches the old bytes
  (`<summary class="pill">`, `<a class="pill" href="/auth/logout">Sign out</a>`), and the new staged
  test demands the opposite (`a` with class `ico`, name in a `span.vh`). The pair is mutually
  exclusive, so no production code turns both green: the old test is the tester's to update. Report
  it by name; editing it is out of a task that forbids touching the test module.
- A clippy warning can land in the tester's test module (its `map.get(x).is_none()` assertion trips
  `unnecessary_get_then_check`), where a task's edit limit forbids touching it. Clippy exits 0 on a
  warning, so report the line and leave the test alone.
- A displayed string is specified twice: the Rust test and the e2e. The reveal's e2e checks forbid the
  literal word `Authorization` in the whole document (`e2e/tests/account.js`) and in `main`'s text
  (`nojs.js`, `crud.js`), where the Rust test only forbids the bearer glued to a `Bearer` prefix. So
  the hint names the shape as "the word `Bearer`, a space, then the key". Run `node e2e/run.js` for
  any change to displayed text, not only `cargo test`.
- Inside an opencode agent run (not in the coordinator's shell, where the suite passes as is), `node e2e/run.js`
  can die with `browserType.launch: Timeout 180000ms exceeded`, and it is
  not the code: `e2e/lib/server.js` launches Edge with no `--no-sandbox` and this machine's Chromium
  sandbox hangs (a bare `chromium.launch({channel:'msedge'})` probe reproduces it; the same launch with
  `--no-sandbox` takes 200ms). The suite reads no env for browser args, and Playwright's own browser is
  not installed (it wants `chromium_headless_shell-1234`, the cache has `1255`), so run it through a
  preload outside the repo: `NODE_OPTIONS="--require /tmp/opencode/nosandbox.js" node e2e/run.js`, where
  that file hooks `Module._load` for `playwright` and appends `--no-sandbox` to `launch`'s args. `e2e/`
  stays byte for byte; say in the report that the run used the shim.
- Playwright's `click()` returns after the event dispatch, not after a promise the handler started, so
  a button label set in `navigator.clipboard.writeText(…).then(…)` is still the old word when the test
  reads `innerText()` a line later. Set the label on the click and replace it in `.catch`.
- The GUI suites' socket tests carry a 5s global ureq deadline (`account_client`, `client`), every
  write in the process serializes on `WRITE_LOCK`, and `write_atomically` fsyncs, so the POST-heavy
  tests intermittently fail at `.expect("a POST response")` with a timeout when the machine is busy
  (a full `cargo test` compiling the other three targets). Re-run before believing it, and prove it
  with `--test-threads=1`: the fix is never to shorten the handler's lock.
- A source file that changes under you (mtime moves, `git diff` grows with code you did not write) has
  a second writer, such as a local-model session still running. Work in an rsynced copy (copy `target/`
  too for a warm build), copy the finished file back in one step, and `cmp` it after a minute.
- The test helper `links_to` returns only the opening `<a ...>` tag, so a test that runs `visible_text`
  or `elements(.., "<svg", ..)` on its result sees nothing. `the_rule` fails on a selector with a
  comment right before it (in **either** sheet), so a rule a test reads by selector takes no comment
  between its preceding `}` and its `{`: the note trails the rule, and when several such rules sit
  back to back each note names the selector it is about.
- A `theme.css` comment that spells a token **with its colon** (`--input-bg:`) is counted as a
  definition: `the_theme_defines_every_token_in_all_four_arms` asserts each name occurs exactly 3
  times and `the_token_set_is_the_contract` scans every `--name:` in the file, comments included.
  A note about a token writes the name bare. The 8d-1 readers (`flat_rules`, `arm_value`,
  `theme_arms`) strip comments first, so a note beside a rule is safe for those.
- A slice that lifts a bound invalidates an **older** test's fixture that relied on the old refusal
  (`only_the_reveal_policy_names_the_copy_script` posts `duration=never` to the self-service mint and
  expects a `400`, which §13.15 made a legal window). Grep the suite for the value the slice made
  legal before writing code; the fix is the fixture's, never the production code's.
- maud 0.27 escapes only `&`, `<`, `>`, `"` (`maud-0.27.0/src/escape.rs`): a `'` in a `K` string
  reaches the page **raw**, which is valid HTML. A test that expects `&#39;` rests on a false
  premise; the only way to satisfy it is `PreEscaped(html_escape(…))`, a double-escape, so report
  the test. `html_escape` (the library) does escape `'`.
- Retiring a page's words can leave a `K` variant with no **production** caller while tests still
  name it as the string to assert the absence **of** (the footer's `SignedInAs`): that is a
  `dead_code` warning in the bin, and the repo has no `#[allow(dead_code)]` to borrow. Report it
  for the tester to remove the key and its assertions together; do not silence it.
- A `<button>` sits on the UA sheet's `line-height:normal`, not the body's 1.55, so a pill and a
  button with identical padding measure 43.25px against 37px and no padding arithmetic on the pill
  closes that gap. An author `line-height` does reach a button (Chromium's UA value is not
  `!important`, verified on a blank page), so the fix is the third name of the inherit trio,
  `line-height:inherit`, on the shared `button{}` rule in `base.css`.
- Replacing a visible control with a hidden input breaks the **e2e** that reads the control's
  attributes, not just the Rust test: `e2e/tests/account.js` §2 asserts the single
  `input[name=restrict]` is `checked`, and 8c-2's `type=hidden name=restrict value=all` carries no
  `checked`. The staged Rust test demands the hidden input, so the pair is mutually exclusive and
  the e2e is the tester's to update. Grep `e2e/tests` for the control's name before shipping the
  swap, and report the label (`restrict=all is on offer and checked`).
- Two Rust tests (`every_small_control_is_a_pill_of_the_same_family`, `sign_out_is_in_the_bar_when_configured_and_absent_when_not`)
  assert `CSS.contains(".bar .pill,")` **with the trailing comma**: their comments describe the
  desktop bar rule (`.bar .pill{`, admin.css:59), but the comma is satisfied only by the phone
  selector list, so shrinking that list to `.bar .pill{` turns both red. The pair is mutually
  exclusive with any edit to that rule; the tester's fix is the one character (`.bar .pill{`
  matches the desktop rule and the intent). Grep the Rust suite for the selector string before
  editing a rule a test reads by `CSS.contains`.
- The Preferences menu's light dismiss (§13.20) is **CSS**: `details.settings[open]>summary::before`
  is a `position:fixed;inset:0` cover at `z-index:9`, one under `.menu`'s 10, so an outside click
  lands on the `summary` and closes the `details`. A `position:relative` ancestor does not shrink
  that box, but `transform`, `filter`, `perspective` or `will-change` on `header.top`, `.bar`,
  `nav.acct` or `details.settings` does, quietly and only in a browser. `an_open_menu_closes_on_a_click_outside_it`
  is where that lands red; keep any such property off those four selectors.
- ureq 3 with `http_status_as_error(false)` and `max_redirects(0)` returns a `3xx` as a response, not
  an error: only `Error::Timeout` means Cognito did not answer, and a redirect is handled as a refusal.
- On an `/account` page the body's first `class="lede"` is the bar's menu, not the page's lede; a
  test or helper looking for the page's lede must skip the header.
