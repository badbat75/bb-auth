---
name: designer-playbook
description: How the designer designs the pages of this project, and the pitfalls met so far. Use when designing or reviewing a page's interface.
---

Rules are in `AGENTS.md`. Format of this file: `AGENTS.md`, under "Skills".

## How to

- Render the current pages with `node e2e/shots.js <scene-filter>` from the repo root; screenshots land in
  `e2e/artifacts/visual/{light,dark}/`. The full walk is long, so always pass a filter.
- The self-service page is `/account/` in `src/bin/bb-auth-web.rs` (`handle_account`, `account_key_forms`,
  `bearer_reveal`); its CSS is under `.selfserve` in `src/assets/admin.css`.
- The console's `403` (a non-administrator on `/admin/`) is the `forbidden` scene of `shots.js`.
- A confirmation with no JavaScript is a GET page with a POST form on it (the console's `page_confirm`).
- `shots.js` scenes for the account page: `account`, `account-menu`, `account-new`, `account-error`, `account-rm`.
  For another state, a scratch script calls `boot()` from `e2e/lib/server.js` and opens `/account/` with header
  `X-Auth-Email` (`you@example.com` has no keys, `bot@example.com` has two).
- A mockup: plain HTML under `/tmp` linking `file:///…/src/assets/{theme,base,admin}.css` plus a
  `proposed.css`, shot with `require('<repo>/e2e/node_modules/playwright').chromium.launch({channel:'msedge'})`
  at 1280 light/dark, 360 and 320; log `document.documentElement.scrollWidth` to prove no page scroll.
- Start from the console's pieces (`shell`'s header, `page_confirm`, `form_shell`, `text_field`, `url_list`,
  `expiry_markup`, `act`/`act_rm`, `p.primary`, `.limit`): the user wants reuse first, and each new rule
  must say in the design what existing piece was tried and why it did not fit.
- A form row inside a table: one `td colspan` holding a `form.edit` (a form may sit in a cell, not wrap a row).
- A theme mockup over real pages: boot the e2e server (`boot()` from `e2e/lib/server.js`), save
  `page.content()` of each page to `/tmp`, then `setContent` it with a proposed `<style>` (and the
  operator's tokens after it) before `</head>`. The sign-in page: fill `src/assets/login.html`'s
  `__BB_HEAD__` with theme+base+auth CSS and strip its script. A delta appended after `base.css`
  also beats `auth.css`, so restore any layout override it clobbers (the sign-in card's shadow).
- Shoot every mockup twice: built-in palette, and the operator's token file (a copy is under
  `/tmp/claude-1000/bb-auth-tasks/ext/tokens.css`) linked after our CSS; block network fetches in the shot.
- To try a CSS rule on the real pages (scripting on and off): `boot()`, then `page.route` the page's own
  path, `fetch()` it, insert a `<style>` before `</head>` and fulfil with the `content-security-policy`
  header deleted (the hash-only CSP drops any added style). Example: `/tmp/menu9/proto.js`.
- To find a size or alignment fault, measure it: `page.evaluate` over `getBoundingClientRect()` and
  `getComputedStyle()` of every control in `main` at 1280 and 390 (example: `/tmp/d8f/m2.js`), before
  and after the injected rule.

- The profile flow against the fake Cognito, outside `shots.js`: `/tmp/d5r/check.js` (boot, write
  `profileSettingsBytes()` to `ctx.settingsFile`, send `PROFILE_HEADERS` plus `X-Auth-Email`), which
  reads `scrollWidth`, the `#err` wiring and the change list's text at 320.
- To measure a CSS change without a server: `setContent` a minimal page with the three asset files
  inlined plus the delta, at 320/360/1280, and read `scrollWidth` and `getBoundingClientRect()`
  (example: `/tmp/d5g/m.js`).
- Before proposing a new helper or rule, grep `bb-auth-web.rs` for a console one with a `View`
  argument: the account page copies those because it has no `View`, so the fix is a `View`-free
  core (`form_shell_at`, `page_confirm_at` are the precedent), not a third copy.
- A mockup of a whole account flow with no server: `/tmp/d5b/gen.js` writes pages from the real CSS and a
- A mockup of a sign-in step with no server: `/tmp/d6/gen.js` fills `login.html` with the three real stylesheets, strips the script, makes one step `.active` and shoots it light/dark at 1280/360/320.
  copied bar, `/tmp/d5b/shot.js <names>` shoots them light/dark/360 and reports any sideways scroll.

- The real sign-in page past its email step: `/tmp/d6r/walk.js` runs the debug `bb-auth` (env:
  `BB_AUTH_LISTEN`, `BB_AUTH_HMAC_KEY` of 32+ bytes, `BB_AUTH_ACCESS_FILE`, `BB_AUTH_ORIGINAL_URL_HEADER`;
  `settings.json` beside the access file with an empty `gate.issuer`, so no JWKS fetch), then answers the
  page's Cognito `fetch` with `page.route` on the `X-Amz-Target` header (`UserNotFoundException` opens
  the registration step). An empty issuer leaves `connect-src` empty, so the context needs `bypassCSP: true`.
- A mockup of the shared header and its account menu (§13.28): `/tmp/d8h/{console,account}-{light,dark}.html` over the real CSS plus `/tmp/d8h/proposed.css`, shot by `/tmp/d8h/shot.js` (logs `scrollWidth`, the panel's box and the trigger's size). Whether the real console's bar stays one row across widths: `/tmp/d8h/wrap/v4.js <breakpoint>` (boots the e2e server, injects the header rules, walks 320 to 1400).
- To check the ground for a band, scan one gutter column of a full-page shot with PIL and list every row where a channel steps by more than 3 (example in the 8F review: only the header border at 112-114 device px should show); the glow's outer stop equals `--bg`, so a smooth fade into a flat run is correct.
- A mockup over the real account shell with no handler work: `/tmp/d7/mock.js` boots the e2e server, takes
  `page.content()` of `/account/`, replaces `<main>…</main>` per variant, `setContent`s it with `data-theme`
  stamped on `<html>`, and injects a menu row with `insertAdjacentHTML` into `.menu` before opening it.
- A mockup with no server and no Edge: `/tmp/d7w/mock.js` inlines the three real stylesheets in a `<style>` and
  launches Playwright's chromium with `executablePath` set to the cached `chromium_headless_shell-1255` binary.

- To find Italian accents typed as apostrophes in the `K` table, extract each `m(lang, en, it)`'s third string with Python and apply §13.31 §10a's rule (a `'` after a vowel, before a non-letter, not closing a quote opened after a space or `(`); a plain regex also flags `'chiunque'`.
- The stranger's `/account/` (no roster row) has no `shots.js` scene: `/tmp/rev13/stranger.js` boots the e2e server and shoots it as `friend@example.com` in light, dark, 360 and `it`, menu open, listing any visible submit in the menu.
- A notice on the sign-in page with the three real stylesheets: `/tmp/d14/gen.js` (§13.33).
- How wide the bar's tabs need the viewport, per label and language: `/tmp/d15/probe.js` (injects a tab, walks 320 to 1400, reports the narrowest width with the brand whole); the two-menu bar with a ☰: `/tmp/d15/ham.js`; a panel's size on both surfaces: `/tmp/d15/size.js`.
- The real two-menu bar after step 15 (one row at 320 to 1280, JS on and off, both panels' widths on /admin and /account, focus order, `name` exclusivity): `/tmp/r15p/p.js`; a brand give-order fix tried by injection: `/tmp/r15p/fix.js`.
- The breakpoint with a rule injected and a node removed: `/tmp/d17/edge2.js` (`NOTAG=1`, `EXTRA='<css>'`, four brands); the whole bar 1400 to 320 at a given breakpoint with shots: `/tmp/d17/ham.js` (`BP=`, `EXTRA=`, `SHOTS=`).
- The real bar after step 17, no injection (span, cursor, hover, first Tab, one row 1400 to 320, ☰ exactly at 883, seven brands with a working, a 404 and no logo, EN/IT, light/dark): `/tmp/rev17/p.js`.
- The brand's width on both surfaces with a CSS candidate injected (`CAND=` in the file, `ONLY=`, `SCHEMES=`, `STEP=`; reports cut-with-room above 884, row faults incl. bar height, pill minimums, phone cuts): `/tmp/d19/probe.js`; a broken versus a working logo per variant with shots: `/tmp/d19/broken.js`.
- Reviewing the real bar with no injection: `CAND=today STEP=4 SCHEMES=light,dark node /tmp/d19/probe.js` (boots and stops its own server); a `cutWithRoom` line is a fault only if §13.34 §12 did not accept it (it accepts 86px with logo, long brand and "Ada" at 884 to 956).
- Whether the mark ever overlaps the name pill, 640 to 320 in 1px steps (no logo, a working one, a 404; short and long names; EN/IT, light/dark; /users and /account/): `/tmp/d19c/p.js`, which reports the smallest mark-to-pill gap and any row, scroll or pill-overflow fault.
- The exact breakpoint for a bar label: `/tmp/d15b/edge.js` (strip forced visible, 1px steps 1100 to 641, light and dark, prints the widest failing width per brand, name and language). One row and no scroll alone never fail above 641, since the brand and name truncate: the binding test is the brand as wide as at 1400 and the name pill at least 128px.

- The console's singular word for each object, in both languages, is in `K::Msg*Added` (`scope`/`scope`, `user`/`utente`, `user group`/`gruppo di utenti`); the plural tab headings differ (`Scopes` is "Ambiti"), so take a kind word from the messages, not the headings.

- The `shots.js` fixture's dashboard raises only two warnings (user reaches nothing, group unreferenced); all five, with Tab focus, link targets and EN/IT light/dark/390 shots: `/tmp/rev20/p.js` (boots, edits `ctx.accessFile` before the first request).

## Pitfalls

- A bar's brand shrinks below its fixed-width mark at 320 with a long given name, so the `img` overflows onto the pill; measure the img's right against `nav.acct`'s left, not only the brand box (`/tmp/d19b/s320.js`, `/tmp/d19b/a11y.js` for the a11y tree and the broken-img gap).

- `.menu` is shrink-to-fit (absolute, `min-width` only), so the same panel is a different width wherever its longest row differs: compare the computed width on both surfaces, not the classes.
- A bar check that injects CSS with `addStyleTag` fails on the hash-only CSP: create the context with `bypassCSP: true`.

- `shots.js` wipes `e2e/artifacts/visual/` on every run, so two runs leave only the second's shots: pass every filter to one run (`node e2e/shots.js account-delete account-menu-delete`).
- Pills placed side by side straight in a `p.primary` touch (maud emits no whitespace between them): two or more actions belong in `div.actions`, which has the gap.

- A refused field's group opens through `settings_group_of`, keyed by `name=`: a refusal's field must be the real `name=` (the theme box is `ui_theme`), or it opens the wrong group.

- The `config-*` scenes open `/config?groups=open`, so they cannot show whether a refusal opens its own group: check that from a scratch script on plain `/config`, setting the hidden field with `page.evaluate` (Playwright's `fill` refuses an input inside a closed `details`). Example: `/tmp/s8r/probe.js`.

- `autofocus` is ignored when the URL has a fragment (MDN): a link that opens a form must not add `#id`.
- A cell's class can collide with a component's: `td.pills` also matches `base.css`'s `.pills{display:inline-flex}`, so it stopped being a table cell after its own rule lost `display:flex`. Check computed values, not the rule text.
- Edge ignores `line-height` on a `select`: to match a field's height to a pill's, use `min-height`, measured.
- `aspect-ratio` on a padded, border-box `.pill` squeezes its vertical padding to nothing: give an icon pill equal padding instead.
- A `summary` has no ARIA role (MDN), so name an icon-only one with hidden text (`.vh`), not `aria-label`.
- A verb-plus-id `aria-label` passes WCAG 2.5.3 in English and fails in Italian when the two `K` keys are worded apart (`Rotate` "rigenera" vs `AccountKeyRotate` "Ruota la chiave"): review the `it` view's names, not only its look.
- A refusal sentence must name the field by its visible label (`Name`), not the file's word (`id`), or the person cannot find what to fix.
- `you@example.com` in the fixture has no scope a key can reach, so `account-new` never shows the scope radios: review that block from a scratch shot or a fixture caller who has one.
- The ground is one viewport tall (`html{height:100%}`), so a background without `no-repeat` restarts one viewport down: a band of a second shade on any long page.
- `nav .pill` also matches the header icons, because `nav.acct` is a `nav` too.
- A desktop rule that sizes `.pill` is undone on a phone by the `@media` block in `admin.css` (line `.bar .pill,p.primary .pill,.actions .pill`): check every size change in the `phone` view too.
- At 360 the Preferences panel covers the middle of the screen: a "click outside" in a phone check must aim at a corner (bottom-left), not the centre.
- A prefilled field must not use `type="date"` or `type="url"`: the browser blanks or refuses a stored value it cannot parse, and on the profile form a blank posts as a deletion.
- The `K` table had no placeholders (a sentence around a value was two keys, `…Lead`/`…Tail`); §13.31 adds `fill` with positional `{0}`, `{1}`, so check which a key uses.
- A review by screenshot misses small markup the design named (the change list's `(was …)` parentheses and `span.muted`, the one-rule `input.f-code` width): read the rendered `textContent` and computed widths too.
- The gate cannot tell a federated session from a pre-5f native cookie (both send no `X-Auth-Native-Username`): copy for that state must cover both cases.
- `node e2e/shots.js <filter>` deletes all of `e2e/artifacts/visual/` first: shooting a console scene for comparison wipes the shots under review. Copy them to `/tmp` before, or rerun their filter after.
- `docs/ARCHITECTURE.md` fails markdownlint MD024 on a repeated heading ("8. Open questions for the user" already exists twice): give a new section's `####` headings a suffix naming it.
- The sign-in page's social buttons live inside the email step, so they are hidden on the registration and code steps: anything that points at "your provider" on a later step must render them there too.
- `node e2e/shots.js` takes one substring filter, not a regex (`a|b` matches nothing): run one filter per call.
- Every pill inside the header panel is also matched by `nav .pill` and `.bar .pill` (it sits in `nav.acct`), and the phone block hides `nav.acct .who`: check a new header element against both before measuring it.
- An inline `svg` outside `.pill.ico` gets no size and no stroke (300x150, filled black): a glyph in a worded pill needs its own `width/height/fill:none/stroke:currentColor` rule. The 8H panel shipped that way, and `shots.js menu` showed it but no test did.
- The "one row" check must use a long given name with a long brand (`X-Auth-Given-Name` plus `profile_claims:['given_name']`), measuring `.bar` height and not only item midpoints: as built, the tab `nav` wrapped inside itself from 804 to 900px (`/tmp/d8h-review/probe/r.js`).
- `shots.js`'s `phone` view is light only: there is no dark phone screenshot to show, so shoot one with a scratch script if a review needs it.
- `ul.plain` has no margin, so a second `p.lbl` after it sits against the last item: a second group of facts in one card reads better as `p.muted` sentences than as a second labelled list.
- Every row of the header panel carries a glyph with a `.5em` margin, so a row without one starts its word left of the others: a new panel row needs a glyph too.
- Before rewording a `K` key, grep every `K::Name` use: `AdminsKeepYourself` is also a help text and `AdminsNeverEmpty` a file-error line, so a label-first rewording must split them, not edit them.
- `Route::title` gives untranslated file-section names, but `/config` and the dashboard are titled `t(lang, …)` on `GET`: a `POST` that takes `Route::title` changes the tab's title after a save.
- A library refusal's English can be narrower than its check (`url_not_printable` said "spaces and control characters" for a printable-ASCII test, so an accented letter got the wrong reason): read the check's code, not its sentence, before wording the `K` key.
- `boot()`'s Edge can time out at launch while other agents' Edge processes run, and Playwright's own chromium
  asks for a build the cache lacks: pass `executablePath`. A `<link href="file://…">` in `setContent` is blocked,
  so a mockup shot that way is unstyled: inline the CSS.
- On the sign-in page `auth.css` hides a bare `.msg` and shows `.msg.show`, which outranks `[hidden]`: a hidden message box needs `.msg[hidden]{display:none}` after `.msg.show`.
- A native `title` tooltip never appears in a headless screenshot: judge one in a real browser, not from `shots.js`.
- "Brand whole" was measured only at 942 and up: below the breakpoint the ☰ takes ~40px and `.brand .t` and `.brand .v` shrink alike, so the product name cuts before its muted tag line. Measure `.t`'s `clientWidth` against `scrollWidth` at 320/360/390 too.
- Removing an element from the bar can raise the breakpoint: a part with a large `flex-shrink` (the console tag) was absorbing the shortfall, so the name behind it is cut sooner without it. Remeasure, and move the give to another element explicitly.
- "The brand as wide as at 1400" hides `.brand{max-width:14rem}`: with a logo the words get 118px at every width, so a brand over ~12 characters is cut even at 1280 with room to spare. Compare `.t`'s `clientWidth` with its `scrollWidth`, not with itself at 1400.
- A broken `img alt=""` is a 0x30 box in Chromium, not its CSS box: a walk with `logo_url:'/img/logo.png'` (the test server's 404) measures no logo. Route a real SVG (`page.route('**/img/logo.svg', …)`).
- The one-row check by children's centres misses a wrap inside the brand slot (`.selfserve-brand{flex-wrap:wrap}` made `/account/` 58px tall with every child still centred): also assert `.bar` height at most 40px.
