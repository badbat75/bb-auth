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

## Pitfalls

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
- The `K` table has no placeholders: a sentence around a value is two keys (`…Lead`/`…Tail`), so plan copy that way.
- A review by screenshot misses small markup the design named (the change list's `(was …)` parentheses and `span.muted`, the one-rule `input.f-code` width): read the rendered `textContent` and computed widths too.
- The gate cannot tell a federated session from a pre-5f native cookie (both send no `X-Auth-Native-Username`): copy for that state must cover both cases.
- `node e2e/shots.js <filter>` deletes all of `e2e/artifacts/visual/` first: shooting a console scene for comparison wipes the shots under review. Copy them to `/tmp` before, or rerun their filter after.
- `docs/ARCHITECTURE.md` fails markdownlint MD024 on a repeated heading ("8. Open questions for the user" already exists twice): give a new section's `####` headings a suffix naming it.
- The sign-in page's social buttons live inside the email step, so they are hidden on the registration and code steps: anything that points at "your provider" on a later step must render them there too.
