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

## Pitfalls

- `autofocus` is ignored when the URL has a fragment (MDN): a link that opens a form must not add `#id`.
- `td.pills` is `display:flex`, so its border stops short whenever another cell in the row wraps.
- `aspect-ratio` on a padded, border-box `.pill` squeezes its vertical padding to nothing: give an icon pill equal padding instead.
- A `summary` has no ARIA role (MDN), so name an icon-only one with hidden text (`.vh`), not `aria-label`.
- A verb-plus-id `aria-label` passes WCAG 2.5.3 in English and fails in Italian when the two `K` keys are worded apart (`Rotate` "rigenera" vs `AccountKeyRotate` "Ruota la chiave"): review the `it` view's names, not only its look.
- A refusal sentence must name the field by its visible label (`Name`), not the file's word (`id`), or the person cannot find what to fix.
- `you@example.com` in the fixture has no scope a key can reach, so `account-new` never shows the scope radios: review that block from a scratch shot or a fixture caller who has one.
- The ground is one viewport tall (`html{height:100%}`), so a background without `no-repeat` restarts one viewport down: a band of a second shade on any long page.
- `nav .pill` also matches the header icons, because `nav.acct` is a `nav` too.
