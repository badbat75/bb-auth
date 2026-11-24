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
- A confirmation with no JavaScript is a GET page with a POST form on it (the console's `page_confirm`).
- `shots.js` has no `/account/` scene yet: drive it with a scratch script that calls `boot()` from
  `e2e/lib/server.js` and opens `ctx.origin + '/account/'` with header `X-Auth-Email`
  (`you@example.com` has no keys, `bot@example.com` has two).
- A mockup: plain HTML under `/tmp` linking `file:///…/src/assets/{theme,base,admin}.css` plus a
  `proposed.css`, shot with `require('<repo>/e2e/node_modules/playwright').chromium.launch({channel:'msedge'})`
  at 1280 light/dark, 360 and 320; log `document.documentElement.scrollWidth` to prove no page scroll.
- An editable table row with no script: the `form` element sits in one cell and every input names it
  with the `form` attribute, since a form cannot wrap a `tr`.

## Pitfalls

- `autofocus` is ignored when the URL has a fragment (MDN): a link that opens a form must not add `#id`.
