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

## Pitfalls
