# bb-auth-web E2E suite

Browser-level tests for the admin GUI (`src/bin/bb-auth-web.rs`), driven through a real
Chromium so the contract is tested where it actually holds: no JavaScript on the pages,
PRG on every mutation, `rev` optimistic locking, the reveal-once bearer, and the
bilingual copy. The Rust unit tests pin the handlers; this suite pins what a browser —
Back button, reloads, resubmits, cookies — does to them.

It is deliberately **outside** `tests/`: nothing here is a cargo target, and nothing in
cargo, fmt, clippy or rustdoc may ever pick it up.

## What it needs

- **Node.js** ≥ 20 (uses global `fetch`).
- **Microsoft Edge** (default) or **Chrome** — Playwright drives the *system* browser via
  a channel, so no browser download is needed. Override with
  `E2E_BROWSER_CHANNEL=chrome` (any Playwright channel name works).
- A Rust toolchain: the runner builds `bb-auth-web` itself (`cargo build`).

Dependencies (`playwright` only) are installed automatically on first run.

## Run it

```
node e2e/run.js        # from the repo root (or `npm test` inside e2e/)
```

The runner builds the binary if needed, copies `deploy/users.example.json` to a per-run
temp file (tests mutate it — the server is **never** pointed at a repo file), starts
`bb-auth-web` on an ephemeral loopback port with `BB_AUTH_WEB_BASE_PATH=/admin`, waits
for its listening line, runs every test area against it, kills it, and exits non-zero on
any failure. Each area starts from a fresh copy of the fixture, so the suite is
idempotent and areas are order-independent.

| Env var | Default | Meaning |
| --- | --- | --- |
| `E2E_BROWSER_CHANNEL` | `msedge` | Playwright browser channel (`chrome`, `msedge`, …) |
| `E2E_SHOTS` | off | `1` = save a screenshot per checkpoint into `e2e/artifacts/` (gitignored) |

## Test areas (`tests/*.js`)

| File | Contract under test |
| --- | --- |
| `auth.js` | identity comes from `X-Auth-Email` and nowhere else: 401 / 403 / 200, 404 in and outside the base path, 405 on GET of a POST-only route, the same-origin guard on every POST |
| `crud.js` | full CRUD through the forms — url_groups, sites (incl. reorder), denied, users, api_keys (mint / reveal-once / edit / rotate / remove) — each asserted against the JSON file's actual state |
| `validation.js` | refused submissions: 400, in-context error, typed input preserved, and **zero bytes written** — incl. the v3.0.1 malformed-email refusals on `users · add` and `denied · add` |
| `conflict.js` | the `rev` check: generic 409 (Back-button recovery hint, en+it), stale-form resubmit, and the v3.0.1 mint-specific 409 on a reloaded reveal page (rotate link, exactly one key, en+it) |
| `i18n.js` | `?lang=` switch: 302 + display cookie, persistence across plain navigations, translated 401/403/verdict copy, `html lang=` |
| `nojs.js` | zero `<script>` tags, PRG (a reload after save repeats nothing), and the read-only `can` page answering with the gate's verdicts |
