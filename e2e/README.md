# bb-auth-web E2E suite

Browser-level tests for the admin GUI (`src/bin/bb-auth-web.rs`), driven through a real
Chromium so the contract is tested where it actually holds: no page needing JavaScript,
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

```sh
node e2e/run.js        # from the repo root (or `npm test` inside e2e/)
```

The runner builds the binary if needed, copies `deploy/access.example.json` to a per-run
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
| `crud.js` | full CRUD through the forms — user_groups, applications, scopes (incl. reorder and `excluded`), denied, users, api_keys (mint / reveal-once / edit / rotate / remove) — each asserted against the JSON file's actual state |
| `validation.js` | refused submissions: 400, in-context error, typed input preserved, and **zero bytes written** — incl. the malformed-email refusals on `users · add` and `denied · add` |
| `conflict.js` | the `rev` check: generic 409 (Back-button recovery hint, en+it), stale-form resubmit, and the mint-specific 409 on a reloaded reveal page (rotate link, exactly one key, en+it) |
| `i18n.js` | the two display preferences: `?lang=` / `?theme=` answer 302 + a cookie, the choice persists across plain navigations, the 401/403/verdict copy is translated, `html lang=` is the proof; plus the Settings menu, where picking an option applies it on the spot, keeps the rest of the query, and offers `auto` as a real stored choice |
| `nojs.js` | no page needs a script: zero `<script>` tags, and the only handler in the GUI is the two Settings list boxes' — then the whole thing again with **scripting disabled**, where the menu grows its submit button back and one click sets both preferences. Plus PRG (a reload after save repeats nothing) and the read-only `can` page answering with the gate's verdicts |

## The visual walk-through (`shots.js`)

```sh
node e2e/shots.js               # every scene, every view
node e2e/shots.js users conflict   # only scenes whose name contains one of these
```

Same binary, same bootstrap, same throwaway fixture as the suite (`lib/server.js` is
shared), but it asserts nothing: it renders **every page shape bb-auth-web can produce**
and saves a full-page screenshot of each into
`e2e/artifacts/visual/<view>/`. That is the input to a design review, where
the suite's input is a pass/fail count.

The half of the inventory that matters most cannot be reached with a `GET` — the flash
after a save, the in-context `400`, the `409`, the reveal-once bearer are all `POST`
responses — so a scene may drive forms; the fixture is restored before each one, exactly
as the suite restores it before each area.

Two kinds of thing are captured:

- **`SCENES`** are page shapes: one per thing the binary can render.
- **`STATES`** are what the pointer and the keyboard do to a control: `hover-row-remove`,
  `focus-input`, and so on. A screenshot of a plain `GET` can never show a hover colour or
  a focus ring, and those are exactly the rules that rot unseen. They are captured here,
  under a name, rather than in a scratch script written fresh for each review: a check
  that is needed every time the chrome changes is part of the tooling, not a one-off.
  Focus is reached by pressing Tab (`tabTo`), never `element.focus()`, because Chromium
  only matches `:focus-visible` after a key: a programmatic focus photographs a ring a
  real user would never see.

The views:

| View | What it is for |
| --- | --- |
| `light` / `dark` | The two `prefers-color-scheme` arms, with no theme chosen: the System path. The only views that run `STATES`, since every state is a colour. |
| `phone` | 390px, which forces every wrap and exposes anything that only fits on a laptop. |
| `it` | The bilingual half of the review. It sets the language cookie through the real `?lang=` redirect, then renders the scenes that carry prose. |
| `theme-light` / `theme-dark` | An explicit theme, set through the real `?theme=` redirect, deliberately photographed against the **opposite** OS scheme. That pairing is the only one that proves the choice beat the operating system: under a matching OS these would be pixel-identical to `light` and `dark`, and would prove only that the cookie did no harm. |
| `noscript` | Scripting off. Exactly one shape differs: the Settings menu grows back the submit button its one inline handler makes unnecessary. Otherwise a reviewer would never see the half of that menu a scriptless browser gets. |

Do not run two `shots.js` at once: the first thing it does is empty `artifacts/visual/`.
