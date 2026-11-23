# Plan

What the user asked for, when work counts as done, and what is left to do, in order. Rules in
`AGENTS.md`, under "Working from this plan".

This plan is not set in stone: the coordinator or the user can change any part of it when needed.

## User requirements

These stay here when met: unlike steps, they are not removed for being done. "Met" means checked as far
as the column says. A requirement still open must be covered by a step.

### Product

| ID | Requirement | State |
|---|---|---|
| R1 | Self-service API keys: a user mints, rotates and removes their own `bbk_` tokens, without an administrator | Steps 1, 2, 3 |
| R2 | Self-service profile: a user sees what bb-auth knows about them and edits their own Cognito profile attributes | Steps 1, 2, 4 |
| R3 | The self-service surface is a fourth binary of its own, dedicated to users and separate from the admin GUI, so further user-facing features have a home | Steps 1, 2 |
| R4 | Self-service deletion: a user deletes their own account and its related data, at once, after a confirmation: the roster row, keys, references in scopes and groups, and the Cognito user. The audit is not edited: their lines expire with `audit.retention`, and the page says so | Steps 1, 5 |

### How we work

| ID | Requirement | State |
|---|---|---|
| W1 | Test driven, always: tests first, then the code | Applies to every step |
| W2 | Keep it simple | Applies to every step |
| W3 | One agent each for coordination, architecture (software and infrastructure), code, tests and documentation | Met: `.opencode/agents/` |
| W4 | AI scaffolding as standard as possible, readable by other harnesses | Met: `AGENTS.md`, shared role files |
| W5 | A maintained plan: closed points removed, evidence in the commit log, so an agent starting from zero knows what to do | Met: this file and `git log` |
| W6 | The coordinator or the user can change the plan when needed | Met: rule in `AGENTS.md` |
| W7 | Each agent has its own skill, saying how it works in this project and the pitfalls met so far, which it can update itself or the coordinator can | Met: `.agents/skills/`, format in `AGENTS.md` |
| W8 | Everything in English; only the conversation with the user may be in their language | Applies to every step |
| W9 | Displayed text in the `K` translation table or the page templates, ready for more languages | Applies to every step |
| W10 | Agents run only the tests of the part they work on, plus linter and format check; the user runs the full suite once, on main after the merge, before installing | Applies to every step |

## Definition of Done

Every step must meet all of this, as well as its own "Done when". What cannot be checked is reported
as not checked, and the step stays open.

1. **Test first.** Each behaviour has a test that was seen failing for the right reason, then passing.
2. **All green.** The checks under "Agent commands" in `AGENTS.md` pass: the tests of the part that
   changed, the linter and the format check. The full suite is the user's, after the merge.
3. **Tried for real.** Behaviour is checked in the real thing, not only in tests: the check the Commands
   table in `AGENTS.md` matches to the change, including a look at the page in a browser where it says
   so. A deploy only with the user's go-ahead.
4. **Safe.** No invariant in `AGENTS.md` breaks: nobody is locked out, nobody is let in, and a bad file
   is refused before it takes effect. Failure paths are tested first.
5. **Requirements hold.** The step meets those it covers and breaks none of the others. Their "State"
   above is updated.
6. **Language rules hold.** Everything is in English, and displayed text is in the `K` table or the page
   templates.
7. **Docs are true.** README, `AGENTS.md` and `docs/` match what now exists. Facts have a source, and guesses
   are marked as guesses.
8. **Plan and history.** The step is removed from this file, in the commit with the work, whose message
   says what was closed and how it was checked.

## Where things stand

The gate, the CLI (`bb-auth-adm`) and the admin GUI (`bb-auth-web`) are built and deployed; `README.md`,
`AGENTS.md` and `CHANGELOG.md` say what they do. The agent structure (roles, skills, this plan) was added
on 2026-11-23; the work before it is in `git log`.

## Next steps

Decided by the user on 2026-11-23: the self-service surface is **a fourth binary**, not a route
inside `bb-auth-web`, because a non-admin surface must not share a binary with the admin CRUD and
more user-facing features are expected. Its features are the API keys (R1), an **editable** Cognito
profile (R2) and deleting one's own account (R4).

### 1. Design the user binary (architect)

Covers: R1, R2, R3, R4 (design only, no code).

The architect writes the design into `docs/ARCHITECTURE.md` and the decisions into this plan, in the
register the settings-file invariant uses: what the surface can reach, and what it cannot. It must
settle:

- **Name, unit and package**: binary name, systemd unit, service user, env file, `.deb` (optional,
  like the other admin tools), what it may write (the access file only, through `AccessWrite`) and
  what it may not (settings file, audit). Ownership: today installing `bb-auth-web` moves the access
  file to `bb-auth-web:bb-auth 0640`; a second unprivileged writer needs an answer that keeps both
  writers and the gate working, with or without `bb-auth-web` installed.
- **Who reaches it**: nginx `auth_request` with an `authenticated` (or `restricted`) scope, identity
  from `X-Auth-Email` only, and the four cases: roster user, admin, `authenticated` stranger, denied.
- **What it shares**: what moves into the library (and why, under "the library is the shared files,
  and nothing else"), and what stays in the binary. Presentation: `THEME_CSS`/`BASE_CSS`, the `ui`
  settings, the no-JavaScript rule, `PAGE_SECURITY_HEADERS`/`page_csp`, `request_site`.
- **API keys**: the narrow-only rule, reveal-once (`SealedKey` + `Written`), `rev`, audit events,
  and the abuse bound (key count cap, `duration` floor/ceiling, roster rows only).
- **Cognito profile**: how a server-rendered, no-JavaScript page changes Cognito attributes. Today
  bb-auth holds no Cognito credential and receives only an `id_token`. Options to weigh (check each
  against the AWS documentation, not memory): the user's own access token with
  `UpdateUserAttributes` (how does the binary get it?), or an admin call with IAM credentials (a
  secret, and the pure-Rust dependency invariant). Which attributes are editable, and why. The
  **email** attribute is the roster's identity key: changing it in Cognito can lock the person out
  or let them claim another row, so say whether it is editable at all. Profile claims are
  self-asserted and authorize nothing, which must stay true.
- **Account deletion**: how the Cognito user is deleted (same credential question as the profile),
  in which order the two deletions happen and what a half-done deletion leaves (a roster row with no
  Cognito user is harmless; a Cognito user with no roster row is an `authenticated` stranger). What
  happens to a `denied` entry naming the person: a veto must never be lifted by the person it vetoes,
  and a denied identity reaches nothing here anyway. The audit is not edited (user decision).
- **Steps**: confirm or rewrite steps 2 to 5 below, each small enough for one slice.

- Done when: the design is in `docs/ARCHITECTURE.md`, the user has approved it, and steps 2 to 5
  reflect it.

### 2. The user binary: skeleton, identity and a read-only profile page

Covers: R3, part of R1 and R2. Shape set by step 1.

The binary builds, packages and serves one page showing what bb-auth knows about the caller (uuid,
emails, groups, reachable applications and scopes, denied or not), with the four identity cases
tested (roster user, admin, stranger, denied).

- Done when: the four cases are tested, the page is checked in a browser, and the package installs
  beside the others without changing who owns the access file in a way that breaks a writer.

### 3. Self-service API keys

Covers: R1.

Hard requirements (invariants this feature touches):

- **Keys only narrow.** The form may offer a key `id`, a `duration`, and a *subset* of the scopes the
  owner already reaches; it must never mint a key that reaches more than its owner, nor let the
  caller name arbitrary `application/scope` pairs.
- **One identity.** The page acts on `X-Auth-Email` and on no form field. A caller with no roster
  row gets an explanatory page, never a form that mints an ownerless key.
- **`denied` is checked before anything.** A vetoed identity mints nothing.
- **Reveal-once stays.** The raw bearer shows exactly once, after the write lands, and is never
  stored, re-rendered or audited.
- **Write path unchanged.** All mutations go through `AccessWrite` and the `rev` 409 check, against a
  concurrent `bb-auth-adm` or `bb-auth-web`.
- **No JavaScript.** GET never mutates; POST carries the same-origin check and `rev`.
- **Audit and abuse bound** as decided in step 1.

Tests: the route's authorization (admin, roster user, stranger, denied), narrow-only, reveal-once,
the `rev` conflict, and the e2e flow.

- Done when: a roster user mints, rotates and removes a key of their own in a browser, while a
  stranger and a denied user cannot.

### 4. Editable Cognito profile

Covers: R2.

Mechanism, editable attributes and the email question as decided in step 1. Tests never touch the
real user pool; the first real edit against it needs the user's go-ahead.

- Done when: a user changes an editable attribute of their own in a browser against the real pool
  (with the user's go-ahead), cannot change another person's or a non-editable one, and the change
  shows in their next token's profile claims.

### 5. Delete my account

Covers: R4.

A confirmation step (a second `POST`, no JavaScript), then the roster row goes through the same
sweep `remove_user` does (keys, scope and group references, `excluded`), through `AccessWrite` and
`rev`, and the Cognito user is deleted as step 1 decided. `denied` entries are never removed by
this. The audit is not edited; the page says how long the person's lines are kept. Tests never touch
the real pool; the first real deletion needs the user's go-ahead.

- Done when: a roster user deletes their own account in a browser (test account, real pool, with the
  user's go-ahead), the access file no longer names them anywhere it named them, they can no longer
  sign in, and a denied user cannot use this to lift their veto.

## Waiting for the user

- Step 1: approval of the architect's design, before any code.
