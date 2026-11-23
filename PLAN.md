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
| R1 | Self-service API keys: a user mints, rotates and removes their own `bbk_` tokens, without an administrator | Step 1 |

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

### 1. Self-service API keys: let a user mint their own `bbk_` token

Covers: R1.

#### The feature

An authenticated person reaches a page of their own, lists the API keys that belong to them,
and mints, rotates and removes them. Today the only doors to `api_keys` are `bb-auth-adm`
over SSH and the `bb-auth-web` Users tab, and both are administrator surfaces: minting a key
for a laptop, a CLI profile or a CI job means asking someone in `web.admins`.

#### The design decision to make first

`bb-auth-web` is admin-only end to end (`web.admins` is required, never empty, and gates
every route). A self-service page is for people who are *not* admins, so one of:

1. **A self-service route inside `bb-auth-web`** (e.g. `/me/keys`) exempt from the
   `web.admins` check, gated by an `authenticated` scope in nginx instead. Cheapest wiring,
   but it puts a non-admin surface in the same binary as the admin CRUD, so the exemption
   must be exact: the route may read and write only the caller's own user row.
2. **A separate target** (a fifth binary, or a mode of the GUI) whose whole job is the
   personal key page. More isolation, more packaging.

Pick one and write the argument down in this step before coding, in the register the settings-file
invariant uses: what the surface can reach, and what it cannot.

#### Hard requirements (invariants this feature touches)

- **Keys only narrow.** The self-service form may offer a key `id`, a `duration`, and a
  *subset* of the owner's existing scope restrictions; it must never be able to mint a key
  that reaches more than its owner. `decide_api_key` already enforces the owner check, and
  the mint path must not let a caller name arbitrary `application/scope` pairs.
- **One identity.** The page acts on the email nginx injects (`X-Auth-Email`) and on no
  form field. A caller with no roster row (an `authenticated`-scope stranger) has no keys
  and gets an explanatory page, not an empty form that mints an ownerless key.
- **`denied` is checked before anything.** A vetoed identity mints nothing.
- **Reveal-once stays.** The raw bearer prints on the page exactly once, after the write
  lands (`SealedKey` + `Written` receipt), and is never stored, never re-rendered, never in
  the audit line.
- **Write path unchanged.** All mutations go through `AccessWrite` (validate on the exact
  bytes, atomic rename, preserve mode/owner) and bump `rev`, so the 409 stale-form check
  works against a concurrent `bb-auth-adm` the same way it does today.
- **No JavaScript.** The page follows the GUI's rules: GET never mutates, POST carries the
  same-origin check and `rev`, lists carry filter/pager in the query string.
- **Audit.** Mint, rotate and remove are credential events on a named identity; decide
  whether they join the audit schema (they read as authentication-adjacent, not traffic)
  and pin the event names.
- **Abuse bound.** Self-minting is a long-lived credential an authenticated stranger can
  request in a loop once any `authenticated` scope exists. State the bound (per-user key
  count cap, minimum `duration` floor, or "roster rows only") in the design note, and make
  the choice visible to `--check-access` output or the startup banner if it changes what is
  reachable.

#### Checks that must pass

`cargo test`, `cargo clippy --all-targets`, `cargo fmt`, `cargo doc --no-deps` clean; new
tests for the route's authorization (admin, roster user, `authenticated` stranger, denied
user), the narrow-only rule, reveal-once, and the `rev` conflict; `node e2e/run.js`
extended with the self-service flow.

- Done when: the checks above pass, and a roster user mints, rotates and removes a key of their own in a
  browser, while a stranger and a denied user cannot.

## Waiting for the user

- Step 1: the design decision (a route inside `bb-auth-web`, or a separate target), before any code.

