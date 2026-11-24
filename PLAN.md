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
| R1 | Self-service API keys: a user mints, rotates and removes their own `bbk_` tokens, without an administrator | Step 4 |
| R2 | Self-service profile: a user sees what bb-auth knows about them and edits their own Cognito profile attributes | Step 5 |
| R3 | The self-service surface is a section of the admin GUI (`bb-auth-web`), served at its own prefix `/account/` (`BB_AUTH_WEB_ACCOUNT_PATH`) beside the admin pages at `/admin/`, open to any signed-in identity, never reading `web.admins` and acting only on the caller's own account, so further user-facing features have a home. Changed by the user on 2026-11-23 from "a fourth binary of its own", and that evening from `<base>/me/` to `/account/` so the administrators' URLs do not move | Design revised (`docs/ARCHITECTURE.md` §13); page built in `bb-auth-web` at `/account`, not yet exposed; steps 3c2, 3d |
| R4 | Self-service deletion: a user deletes their own account and its related data, at once, after a confirmation: the roster row, keys, references in scopes and groups, and the Cognito user. The audit is not edited: their lines expire with `audit.retention`, and the page says so | Steps 6, 7. For a social-only user the Cognito half is left to an administrator and the page says so: accepted by the user on 2026-11-23 |

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
| W10 | Agents run only the tests of the part they work on, plus linter and format check; the tester runs the full suite once, on main after the merge, before installing | Applies to every step |
| W11 | The version is the last released (deployed) version plus one, and stays there until the next release: bump the patch number in `Cargo.toml`, `Cargo.lock` with it, and the version `CHANGELOG.md` says is due out, once, right after a release, never per commit | Applies to every step |

## Definition of Done

Every step must meet all of this, as well as its own "Done when". What cannot be checked is reported
as not checked, and the step stays open.

1. **Test first.** Each behaviour has a test that was seen failing for the right reason, then passing.
2. **All green.** The checks under "Agent commands" in `AGENTS.md` pass: the tests of the part that
   changed, the linter and the format check. The full suite is the tester's, after the merge.
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
on 2026-11-23; the work before it is in `git log`. The self-service page is the `/account` section of `bb-auth-web`, not yet exposed through nginx
(step 3d).

## Next steps

Decided by the user on 2026-11-23 (afternoon), reversing the morning's fourth binary: the
self-service surface is **a section of `bb-auth-web`**, at `/account/` beside the admin pages at `/admin/` (changed that evening from `<base>/me/`), open to any identity
nginx vouches for, never reading `web.admins`, and acting only on the caller's own account:
the API keys (R1), an **editable** Cognito profile (R2) and deleting one's own account (R4). The
page first built as `bb-auth-me` (steps 2b-1 to 2b-3) has moved there and that target is gone. The
reversal's cost, stated in `docs/ARCHITECTURE.md` §13.12, is that strangers now talk to the
process that writes both files, so two gaps found the same day are closed **first**, before the
GUI is opened to anyone who is not an administrator: `bb-auth-web` can read the HMAC key, and it
believes `X-Auth-Email` from any local process. The design is `docs/ARCHITECTURE.md` §13.

### 3c2. Two blemishes on the account page

Covers: R3. Found on 2026-11-24 while closing step 3c, in the screenshots.

The Italian "None." under *Chiavi API* reads "Nessuno." and should agree with the feminine noun
("Nessuna."), while the profile section keeps its own wording; and the page background stops short
of the viewport, leaving a band of another shade at the bottom in both themes.

- Done when: a test that failed first pins the Italian wording per section; the background fills
  the viewport in both themes in a fresh screenshot; the slice's checks are clean.

### 3d. The nginx recipe for `/account/`, and install on rpi-01

Covers: R3. Test host named by the user on 2026-11-23: `rpi-01.bombicci.local`.

The README documents a second location, `/account/`, mirroring the admin one with the same
secret include but forwarding the configured profile headers, plus `location = /account` as a
`301` to `/account/`, and the access-file scope that opens it (`authenticated`, covering
`https://<host>/account` and `https://<host>/account/*`), and in one line that the first
`authenticated` scope makes `/auth/session` mint cookies for strangers (§13.5). Decided by the
user on 2026-11-23: on rpi-01 the new location **replaces** the static `/account/` page and its
`/account/whoami` and `/account/delete` locations, so self-service account deletion is missing
until step 7; the backend on 8480 behind those two is left running, unused, and is not ours to
remove. With the user's go-ahead for each change: the packages installed, the nginx locations
replaced and reloaded, and the bare URL added to the existing `auth/self-service` scope.

- Done when: `nginx -t` passes on rpi-01; `curl -I` shows `/account` answering `301` to
  `/account/`; `bb-auth-adm can` grants a stranger `/account/` and `/account` and refuses them
  `/admin/`; and in a browser through nginx a signed-in non-administrator sees their page and is
  refused the admin pages, while an administrator reaches both.

### 4. Self-service API keys

Covers: R1.

Hard requirements (invariants this feature touches):

- **Keys only narrow.** The form offers an `id`, a `duration`, and either no restriction or any
  subset of the scopes the owner's keys reach (`Access::key_scopes_for`, added to the library
  test first, §13.8), grouped under their application. It submits `application/scope` pairs;
  each is checked against that set, and one outside it is a `400` with nothing written, never
  dropped silently.
- **No URLs on screen.** The key form and key list show application and scope names, never a URL
  pattern or base. A key entry the owner no longer reaches is shown and marked.
- **Rotate keeps the restriction byte for byte.** Only `key_hash` and `released` change.
- **One identity.** The page acts on `X-Auth-Email` and on no form field. A caller with no roster
  row gets an explanatory page, never a form that mints an ownerless key.
- **`denied` is checked before anything.** A vetoed identity mints nothing.
- **Reveal-once stays.** The raw bearer shows exactly once, in the `200` answering the `POST`,
  after the write lands, with `Cache-Control: no-store`, and is never stored, re-rendered or logged.
- **Write path unchanged.** `add_api_key`, `rotate_api_key`, `remove_api_key` through
  `AccessWrite`, the `rev` 409 check and `bb-auth-web`'s write lock.
- **No JavaScript.** GET never mutates; POST carries the proxy secret, the strict same-origin
  check and `rev`.
- **Bound**: at most 10 keys per row, `duration` from `1d` to `365d`, `id` matching `[a-z0-9-]{1,32}`.
- **Journal**: `[bb-auth-web] <uuid> (self): key add|rotate|remove <id>`, nothing else.

Tests: authorization (administrator, roster user, stranger, denied); `key_scopes_for` agrees
with `decide` for a key; a pair outside the set `400` with the file unchanged; the file gets
exactly the submitted pairs; an administrator-narrowed key displayed by scope name with no URL;
rotate leaves its `scopes` bytes identical; the bounds, reveal-once, the `rev` conflict, and the
e2e flow with scripting off.

- Done when: a roster user mints, rotates and removes a key of their own in a browser, while a
  stranger and a denied user cannot.

### 5. Editable Cognito profile

Covers: R2.

`cognito_endpoint` moves to the library as a `Settings` method (the gate's test keeps passing).
The re-authentication of §13.7: choose one of one's own emails, `InitiateAuth` (`USER_AUTH`,
`EMAIL_OTP`), a code form carrying Cognito's `Session` in a hidden field, then
`RespondToAuthChallenge` and `UpdateUserAttributes`, with the tokens dropped at the end of that
request. Editable: `gate.profile_claims` minus `email`, `phone_number`, `preferred_username`;
`email` shown read-only. `bb-auth-web.service` loses `IPAddressDeny=any` and
`IPAddressAllow=localhost`, which block the call to Cognito (cost in §13.7). Tests use a fake
Cognito endpoint and never the real pool; the first real edit needs the user's go-ahead.

- Done when: tests show a wrong code changes nothing, an email not among the caller's and a
  non-editable attribute are refused before Cognito is called, and no token reaches a response
  or a log; a non-loopback `BB_AUTH_WEB_LISTEN` without the opt-in still refuses to start; and a
  user changes an editable attribute in a browser against the real pool (with the user's
  go-ahead), and it shows in their next token's profile claims.

### 6. `remove_user` keeps an exclusion as an email

Covers: R4 (prerequisite), and changes `bb-auth-adm` and the admin pages too, as decided.

Today `remove_user` drops the removed uuid from every scope's `excluded`; it must rewrite it to
the row's primary email, as it already does for `denied`, so a removed person who re-registers is
still kept out (§13.8). Library change, test first.

- Done when: a library test that failed first shows a scope that excluded the uuid now excludes
  the primary email, a row with no email leaves nothing behind, and the written file compiles;
  `bb-auth-adm user rm` and the GUI's removal show the same result. Note for the docs agent:
  AGENTS.md's `excluded` invariant ("`remove_user` and `user_group_refs` count an exclusion as a
  reference") and the comment on the sweep must say the exclusion is rewritten, not swept.

### 7. Delete my account

Covers: R4.

A confirmation page (it says the audit keeps their lines until `audit.retention` drops them),
the re-authentication of step 5, the roster row through `remove_user`, `AccessWrite` and `rev`,
then `DeleteUser`. A stranger deletes only their Cognito user and the access file is not touched.
A social-only user, who cannot re-authenticate by email code, gets the access-file half only, and
the page says an administrator must delete their Cognito account. `denied` is never lifted. The
final page links to `/auth/logout`.

- Done when: tests show a failed write never calls `DeleteUser`, a failed `DeleteUser` leaves the
  row gone and says so (with a retry the person reaches as a stranger), a denied user is refused,
  a stranger's deletion leaves the file's bytes unchanged, and a social-only user's deletion
  calls no Cognito operation; and a roster user deletes their own test account in a browser
  against the real pool (with the user's go-ahead), the access file no longer names them where it
  named them (an exclusion now names their email), and they can no longer sign in.

## Waiting for the user

- Before step 5: a read-only check of the real pool (`aws cognito-idp describe-user-pool` and
  `describe-user-pool-client`): email sign-in, `ALLOW_USER_AUTH`, `WriteAttributes`,
  `AuthSessionValidity`, `AttributesRequireVerificationBeforeUpdate`. The user runs it, or
  approves it being run.
