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
| R1 | Self-service API keys: a user mints, rotates and removes their own `bbk_` tokens, without an administrator | Done: live on rpi-01, checked in a browser by the user on 2026-11-26 (step 4 closed) |
| R2 | Self-service profile: a user sees what bb-auth knows about them and edits their own Cognito profile attributes | Done: live on rpi-01, a real edit checked in a browser by the user on 2026-11-26 (step 5 closed); federated users see one sentence instead of the form, by design |
| R3 | The self-service surface is a section of the admin GUI (`bb-auth-web`), served at its own prefix `/account/` (`BB_AUTH_WEB_ACCOUNT_PATH`) beside the admin pages at `/admin/`, open to any signed-in identity, never reading `web.admins` and acting only on the caller's own account, so further user-facing features have a home. Changed by the user on 2026-11-23 from "a fourth binary of its own", and that evening from `<base>/me/` to `/account/` so the administrators' URLs do not move | Design revised (`docs/ARCHITECTURE.md` §13); Read-only page live on rpi-01 at `/account/` since 2026-11-24; the writes are steps 4, 5 and 7 |
| R4 | Self-service deletion: a user deletes their own account and its related data after a confirmation: the roster row, keys and references in scopes and groups at once, and every Cognito user with their address (federated twins included) through the owner's deletion worker (`bb-account-delete`, the user's choice on 2026-11-26). The audit is not edited: their lines expire with `audit.retention`, and the page says so | Step 7 (the step 6 it once named is done). Changed on 2026-11-26: the worker deletes a social-only user's Cognito account too, so the 2026-11-23 "left to an administrator" exception goes |
| R5 | The sign-in page warns, where it offers registration, that registering by email code creates an account separate from a Google or Microsoft one with the same address, and points such a person at their provider's button (the user's choice on 2026-11-25, option 1 of three: no Cognito change; a pre-sign-up Lambda or linking accounts stay for later) | Met: live on rpi-01 since 2026-11-25 (`v1.99.9-gfb2bd75`), seen in a browser by the designer in both themes, both languages and at phone width |

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
| W11 | The version stays the same between releases; a deploy does not bump it, and the build string (`v<version>-g<commit>`) is what tells two deploys apart (the user's decision, 2026-11-25, replacing "the last deployed version plus one"). `v1.99.8` was tagged on 2026-11-25 as a pre-release of 2.0.0; the work after it is 1.99.9 (the user, 2026-11-25) | Applies to every step |
| W12 | JavaScript sparingly: HTML and CSS first, a small inline script only where it clearly improves an interaction, allowed by the page's CSP, never from another host (the user's rule, 2026-11-25, replacing "no page may need JavaScript"; stated in `AGENTS.md`) | Applies to every step |
| W13 | The admin console and the account page share their front end: one width (1000px, the user's choice on 2026-11-25), one header, the same components, helpers and parameters; a thing the console already has is reused on `/account`, never rebuilt, and only what is genuinely different stays apart, with the reason written down (the user, 2026-11-25: "non reinventiamo l'acqua calda") | Every step touching either page |

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
on 2026-11-23; the work before it is in `git log`. The self-service page is the `/account` section of `bb-auth-web`, live on rpi-01 since
2026-11-24, with its key writes, header and theme since 2026-11-25. `v1.99.8` (g978eca8) is tagged, on GitHub as a
pre-release; rpi-01 runs `v1.99.9-g8a522b8` since 2026-11-26 (the one-row account menu, step 8's later items, settings refusals in the page's language, and 7a's configuration, off there) with `gate.landing_url` set to its `/account/` page; self-service account deletion is missing there until step 7.

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

### 7. Delete my account

Covers: R4.

A confirmation page (it says the audit keeps their lines until `audit.retention` drops them) where
the person types their address; no email code (the user, 2026-11-26). bb-auth-web asks the owner's
intake (`BB_AUTH_WEB_DELETE_INTAKE`, loopback only) whether any of the caller's addresses is
protected, removes the roster row through `remove_user`, `AccessWrite` and `rev`, then queues every
address of the row with the intake, which the `bb-account-delete` worker deletes from Cognito
(federated twins included). A stranger queues only, and the access file is not touched. `denied`
is never lifted. The final page says the Cognito half is queued, never deleted, and links to
`/auth/logout`. bb-auth-web holds no AWS credential.

Designed in §13.29 W1 to W12 (2026-11-26, on the user's choice (a)); the pages are §13.30, whose
strings the redesign made untrue are listed in its §5 for the designer. The intake's shared secret
(`BB_AUTH_WEB_DELETE_SECRET`) is optional for now (the user); W8 lists proposals for itadmin, at the
owner's word. Slices: **7a** the configuration and the menu row (done); **7b** the confirmation page;
**7c** the stranger's deletion and a fake intake; **7d** the roster row removed first; **7e** the
partial outcomes; **7f** the browser suite; **7g** the real run on rpi-01, the worker in dry run
first, each step with the user's go-ahead. §13.30 was reworded for the worker on 2026-11-26 (mockups in /tmp/d7w/).

- Done when: tests show a protected address changes nothing, a failed write posts nothing, the row
  is gone before the first `POST`, a refused or unanswered `POST` says so with a retry the person
  reaches as a stranger, a denied user is refused, a stranger's deletion leaves the file's bytes
  unchanged, each request carries one address (never the joined header), and no secret reaches a
  response or a log; and a roster user deletes their own test account in a browser on rpi-01 (with
  the user's go-ahead, the worker in dry run first and then for real): the access file no longer
  names them where it named them (an exclusion now names their email), their key is refused at
  once, and after the worker's run they can no longer sign in. If `gate.allow_unverified_social` is
  on, it is turned off first (the user, 2026-11-26).

### 13. Loose ends of step 8

Covers: R3. Left over when the user approved step 8's screenshots on 2026-11-26: the module rustdoc of
`bb-auth-web.rs` (about line 253) still calls the account page's arrangement a centred card and
names a Settings menu; and one look by hand at the native "Preferences" tooltip while the open
menu's cover is up.

Added by the user on 2026-11-26: when the caller has no roster row, `/account` writes **nothing**
in its place, neither in the lede (today "bb-auth has no roster row for you." under the
addresses, where a row shows "Account id") nor on 7b's deletion page; the line and its `br`
simply go. `K::AccountNoRow` goes if nothing else uses it, and AGENTS.md's self-service paragraph
("where a caller with no row is told there is none") is corrected. To do after 7b, which touches
the same file.

- Done when: the rustdoc says what the page is (the console's column and one account menu); a
  test shows a stranger's `/account` (and the deletion page) carries no no-row sentence and no
  empty line where the id would be; and the tooltip has been looked at in a browser, or the look
  is reported as not done.

## Waiting for the user

- Step 7, answered by the user on 2026-11-26: a deleted administrator stays in `web.admins`; the
  typed-address field has no `autocomplete` (the confirmation stays the person's own act, a
  deliberate exception to WCAG 1.3.5); the places a person reaches are not listed among what is
  deleted; 7g's test account is a new one, for which the coordinator prepares the commands. The
  proposals for itadmin (§13.29 W8 §1 to §3 and §5) go to IT-Admin, which asks the owner before
  applying them on rpi-01.
