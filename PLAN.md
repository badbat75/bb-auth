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
| R4 | Self-service deletion: a user deletes their own account and its related data after a confirmation: the roster row, keys and references in scopes and groups at once, and every Cognito user with their address (federated twins included) through the owner's deletion worker (`bb-account-delete`, the user's choice on 2026-11-26). The audit is not edited: their lines expire with `audit.retention`, and the page says so | Done: live on rpi-01 since 2026-11-26 (`v1.99.9-gadf4556`), a real deletion of a test account checked in a browser by the user (step 7 closed); signing out on deletion and the stale-cookie gap are step 14 |
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
| W11 | The version stays the same between releases; a deploy does not bump it, and the build string (`v<version>-g<commit>`) is what tells two deploys apart (the user's decision, 2026-11-25, replacing "the last deployed version plus one"). `v1.99.8` was tagged on 2026-11-25 as a pre-release of 2.0.0, `v1.99.9` on 2026-11-27 as its release candidate, `v1.99.10` the same day as the second, and `v1.99.11` the same day as the third | Applies to every step |
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
pre-release; `v1.99.9` was tagged on 2026-11-27 as the release candidate of 2.0.0, `v1.99.10` the same day as the second release candidate and `v1.99.11` that evening as the third, all published on GitHub as pre-releases; rpi-01 runs `v1.99.11-g19b5494` since the evening of 2026-11-27 (the users tab as three sub-pages with a page per user group; self-service account deletion through the owner's worker, signing the browser out on completion; the two menus; the console's brand without its tag or link, as wide as the bar allows, and a phone bar that keeps the logo; dashboard warnings that name their kind; the AGPL licence) with `gate.landing_url` set to its `/account/` page and `gate.allow_unverified_social` on for `MicrosoftPersonal` alone. Google's `email_verified` is mapped in the pool (OpenTofu, through IT-Admin), so a Google sign-in proves its address. Microsoft's personal accounts send no claim Cognito accepts as a boolean (mapping `xms_edov` broke the sign-in, so the mapping was removed), so that one provider is the exception (the user, 2026-11-26).

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

### 25. The fourth release candidate, 1.99.12

Covers: the user's request of 2026-11-27 to carry step 25 (the GUI and the library split into
modules, now built, §13.39) to its end and then cut a fourth release candidate.

- Done when: version 1.99.12, its CHANGELOG heading, the full board on main, the packages, the
  deploy to rpi-01, the push, the `v1.99.12` tag and a GitHub pre-release (1.0.0 stays Latest),
  as for 1.99.11.
