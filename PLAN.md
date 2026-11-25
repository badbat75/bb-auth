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
| R3 | The self-service surface is a section of the admin GUI (`bb-auth-web`), served at its own prefix `/account/` (`BB_AUTH_WEB_ACCOUNT_PATH`) beside the admin pages at `/admin/`, open to any signed-in identity, never reading `web.admins` and acting only on the caller's own account, so further user-facing features have a home. Changed by the user on 2026-11-23 from "a fourth binary of its own", and that evening from `<base>/me/` to `/account/` so the administrators' URLs do not move | Design revised (`docs/ARCHITECTURE.md` §13); Read-only page live on rpi-01 at `/account/` since 2026-11-24; the writes are steps 4, 5 and 7 |
| R4 | Self-service deletion: a user deletes their own account and its related data, at once, after a confirmation: the roster row, keys, references in scopes and groups, and the Cognito user. The audit is not edited: their lines expire with `audit.retention`, and the page says so | Step 7 (the step 6 it once named is done). For a social-only user the Cognito half is left to an administrator and the page says so: accepted by the user on 2026-11-23 |
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
pre-release; rpi-01 runs `v1.99.9-gfb2bd75` (the profile edit bound to the session's native user, and the sign-in page's duplicate-account notice) with `gate.landing_url` set to its `/account/` page; self-service account deletion is missing there until step 7.

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
- **JavaScript sparingly** (4g's copy script on the reveal is one). GET never mutates; POST carries the proxy secret, the strict same-origin
  check and `rev`.
- **Bound**: at most 10 keys per row, `duration` at least `1d` or `never` (the 365-day bound was
  lifted by the user in 4h), `id` matching `[a-z0-9-]{1,32}`.
- **Journal**: `[bb-auth-web] <uuid> (self): key add|rotate|remove <id>`, nothing else.

Tests: authorization (administrator, roster user, stranger, denied); `key_scopes_for` agrees
with `decide` for a key; a pair outside the set `400` with the file unchanged; the file gets
exactly the submitted pairs; an administrator-narrowed key displayed by scope name with no URL;
rotate leaves its `scopes` bytes identical; the bounds, reveal-once, the `rev` conflict, and the
e2e flow with scripting off.

Done so far: `Access::key_scopes_for` (4a), minting (4b), rotating and removing (4c) from
`/account`. Made reliable in parallel (4d); the worker count is
`BB_AUTH_WEB_WORKERS` (4e). The e2e flow with scripting off passes (`nojs.js`).

8a to 8e installed on rpi-01 on 2026-11-25 (as 1.99.9, gb9d7100, then the same code as 1.99.8,
g75f788a), verify.sh green; still to see
in a browser: a rotate, the copy icon, the confirmations, the header and the theme; and, since
v1.99.8, that a sign-out from `/account` followed by a sign-in lands back on `/account`. Earlier,
installed on 2026-11-24 (gd49d43a): the user minted and removed a key in a browser
(journal: `(self): key add test`, `key remove test`); a rotate is still to be seen. The reveal page shows only the key with a copy button (4g, done).

The user's rework after trying 4g (4h: copy icon, confirmations, five duration choices, the
365-day bound lifted) is done in 8a, designed in `docs/ARCHITECTURE.md` §13.15 and §13.16. Left: a
new install on rpi-01 and the browser check below, now including a rotate, the copy icon and the
two confirmations.

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

The real pool, read on 2026-11-25 (read-only `describe-user-pool` and `describe-user-pool-client`,
run by the IT-Admin session at the user's request; nothing changed): email is the username
(`UsernameAttributes: [email]`), `AllowedFirstAuthFactors` has `EMAIL_OTP` and `PASSWORD`, MFA off,
self-signup open, no custom attributes, `DeletionProtection` inactive. The native client
`39c7grfrau8i7tvqqkej86sh98` (`gate.client_id`) allows `ALLOW_USER_AUTH` with
`AuthSessionValidity` 3 minutes, no secret, and `ReadAttributes`/`WriteAttributes` unset (Cognito's
default, all writable standard attributes; unverified). The social client
`jsahvqjbm5v8idb6kj577ggbh` allows only `ALLOW_REFRESH_TOKEN_AUTH`, so a person who signed in only
through Google or Microsoft cannot re-authenticate by email code there. Two consequences for the
design: `AttributesRequireVerificationBeforeUpdate` is empty, so an email change would apply
unconfirmed (moot while `email` stays read-only, which it does); and the pool and both clients
are managed in OpenTofu (the itadmin repository, `infra/tofu/stacks/aws/production/cognito.tf`),
so any change to them goes through that repository's plan and apply, never the AWS CLI.

Slices (§13.22-§13.24): 5a to 5d are done (the library move, the form up to the emailed code,
the code step and the save, the e2e fake Cognito with the profile's walks and 11 scenes, cf9109b).
Installed on rpi-01 on 2026-11-25 as `v1.99.9-gcf9109b`, verify green, the unit's IP filter gone
and the listener still on 127.0.0.1. Left: **5e**, a real edit in a browser against the real pool
(the user's), including a Google-only account's case, then the docs.

The real run on 2026-11-25 found a bug: signed in through MicrosoftPersonal, the user's edit
reached a separate **native** Cognito user with the same email (confirmed read-only by the IT-Admin
session: two unlinked users, only the native one modified), because the re-authentication looks
the user up by email. The Google-only case answered correctly. The fix is designed in §13.25 and
comes before 5e: **5f**, the gate forwards `X-Auth-Native-Username` (the token's
`cognito:username`, only for a native sign-in; a new key in the cookie's JSON claims, no
`COOKIE_VERSION` bump; an older cookie fails closed); **5g**, `bb-auth-web` offers the edit only
with that header, asks Cognito for that username, and requires the same username after the code
(`the_rpi01_twin_is_never_written`), and with it the page's sections reordered as the user asked on
2026-11-25: Profile first, then API keys, then Groups, then Where you reach; 5f and 5g ship together; **5h**, the nginx change on rpi-01
first (the user's go-ahead), then the deploy and the real run. From the designer's review of
5b-5d (no WCAG failure): the code page's change list should read "Given name: Augusta (was Ada)"
(the Italian `AccountProfileWas` becomes "prima") and the code field wants `max-width:14ch`;
later, the date hint order, a gap under the read-only phone line, browser defaults for
autocapitalize on names, autofocus on the refused field, and §13.23 to say the edit page's h1 is
"Edit profile".

5f and 5g are committed (98bb8ff, 13d0dc0, the code field's `max-width:14ch` in d90cf10) and
**5h is done**: the nginx lines are in rpi-01's `location /account/` (backup `.bak-5h`), and
`v1.99.9-gd90cf10` is installed there with verify green, on 2026-11-25 with the user's go-ahead. The
IT-Admin session was told, to carry the nginx change into its own record of the host. On 2026-11-25, at the user's request, the IT-Admin session
deleted the native twin (`a3144842-…`), so that email now matches only the MicrosoftPersonal
user. A real 5e run therefore needs an account that signs in by email code.

Federated users, read-only from IT-Admin on 2026-11-25 (`cognito.tf`; AWS: "Amazon Cognito updates
mapped attributes when users sign in to your application through an IdP"): MicrosoftPersonal maps
`email`, `name`, `given_name`, `family_name`, and Google maps `email`, `given_name`, `family_name`.
Any edit of those on a federated user would therefore be reverted at that user's next sign-in, so the
one sentence 5g shows instead of a form is the honest answer, not a gap. A federated edit path would
need the user's decision first: drop those mappings in OpenTofu (edits stick, the automatic name sync
is lost), plus a re-authentication through the social client whose `prompt=login`/`max_age`
forwarding nobody has verified. Not planned.

Inherited from §13.13: every Cognito call carries `timeout_global` of 5 s (assumed, not measured),
no retry, at most two calls per request, so a slow Cognito cannot pin the workers; a test with a
fake endpoint that never answers shows the handler answering within the bound and the worker
serving the next request.

- Done when: tests show a wrong code changes nothing, an email not among the caller's and a
  non-editable attribute are refused before Cognito is called, and no token reaches a response
  or a log; a non-loopback `BB_AUTH_WEB_LISTEN` without the opt-in still refuses to start; and a
  user changes an editable attribute in a browser against the real pool (with the user's
  go-ahead), and it shows in their next token's profile claims.

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

### 8. The account page's look

Covers: R3. First decided to wait for steps 4, 5 and 7; brought forward by the user on 2026-11-24
after trying 4g, with the designer (the UX/UI role created that day). Designed in
`docs/ARCHITECTURE.md` §13.16 (the keys table) and §13.17 (the page), approved by the user on
2026-11-24: rotate as ↻ beside × in each row, "+ New key", the uuid kept as "Account id". The user
then asked for a **header** with the person's identity, the settings (theme, language) and sign
out, the usual pattern, replacing the preferences form at the foot of the page; the designer adds
it to §13.17.

Slices 8a to 8f are done (8f, §13.21: row rules, one control size, ticks in the accent). Then the
shared front end (W13), designed in §13.26 §6 as small slices after 5g: **P** one `pill_link` /
`pill_link_rm` / `back_link` with the console's `act`/`act_rm`/`back` as wrappers; **M** one
`prefs_menu` for both shells; **D** one `page_document` skeleton; **T** `text_field` with
`FieldOpts`, absorbing `account_key_id_field` and the profile inputs; **F** the account page's flat
ground goes, so it wears the console's ground and cards (the user, 2026-11-25); **L** the brand's
logo in the console's bar too, widening the console's CSP `img-src` (the user, 2026-11-25); **H**
one **account menu** in the shared header (the user, 2026-11-25, to slim the header): the bar shows
the person's name (`given_name`, else the email) as a `details/summary` that opens a panel with the
full email, the Preferences (theme, language) expanding inside it, and Sign out at the foot. On
desktop the console's tabs stay visible in the bar, because they are the primary navigation; at
phone width they move into that panel too. The user agreed to this compromise over "tabs always in
the menu". It works with scripting off, replaces the separate Preferences menu (so it absorbs M),
and the designer designs it before any test. Kept
apart on purpose, with reasons in §13.26: the section pattern and the mint row's missing owner
field. Left,
as later items: base.css's accent-color rule sits above a note whose "above" meant the field
rule (move it below); library refusals on the Settings tab are in the file's English words rather
than the page's labels and language (its own slice, sketched in §13.21); one look by hand at the
native "Preferences" tooltip while the open menu's cover is up. Steps 5 and 7 add their forms into this layout later (Profile now first: §13.26).

- Done when: the user approves screenshots of the page in both themes and both languages, at
  desktop and phone width, with the forms of steps 4, 5 and 7 on it; e2e and the scripting-off
  walk still pass.

## Waiting for the user

- Decisions taken without the user, to review (the user asked for autonomy on 2026-11-25):
  - 8b: on `/account` the Sign out link is `BB_AUTH_WEB_LOGOUT_URL` with its `rd` removed
    (`logout_without_rd`), so a person who is not an administrator lands on the sign-in page
    instead of a `403` on the console; no new setting (§13.17).
  - 8b-1: the tester's part went to a Claude tester on Sonnet after two local runs failed (an
    opencode error, then a run that lost its task after compaction), by extending the user's
    Sonnet fallback rule from the coder to the tester.
  - 8c (designer, §13.17): `K::AccountKeyBound` split into three `/account` refusals (bad name,
    shorter than a day, scopes chosen by hand) worded "name" as the field is labelled;
    `KeyDaysWithoutCustom` and `KeyDaysInvalid` reworded as sentences on both surfaces; a "days"
    placeholder on `/account` only (the console's box also takes hours); the box named "Number
    of days" on both; no scope block at all (a hidden `restrict=all`) when there is nothing to
    narrow; the console's `403` keeps its Sign out with `rd` and gains "Go to your account",
    shown even to a vetoed person, who then gets the account page's own `403`; the Italian
    `AccountKeyNotYours` says "rigenerarla" to match the button.
  - 8d (designer, §13.18): the theme contract is untouched (no token added, renamed or removed),
    so no migration guide; three default values change (light `--input-border` and
    `--input-bg`, dark `--input-border`), which the CHANGELOG lists for theme authors, and
    rpi-01's `tokens.css` should set the same three to get the 3:1 field borders. The console's
    brand becomes `ui.brand_name` with an "Administration" line, the version only in the footer;
    header tabs and icons lose their boxes; secondary pills become neutral; light fields white;
    uppercase table headings kept. Before and after images: /tmp/d8d/shots/{before,after}/.
    The logo in the console brand left for a later step (it widens the CSP); the cancel pill on a
    phone fixed in 8d rather than later.
  - 6: the CLI's `user rm` report says "still kept out of APP/SCOPE by email EMAIL" (and "still
    denied by email") where it used to say "also removed from ... (excluded)", which the new
    behaviour made false. The admin GUI says nothing about exclusions on removal, so it is
    unchanged, though §13.8 had said the admin pages would change too.
