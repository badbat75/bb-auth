# Changelog

What changed between releases, and above all what an **upgrade does to people who are
signed in**. That last question is why this file exists at all: the session cookie is a
versioned wire format and exactly one version is ever accepted, so a change to it logs
every user out, and the invariant that says so nominates release notes as the place it must
be announced. There were none.

Versions are the crate's (`Cargo.toml`); packages add a Debian revision
(`1.99.1-1`), which is bumped by `--revision` when the same code is repackaged.

## Standing facts

* **Cookie format**: `bb1`. Unchanged since 1.0.0. While this line does not change, an
  upgrade logs nobody out.
* **Access file format**: `"version": 1`. A file declaring anything else is refused, with
  an explanation, rather than compiled into a different set of grants.
* **Settings file format**: `"version": 3`. Versions 1 and 2 are each refused with a
  sentence naming the fields to move in, rather than a type error three levels down.
* **Rollback**: safe by construction while the cookie format is unchanged, because sessions
  are stateless and no state is packaged. See "Rollback" in [README.md](README.md).

## Unreleased

Builds say 1.99.9 and their commit until the next release (plan W11).

**The cookie format stays `bb1` and the access-file format is untouched, so this upgrade logs
nobody out.** The claims segment gains a key of the gate's own, and that segment names its keys,
which is what makes it a no-logout change: see the section named "the gate names the session's
native Cognito user to nginx" below.

**One nginx change is needed for the new profile edit to appear**, and it is the whole of the
upgrade: the `/account/` location forwards `X-Auth-Native-Username` and every other gated
location clears it. The packages need no order. Without that line the page shows the profile
list and the sentence where the edit pill would be, to everybody, native accounts included.

### Changed: the settings page says why it refused, in the reader's language

* **A refused save names the field, in the language the page is read in.** Every reason the
  settings file can be refused is now a code (`SettingsRefusal` in the library, the 46 of
  `SETTINGS_REFUSAL_CODES`), and the page maps each code to a sentence in English and in Italian
  that opens with the field's visible label: "Landing page: must be on one of the Authorized
  hosts, …" / "Pagina di arrivo: deve stare su uno degli Host autorizzati, …". The input refused
  is the one marked, the group it sits in opens itself, and the message is the first thing in the
  page. It used to print the library's sentence, so an Italian page answered
  "refusing to write: landing_url: its host is not covered by authorized_hosts, …", naming keys
  nobody types into that form (docs/ARCHITECTURE.md §13.31).
* **The page's own refusals read the same way** (a lifetime that is not a number, an empty
  administrator list, a missing app client, a theme the list box does not offer), and a refused
  save keeps the page's title: every response to `/config` is titled "System settings" /
  "Impostazioni di sistema", as the `GET` is, so the browser tab does not change language after a
  save.
* **`bb-auth-adm` and `bb-auth --check-settings` print exactly what they printed before**, byte
  for byte, in English: the sentence is the refusal's `Display`, kept in the library because two
  programs print it, and three golden tests pin it (`settings_refusals_read_as_they_always_have`,
  `settings_leaf_refusals_read_as_they_always_have`, `a_refused_write_reads_as_it_always_has`).
  Checked here by running `bb-auth-adm settings set --landing-url https://evil.example.org/x` on a
  scratch file: it printed that sentence and left the file byte for byte as it was.
* **Five refusals this form cannot produce** (the file's `version`, and four about a social
  button's identity provider) answer with a translated lead naming `bb-auth-adm` over SSH and then
  the gate's own English sentence, because the operator who meets one of those reads it at a
  shell, where those are the words they will see.
* **Italian accents are letters** (`può`, `è`, `perché`), not apostrophes: 22 occurrences in five
  strings were fixed, and `italian_k_strings_write_accents_as_letters` keeps them out.

### Changed: one account menu in the header, on one row, with the logo

* **The bar is one row at every width.** It used to wrap onto a second row below about 820px
  (measured in docs/ARCHITECTURE.md §13.28 §0). The bar now shows the deployment's logo
  (`ui.logo_url`, which the sign-in page already wore and `/account`'s bar already showed, and
  the console's `img-src` admits it), the brand, **four** tabs (Dashboard, Applications, Users,
  Audit) and one pill: your given name, or your first address where the deployment forwards no
  name. Nothing wraps, so a long name, and then a long brand, are cut with an ellipsis, and the
  pill's tooltip carries the whole name.
* **The pill opens one panel**, a `details`, so it opens with no script and closes itself when a
  row navigates away. In it: your name and every address of your roster row, the System settings
  page, "Go to your account", then Preferences (theme and language) nested and closed by default,
  then Sign out. At 800px and below the four tabs ride in that panel too, which is the price of
  one row: the tabs are one tap away rather than on a second line.
* **The Settings tab is now "System settings"**, a row of that panel, and the page's own heading
  says the same. Its URL is unchanged (`/config`), so a bookmark still lands, and nothing on disk
  is renamed: the file, the `bb-auth-adm settings` commands and the settings keys are as they were.
* **The theme's automatic choice is labelled "Auto (system)"** ("Auto (sistema)"): the bare word
  "System" read as the settings page beside it.
* **No new script**, and every page still works with scripting off.

### New: the sign-in page warns before a duplicate account

* **The registration step opens with a warning.** When Cognito answers that no native user has
  the address someone typed, the step that offers "Create account" now says what that does:
  signing up with a code creates a **second, separate account** beside the federated one, and
  asks whether this person usually signs in with one of the buttons below.
* **The deployment's social buttons are repeated under it**, before the divider and the form,
  which stays open: a person who signs in with a provider has the way back in front of them at
  the exact moment they were about to make a twin. The gate decides that the buttons exist,
  exactly as it decides the social section of the email step, so on a deployment with no
  `gate.social_buttons` neither the panel nor the buttons is in the document at all.
* **This is the front-end half of the twin.** Step 5's bug reached a real one: the pool holds a
  native user and a federated one under one address, and the page offered the second without
  saying so (`docs/ARCHITECTURE.md` §13.27).

### Changed: the self-service page's order, its width, and who is offered the profile edit

* **The four sections are in the order a person reads them**: Profile, API keys, Groups, Where
  you reach. Reach and Groups stay read-only.
* **The page takes the console's width.** The account page's own width rules are gone: it rides
  the console's `main` column, one width for both surfaces, with prose capped at 75ch (WCAG
  1.4.8, applied because it costs one rule). The header, the table cards, the Preferences menu
  and the phone stacking are the console's already.
* **The profile edit is offered to a native sign-in only.** The pill appears when nginx forwards
  `X-Auth-Native-Username` (the section below), and the pool is asked by that **username**, never
  by an email: the form names no address and a posted email field is refused before any call.
  After the code, the IdToken Cognito returns must carry the same `cognito:username`, so a
  challenge or a token for anybody else is a `403` that writes nothing. That binding replaces the
  email check that let a native twin through. The code page names Cognito's masked destination,
  and the code field is capped at the measure the id and duration fields use, because a
  full-width box reads as a field for a sentence (§13.26).

### New: the gate names the session's native Cognito user to nginx

* **A `204` carries `X-Auth-Native-Username`** for a **native** sign-in: an `id_token` with no
  `identities` claim. Never for a federated sign-in, never for an API key, never for a cookie
  minted before this version, which names no username.
* **It travels in the cookie, as a `native_username` key of the JSON claims segment, and
  `COOKIE_VERSION` stays `bb1`.** That segment is a self-describing object, so a key added to it
  is not a format change: a binary that never wrote the key verifies a cookie that carries it,
  and this binary names no username for a cookie minted before it existed. The key is taken out
  on the way back, so it never becomes a profile claim.
* **The name is defined once, in the library, and its header is reserved.** `compile_profile_claims`
  refuses every claim spelling that would derive `X-Auth-Native-Username`, because a self-asserted
  claim arriving on the header the profile edit acts on would be a pool name an attacker typed.
* **It authorizes nothing.** No field of the access file mentions it, and it is not an
  `identity_attrs` entry: it is the name the self-service profile edit acts on, and nothing else
  (§13.25).

## 1.99.8 (2026-11-25, pre-release)

**Pre-released on 2026-11-25 as `v1.99.8`**, the first tag since 1.0.0 and a **pre-release** of
2.0.0, by the user's decision of that day: the tag names the tree it was cut from, it is pushed
to GitHub with its GitHub release marked pre-release (1.0.0 stays the latest release), and its
packages are installed on rpi-01. It is a candidate for 2.0.0 and carries that content: the findings of an architecture and process review, addressed; the gate's whole
Cognito wiring and the estate it serves moved out of the environment and into the settings
file; and a confirmation step in front of the five settings that can stop people getting in.
The number says what shipped, not what comes next: the configuration surface moved far enough
in one window that calling it 1.2.0 would have undersold what an upgrade has to do.

**A deploy no longer bumps the version (plan W11, changed on 2026-11-25).** `Cargo.toml` stays
1.99.8 after the release, so every build between this tag and the next says
`v1.99.8-g<commit>`: what tells two deploys apart is the commit in the build string, not the
number.

**A version gets a section of its own here once it is tagged, as a release or a pre-release.**
That is what this section is, and it reverses the rule this file carried before, which said a
candidate is not tagged and that this section would become `## 2.0.0` on the day 2.0.0 was
tagged: the user tagged the candidate as a pre-release instead of waiting for it. The same rule is
what took 1.1.0 out of this file: it was built, deployed and never released, with no tag and no
artefact anybody could have installed from, and the single host that ran it was running a
working tree. It had a section here as though it had shipped, which is a version number
somebody could have gone looking for. What it contained is the first section below, because
this is the release that actually ships it.

The practical consequence is worth knowing before you need it: **an untagged build's handle is
its commit**, which every binary bakes in and `--version` prints. That string changed shape in
this release for exactly this reason: it used to be the crate version followed by
`git describe`, and describe anchors on the last **tag**, so an untagged candidate read
`bb-auth 1.99.1 (v1.0.0-18-g0a8d129)` — the true version, then a string opening with a version
one minor number and eighteen commits out of date. It now reads `bb-auth v1.99.1-g0a8d129`:
cargo's version, which cannot be wrong, and the commit, which is what a rollback checks out
when there is no tag to check out.

**The 1.99.x numbers before this tag name packages that were installed on hosts, and none of
them was tagged**, which is why they have no section of their own. Newest first: 1.99.9 went to
rpi-01 on 2026-11-25 from `gb9d7100`, carrying everything below except the two sections at the
top of this list, and was replaced the same morning by a 1.99.8 package of the same code
(`g75f788a`), a downgrade by number only. 1.99.8 was installed on 2026-11-24 from `gc1a9fd8`,
carrying everything below except the first seven sections, from `gate.landing_url` down to a
key's duration being one of five; that package is not the bytes this tag names, and the commit
in the build string is what tells them apart. 1.99.7 was spent by a deploy on 2026-10-17 from
`g4041845`, carrying everything below except the two sections above the audit's. 1.99.6 was
spent by a deploy on 2026-09-11 from `gb855ed2`, carrying everything below except those two and
the section named after 1.99.7. 1.99.5 was spent by a deploy on 2026-09-11 from `g15ae13e`,
carrying everything in the section named after it except the Settings page opening folded.
1.99.4 was spent by a deploy on 2026-09-10 from `gfd77f1f`, carrying the audit and nothing of
what the section below calls new after it. 1.99.2 was spent by a deploy: a build carrying it
went to a host on 2026-08-20 from `g3b40e77`, which had the `form-action` fix below and nothing
of the `403` work. 1.99.3 is left behind one step along, and without the same claim being made
about it, because the claim is not the point: the refusal page's sign-out link changed after
that number was written, so the bytes under it are not the bytes under this one, whether or not
any host ever ran them. Reusing one of these numbers for bytes nobody installed would put two
different sets of bytes behind one version string, which is the failure the commit in the
version string exists to catch rather than to cause.

**Nothing here changes the cookie format or the access-file format, so no upgrade in this
release logs anybody out.** The settings file goes from version 1 to version 3, which needs an
edit before the binaries land: see "Upgrading" below.

### New: `gate.landing_url`, where a sign-in lands when nothing named a place

* **One new settings-file value, `gate.landing_url`**: where a sign-in with no `rd` lands.
  Empty, the default, keeps the old behaviour, which is the **caller's root**: the host that
  served the sign-in page. On a deployment whose sign-in host redirects its own root to
  `/auth/login`, that is a loop after every logout, and it is also where a bookmark to the
  sign-in page lands. A present `rd` still wins, so every `401` round trip ("sign in, and be
  where you were") is untouched; a **rejected** `rd` still falls back to the sign-in page; and
  a logout with nothing said still ends at the sign-in page, because the sign-in it leads to is
  what lands on the landing page.
* **It is refused off the estate.** Absolute `https://`, printable ASCII, no userinfo `@`, no
  backslash, and its host must be one `gate.authorized_hosts` covers, or `compile_settings`
  refuses the file. The host check is the one that matters: `safe_rd` refuses a landing page
  outside the authorized hosts at every login, so such a value is today's loop with a setting
  standing beside it saying it is fixed. Refusing it on the way to disk is what both editors can
  still say out loud.
* **Not a guarded change**, and the five stay five: it is read after the token is verified and
  the cookie is built, deciding only where a browser that is already signed in is sent, so the
  worst a wrong value costs is a `403` landing and the editor keeps the session they would undo
  it with.
* **Both editors, and the checks**: `bb-auth-adm settings set --landing-url URL` (an empty value
  unsets it) and `settings show`, which prints `(caller's root)` when empty; the console's
  Settings tab has a "Landing page" field beside the refusal page; `bb-auth --check-settings`
  prints a `landing page:` line naming the value or what an empty one is.
* **Deploy first, then set it; unset it before rolling back.** There is no settings-file version
  bump, and an empty value is **never written**, so a host that never set one is untouched and
  rolls back with no step at all. `GateSettings` refuses unknown keys, so an **older binary
  refuses a file that carries the key**: on a SIGHUP it keeps the live values, at a restart it
  does not start. So on a host that does set one, install all three packages before setting it,
  and run `bb-auth-adm settings set --landing-url ''` before any rollback to an older binary.

### Changed: the Preferences menu closes on a click outside it

* **The menu closes on a click anywhere outside it**, on the console and on `/account` alike, in
  CSS and with no script: while the menu is open its trigger draws a transparent box over the
  whole viewport, so a click outside the panel lands on the `summary` itself and the browser
  closes the disclosure the way it always closes one. Nothing is added to any page's script, so
  it works with scripting off and `/account` keeps its "no handler at all". The open trigger
  wears the accent border for as long as it is open, which is what keeps its hover look from
  flickering as the pointer crosses the panel's edge.
* **Escape does not close it, deliberately.** The control is a disclosure, whose keyboard
  contract is Enter and Space, and Escape would cost a script on a page that carries none. The
  click that closes the menu does nothing else, so a click meant to dismiss never navigates by
  accident: a second click follows the link.

### Changed: removing a user keeps them out of the scopes that excluded them

* **`remove_user` rewrites a uuid in a scope's `excluded` to the row's primary email**
  instead of dropping it, exactly as it already does for a `denied` entry: an exclusion is a
  veto, and dropping it lifts it. The sequence is ordinary housekeeping (keep somebody out
  of one area, tidy the roster afterwards), and with an `authenticated` scope anywhere in
  the file that person re-registers on Cognito under the same email and walks back into the
  scope they were just shut out of. This changes what `bb-auth-adm user rm` and the admin
  GUI write. A row with no email has no email to leave behind, so its entry is dropped as
  it always was, and a `@group` entry stays a group reference.
* `bb-auth-adm user rm` reports the rewrite as what it is: "LABEL: still kept out of
  APP/SCOPE by email EMAIL", and "still denied by email EMAIL" for the veto, where a swept
  grant keeps the old "also removed from" line. The old wording said the person was removed
  from the very scope that was keeping them out.

### Changed: the theme, reviewed: fields carry a border, and only what floats casts a shadow

* **A field's border carries the field.** Three *values* in the built-in `theme.css` move, and no
  token is added, renamed or removed: light `--input-border` `#d8d9e4` to `#8a8c9e`, light
  `--input-bg` `#f6f7fb` to `#ffffff`, and `--input-border` `#3a3a48` to `#6e6e86` in both dark
  arms. The border is what says a box is a field, and the old one measured 1.40:1 against the card
  it sits on (1.44:1 in dark), under the 3:1 WCAG 2.2 SC 1.4.11 asks of that boundary; a pale field
  on a pale card read as disabled. The new ones measure 3.32:1 on `--card` and on their own fill
  and 3.10:1 on `--bg` in light, and 3.26:1, 3.49:1 and 3.64:1 in dark, and the fill is the card's
  own white so the border carries the field alone. `fields_have_a_three_to_one_border_in_every_arm`
  reads the values out of the file and computes the ratio, so a value that drifts back under 3:1 is
  a red test, not a design note.
* **Only what floats casts a shadow.** The six resting surfaces (`.card`, `.panel`, `.msg`,
  `.flash`, `.err`, `.secret`) lose their drop shadow, and the sign-in card and the Preferences
  menu keep theirs from their own layout. A shadow says "this floats above the page", which those
  two do and a column of sections does not: stacked down a page, six shadows added a grey haze
  between panels and made a column of sections read as a pile of cards.
* **The ground is painted once.** `body`'s gradient is `no-repeat`, so the glow sits at the top and
  the flat `--bg` it fades into carries the rest of the page. It repeated: `html{height:100%}`
  makes the positioning area one viewport tall, so any page longer than the window showed a hard
  band of a second shade one screen down.
* **A pill is no longer a loud blue box.** A secondary pill reads `--text` on the same 3:1
  `--input-border` border a field has, so it still reads as a control on every surface, and shows
  the accent only on hover; `.pill.on`, the selected tab, is the only accent fill, as it was. A
  pill in a `nav` loses its box and reads as a tab, which is what the five tabs are. Links in a
  table cell or a list item are underlined on hover only: a roster of emails was a column of blue
  rules, and an underline is what says a word is a link when there are sentences around it.
* **The header meets the content.** The bar's content edge is `main`'s, where the bar had no inner
  padding and its brand started 16px left of every heading under it, and on `/account` the bar is
  that page's own 620px column, so the brand sits over its column instead of far to its left. The
  header's pills are smaller, a pill beside a button takes the button's height (on a phone too,
  where the phone rule was shrinking it back), and the dashboard's six count tiles sit on one row
  at desktop width and wrap evenly on a phone.
* **Both bars name the deployment.** The console's brand was the binary's name over the version. It
  is now `ui.brand_name`, falling back to `bb-auth`, the same name `/account` already showed, over
  a second line saying what this surface is: "Administration" ("Amministrazione" in Italian). The
  version stays in the footer, where the full build string was already printed and where a person
  reading a deploy looks.
* **Two small things on `/account`.** The account id is one unbroken token (`code.uid`,
  `white-space:nowrap`, a smaller size under 640px), so on a phone it moves to its own line whole
  instead of breaking in the middle at a hyphen. And a key field that carries a refusal stops
  showing its hint, because the refusal says in a sentence what the hint said in a fragment, and
  the two side by side read as two complaints.
* **The headings have a scale.** `h1` is 1.5rem, line-height 1.25, weight 650, letter-spacing
  `-.01em`, `margin:0 0 6px`; `h2` is 1.0625rem, weight 600, `margin:28px 0 10px`. `h2` had been
  1rem against the page's 15px body text, so a section heading read as a paragraph and every page
  was one flat column: a size gap is what says "new section" with no rule and no icon. `BASE_CSS`
  is emitted by both HTML programs, so the gate's four pages, the console and `/account` all take
  it; the sign-in page's brand heading is that page's own arrangement (`.brand h1` in `auth.css`)
  and keeps its own size. `the_headings_follow_the_type_scale` pins the values. For theme authors:
  no token changed, these are literal sizes in the component file, so a token file has nothing to
  follow.
* **For theme authors**: no token is added, renamed or removed, so a token file written for the
  last release renders as it did, and nothing in it needs removing. Three *defaults* moved, and a
  file that pins them keeps the old look, so to follow: in `:root`, `--input-bg:#ffffff` and
  `--input-border:#8a8c9e`, and in both dark arms `--input-border:#6e6e86`. Nothing else here needs
  a line in a token file, because the rest of this section is rules that read existing tokens, and
  they reach an operator's file untouched.

No cookie, access-file or settings-file format changes, and nothing here logs anybody out. The
three stylesheets are emitted by both HTML programs, so the gate's four pages, the console and
`/account` repaint together.

### Changed: the account page says what each section is for, and the console's 403 points at it

* **`/account` opens with one lede**: every address of the caller's roster row, and on the line
  below the uuid they resolve to, labelled "Account id". The "signed in as" paragraph is gone,
  because the header has named the person since the section above, and one fact in two places is
  one fact that starts disagreeing with itself. A caller with no roster row is told so in that
  same place: this URL is an `authenticated` scope, so "bb-auth has no roster row for you" is a
  page a real person reaches, not a defensive one.
* **Each of the four sections says what it is for**, in a sub-line under its heading, and each
  empty state names what is missing ("You are in no group.", "Your sign-in opens no application
  yet.") where a bare "None." said only that something was absent. A profile claim the
  deployment configured and the proxy did not forward reads "not provided": a bare colon after
  the claim's name reads as "your name is empty", which is a statement nobody made.
* **The lists are plain.** Reach is one flat list of `app/scope` pairs in the file's order, as
  the console's person page lists them, where it was a list nested under each application's
  name: the question a person asks is "where can I go", and each answer is one place. The groups
  heading is the page's own "Groups", not the console's "User groups", which names the file
  section an administrator edits.
* **The `/account` key form refuses one field at a time.** A bad name says what a name is, and a
  key shorter than a day says so, each on the field at fault: the sentence these replaced
  (`AccountKeyBound`) named the id and the window whatever was wrong, so a person who typed
  `My Laptop` read about durations. On **both** surfaces the days box is now named "Number of
  days", which contains the placeholder's word where "Custom duration" named nothing on screen,
  and the two refusals beside it say what to write instead (`KeyDaysWithoutCustom` named a
  "Custom" option that no longer exists; `KeyDaysInvalid` asks for a whole number of days, at
  least 1). `/account` carries a "days" placeholder in place of the lone hint, because that box
  takes a number and nothing else; the console keeps its `<n>d · <n>h` hint, because its box
  also takes `12h`. When an account has no scope to narrow to, the scope block is left out and a
  hidden `restrict=all` takes its place: a choice of one is a control that can only be answered
  wrong.
* **The console's `403` to a signed-in person who is not an administrator names that person in
  the bar**, which was empty there on the one page whose sentence is about its reader, **and ends
  in one action**: a "Go to your account" pill to `/account`. The console has no page that person
  may open, and the self-service page is theirs by design, so the refusal ends in a way forward
  rather than in two icons.

No cookie, access-file or settings-file format changes, and nothing here logs anybody out.

### Changed: the console and `/account` wear one header, and it names who is signed in

* **One bar, both surfaces.** The console's bar is factored out as `top_bar` and the
  self-service page wears it: the operator's logo and brand name (not a link, since this page
  is the only one its visitor came to the estate for), an empty tabs nav, the identity, the
  Preferences menu and Sign out. Two copies of one bar is how two surfaces drift a pixel at a
  time, each editor changing the file in front of them.
* **The bar says who is signed in.** The console said it only in its footer, below the fold on
  a long page. It sits with the session controls now: the forwarded `given_name` claim when the
  deployment configures that claim, then the first address of `X-Auth-Email` ("Bot ·
  `bot@example.com`", the address alone when there is no name), in `nav.acct` and as the first
  line of the Preferences menu, which is where it survives on a phone. The footer keeps the
  version and says nothing else, because one fact gets one home.
* **Preferences and Sign out are icons**, the estate's shared `pill ico` component (sliders,
  and an arrow leaving a bracket), each named by text a screen reader reads and no browser
  shows, with the same words as the pointer tooltip.
* **The theme and language form at the foot of `/account` is gone: it is the header's
  Preferences menu.** The menu is the console's as a browser with scripting off sees it, with
  **no handler at all** and the Apply button always present, because here that button is not a
  fallback, it is the only way. The write is what it was: one submit, one `302` setting the
  `theme` and `lang` cookies, the same names the console writes.
* **On `/account` the Sign out link is `BB_AUTH_WEB_LOGOUT_URL` with its `rd` parameter
  dropped.** That `rd` is the console's round trip, so a person who is not an administrator
  followed it to a `403` on the console. The link can only lose a parameter, never gain one, so
  it names no landing place the operator did not already write, and the gate's `safe_rd` still
  decides where a logout lands: the person signs out and stops on the sign-in page. The
  console's pill keeps the URL as written, and an unset variable is no pill on either surface.
* **Each `/account` confirmation page carries one `h1`**, naming the action ("Rotate key",
  "Revoke key"), where it read "Your account" and then the action. The bar answers "whose
  account is this" above the page, as it already does on the console.

No cookie, access-file or settings-file format changes, and nothing here logs anybody out.

### Changed: a key's duration is one of five, `/account` is a key table, and an empty `duration` is refused

* **A key's duration is now chosen from five, on both editors.** The console's mint and edit
  forms and `/account`'s mint offer **1 year, 6 months, 3 months, a number of days, no expiry**,
  posting `duration` = `365d`, `182d`, `91d`, `custom` (with `days`) or `never`. The presets are
  the file's own strings, so `bb-auth-adm`, the gate and every existing file see nothing new, and
  the console's custom box still takes the whole grammar (`40`, `40d`, `12h`). 182 and 91 days are
  exactly 26 and 13 weeks, so a key minted on a working day expires on a working day.
* **Breaking, for a client that posts the form itself: an empty `duration` is refused.** It used
  to mean "no expiry" (`parse_duration("")` is `Dur::Never`), so a form that lost its field minted
  a key that never dies: the one outcome nobody asked for, and the one a person cannot undo from
  the page. A `POST` that omits `duration` or sends it empty is now a `400` naming the field, on
  the console's mint, the console's edit and `/account`'s mint alike. Two refusals stand beside it
  for the same reason, each a form that contradicts itself: a number in the days box while a
  preset is picked (`duration=365d&days=40`), on all three, and on `/account` alone, scopes
  ticked while "all scopes" is picked.
  Nothing stored changes: the file's grammar is untouched, so `bb-auth-adm key add --duration` and
  every existing file keep working.
* **The 365-day self-service bound is lifted: a person may mint their own key that never
  expires.** The user's decision, 2026-11-24. The one-day floor stays, because a self-service key
  that dies before anybody has used it is a support ticket and not a credential, and so do the ten
  keys per account and the `[a-z0-9-]{1,32}` id grammar. An administrator's own pages were never
  bound.
* **`/account`'s keys section is the console's key table**, with the console's row actions: a
  `rotate` pill and a revoke icon (an `×`), each a link to a confirmation page (`GET
  /account/keys/rotate?id=`, `/account/keys/remove?id=`) whose `POST` is the only thing that
  writes, so a misclick costs nothing and an id that is not on the caller's row is a `404` naming
  nothing. "+ New key" opens `GET /account/keys/new`, the same page with one row more holding the
  form, and a refused mint keeps that row with the values as posted. At ten keys the `+` is the
  sentence that says why there is none.
* **The reveal's copy control is an icon**, the estate's shared `pill ico` component, its name
  carried by text a screen reader reads and no browser shows. It is still revealed only by
  `COPY_SCRIPT`, and only in a secure context: with scripting off, on plain HTTP, or with no
  `navigator.clipboard`, no button shows and one click on the key still selects all of it.

No cookie, access-file or settings-file format changes, and nothing here logs anybody out.

### Changed: the bearer reveal shows only the key, with a copy button

* **The page that reveals a bearer now carries the estate's one script.** A freshly minted or
  rotated `bbk_` key shows the key alone, with a copy button, on the admin console and on
  `/account` alike. Copying needs scripting, so the rule is "no page needs a script" rather
  than "no page carries one": `COPY_SCRIPT` is a compile-time constant, is emitted on that page
  only, and is allowed by that response's CSP by its hash. With scripting off, in a browser that
  is not a secure context, or with no `navigator.clipboard`, no button shows and one click on
  the key still selects all of it, and the hint says how to send it: the word `Bearer`, a space,
  then the key. No cookie, access-file or settings-file format changes.

### New: the self-service page is part of `bb-auth-web`, at `/account`

**Upgrade note: a GUI mounted at the root no longer starts.** The self-service page is mounted
beside the admin console, and a console at `/` is every path, leaving no prefix beside it, so a
`BB_AUTH_WEB_BASE_PATH` that is unset, empty or `/` is now a **fatal startup** naming both prefixes
and saying "Mount the console under a prefix". Set it to a prefix, for example `/admin`. The env
template the install writes names `/admin`, so a host installed from the template needs nothing;
a hand-written env file that left the variable out is the one that fails, and it fails before it
binds a port, so nothing is served half-configured.

**What moved.** The page one signed-in person uses for **their own** account is now a section of
`bb-auth-web`, at `/account` (`BB_AUTH_WEB_ACCOUNT_PATH`, default `/account`), on the console's own
listener and unit. It is the console's trust model with the privilege taken out: the proxy secret
is checked first on every request, exactly as it is on the admin URLs, the identity comes from the
`X-Auth-Email` nginx injects and nowhere else, and `web.admins` is **not** read at all, because an
administrator there is one more person looking at their own account. That is why the prefix is
dispatched *ahead of* the allowlist, and why the two prefixes must be siblings: a page nested
inside `/admin` would answer the console's URLs as the page, so `compile_account_path` refuses
equal, nested and containing at startup. It shows the caller's addresses and roster uuid, then four
read-only sections: where they reach (the applications and scope names, grouped by application,
never a URL), the groups naming them, their API keys (id, expiry date or "never", and the
restriction, never the hash or the bearer) and the profile claims the deployment forwards, decoded.
A `403` answers a denied identity, a `401` when nginx sent no identity. The page wears the `ui`
section like the console does, in a centred card, and its theme and language selector is a form
with a submit button and no handler at all: one submit answers one `302` setting the `theme` and
`lang` cookies, the same names the console writes, so a choice carries between the two surfaces on
one host.

**`bb-auth-me` is gone, and there is nothing to uninstall.** The fifth target, its `[[bin]]` and
its file are deleted, and its tests moved with the page. It was **never packaged**: no `.deb`, no
unit, and the build and package scripts never knew it, so an upgrade installs nothing new and
removes nothing from a host. Nothing here changes the cookie, access-file or settings-file format.

### New: bb-auth-web requires a secret only nginx sets, and cannot read the HMAC key

**Upgrade note, and it is the one section here with work in it: after installing, every request
to the admin GUI is a `403` until nginx sends the secret.** Add
`include /opt/bb-auth/etc/bb-auth-web.nginx;` inside the GUI's `location`, then
`systemctl reload nginx`. Do both in the same maintenance window as the package: the install
restarts the service, and from that restart until the nginx reload every page of the GUI answers
`403`. The file to include is written by the install from the secret in the GUI's env file, so it
is there to include before nginx is touched, and the `403` page says the request did not come
through the proxy.

**Why.** `bb-auth-web` believes `X-Auth-Email`, and its trust model said nothing reaches that
port except nginx. Loopback is not that: every user and every other service on the host can reach
the port, and each of them can write that header, so a forged one got the admin dashboard, `200`,
and with it the roster with every email and uuid, the settings, and the audit with every sign-in's
address, user agent and account. So every request, `GET` or `POST`, now carries
`X-BB-Web-Secret`, which nginx sets from `BB_AUTH_WEB_PROXY_SECRET`, and a request whose value
does not match is a `403` answered before the identity header or the settings file is read. The
value is required at startup (at least 32 characters of `[A-Za-z0-9_-]`, which is what lets it go
into an env file, a shell, a header and an nginx line with nothing to quote), compared in constant
time, and never printed, logged or rendered: the startup banner says only "proxy secret: set". The
install appends a generated 44-character value to `bb-auth-web.env` when that line is absent, and
never rewrites one that is already there.

**The GUI can no longer read the HMAC key.** `bb-auth.env` is `root:bb-auth 0640` and the GUI is
in group `bb-auth` (it has to be, to restore the access file's group), so the process a stranger's
browser talks to could read the key that signs every session cookie and mint a cookie for anybody.
Its unit now sets `InaccessiblePaths=/opt/bb-auth/etc`, and that is safe because the binary reads
nothing under that directory at run time: systemd reads an `EnvironmentFile=` before the sandbox
exists. Nothing to do for that half, and nothing here changes the cookie, access-file or
settings-file format.

### Carried by 1.99.7: Cognito's `acr` and `amr`, and a reload that could hang a worker

**Nothing to do before November 2026.** AWS adds an `acr` string and an `amr` array to every
Cognito token from 2026-11-04, ramping to every user pool by 2027-02-28. The gate already
tolerated both, because it reads the claims it needs by name and keeps the rest as raw
values; a test now signs a token carrying them and requires the login to go through, so a
stricter claims struct cannot land without failing it. Configured as a profile claim, `acr`
is captured like any string, and `amr` costs that claim and never the login. The gate does
not read the discovery document, so the new members there do not reach it.

**A token's validation took the settings lock twice on one thread.** A SIGHUP reload queued
between the two reads could leave that worker waiting forever, since std's `RwLock` puts a
new reader behind a waiting writer. It now reads once.

### Fixed: an administrator with a second email was locked out of the admin GUI

**Nothing to do.** A person `web.admins` names and the admin GUI refused is admitted again by
this build, with no config, settings or nginx change: the list is written exactly as it was.

The gate names an identity by **every** email on the caller's roster row, joined by a single
space (`identity_headers`), since a person is a uuid plus the addresses that resolve to it.
`bb-auth-web` compared that whole string against `web.admins`, so a row carrying a second
address arrived as `admin@x.com other@x.com` and matched nothing: the lockout landed on the
one interface that edits the list naming its own administrators. The header is now read as
the list it is, and any one address in it admits the request. The `403` still shows the
header as it arrived, since debugging a lockout means seeing what nginx actually sent, and
nothing here changes the cookie, the access file or the settings file's version.

### New: bb-auth-me, the self-service page (not packaged yet)

**Superseded:** this target no longer exists. The page is a section of `bb-auth-web`, at
`/account`: see the section above the proxy secret's. What follows is what shipped at the time.

**Nothing to do, and nothing installed.** A fifth target, `src/bin/bb-auth-me.rs`: the page one
signed-in person uses for **their own** account, so that minting a key and reading or editing a
profile stop needing an administrator. It is `bb-auth-web`'s trust model with the privilege
taken out: loopback, plain HTTP behind nginx, identity from the `X-Auth-Email` nginx injects
and nowhere else, no token validated, no cookie minted, no secret held, `web.admins` not read.
It shows the caller's addresses and roster uuid, then four read-only sections: where they reach
(the applications and scope names, grouped by application, never a URL), the groups naming them,
their API keys (id, expiry date or "never", and the restriction the key carries, never the hash
or the bearer) and the profile claims the deployment forwards, decoded, a configured claim with
nothing forwarded shown as "None.". The page wears the settings file's `ui` section like the
other two HTML programs: brand name and logo, the operator's stylesheet, and `ui.theme` as the
default theme, in a centred card. The person can choose only the theme (light, dark, system) and
the language (English, Italian, auto), from a selector with a submit button and no script; one
submit answers one `302` that sets the `theme` and `lang` cookies, the same names `bb-auth-web`
writes, so a choice made in one program carries to the other on one host. A `403` answers a denied
identity, a `401` when nginx sent no identity, and a `500` naming the setting when the deployment
injects none. No package and no unit yet, so an upgrade installs nothing new.

### New: the audit, and an Audit tab to read it

The gate now records what it has answered, and `bb-auth-web` grew a fifth tab that reads it
back: newest first, filtered by person, by credential (social, Cognito account, API key,
session) and by period, paged like every other list here and needing no JavaScript for any of
it. Refresh is a link to the same address, because the page reads the file on every request.

**It is on by default at `/var/log/bb-auth/audit.jsonl`, and there is one thing to know before
upgrading: the events move.** With an audit file, a sign-in, a sign-out and a refusal go to
that file *instead* of into the journal, because the same event in two places is one somebody
has to reconcile by eye. `journalctl -u bb-auth` keeps everything else it ever had (startup,
configuration, reloads, failures), `journalctl` at `BB_AUTH_LOG_LEVEL=debug` prints the
request lines regardless, and `BB_AUTH_AUDIT_FILE=` (empty) turns the file off and puts the
journal back exactly as it was. If the file cannot be written the events fall back into the
journal on their own, with one line saying so.

What it records is **authentication, not traffic**: sign-ins, sign-outs, refusals, and the one
grant worth a line, which is somebody Cognito vouches for walking into an `authenticated`
scope while being in no `users` entry. Not the ordinary allowed request: the gate answers an
`auth_request` for every asset of every page, so that is nginx's log and always was, and it
has the URL, the status and the byte count of every request. Refusals that carry no
credential at all are not recorded either, being what every signed-out browser gets on its way
to the login page. A refusal repeated inside five minutes is recorded once.

The file is JSON, one object per line, with a schema version on every one, and it rotates
itself at 4 MB onto `.1`, so the pair cannot exceed 8 MB whatever happens. Nothing about it
can cost a login: a write that fails is one journal line and the request proceeds.

Two deployment notes. The gate's unit gains `LogsDirectory=bb-auth`, so **the unit file has to
land and `systemctl daemon-reload` has to run** before the gate can write anything (the
package does both); until then the audit fails soft and the events stay in the journal. And
`bb-auth-web` reads that directory through the `bb-auth` group it already belongs to for the
access file, so a GUI host needs no new privilege. One credential is recorded less precisely
than it might be: a session cookie says who you are and not how you proved it, so a refusal
carrying one reads "Session" rather than "Google". Stamping the provider into the cookie is a
cookie-format bump, and a cookie-format bump logs everybody out. The sign-in event carries the
exact answer, which is where the question is really being asked.

### Carried by 1.99.5: where a request came from, how long it is kept, and in which time zone

Every audit row can now say where its request came from: the client's **address**, nginx's
own **id for the request** (which finds that request's line in nginx's access log, where
everything the audit leaves out is), the client's **user agent** (cut at 256 bytes), and, on a
sign-in, the Cognito **account** behind the token (`sub`), which is what tells this month's
owner of an address from last month's once an account has been deleted and registered again.
The Audit tab shows them in a Client column and under the name, and its filter box finds a
row by any of them, so an address pasted from a firewall's log or an id from nginx's lands on
the row. The credential moved under the event to make room, and reads as one fact with it:
"Signed in, Social Google".

**The address and the request id are off until you say which headers to believe**, and that
is the one thing to know before switching them on. The gate listens on loopback, so an
address is only as true as the nginx in front of it, and a header nginx does not overwrite is
whatever the client sent. Two new settings name the headers, `audit.client_ip_header` and
`audit.request_id_header` (`bb-auth-adm settings set --client-ip-header X-Real-IP
--request-id-header X-Request-ID`, or a new group on the Settings tab), and the README's
nginx recipe sets `X-Real-IP $remote_addr` and `X-Request-ID $request_id` on the three
locations that reach the gate, plus a `log_format` carrying `$request_id`. A list such as
`X-Forwarded-For` is read from its last entry, the one nginx added; neither setting may name
`Authorization`, `Cookie` or `Proxy-Authorization`. The user agent needs no setting, being
the client's word about itself and recorded as nothing more.

They live in a **new `audit` section** of the settings file, with the two below, and that
has one convenient consequence: an older gate keeps an unknown top-level key rather than
refusing the file, so the section can be written before the binaries that read it land.

A refusal repeated inside five minutes is still recorded once, but the window is now per
address as well: the same key refused from a second machine is a second row, and usually the
interesting one.

**How long the audit is kept is now a setting**, two in fact, each an amount and a unit of
time (`weeks`, `months`, `years`) or of space (`MiB`, `GiB`). `audit.rotation` is when the
live file moves onto `.1` (at a size, or when its oldest event reaches an age), still keeping
only the last one; `audit.retention` is the most kept across the two files (no event older
than an age, or the pair never over a size). The defaults, `4 MiB` and none, are exactly what
the audit did before. **At least one of the two has to be a size**, or a flood of refusals could
fill the disk, and a file with both in time is refused with a sentence saying so. A retention in
time is applied hourly, at startup and on every reload, so a quiet deployment still forgets an
address on the day it said it would, and the Audit tab shows nothing past it even in the hour
between. For personal data such as addresses this is the setting that answers "for how long".
The audit's files are also read backwards in blocks now, so a rotation set to a gibibyte costs
the Audit tab no more memory than one set to four mebibytes.

The Settings tab's groups **fold**: each heading opens and closes its group (a `details`, so no
script), and "Expand all" / "Collapse all" at the top are remembered per browser like the
language and the theme, so a page somebody opened stays open after a save. **Since 1.99.6 the
page opens folded**, reading as its five headings; 1.99.5 opened it expanded. A group holding a
refused field opens whatever the preference says.

The Audit tab reads its times in UTC (as before, and still the default), in the **host's**
zone, or in one you name (`Europe/Rome`, `+05:30`), chosen beside the filters and remembered
per browser like the language and the theme. "Local" is the host's zone and not the
browser's: no request header carries a browser's zone, and no page here may need a script to
ask. The zones come from the host's own database through one new dependency, `tz-rs`, which
has none of its own and bundles no zone data; a host without `tzdata` offers UTC and says so
above the table.

Nothing here changes the cookie, the access file or the settings file's version: the new
section is additive, and so are the four audit fields, whose schema stays `v: 1` (an older
reader ignores them, a newer one reads an older line without them).

### Fixed in 1.99.2: `form-action` blocked every Chromium login

**If you are running a 1.99.1 build, upgrade.** Between 1.99.1 and this build, the
`Content-Security-Policy` the gate's pages carry named `form-action 'self'` as a constant,
and that blocks the last hop of every login in a deployment whose sign-in page and landing
host are different hosts, on any Chromium browser. Firefox and Safari are unaffected, which
is what made it look like something else.

The shape it takes is the worst one available. Both gate pages hand the id_token over with a
real top-level form `POST` to `/auth/session`, which is same-origin and passes; the response
is a `302` onto wherever the visitor was going; and Chromium applies `form-action` to the
**redirect target** of a form submission, not only to the URL the form names. So the session
is minted, the cookie is set, the journal records `session granted`, and the browser silently
cancels the navigation: the person is signed in and is looking at a spinner that will never
finish, with nothing on screen and nothing in the log to say why.

`form-action` is now derived from `gate.cookie_domain`, like everything else in that policy:
`'self' https://<domain> https://*.<domain>`. Nothing to configure, and no new setting. The
cookie domain is the source rather than `gate.authorized_hosts` because the settings file
already refuses a file whose authorized hosts that domain does not cover, so it is a superset
of every host a login can legitimately reach, and because a host pattern may be a glob that no
CSP source expression can express. Where no cookie domain is set the directive stays `'self'`,
which is correct: a host-only cookie has no second host to survive to. The admin GUI keeps
`'self'` and always did, since it only ever redirects to itself. This is not a change to where
a login may land: `safe_rd` and `gate.authorized_hosts` decide that, exactly as before.

### Carried by 1.99.3: the `403` and the page it lands on

1.99.3 is the number the rest of this section was first built under, and it is written down
because a candidate's handle is its commit while the number is the only thing a host reports
about itself. It carries everything from "A refused request that is signed in gets a `403`,
and a page" onwards, and three things too small to have a section of their own:

* **Shell scripts are checked out with LF** (`.gitattributes`). A `deploy.sh` that reaches a
  Debian host with CRLF line endings dies on `bash: $'\r': command not found` at its first
  line, so the rule is not tidiness: it is the difference between a release leaving this
  machine and not.
* **`scripts/package.sh` works the commit out before handing over to WSL**, for the reason
  `deploy.ps1` already did one script along: the build runs where the checkout is a `/mnt/c`
  mount and `git` may not exist, so asking there answered `unknown`.
* A clippy 1.98 fix (`?` in place of a match that only ever returned `None`), and the
  refusal page's nginx recipe corrected to `rewrite ^ /auth/denied break`, since a named
  location takes no URI on `proxy_pass` and the shorter form fails `nginx -t`.

### Fixed in 1.99.4: the refusal page signed out into a 404

The `Sign out` link on `/auth/denied` was `href="/auth/logout"`, root-relative, and that is
wrong everywhere the page is actually read. nginx answers a `403` with it through
`error_page 403 = @bb_denied`, which **proxies rather than redirects**, so the browser is
still on the gated vhost: the click resolved against a host that mounts a service and not the
gate, and landed in that vhost's catch-all. A `404` for whoever the service knows, and the
refusal page again for whoever it does not, which is the loop the `403` exists to end,
arriving one click later.

The link is now absolute on the origin of that area's login page, and carries that page as
its `?rd=`. The origin is the login page's because it is the host a deployment has already
said the gate answers on, and it is resolved per area, so one gate fronting several hosts
signs each host's people out where they signed in. The `?rd=` is there because a sign-out
offered on this page means "use another account" and has somewhere specific to land; without
one the browser's `Referer` answers instead, naming the page that has just refused them,
which costs a `401` and one more hop.

Nothing to configure, and one thing to know: this is the rule "One logout endpoint for every
vhost" in README already stated, applied to the gate's own page, which was the last thing in
the repository breaking it. **A gated vhost therefore needs no `/auth/logout` location of its
own.** Where `gate.login_url` is empty the link stays relative, which is correct: the gate's
own sign-in page is only reachable when the gate is mounted on the vhost being read from, and
then the endpoint beside it is too.

### The gate serves its own sign-in page

* `/auth/login` and `/auth/callback` are the gate's now, complete on their own: no font, no
  CDN, no second host, because the situation those pages exist for is somebody not being able
  to get in. `gate.login_url` may still point at a page of your own.
* **The look is shared**: the palette (`theme.css`) and the components built out of it
  (`base.css`) live in the library and both programs emit the same bytes, so one
  `ui.stylesheet_url` restyles the sign-in page and the admin interface together.
* The admin GUI's access check moved out of a tab of its own and into the application page and
  the person page, which is where the question is actually asked. There is no `/can` route.
* Logging out is one endpoint for every vhost, and a link that says nothing falls back to
  `Referer`.
* **nginx must leave `/auth/login` and `/auth/callback` ungated**, exactly as it leaves
  `/auth/session` and `/auth/logout`: a sign-in page behind `auth_request` answers a signed-out
  visitor with itself, forever.

### A refused request that is signed in gets a `403`, and a page

* **`/auth/validate` now answers `403` when it identified the caller and no scope admits
  them**, and keeps `401` for a caller it could not identify. That ends a redirect loop that
  had no error anywhere in it: nginx turns a `401` into the login page, and somebody who is
  already signed in signs straight back in, returns to the URL that refused them, and is
  refused again. The line is drawn where each credential is *verified*, so a live `bbk_` key,
  a valid id_token and an unexpired session cookie all reach the new status; an expired
  cookie, a forged one and no credential at all keep the old one. The `403` deliberately
  carries no `X-Auth-Login-URL`: there is nothing to redirect to.
* **nginx needs one more line per gated location**, and without it a `403` is whatever your
  server block does with an unhandled one:

  ```nginx
  error_page 401 = @bb_signin;
  error_page 403 = @bb_denied;          # new
  location @bb_denied {
      proxy_set_header X-Original-URL $bb_url;
      rewrite ^ /auth/denied break;    # a named location takes no URI on proxy_pass
      proxy_pass http://127.0.0.1:4181;
  }
  ```

* **All four of the gate's pages are now files** under `src/assets/`: `login.html`,
  `callback.html`, and the two that used to be built in a `format!` in the middle of the
  gate, `denied.html` and `error.html` (the page a failed `/auth/session` lands on). Same
  `__BB_*__` substitution, same shared `<style>`, so a page is edited, diffed and reviewed as
  HTML.
* **The gate serves the page**, at `/auth/denied`, in the palette the `ui` section gives every
  other page. It answers `403` itself, so `error_page 403 = @bb_denied` keeps the status
  honest, and it says that this account cannot open that page **without** saying whether the
  page exists: a URL outside every application is refused exactly like one whose scope
  excludes you. Its one link is a sign-out, since signing in as the same person lands right
  back on it, and it is absolute on the origin of that area's login page (see "Fixed in
  1.99.4" above). Leave the page's location ungated, like the other two pages.
* **Two ways to use your own page instead**: `gate.denied_url` in the settings file for the
  whole deployment, and `denied_url` on an application in the access file for one area.
  Because an area is an absolute prefix, that second one is **per host**: one gate fronting
  several hosts gives each host its own refusal page, written where every other property of
  an area is. `/auth/denied` then answers `302` to it, which is why the nginx snippet above
  forwards `X-Original-URL`: without it the area cannot be resolved and the global page
  answers, which still says no.

### Security

* `POST /auth/session` now refuses a request the browser reports as `cross-site`, or one
  that says nothing about where it came from. Minting a session cookie for somebody else's
  form is login CSRF, and `SameSite=Lax` does not cover it: that attribute governs when a
  cookie is *sent*, never who may cause one to be *set*. A sign-in page an operator serves
  themselves on a sibling host still works (`same-site` passes); one on another site does
  not.
* Every page either program serves now carries a `Content-Security-Policy`
  (`default-src 'none'` plus exactly what that page uses), plus `Referrer-Policy`,
  `X-Content-Type-Options` and `X-Frame-Options`. The gate's pages use a per-response
  nonce; the admin GUI uses content hashes, since everything it emits is a constant. One
  practical consequence: an operator's `ui.stylesheet_url` and `ui.logo_url` are now named
  in the policy, so a third host cannot be introduced by a page that has one of them.
  `font-src` follows the stylesheet and only the stylesheet, so a token file may bring its
  own `@font-face` from the host it came from (or a `data:` face), and no other host may
  serve a typeface to these pages.
* **The admin GUI's own stylesheet was being refused by its own policy on every build made
  on Windows**, which is every build this project ships: an HTML parser collapses CRLF before
  the CSP check runs, so a browser hashes the LF form of an inline block, while `csp_hash`
  hashed the bytes `include_str!` embedded, and this repository's working tree is CRLF
  (`core.autocrlf=true`, and the cross-compile builds from that same tree). The result was an
  admin interface rendered as unstyled markup, with nothing in any log and nothing in a test:
  the test that checks the pairing compared the function against itself. `csp_hash` now
  normalises newlines, and the test pins a literal hash rather than a round trip. The gate's
  own pages were never affected, because they use a per-response nonce.
* The admin GUI refuses to start on a non-loopback address unless
  `BB_AUTH_WEB_ALLOW_NONLOOPBACK=1` says it was meant. Its only credential is a header
  nginx injects, so a bind to `0.0.0.0` was an unauthenticated remote writer of the access
  list.
* The admin GUI's refusals wear the deployment's look once the settings can be read: a
  `403` for somebody who is authenticated but not on `web.admins` used to render in the
  built-in palette, which on a themed installation looks like a page of another service.
  The two pages that answer *before* the settings are read keep the built-in look, because
  the file that would describe another one is exactly what is missing or broken.
* An `anonymous` scope no longer names a **vetoed** identity in `X-Auth-Email`. The veto
  cannot close an area that is open with no credential at all, but it now stops the gate
  introducing that person to the application behind it.
* An unknown field on an `api_keys` entry is reported at load. A misspelled `scopes` widens
  a key to everything its owner reaches and a misspelled `duration` makes it immortal, both
  silently.
* `remove_user` rewrites a `denied` entry for the removed uuid as that person's primary
  email instead of leaving it dangling: deleting a suspended user used to lift their
  suspension, and with an `authenticated` scope anywhere in the file they could simply
  re-register.

### The settings file, now at `"version": 3`

* **`gate.denied_url`**, the nineteenth setting: where a `403` lands, empty meaning the gate's
  own `/auth/denied`. It is a new optional field rather than a format change, so a version-3
  file that does not mention it is read exactly as before. It passes the three-part rule more
  cleanly than anything else in the file, because it is read *after* somebody has been
  refused: the worst a wrong value achieves is a broken link shown to a person who was never
  getting in, which is why it is not a sixth change that asks before it answers. An
  application's own `denied_url` in the access file overrides it for that area.
* **The user pool, the cookie's domain and the authorized hosts moved in too**, and three more
  environment variables are no longer read: `BB_AUTH_COGNITO_ISSUER`, `BB_AUTH_COOKIE_DOMAIN`
  and `BB_AUTH_AUTHORIZED_HOSTS`, replaced by `gate.issuer`, `gate.cookie_domain` and
  `gate.authorized_hosts` (a list, not a comma-separated string). `bb-auth.env` is down to
  seven values: the listener, the worker count, the HMAC key and its two rotation companions,
  the cookie's **name**, and the path of the access file.

  **What this costs is worth stating, because it retires an argument rather than adding one.**
  Version 2 was safe to hand to a browser-editable file because the *pool* stayed in the
  environment, so the file could only choose among the app clients of an issuer that was
  already trusted. With `gate.issuer` in the file that sentence is no longer true, and the
  honest replacement is that this file is trusted as much as the gate itself: whoever can write
  it can already write the access file beside it and the admin list inside it.

  Two of the three do not pass the settings file's own three-part rule cleanly.
  **`gate.issuer` is not read per request** but once, to fetch a JWKS, so a `SIGHUP` that sees
  a new pool fetches its keys first and swaps the keys and the settings together or swaps
  neither: a gate holding half of that pair would check one pool's tokens against the other's
  keys. And **`gate.cookie_domain` cannot log anybody out, which is worse than if it could**:
  a browser matches a clearing `Set-Cookie` on `(name, Domain, Path)`, so every cookie already
  issued under the old domain stays valid for its full lifetime *and* `/auth/logout` can no
  longer clear it. Putting the old value back makes those cookies clearable again.

  **What the move buys** is a check that was not expressible while the two lived in different
  files: `gate.cookie_domain` must reach every host in `gate.authorized_hosts`, or the file is
  refused. A host the cookie cannot reach is a login that succeeds, redirects, sends no cookie,
  gets a `401` and lands back on the sign-in page it came from, for ever, with nothing anywhere
  saying why.

* **Five settings now take two steps to change**, in both editors: `gate.issuer`,
  `gate.client_id`, `gate.login_url`, `gate.cookie_domain`, and *removing* an entry from
  `gate.authorized_hosts`. `bb-auth-adm` prints what each change costs and writes nothing
  without `--yes`; `bb-auth-web` renders a panel naming the old and the new value and holds the
  save until a second `POST` carries the token that page rendered. Asking rather than refusing,
  because none of them invalidates a cookie: whoever makes the edit still holds a session and
  can undo it, and `bb-auth-adm` over SSH is the way back if not.

  It is five and not fifteen on purpose, and it fires on what is **taken away**: filling in a
  value that was empty is a deployment being finished, not a risk, and *adding* an authorized
  host cannot stop a login. A confirmation that fires on every save is a button people learn to
  click without reading, which is worse than no confirmation because it is also an alibi.

* **`bb-auth-web` refuses to write an empty `issuer`, `client_id` or `authorized_hosts`**,
  while the gate tolerates all three and says so loudly at startup. That is the same rule at
  two distances rather than a contradiction: a package creates this file and cannot know any of
  those values, so refusing to start would be a boot loop on every first install, but a *form*
  should not be able to express a deployment nobody can get into. A fresh install is therefore
  wired with `bb-auth-adm` over SSH, and has to be: `bb-auth-web` is itself behind the gate.

* **Fixed: a page returned by a `POST` carried an empty `rev`**, so submitting it again was a
  `409` about a file nobody else had touched. Fix the field a refusal named, press Save, and
  the answer was a conflict. It never mattered before because every refusal page was reached by
  reloading; the confirmation step above is *designed* to be submitted again, which is how the
  browser suite found it.

* **Every Cognito app client this gate is part of is now in the settings file**, and six
  environment variables are no longer read: `BB_AUTH_CLIENT_ID`, `BB_AUTH_AUDIENCES`,
  `BB_AUTH_LOGIN_URL`, `BB_AUTH_OAUTH_DOMAIN`, `BB_AUTH_SOCIAL_CALLBACK_URL` and
  `BB_AUTH_SOCIAL_IDPS`. What replaces them is `gate.client_id` (the email flow's app
  client), `gate.login_url` (where people sign in, empty meaning the gate's own
  `/auth/login`), `gate.oauth_domain`, `gate.social_callback_url`, and a `gate.social_buttons`
  list whose entries are now `{ "idp": …, "audience": … }`.

  **The audiences are derived from those and no longer configured.** An id_token carries the
  app client it was minted for in `aud`, so naming an app client in this file is what makes
  its tokens acceptable; `BB_AUTH_AUDIENCES` existed only to repeat that by hand. Two lists
  that had to agree with a third are now one, and the startup warning that used to say they
  did not is gone with them. The safety argument at the time was that the **pool** stayed in
  the environment, so this file could only choose among the app clients of one issuer; the
  version-3 entry above is where that argument was retired and replaced.

  **Each social button carries its own app client**, because Cognito federates per app
  client: which providers a client offers is a property of that client, so two providers may
  live on two of them and a single value could not express it. The sign-in page puts the
  clicked button's client id in `sessionStorage` beside the PKCE verifier, and the callback
  exchanges its code with that one.

  **Upgrading is a two-step, in this order.** Write the new settings file first: the running
  gate refuses it (unknown fields, and a version it does not know), keeps the values it already
  has, and says so in the journal, so nothing goes down. Then deploy. Doing it the other way
  round leaves the new binaries with a file they refuse, and a settings file the gate cannot
  read is fatal at startup, which under `Restart=on-failure` is a boot loop.
  `bb-auth --check-settings <file>` validates the new shape before either step, and
  `--check-env` names every retired variable still sitting in `bb-auth.env`. Coming from
  version 1, both moves happen in the same edit; coming from version 2, only the three fields
  the entry above names have to be added.
* ~~**`gate.social_client_id`**~~, introduced and removed on the same day, along with
  `BB_AUTH_SOCIAL_CLIENT_ID`.
  The Cognito app client a social sign-in runs through moved from the env file to the
  settings file, because all three programs have an opinion about it and an env var is
  readable only by the process that was started with it: the admin GUI could only have shown
  it by being handed a second copy, and a value written in two files drifts. It is the
  twelfth setting and the one member of the `BB_AUTH_SOCIAL_*` group to cross that line, so
  it was argued against the three-part rule rather than moved: read per request, unable to
  lock anybody out (a wrong value costs the social buttons, never the email path), and no
  secret, since the sign-in page has always emitted it into its own script. It cannot widen
  what the gate accepts either: the audiences stay in `BB_AUTH_AUDIENCES`, and no button is
  drawn through an app client that is not already one of them, which is what the env var's
  fatal startup check became. Fail-soft on purpose, because a hot file may never be fatal:
  with no app client, or an unusable one, the social section is simply not drawn and the gate
  says which of the two it was at startup and after every reload.
  **Upgrading a deployment with social sign-in requires moving the value**:
  `bb-auth-adm settings set --social-client-id <id>`, then delete the variable from
  `bb-auth.env`. The gate warns while it is still there.
* **`gate.social_buttons`**: which social sign-in buttons the page offers, by Cognito
  `identity_provider` name, in the order they appear, changed with no restart and from the
  admin GUI, where it is a checkbox per provider (`Google`, and `Microsoft` meaning the
  personal account rather than an Entra ID tenant) instead of a list of names to type: a name
  Cognito will not match is a button that never appears with nothing to say why. A provider
  configured from `bb-auth-adm` that this build does not know gets a checkbox of its own, so
  the page can never drop what it cannot name. **Empty offers none**, so a provider is shown
  because somebody enabled it and not because the deployment happens to federate it. It is
  the eleventh setting and was
  checked against the three-part rule before it was added: read per request, unable to lock
  anybody out (the email path is untouched), not a secret. `BB_AUTH_SOCIAL_IDPS` keeps its
  own job, which is a different one: it says what the app client federates, and a button
  needs both. **Upgrading a deployment that had social buttons requires setting this**, or
  the sign-in page will offer none.
* The Settings page is now four boxes grouped by what a setting decides (access policy;
  what the application receives; the sign-in page; administration and look) rather than one
  form with three headings named after the file's own sections. The file is unchanged: each
  box still names the key it writes.
* The ways in are a **table** on that page, a row per way: what a visitor reads, the
  `identity_provider` Cognito matches byte for byte, and the app client the sign-in runs
  through. The email row is in it and has no tick, because the email path is not something a
  deployment turns off and its app client is the same kind of value as every other row's.
  A stacked list of checkboxes ran those three facts together, and the first two differ
  exactly where it matters: `Microsoft` is the word on the button and `MicrosoftPersonal` is
  the name Amazon knows.

### The built-in palette

* **The dark arm's accent moved for contrast, and `--on-accent` moved with it**:
  `--accent` `#5b78ff` to `#6a85ff`, `--accent-hover` to the old `#5b78ff`, `--accent-weak`
  to match, and `--on-accent` `#ffffff` to `#16161b`. Against the dark `--card`, the old blue
  measured 4.28:1 as link text, under the 4.5:1 WCAG AA asks of body text. It could not be
  fixed alone: the same token fills buttons, white on it was already 3.77:1, and lightening
  the blue makes that worse. Text on the card wants a relative luminance of at least .243,
  white on the fill wants at most .183, and no single colour is both, so the pair had to move
  together. The new values measure 4.93:1 and 5.51:1. The light arm is unchanged and already
  passed at 4.96:1 in both roles.
* **Visible consequence**: on a dark theme, text on a filled accent surface is now dark rather
  than white. That affects `button`, `button:hover` and `.pill.on`, which is every primary
  action on the sign-in page and every selected pill in the admin GUI. It is the rule this
  palette already applied to filled STATE surfaces (`--on-state`), and the accent was the last
  token exempt from it.
* **A deployment with its own `ui.stylesheet_url` sees nothing change** if that file already
  redefines these four tokens, which a complete token file does. One that redefines `--accent`
  but not `--on-accent` should check the pairing: it will now inherit a dark `--on-accent`
  under whatever blue it chose.
* No cookie, access-file or settings-file format is touched, so nobody is logged out. The
  admin GUI's `style-src` hash is computed from the emitted bytes at build time and needs no
  manual update.

### The admin interface

* **The access check answers where it was asked.** Both check forms submit to `#check`, which
  the section's heading carries, so the verdict arrives in front of the person who asked for
  it instead of at the top of a fresh document several screens above it. A `GET` form keeps
  the fragment of its `action` and replaces only the query, so this costs one attribute and
  no script.

### Availability

* A `recv()` error is now fatal. `tiny_http` reports at most one accept error per listener
  and then stops accepting, so the previous `continue` left a live process with no listener:
  no exit code, no restart, and every gated request failing.
* An unknown `kid` no longer serialises every worker behind one JWKS fetch. The refresh
  lock is taken with `try_lock`, the fetch timeout is 3s, and a failure is cached for 10s.
* The gate warns at startup when an application's `login_url` is outside
  `gate.authorized_hosts`, and when it is listening on a non-loopback address.
* `session_ttl_secs` has a ceiling as well as a floor, and the cookie's expiry is computed
  with a saturating add.
* `bb-auth-web`'s worker count is now `BB_AUTH_WEB_WORKERS` (default 8, accepted 1 to 64,
  anything else a **fatal startup** naming the variable). It was a constant 2, sized for the
  handful of people on `web.admins`, and the self-service page put every signed-in person on that
  pool. It bounds how many handlers run at once, not how many connections are open, so too few
  shows as latency for everybody, and it is read once at startup, so a change needs a restart
  (docs/ARCHITECTURE.md §13.13).

### Release and operations

* **`bb-auth --self-test`** performs the offline RS256 verification a login performs, with
  no env, no config and no network. `scripts/verify.sh` runs it: every check it had was
  green on the build whose JWT verifier was a `panic!`.
* **`bb-auth --version`** (and the GUI's footer, and both startup banners) reports the
  commit the binary was built from, with a `-dirty` marker: `scripts/build.sh` and
  `scripts/package.sh` export it as `BB_AUTH_BUILD` and the binaries read it at compile
  time. A `.deb` version reads the same for a tagged release and for a working tree somebody
  built by hand. `deploy.ps1` works the string out on the Windows side and passes it in,
  because the build runs inside a WSL distribution where the checkout is a `/mnt/c` mount and
  `git` may not exist: asking there answered `unknown` for every release built the supported
  way, and left the dirty-tree refusal unable to fire.
* **`scripts/package.sh` runs the test suite** before it builds, and refuses an uncommitted
  tree unless `--allow-dirty`. `--skip-tests` exists for repackaging bytes already tested.
* Builds are `--locked`, and `scripts/build.sh` no longer copies the resolved `Cargo.lock`
  back over the tracked one: a dependency bump is a deliberate commit again.
* `cargo-deb` is installed at a fixed version. The toolchain and the cross-linker
  configuration stay where they were, on the release machine (`rustup default`, its own
  `~/.cargo/config.toml`); `scripts/README.md` lists what that machine needs.
* `bb-auth --check-env <file>` answers "is every required variable set?", and the gate's
  postinst asks the binary instead of keeping its own list of six names in shell.
* A staged access file is validated **before** `dpkg -i`, not after: a rejected file now
  costs nothing instead of a red deploy on a host that has already been mutated.
* A failed restart in either postinst is now a failed install. It used to be `|| true`.
* `scripts/deploy.sh` records what it is replacing under `share/previous/`, and README has
  a Rollback section.
* Purging either package now treats `settings.json` exactly as it treats `access.json`.

### Documentation

* The nginx blocks in README now clear **every** identity header, `X-Auth-Uuid` included.
  They stated the rule and shipped the counter-example twice.
* README no longer claims `scripts/deploy.sh` moves a shadowing systemd unit aside. It does
  not, deliberately, and says so.
* AGENTS.md said "ten" settings in one section and "six" in another, and the code comment
  agreed with the wrong one.

## 1.0.0 (2026-08-17)

The first release. The version sequence before it (2.6.0, 3.0.0, 3.1.0) belongs to a
history this release deliberately does not remember: every tag and release was deleted, the
migration tooling was removed, and the two formats were reset to `bb1` and `"version": 1`.

The tag `v1.0.0` points at `7d7cc8c`, six commits after the release commit, and that is
deliberate: `7d7cc8c` is the fix for a build whose JWT verifier was a `panic!`
(`jsonwebtoken`'s crypto is a feature, and selecting none of them compiles). The commits
between the two are not a release anybody should install; `f3a4e48`, `7f3d4a3` and `7650b92`
in particular carry that defect.
