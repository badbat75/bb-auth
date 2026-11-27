use crate::*;

// ---------------------------------------------------------------------------
// The settings file
// ---------------------------------------------------------------------------
//
// The second file this crate owns, and the reason it is a file at all: **everything in it
// takes effect without a restart**. A process cannot re-read its own environment: systemd
// loads `EnvironmentFile=` once, at `ExecStart`, so a setting that must change while the
// gate keeps serving cannot live in an env var, whatever else recommends one. That is the
// whole argument, and it is what is left in `bb-auth.env`: the listener, the worker count,
// the HMAC key, the cookie's name, the path of the access file, and the original-URL header.
//
// The membership rule here is as narrow as the access file's, and deliberately so. A
// setting belongs in this file iff all three hold:
//
// 1. it is read **per request**, so a new value takes effect on the next one: no socket to
//    rebind, no credential to re-issue, no cache to invalidate;
// 2. a wrong value **cannot lock the operator out irreversibly**. The test is not "cannot
//    break a login", since several of these can; it is whether the person who made the edit
//    can still undo it. Nothing here invalidates a cookie, so a bad save leaves every session
//    already minted standing, including the one the editor is holding, and `bb-auth-adm` over
//    SSH is the way back if not. `BB_AUTH_ORIGINAL_URL_HEADER` fails that outright, and
//    `_COOKIE_NAME` fails it by orphaning every cookie already issued;
// 3. it is **not a secret**. The one credential in the system stays in the gate's env file,
//    which no other service reads and no editor writes.
//
// Eighteen settings pass, in three sections, and the file is shaped like what reads them:
// `gate` is the thirteen the gate answers with, `web` is the one the GUI's own door is made
// of, and `ui` is the four that say how a page looks.
//
// **Three of them arrived last and not one passes cleanly**, which belongs here rather than
// in each field's own doc, because what they have in common is the argument they cost.
// `issuer` fails part 1: it is read once, to fetch a JWKS, so a reload has to re-fetch and
// then swap keys and settings together or neither. `cookie_domain` fails part 2 in a way
// nothing else here does: it cannot log anybody out, it does something worse, which is orphan
// every cookie already issued so that a logout stops clearing them, and both editors make it
// a two-step for that reason alone. And `authorized_hosts` was the boundary that made
// `login_url` safe in a file an administrator edits from a browser: the file said where
// people sign in, the environment said which hosts a redirect could land on, and only the
// second was a security boundary. With both in here that sentence is retired, and what
// replaces it covers all three: **this file is trusted as much as the gate itself**, because
// whoever can write it can already write the access file beside it and the admin list inside
// it. What the move buys, and what was not expressible while these lived in two places, is
// that `cookie_domain` must reach every host in `authorized_hosts` or the file is refused. The `ui` four pass the middle part for a reason
// worth stating, because they are the ones that look like they should not: the built-in
// stylesheet is COMPLETE, so an override is only ever an addition to a page that already
// works, and the worst a wrong value there achieves is an unstyled page rather than a closed
// door. They are also the one section BOTH services read, which is what makes one save
// restyle the sign-in page and the admin interface together.
//
// Each service reads its own section and ignores the other's; both go through
// [`compile_settings`], so an edit made by either is one the other would also accept.
//
// The write path is the access file's, unchanged and for the same reason: [`SettingsWrite`]
// is [`AccessWrite`] with a different document, `commit` writes exactly the bytes `prepare`
// compiled, and `write_atomically` stays private so there is no other door.

/// The settings file's `version`. Exactly one accepted value, like the access file's.
pub const SETTINGS_VERSION: u32 = 3;

/// The file name [`default_settings_path`] builds, and the one the packages create.
pub const DEFAULT_SETTINGS_FILE: &str = "settings.json";

/// Where the settings file lives when nothing names it: beside the access file.
///
/// A derived default rather than a second required env var, and that is a lockout argument
/// rather than a convenience: a required variable missing from an operator-owned env file is
/// a fatal startup, and under `Restart=on-failure` a fatal startup is a boot loop. An upgrade
/// that needs no edit to `bb-auth.env` cannot cause one.
/// String surgery rather than [`std::path::Path::join`], and deliberately: the value is
/// echoed back in the startup banner and in every error message about the file, so it must
/// read the way the operator wrote the access path, with the separator they used. Joining
/// through `Path` would rewrite a POSIX path with a backslash when this code is compiled on
/// Windows, which is where it is developed.
pub fn default_settings_path(access_path: &str) -> String {
    match access_path.rfind(['/', '\\']) {
        Some(i) => format!("{}{DEFAULT_SETTINGS_FILE}", &access_path[..=i]),
        None => DEFAULT_SETTINGS_FILE.to_string(),
    }
}

/// The wire name of the header a `401` carries this area's login page in.
///
/// The nginx contract around it is documented on the gate's own `LOGIN_URL_HEADER`, which is
/// this constant: the gate is where that contract belongs. The *string* is here because
/// [`compile_profile_claims`] has to reserve the name, and a claim that quietly stole it
/// would be discovered at runtime, on a header nginx already trusts.
pub const LOGIN_URL_HEADER: &str = "X-Auth-Login-URL";

/// The wire name of the header naming the authorized identity, and what every application
/// behind this gate already reads.
///
/// Here for the same reason [`LOGIN_URL_HEADER`] is, plus one: it is what `bb-auth-web` reads
/// its own administrator's identity out of, so three programs now name it and exactly one
/// should spell it. The nginx wiring is on the gate's constant of the same name.
pub const IDENTITY_HEADER: &str = "X-Auth-Email";

/// The wire name of the header that names **the Cognito user a session is**, and only when
/// that user is one of the pool's own (a native sign-in, no `identities` on the token).
///
/// It is here for the same reason [`IDENTITY_HEADER`] is, plus one: the gate emits it,
/// `bb-auth-web` reads it, and [`compile_profile_claims`] reserves it, so three uses need
/// exactly one spelling. `bb-auth-web` needs it for the profile edit of docs/ARCHITECTURE.md
/// §13.25: that edit must act on the session's own Cognito user, and no email says which one
/// that is. A pool holds a native user and a federated one under the same address, and an edit
/// driven by the email wrote the native twin of a person signed in through a provider, then
/// told them their profile was saved.
///
/// It is **not** an identity attribute and **not** a profile claim. Those are the operator's
/// choice, derived from the roster or self-asserted by the user; this is a fact of the
/// credential that another program's correctness depends on, so an operator switch that
/// could turn it off would silently turn the edit off with it. Reserving the name here is
/// what stops a configured claim from deriving it and answering it with a value the user
/// typed.
pub const NATIVE_USERNAME_HEADER: &str = "X-Auth-Native-Username";

/// The path of the sign-in page the gate serves itself, spelled once because **two programs
/// write one URL**.
///
/// The gate answers a logout, a `401` and an empty `gate.login_url` with this path, and
/// `bb-auth-web` builds the deletion flow's logout `rd` out of it and
/// [`LOGIN_NOTICE_ACCOUNT_DELETED`] (docs/ARCHITECTURE.md §13.32 §1). A constant in each
/// program is two strings that have to agree by eye, and the way they disagree is silent:
/// every browser mid-deletion is sent to a `404`, and the flow's only explanation of itself
/// never appears. The `rd` is relative because `bb-auth-web` knows neither its scheme nor its
/// host, and a path is the shape the gate's own `global_login` answers with for the same
/// reason.
pub const GATE_LOGIN_PATH: &str = "/auth/login";

/// The one notice code the sign-in page understands: arriving at the gate's login page with
/// `?notice=account-deleted` shows one fixed paragraph (docs/ARCHITECTURE.md §13.32 §1,
/// §13.33), the sign-in page of the estate answering "what just happened to my account".
///
/// The code is **fixed, a closed set of one**, and that is what keeps the notice carrying no
/// request data: the query value is compared to this constant byte for byte (case-sensitive,
/// so no casing trick widens the set), and the page's only two changes are the fixed strings
/// `hidden` and `aria-describedby="notice"`. No byte of the query reaches the page, so
/// AGENTS.md's "request data reaches a page in exactly one place, `data-rd`" stays true in
/// substance: a code selects an element, nothing is reflected. A second notice is a second
/// code, a second fixed paragraph and a second dictionary entry per arm, never a value
/// rendered out of the request.
///
/// It lives here, beside [`GATE_LOGIN_PATH`], for the library's membership rule: `bb-auth-web`
/// writes this code into the logout `rd` of a completed deletion and the gate reads it back
/// out of the query string that lands on, and the way the two drift apart is silent (the
/// person lands signed out with no explanation).
pub const LOGIN_NOTICE_ACCOUNT_DELETED: &str = "account-deleted";

/// What this build was made from: a `git describe --always --dirty --tags`, or `unknown`.
///
/// Read from `BB_AUTH_BUILD` at compile time, which is what `scripts/build.sh` and
/// `scripts/package.sh` set from the checkout they are building. `option_env!` and not
/// `env!` because a plain `cargo build` on a workstation sets nothing and must still
/// compile: it then reports `unknown`, which is honest.
///
/// It is the **commit** and nothing else (`g0a8d129`, plus `-dirty` when the tree was not
/// committed), because the version half of the identity is already compiled in by cargo and
/// must not be spelled a second time by a shell script that could get it wrong.
/// [`version_id`] is what puts the two together.
///
/// It is in the library because all three programs print it, and because a version string
/// that meant different things in different binaries of one release would be worse than
/// none. There is deliberately no build script: a `build.rs` that shells out to `git` is a
/// compile-time dependency on a program the build does not otherwise need, and the two
/// scripts that produce a release already know the answer.
pub const BUILD: &str = match option_env!("BB_AUTH_BUILD") {
    Some(b) => b,
    None => "unknown",
};

/// What this build **is**: `v1.99.1-g0a8d129`, or `…-dirty`, or `…-unknown` for a plain
/// `cargo build` that no release script set anything for.
///
/// One string, where this used to be two facts side by side. The old shape printed the crate
/// version and then `git describe`'s output, and **`git describe` anchors on the last tag**:
/// a release candidate is deliberately never tagged, so on the host it read
/// `1.99.1 (v1.0.0-18-g0a8d129)` — the true version, followed by a string that opens with a
/// version eighteen commits and one minor number out of date. Read quickly, it said `v1.0.0`.
///
/// So the version comes from cargo, which cannot be wrong about it, the commit comes from
/// [`BUILD`], and they are joined here. It still answers both questions the old pair
/// answered: `dpkg-query -W` agrees with the version prefix, and the suffix is what an
/// incident needs, since an untagged build's only handle is its commit.
pub fn version_id() -> String {
    format!("v{}-{BUILD}", env!("CARGO_PKG_VERSION"))
}

/// The one line every program answers `--version` with, and the one the gate opens its
/// journal with.
pub fn version_line(program: &str) -> String {
    format!("{program} {}", version_id())
}

/// Claim names bb-auth consumes itself, and so cannot propagate.
///
/// The gate's `Claims` deserializes these into typed fields, and `#[serde(flatten)]` never
/// sees a key a typed field already took, so configuring one of them would propagate
/// nothing, silently and forever. Rejecting them at compile time turns that into an error a
/// form can show.
pub const RESERVED_CLAIMS: [&str; 4] = ["email", "email_verified", "token_use", "identities"];

/// Whether the `email_verified` claim is truthy. Cognito types it as a bool, but some
/// federated flows stringify it, so `"true"` counts. Anything else is false.
///
/// It lives in the library because the gate is not the only program that will validate a
/// token: `bb-auth-web` starts to (docs/ARCHITECTURE.md §13.22, slice 5b), and what
/// Cognito's `email_verified` means must not have two answers.
pub fn email_verified_true(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::String(s) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// Every identity attribute the gate knows how to emit.
///
/// The **set** an installation emits is configuration ([`GateSettings::identity_attrs`]); the
/// derivation from an attribute name to a header is code, exactly as it is for a profile
/// claim, so an operator names an attribute and never a header.
///
/// The set of *possible* names is this array, and it being finite is the security argument.
/// `proxy_set_header` overrides only the names it lists, so nginx must clear every header the
/// gate could ever emit, **including the ones this installation has turned off**: an identity
/// header nginx does not clear is one a client can send. An operator who turns an attribute on
/// later must add nothing to nginx, because the clear was already there, which is exactly
/// what makes this setting safe to change at runtime.
///
/// It is also the reason a new attribute is a code change: `phone` will be a fourth
/// credential's worth of work in the gate's `validate_id_token`, not a string an operator may
/// invent.
pub const IDENTITY_ATTRS: [&str; 2] = ["uuid", "email"];

/// Whether `s` is a syntactically valid profile-claim name: non-empty and `[A-Za-z0-9_:-]`
/// only.
///
/// Shared by [`compile_profile_claims`] (config) and the gate's `decode_claims_segment` (a
/// cookie's claim blob), so a cookie can never carry a key that no config could have produced.
pub fn claim_name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':' || b == b'-')
}

/// Derive a claim's response header. See [`ProfileClaim`] for the rule and why it is code
/// rather than config. Assumes `claim` passed [`compile_profile_claims`]'s checks.
pub fn derive_profile_header(claim: &str) -> String {
    let normalized = claim.replace([':', '_'], "-");
    let mut out = String::from("X-Auth-");
    for (i, token) in normalized.split('-').enumerate() {
        if i > 0 {
            out.push('-');
        }
        let mut chars = token.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars.map(|c| c.to_ascii_lowercase()));
        }
    }
    out
}

/// One configured OIDC profile claim, and the response header derived from its name.
///
/// The **set** is configuration ([`GateSettings::profile_claims`], empty by default); the
/// **derivation** is code, and fixed. That split is the whole point: an operator names a
/// claim, never a header, so the two can never disagree and no header name is attacker- or
/// typo-reachable.
///
/// Derivation: map `_` and `:` to `-`, title-case each `-`-separated token, prefix `X-Auth-`.
/// So `given_name` → `X-Auth-Given-Name` and `custom:department` → `X-Auth-Custom-Department`.
/// Because [`compile_profile_claims`] admits only `[A-Za-z0-9_:-]`, a derived header is always
/// `[A-Za-z0-9-]+`: a valid header token by construction.
///
/// The **value** is emitted percent-encoded per RFC 3986 by the gate, whose `pct_encode`
/// produces printable ASCII for *any* input; that construction, not a validator, is what makes
/// emitting a self-asserted value safe. An absent claim **omits its header entirely**, never
/// sends it empty.
///
/// These are **self-asserted profile attributes**: any Cognito user, verified email or not,
/// writes their own, so they are display hints and nothing may key on them. They authorize
/// nothing, no field of the access file mentions them, and they are never logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileClaim {
    /// The OIDC claim name, exactly as it appears in the id_token.
    pub claim: String,
    /// The response header derived from it. See the type doc.
    pub header: String,
}

/// Compile a list of OIDC claim names into the claims to capture and the headers to emit.
/// Empty (the default) means none: profile propagation is opt-in.
///
/// Every rejection is an error rather than a skipped entry, because a silently dropped claim
/// is a header an application waits for forever. In the gate that is a fatal load; in an
/// editor it is a refusal shown on the field, and nothing is written.
///
/// Rejects, naming the entry: a name outside `[A-Za-z0-9_:-]`; an empty token around a
/// separator (`:dept`, `dept:`, `a--b`), which would derive a header with an empty component;
/// a claim in [`RESERVED_CLAIMS`]; and a derived header that collides case-insensitively with
/// **any possible** identity header, with [`LOGIN_URL_HEADER`], with
/// [`NATIVE_USERNAME_HEADER`], or with another entry's (which also catches a repeated claim,
/// and spellings that differ only in case or separator).
pub fn compile_profile_claims(list: &[String]) -> Result<Vec<ProfileClaim>, String> {
    profile_claims_core(list).map_err(|r| r.sentence())
}

/// [`compile_profile_claims`]'s checks, answering the typed refusal so `compile_settings` can
/// hand one to the GUI as a code (§13.31 §3). The `String` wrapper is what the access file's
/// parser and the CLI's flag-named pre-checks call, and it prints the variant's own sentence,
/// byte for byte as before: the prefix `profile_claims` belongs to the settings file, and a
/// caller that names the value differently has no opinion about it.
fn profile_claims_core(list: &[String]) -> Result<Vec<ProfileClaim>, SettingsRefusal> {
    let mut out: Vec<ProfileClaim> = Vec::new();
    for raw in list {
        let claim = raw.trim();
        if claim.is_empty() {
            continue;
        }
        if !claim_name_ok(claim) {
            return Err(SettingsRefusal::ClaimCharset {
                claim: claim.to_string(),
            });
        }
        if claim.replace([':', '_'], "-").split('-').any(str::is_empty) {
            return Err(SettingsRefusal::ClaimEmptyPart {
                claim: claim.to_string(),
            });
        }
        if RESERVED_CLAIMS.contains(&claim) {
            return Err(SettingsRefusal::ClaimConsumed {
                claim: claim.to_string(),
            });
        }
        let header = derive_profile_header(claim);
        // Every *possible* identity header is reserved, not merely the ones this installation
        // emits: turning an attribute on tomorrow must not collide with a claim configured
        // today, because that discovery would happen at runtime, on a header an application
        // already trusts.
        let reserved = IDENTITY_ATTRS
            .iter()
            .map(|a| derive_profile_header(a))
            .chain(
                [LOGIN_URL_HEADER, NATIVE_USERNAME_HEADER]
                    .iter()
                    .map(|r| r.to_string()),
            );
        for r in reserved {
            if header.eq_ignore_ascii_case(&r) {
                return Err(SettingsRefusal::ClaimHeaderReserved {
                    claim: claim.to_string(),
                    header,
                });
            }
        }
        if let Some(prev) = out.iter().find(|p| p.header.eq_ignore_ascii_case(&header)) {
            return Err(SettingsRefusal::ClaimsCollide {
                first: prev.claim.clone(),
                second: claim.to_string(),
                header,
            });
        }
        out.push(ProfileClaim {
            claim: claim.to_string(),
            header,
        });
    }
    Ok(out)
}

/// One configured identity attribute, and the response header derived from its name.
///
/// The same split as [`ProfileClaim`], for the same reason: the **set** is configuration
/// ([`GateSettings::identity_attrs`], `email` by default), the **derivation** is code. The
/// derivation is literally the same function, so `uuid` becomes `X-Auth-Uuid` and `email`
/// becomes [`IDENTITY_HEADER`].
///
/// These are **not** profile claims, and the difference is the whole point of the split. An
/// identity attribute is what the access file decided a request belongs to: it is checked, it
/// is what `denied` vetoes, and an application may key its own records on it. A profile claim
/// is self-asserted decoration nothing may key on.
///
/// A multi-valued attribute is emitted **space-separated**, and that is safe by construction
/// rather than by convention: every identifier passed [`header_safe_email`], which requires
/// printable ASCII, and a space is not printable ASCII. A comma would not do, because
/// [`well_formed_email`] allows one in a local part.
///
/// An absent attribute **omits its header** rather than sending it empty: nginx reads an unset
/// variable as no header at all, so present-and-empty is a distinction the application cannot
/// make. An identity granted by an `authenticated` scope is in no roster row, so it has no
/// `uuid` to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityAttr {
    /// The attribute name, one of [`IDENTITY_ATTRS`].
    pub attr: String,
    /// The response header derived from it.
    pub header: String,
}

/// Compile the identity attributes a `204` names. Default `email`, which is exactly what every
/// version before the settings file emitted.
///
/// Fatal on every rejection, and fatal on an **empty** list above all: an authorized `204` that
/// names nobody is an application silently losing its identity, and silence is the one failure
/// mode this gate does not accept. Unknown names are rejected against [`IDENTITY_ATTRS`] rather
/// than passed through, so a typo cannot quietly turn an attribute off.
pub fn compile_identity_attrs(list: &[String]) -> Result<Vec<IdentityAttr>, String> {
    identity_attrs_core(list).map_err(|r| r.sentence())
}

/// [`compile_identity_attrs`]'s checks, answering the typed refusal (§13.31 §3), with the same
/// split as [`compile_profile_claims`]: the settings file adds the `identity_attrs` prefix, the
/// leaf's other callers print this sentence alone.
fn identity_attrs_core(list: &[String]) -> Result<Vec<IdentityAttr>, SettingsRefusal> {
    // The one place the derivation and the documented constant are checked against each other.
    // Every application behind this gate reads `X-Auth-Email`, and every nginx snippet in the
    // README names it literally, so a change to the derivation must not be allowed to rename it
    // in silence.
    assert_eq!(derive_profile_header("email"), IDENTITY_HEADER);
    let mut out: Vec<IdentityAttr> = Vec::new();
    for raw in list {
        let attr = raw.trim();
        if attr.is_empty() {
            continue;
        }
        if !IDENTITY_ATTRS.contains(&attr) {
            return Err(SettingsRefusal::AttrUnknown {
                attr: attr.to_string(),
            });
        }
        if out.iter().any(|a| a.attr == attr) {
            return Err(SettingsRefusal::AttrTwice {
                attr: attr.to_string(),
            });
        }
        out.push(IdentityAttr {
            attr: attr.to_string(),
            header: derive_profile_header(attr),
        });
    }
    if out.is_empty() {
        return Err(SettingsRefusal::AttrNone);
    }
    Ok(out)
}

/// The shortest session lifetime that is not a login loop.
///
/// A cookie is minted with this as its `Max-Age` and the same value inside the signed
/// message, so a tiny one means the browser presents an expired cookie moments after the login
/// page handed it over, which looks exactly like a broken login rather than a bad setting. A
/// minute is arbitrary; being non-zero is not.
pub const MIN_SESSION_TTL: u64 = 60;

/// The longest lifetime a browser will actually honour: 400 days, the cap Chrome (and Safari,
/// lower) applies to `Max-Age` regardless of what the header says. Beyond it the value is not
/// wrong, it is merely fiction, so this is a warning rather than a refusal.
pub const MAX_HONOURED_SESSION_TTL: u64 = 400 * 86_400;

/// The longest lifetime that is arithmetic rather than fiction: a hundred years.
///
/// Past [`MAX_HONOURED_SESSION_TTL`] a value is merely ignored by the browser, which is worth
/// a warning and nothing more. Past *this* it stops being a number the gate can work with: it
/// is added to the wall clock to make the cookie's `exp` and cast to `i64` for its `Max-Age`,
/// and near `u64::MAX` both of those wrap into a cookie that is already expired, which is the
/// login loop [`MIN_SESSION_TTL`] exists to prevent, reached from the other end. A ceiling
/// three orders of magnitude past any real session leaves the setting's honest range
/// untouched and takes the arithmetic out of reach.
pub const MAX_SESSION_TTL: u64 = 100 * 365 * 86_400;

/// The gate's half of the settings file: what it answers a request with.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GateSettings {
    /// OIDC claim names to capture from an id_token and hand to the application. Empty by
    /// default: profile propagation is opt-in. See [`ProfileClaim`].
    ///
    /// Order is the operator's, and is the order the headers come out in. Removing one stops
    /// it being emitted at once, from cookies that still carry it; adding one appears at each
    /// holder's next sign-in, because the value rides inside the cookie. Neither is a
    /// cookie-format change and neither logs anybody out.
    #[serde(default)]
    pub profile_claims: Vec<String>,
    /// Which identity attributes a `204` names. `["email"]` by default. See [`IdentityAttr`].
    #[serde(default = "default_identity_attrs")]
    pub identity_attrs: Vec<String>,
    /// Relax the `email_verified` requirement, but ONLY for federated (social) logins, never
    /// for native Cognito users, whose self-signup is open and whose unverified email is
    /// therefore attacker-controlled.
    #[serde(default)]
    pub allow_unverified_social: bool,
    /// The Cognito **app client the email flow uses**: the `client_id` the sign-in page runs
    /// `USER_AUTH` against, and the first audience a token is accepted for.
    ///
    /// **Empty is tolerated and means no login can complete**, which is the state a fresh
    /// install is in before an operator says which app client this deployment is. It is a
    /// warning and not a refusal for the reason `web.admins` is one: a package creates this
    /// file, and a gate that refused to start over a value the install cannot know would be a
    /// boot loop on every first install. Sessions already minted keep working either way,
    /// since this is read when a token is validated and never when a cookie is.
    ///
    /// It is the one setting here that can stop **new** logins, so where it sits against the
    /// three-part rule is worth stating rather than assuming. It is read per request; it is
    /// not a secret, since the sign-in page emits it into its own script; and while a wrong
    /// value does shut the door on new logins, it shuts it in the one way that is recoverable
    /// from the wrong side: no cookie is invalidated, so whoever made the edit still holds a
    /// session and can undo it, and `bb-auth-adm` over SSH is the way back if not. What it
    /// must never become is a way to reach another *pool*: `BB_AUTH_COGNITO_ISSUER` stays in
    /// the environment, so this file can only ever choose among the app clients of the pool
    /// the gate already trusts.
    #[serde(default)]
    pub client_id: String,
    /// **Where people sign in**: the page a `401` names, and the page a rejected redirect
    /// target falls back to. Absolute https, validated by [`compile_login_url`].
    ///
    /// Empty means *this gate's own* `/auth/login`, on whatever host the request arrived at,
    /// which is the only page it can promise exists. That default is what makes the value
    /// optional at all: the gate serves the sign-in page itself now, so naming one is
    /// how an operator points somewhere *else*, not how they get one.
    ///
    /// It is a setting and not an env var by the same argument as [`GateSettings::client_id`],
    /// and it is the other value here that can stop **new** logins if it is wrong: it cannot
    /// invalidate a cookie, so whoever made the edit still holds a session and can undo it.
    /// What keeps it from being a redirect gadget is unchanged and stays in the environment:
    /// `BB_AUTH_AUTHORIZED_HOSTS` is the only authority on where a post-login redirect may
    /// land, and it is not in this file.
    #[serde(default)]
    pub login_url: String,
    /// **Where a refusal lands**: the page `/auth/denied` stands in for. Absolute https,
    /// validated by [`compile_page_url`].
    ///
    /// Empty means the gate's own `/auth/denied`, which is the page it builds itself out of
    /// the `ui` section, so this is how an operator points somewhere *else* rather than how
    /// they get a page at all. It is the only value here that no login depends on: it is read
    /// when somebody has already been refused, so the worst a wrong one can do is send that
    /// person to a page that is not there, and no cookie, no scope and no grant is touched.
    /// A gate whose `/auth/denied` answers `302` to it is the one redirect in this design
    /// nginx does not perform itself, and it exists because nginx cannot proxy to a host the
    /// settings file names without a resolver and a rewrite of the recipe.
    #[serde(default)]
    pub denied_url: String,
    /// **Where a sign-in lands when nobody named a place**: what `safe_rd` answers when
    /// `/auth/session` arrives with no `rd`. Absolute https, validated by [`compile_page_url`],
    /// and its host must be one `gate.authorized_hosts` covers, or [`compile_settings`] refuses
    /// the file.
    ///
    /// Empty, the default, is the **caller's root**, exactly as before this setting existed: the
    /// host the sign-in page was served from, which on a host that serves only the sign-in page
    /// is a page nobody chose, and often the sign-in page again. Naming one is how an operator
    /// says where a login ends when the visitor, the `401` round trip and the `Referer` all said
    /// nothing. A present `rd` still wins, and a *rejected* `rd` still falls back to the sign-in
    /// page, so the one path this touches is the one that had no answer.
    ///
    /// It passes the settings file's three-part rule cleanly, and that is why it is **not** a
    /// guarded change: it is read per request, after the token is verified and the cookie built;
    /// it decides only where a browser that is already signed in is sent, so the worst a wrong
    /// value achieves is a `403` or a `404` landing, the cookie is set either way, and whoever
    /// made the edit still holds a session to undo it with; and it is a `Location:` a browser
    /// follows, not a secret.
    ///
    /// It is the one value in this section written **only when set**, because `GateSettings`
    /// refuses unknown keys and an older binary therefore refuses a file that carries it: an
    /// editor that never touched it never writes the key, so a host that does not use this
    /// setting can roll back to an older binary with no step at all.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub landing_url: String,
    /// The Cognito **hosted-UI domain**, as a bare host with no scheme and no path, e.g.
    /// `pool.auth.eu-central-1.amazoncognito.com`. Empty means this deployment offers no
    /// social sign-in at all.
    ///
    /// It is configured rather than derived because a pool's hosted UI can sit on a custom
    /// domain, so the issuer does not give it away.
    #[serde(default)]
    pub oauth_domain: String,
    /// The `redirect_uri` a social sign-in comes back to, which Cognito compares **byte for
    /// byte** with the one registered on each app client below. Normally `/auth/callback` on
    /// the host that serves the sign-in page. Empty means no social sign-in.
    #[serde(default)]
    pub social_callback_url: String,
    /// Which social sign-in buttons the page offers, in the order they appear, and **the app
    /// client each one runs through**. Empty offers none, which is the whole point: a
    /// provider is offered because somebody listed it, never because a deployment happens to
    /// federate it.
    ///
    /// The app client is per button rather than per deployment because Cognito federates per
    /// app client: which identity providers a client offers is a property of that client, so
    /// two providers may perfectly well live on two of them, and one value for all of them
    /// would have made that arrangement inexpressible. Each has to be registered with the
    /// `social_callback_url` above, which is Amazon's rule and not this file's.
    ///
    /// Every audience the gate accepts comes from here and from [`GateSettings::client_id`],
    /// which is what makes this file the whole answer to "which app clients is this gate part
    /// of". The pool they belong to is `BB_AUTH_COGNITO_ISSUER` and stays in the environment.
    #[serde(default)]
    pub social_buttons: Vec<SocialButtonSpec>,
    /// Narrows the relaxation above to these IdPs, matched case-insensitively against the
    /// token's `identities[].providerName`. Empty = any federated provider.
    ///
    /// Not to be confused with [`GateSettings::social_buttons`] above, which decides what is
    /// *offered*; this one decides whose unverified email is *accepted*.
    #[serde(default)]
    pub social_providers: Vec<String>,
    /// The session cookie's lifetime in seconds. Affects cookies minted from now on and no
    /// others, which is what keeps changing it out of the logout business.
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    /// The Cognito **user pool**: the `iss` every id_token must carry, and the host its JWKS
    /// is fetched from. Absolute https, no trailing slash. Empty means no login can complete.
    ///
    /// It is the one setting in this file that is **not read per request**, so it is here in
    /// spite of the membership rule rather than because of it, and the cost is paid in the
    /// reload: a SIGHUP that sees a new value fetches that issuer's JWKS first and swaps the
    /// keys and the settings together, or swaps neither. Half of that pair applied is a gate
    /// checking this pool's tokens against the other pool's keys, which is every login
    /// failing on a signature.
    ///
    /// What it costs is stated with the other two at the top of this section: it used to be
    /// the reason the app clients were safe in a file a browser can edit (the file could only
    /// choose among the clients of a pool the environment already trusted), and that sentence
    /// is now retired rather than quietly untrue.
    #[serde(default)]
    pub issuer: String,
    /// The session cookie's `Domain`, with or without a leading dot. Empty is a **host-only**
    /// cookie, which only serves a deployment where the gate and the application are one
    /// host; a parent domain is what makes one session cover every service behind the gate.
    ///
    /// **Changing it does not log anybody out, and that is the problem.** A browser matches a
    /// clearing `Set-Cookie` on `(name, Domain, Path)`, so every cookie already issued under
    /// the old domain stays valid for its full lifetime and `/auth/logout` can no longer
    /// clear it: a logout that silently succeeds at nothing, for everybody who signed in
    /// before the edit. The way back is to put the old value back, which makes those cookies
    /// clearable again. Both editors therefore make this a **two-step** with the consequences
    /// on screen, which is the one place in this file where saying it once is not enough.
    #[serde(default)]
    pub cookie_domain: String,
    /// The hosts a post-login `rd` may land on, as host globs (`badbat75.com`,
    /// `*.badbat75.com`). The **only** authority on where a redirect may go: see
    /// [`compile_host_pattern`], and note that `*.x.com` does not match the apex `x.com`,
    /// which has to be listed.
    ///
    /// Empty refuses every redirect target there is, so every login lands on the sign-in page
    /// instead of where the visitor was going. That is useless but fail-closed, and it is
    /// tolerated for the reason an empty `client_id` is: a package creates this file and
    /// cannot know the answer, and a gate that refused to start over it would be a boot loop
    /// on every first install.
    ///
    /// It sits beside [`GateSettings::login_url`] now, which used to be the thing it guarded.
    /// What compensates is the check that only became possible once the two were in one file:
    /// [`GateSettings::cookie_domain`] must reach every host listed here, or
    /// [`compile_settings`] refuses the file. A host the cookie cannot reach is a redirect
    /// into a `401`, a bounce back to the sign-in page, and a loop with nothing in the
    /// journal to say why.
    #[serde(default)]
    pub authorized_hosts: Vec<String>,
}

fn default_identity_attrs() -> Vec<String> {
    vec!["email".to_string()]
}

fn default_session_ttl() -> u64 {
    2_592_000
}

impl Default for GateSettings {
    /// Hand-written, and it must stay in step with the `serde(default = …)` above: a derived
    /// `Default` would give an empty attribute list (fatal) and a zero TTL (a login loop),
    /// which is the wrong answer to a section somebody left out.
    fn default() -> Self {
        GateSettings {
            profile_claims: Vec::new(),
            identity_attrs: default_identity_attrs(),
            allow_unverified_social: false,
            // Empty on purpose: a fresh file names no app client, offers no social sign-in,
            // and a button exists because somebody wrote one.
            client_id: String::new(),
            login_url: String::new(),
            denied_url: String::new(),
            landing_url: String::new(),
            oauth_domain: String::new(),
            social_callback_url: String::new(),
            social_buttons: Vec::new(),
            social_providers: Vec::new(),
            session_ttl_secs: default_session_ttl(),
            // Empty for the same reason, one step further: a fresh file names no pool, no
            // cookie domain and no redirect target, and says so loudly rather than guessing.
            issuer: String::new(),
            cookie_domain: String::new(),
            authorized_hosts: Vec::new(),
        }
    }
}

/// The audit's section of the settings file: which headers it believes about where a request
/// came from, when its live file rotates, and how much of it is kept.
///
/// A section of its own rather than four more fields of `gate`, although the gate is what
/// reads it, because it answers a different question from the rest of `gate`: not how a
/// request is answered but what is written down about it afterwards. It is also the section an
/// older binary can be handed without refusing the file, since an unknown key at the top level
/// is preserved rather than refused.
///
/// All four pass the three-part rule, and say so rather than assume it. Each is read when an
/// event is recorded or the files are maintained, which is per request or hourly and never
/// once at startup; none can close a door, since the audit is written after the decision and
/// can fail without costing a login; and none is a secret.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditSettings {
    /// The request header the **client's address** is read from: `X-Real-IP` in the README's
    /// recipe, which Debian's `proxy_params` already sets. Empty, the default, records no
    /// address at all.
    ///
    /// **Off unless named, because naming it is a promise about nginx that this file cannot
    /// check.** The gate listens on loopback and never sees a client itself, and nginx hands a
    /// client's own headers through untouched unless a `proxy_set_header` overwrites them. On
    /// a location that forgets to, the address in the audit is whatever the client chose to
    /// say, which is worse than none: an audit that can be told a lie is an audit that tells
    /// one. So it is switched on by whoever wires nginx, in the same edit.
    ///
    /// A list is accepted and its **last** entry is taken, which makes `X-Forwarded-For` usable
    /// as well: `$proxy_add_x_forwarded_for` appends the address nginx saw to whatever the
    /// client sent, so the last entry is nginx's and everything before it is the client's
    /// word. A value that is not an address is not recorded.
    #[serde(default)]
    pub client_ip_header: String,
    /// The request header nginx's **id for the request** is read from: `X-Request-ID`, set
    /// from `$request_id`, in the README's recipe. Empty, the default, records none.
    ///
    /// It is the audit's way to everything it deliberately does not hold. nginx's access log
    /// has the request line, the status, the byte count and the referrer for every request,
    /// and with `$request_id` in its `log_format` one search for this value finds the line an
    /// audit row is about. Off unless named for the reason the address is: a header nginx does
    /// not overwrite is the client's, and an id the client chose points at somebody else's line.
    #[serde(default)]
    pub request_id_header: String,
    /// When the live file moves onto `.1`, replacing the one before: an amount and a unit, of
    /// space (`4 MiB`, `1 GiB`) or of time (`1 month`, the age of the file's oldest event).
    /// Empty means [`AUDIT_MAX_BYTES`]. See [`AuditPolicy`].
    #[serde(default)]
    pub rotation: String,
    /// How much of the audit is kept at most, across both files: of time (`6 months`: no event
    /// older than that stays on disk, whichever file it is in) or of space (`64 MiB`: the two
    /// files together never exceed it). Empty keeps what the rotation keeps and nothing less.
    ///
    /// A retention in time is the one to reach for when the question is personal data: an
    /// address is kept for as long as it says and not for as long as the bytes happen to last,
    /// which on a quiet deployment is years.
    #[serde(default)]
    pub retention: String,
}

/// The GUI's half of the settings file: who may open its door.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebSettings {
    /// The emails allowed to use `bb-auth-web`, matched against the identity nginx injects.
    ///
    /// **Never empty**, and never "everyone": it is the backstop that keeps an `anonymous` or
    /// `authenticated` scope covering the admin URL from handing the admin surface to any
    /// Cognito account. It is enforced where it can be acted on: `bb-auth-web` refuses to
    /// serve without it, and both editors refuse to write an empty list, rather than here,
    /// because the *gate* has no business failing to start over a list it never reads.
    #[serde(default)]
    pub admins: Vec<String>,
}

/// The look, shared by both services: the section that says how a page presents itself, and
/// never who may see one.
///
/// Every field in it passes the three-part rule the settings file exists for. Each is read
/// **per request**, when a page is rendered. None can lock anybody out: the worst a wrong
/// value here achieves is an unstyled page or a missing logo, because the built-in
/// stylesheet is complete on its own and an override is only ever an addition to it. And
/// none is a secret. A value that fails any of the three belongs in `bb-auth.env`, however
/// convenient it would be to edit it from a GUI.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UiSettings {
    /// A stylesheet to load after the built-in one, or empty for none.
    ///
    /// It is expected to redefine the custom properties in [`THEME_CSS`] and nothing else:
    /// that is what makes one file restyle the gate's pages and the admin GUI at once,
    /// without knowing what either page is made of. It is emitted as an ordinary `<link>`,
    /// so a host that does not answer costs the page its palette and nothing else.
    #[serde(default)]
    pub stylesheet_url: String,
    /// A logo for the gate's login page, or empty for none, in which case the page shows the
    /// brand name alone.
    #[serde(default)]
    pub logo_url: String,
    /// The product name a page introduces itself with. Empty means each page falls back to
    /// its own name, which is what a deployment nobody has told a brand should show.
    #[serde(default)]
    pub brand_name: String,
    /// Which arm of the palette a page starts in: `system` (the default), `light` or `dark`.
    ///
    /// The gate's pages have nowhere to keep a per-visitor choice, so for them this is the
    /// whole answer. `bb-auth-web` treats it as the default an administrator's own cookie
    /// then overrides, which is why a deployment that pins `dark` here still leaves one free
    /// to work in light.
    #[serde(default)]
    pub theme: String,
}

/// A settings file as it is written: three sections, a version, and whatever else was in it.
///
/// The sections answer four different questions, which is why they are four and not one:
/// `gate` is how the gate answers a request, `audit` is what it writes down about one and for
/// how long, `web` is who may use the GUI, and `ui` is how a page looks to whoever reaches one.
/// `ui` is the one *both* programs render from, and `audit` the one both read (the gate to
/// write the audit, the GUI to show no more of it than the retention keeps).
///
/// Unknown keys are rejected inside each section, for the reason [`AppSpec`] rejects them,
/// a typo in a setting that narrows behaviour must not be dropped in silence, and preserved
/// at the top level, where `_comment` is the only thing anyone puts.
#[derive(Deserialize, Serialize, Default)]
pub struct SettingsFile {
    /// The format this file is written in. The only accepted value is [`SETTINGS_VERSION`].
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub gate: GateSettings,
    #[serde(default)]
    pub audit: AuditSettings,
    #[serde(default)]
    pub web: WebSettings,
    #[serde(default)]
    pub ui: UiSettings,
    /// Unknown top-level keys, preserved verbatim across an edit.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The settings as the two services use them: names resolved to headers, lists normalised,
/// every refusal already made.
///
/// One compiled type for both, rather than one each, so that "would the other program accept
/// this?" is not a question an editor has to answer for itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// See [`GateSettings::profile_claims`].
    pub profile_claims: Vec<ProfileClaim>,
    /// See [`GateSettings::identity_attrs`]. Never empty.
    pub identity_attrs: Vec<IdentityAttr>,
    /// See [`GateSettings::allow_unverified_social`].
    pub allow_unverified_social: bool,
    /// `None` = any federated provider, which is what an empty list means.
    pub social_providers: Option<Vec<String>>,
    /// See [`GateSettings::client_id`]. May be empty, which is a deployment that cannot
    /// complete a login yet; the gate says so at startup rather than refusing to start.
    pub client_id: String,
    /// Every app client a token may be minted for: [`Settings::client_id`] first, then each
    /// button's, deduplicated and in file order. **Derived, never configured**, which is what
    /// removed the last list in this system that had to agree with another one by hand.
    ///
    /// Empty when no app client is named at all, and that is a state to keep working rather
    /// than to refuse: `aud` is a required claim, so an empty list accepts no token, which is
    /// the honest reading of a deployment that has not said which app clients it is part of.
    pub audiences: Vec<String>,
    /// See [`GateSettings::login_url`]. Empty = the gate's own `/auth/login`, and the gate
    /// is where that default is applied, because only it knows the path it serves.
    pub login_url: String,
    /// See [`GateSettings::denied_url`]. Empty = the gate's own `/auth/denied`, and the gate
    /// applies that default too, for the same reason.
    pub denied_url: String,
    /// See [`GateSettings::landing_url`]. Empty = the caller's root, and the gate is where that
    /// default is applied, because only it knows the origin of the request that logged in.
    pub landing_url: String,
    /// See [`GateSettings::oauth_domain`]. `None` = no social sign-in.
    pub oauth_domain: Option<String>,
    /// See [`GateSettings::social_callback_url`]. `None` = no social sign-in.
    pub social_callback_url: Option<String>,
    /// See [`GateSettings::social_buttons`]. Empty = the sign-in page offers no social button
    /// at all: no divider, no button, nothing hinting at a way in this page is not offering.
    /// Never non-empty without the two above, which [`compile_settings`] enforces.
    pub social_buttons: Vec<SocialButton>,
    /// See [`GateSettings::session_ttl_secs`].
    pub session_ttl: u64,
    /// See [`GateSettings::issuer`], trailing slash removed. Empty accepts no token at all.
    pub issuer: String,
    /// See [`GateSettings::cookie_domain`], lowercased and kept exactly as written, leading
    /// dot and all, because that is what goes into the header. `None` = a host-only cookie.
    pub cookie_domain: Option<String>,
    /// See [`GateSettings::authorized_hosts`], compiled. Empty refuses every redirect target.
    pub authorized_hosts: Vec<UrlPattern>,
    /// See [`AuditSettings::client_ip_header`]. `None` = no address is recorded.
    pub client_ip_header: Option<String>,
    /// See [`AuditSettings::request_id_header`]. `None` = no request id is recorded.
    pub request_id_header: Option<String>,
    /// [`AuditSettings::rotation`] and [`AuditSettings::retention`], compiled into the one
    /// thing both programs need of them.
    pub audit_policy: AuditPolicy,
    /// See [`WebSettings::admins`], normalised with [`norm_email`] and deduplicated. May be
    /// empty here; `bb-auth-web` is where that is fatal.
    pub admins: Vec<String>,
    /// See [`UiSettings::stylesheet_url`]. `None` = no override, and the built-in stylesheet
    /// is the whole answer.
    pub stylesheet_url: Option<String>,
    /// See [`UiSettings::logo_url`].
    pub logo_url: Option<String>,
    /// See [`UiSettings::brand_name`]. `None` = each page falls back to its own name.
    pub brand_name: Option<String>,
    /// See [`UiSettings::theme`].
    pub theme: UiTheme,
}

impl Settings {
    /// Whether `email` (already [`norm_email`]-normalised) may use the GUI.
    pub fn is_admin(&self, email: &str) -> bool {
        self.admins.iter().any(|a| a == email)
    }

    /// The Cognito JSON API endpoint a browser-side client talks to: the issuer's origin,
    /// since the pool id is the only part of an issuer URL that is not it.
    ///
    /// **Derived and never configured**: a page that named its own endpoint could name a
    /// pool this deployment does not validate against, and the symptom would be a login
    /// that succeeds in the browser and is refused by the gate a redirect later. Computed
    /// per use rather than held, because the issuer is a setting and a held copy would be
    /// the stale half of a reload.
    ///
    /// It lives in the library because the gate is not the only program that needs the
    /// answer: the gate stamps it into the sign-in page it serves, and `bb-auth-web` will
    /// call Cognito itself (docs/ARCHITECTURE.md §13.22, slice 5b), so a second answer to
    /// "where does this pool's API live" is exactly the drift this library exists to end.
    ///
    /// Empty when the issuer has no origin: a page must never be handed a bare "/" to
    /// post a credential to.
    pub fn cognito_endpoint(&self) -> String {
        match self.issuer.find("://") {
            Some(i) => {
                let rest = &self.issuer[i + 3..];
                let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
                if end == 0 {
                    String::new()
                } else {
                    format!("{}/", &self.issuer[..i + 3 + end])
                }
            }
            None => String::new(),
        }
    }
}

/// The social identity providers this project knows by name, as `(identity_provider, label)`.
///
/// Two programs have an opinion about this list now, which is what puts it here rather than
/// in either of them: the gate draws a button per enabled provider, and the admin GUI offers
/// a checkbox per provider to enable. A second table would mean a provider an operator can
/// switch on and no button, or a button whose name the switch spells differently, and the
/// spelling is not cosmetic: the first field is what Cognito is sent as `identity_provider`,
/// and Amazon matches it exactly.
///
/// What is NOT here is the icon, which stays in the gate beside the pages that draw it: an
/// inline SVG is presentation, the admin GUI has no use for one, and the membership rule is
/// about what more than one program must agree on rather than about keeping like with like.
///
/// **`MicrosoftPersonal` is the personal-account provider**, the one behind an `outlook.com`
/// or `hotmail.com` address, and it is deliberately not the work-and-school one: an Entra ID
/// tenant is a different provider, configured separately on the user pool under whatever name
/// its administrator gave it, and offering the two under one label would be telling somebody
/// their work account will work when it will not.
///
/// A pool may federate a provider this table has never heard of, which is why nothing here is
/// a whitelist: [`compile_social_buttons`] takes any well-formed name, the gate labels an
/// unknown one with the name itself, and the GUI shows it as a checkbox of its own so that
/// enabling it from `bb-auth-adm` does not make the page unable to represent the file.
pub const SOCIAL_IDPS: [(&str, &str); 2] =
    [("Google", "Google"), ("MicrosoftPersonal", "Microsoft")];

/// What a person calls `name`, or the name itself when this project has never heard of it.
pub fn social_idp_label(name: &str) -> &str {
    SOCIAL_IDPS
        .iter()
        .find(|(idp, _)| idp.eq_ignore_ascii_case(name))
        .map(|(_, label)| *label)
        .unwrap_or(name)
}

/// One social sign-in button as the file writes it: the provider, and the app client it runs
/// through.
///
/// The bare-string arm is the shape this field had before the app clients moved into this
/// file, and it exists to be **refused with a sentence** rather than to be supported. A type
/// error three levels down would say `invalid type: string` about a file somebody's previous
/// version wrote, which is the least useful moment to be terse; this is the same reflex the
/// access file's `version` check has.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum SocialButtonSpec {
    /// `{ "idp": "Google", "audience": "…" }`, the only shape that compiles.
    Wired(WiredButton),
    /// `"Google"`, written by a version that had one app client for every button.
    Name(String),
}

/// The object arm of [`SocialButtonSpec`].
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WiredButton {
    /// Cognito's own `identity_provider` name, e.g. `Google`.
    pub idp: String,
    /// The app client this provider is federated by, and the `aud` its tokens carry.
    #[serde(default)]
    pub audience: String,
}

/// One social sign-in button, compiled: both halves present and well formed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocialButton {
    /// Cognito's own `identity_provider` name.
    pub idp: String,
    /// The app client the hosted UI is handed and the callback exchanges its code with.
    pub audience: String,
}

/// Validate one Cognito app client id, for the setting `what` names.
///
/// Empty is not a refusal here: it is the caller that decides whether an absent app client is
/// a warning (the email flow's, on a file a package just created) or an error (a button's,
/// which cannot be drawn without one).
///
/// The charset is the `identity_provider` one, and it carries more weight than it does there.
/// This value is substituted into the sign-in page as a JavaScript string literal, into an
/// HTML attribute on a button, and into the query string of Cognito's authorize URL, so
/// restricting it to letters, digits, `.`, `_` and `-` is what makes all three safe by
/// construction rather than by escaping: the same argument the gate's `env_page_value` makes
/// for the values these arrived as until they became settings. A Cognito app client id is 26
/// lowercase alphanumerics, so nothing this refuses could have been one.
/// The tail of an app client id refusal, byte for byte as the leaf spelled it before
/// [`SettingsRefusal::AppClientId`] existed (§13.31 §2 row 12). It is a `const` because two
/// callers print it under two different names: the enum's `sentence()` spells the settings key
/// and the button's name, and this leaf's wrapper spells whatever its caller names (`client_id`,
/// the CLI's `--client-id`, the GUI's `audience`), so the tail must have exactly one home.
pub(crate) const APP_CLIENT_TAIL: &str =
    "is not an app client id, which is letters, digits, '.', '_' and '-'";

pub fn compile_app_client_id(what: &str, raw: &str) -> Result<String, String> {
    app_client_id_core(raw)
        // The caller's name in front of the shared tail: the CLI calls this leaf with its own
        // flag and the GUI with its own field name, and neither is a settings key, so the
        // variant's own sentence, which names `client_id`, is not what these callers print
        // (§13.31 §3).
        .map_err(|_| format!("{what}: '{}' {APP_CLIENT_TAIL}", raw.trim()))
}

/// [`compile_app_client_id`]'s checks, answering the typed refusal (§13.31 §3). The refusal
/// carries the **trimmed** id, which is what today's sentence quoted. Empty is
/// `Ok(String::new())`, the setting unset, and so is never a refusal.
fn app_client_id_core(raw: &str) -> Result<String, SettingsRefusal> {
    let id = raw.trim();
    if id.is_empty() {
        return Ok(String::new());
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(SettingsRefusal::AppClientId {
            button: None,
            id: id.to_string(),
        });
    }
    Ok(id.to_string())
}

/// Validate the hosted-UI domain: a bare host, which is what the two OAuth URLs are built out
/// of.
///
/// No scheme and no path, and that is checked rather than stripped, because a value that
/// carries either was written by somebody who meant a URL and would otherwise be turned into
/// one that quietly resolves somewhere else.
pub fn compile_oauth_domain(raw: &str) -> Result<String, String> {
    oauth_domain_core(raw).map_err(|r| r.sentence())
}

/// [`compile_oauth_domain`]'s checks, answering the typed refusal (§13.31 §3). The refusal quotes
/// the **trimmed** value, which is what today's sentence printed, and an empty one is
/// `Ok(String::new())`, the setting unset, so it is never a refusal.
fn oauth_domain_core(raw: &str) -> Result<String, SettingsRefusal> {
    let d = raw.trim();
    if d.is_empty() {
        return Ok(String::new());
    }
    if !d
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || d.starts_with('.')
        || d.ends_with('.')
    {
        return Err(SettingsRefusal::OauthDomainNotBare { raw: d.to_string() });
    }
    Ok(d.to_string())
}

/// Validate the Cognito issuer: the absolute https URL an id_token's `iss` must equal, with
/// any trailing slash removed.
///
/// The same guard [`compile_login_url`] applies, for a longer list of reasons: this value is
/// fetched from over the network, compared byte for byte against a token claim, and emitted
/// into the sign-in page's `connect-src` as the one origin that page's script may talk to.
/// Printable ASCII is what makes the last of those safe with no escaping at all.
///
/// A query or a fragment is refused rather than trimmed. Cognito's `iss` is an origin and a
/// pool id and nothing else, so a value carrying either was written by somebody who meant a
/// different URL, and trimming it would build a JWKS URL they never asked for.
pub fn compile_issuer(raw: &str) -> Result<String, String> {
    issuer_core(raw).map_err(|(raw, fault)| format!("issuer '{raw}': {fault}"))
}

/// [`compile_issuer`]'s checks, answering the typed refusal (§13.31 §3). The value it quotes is
/// `raw` as given, which is what today's sentence printed, and the trailing-slash trim happens
/// here, so `"https://"` is refused as not https, exactly as before. An empty issuer is
/// `Ok(String::new())`, the setting unset, and the gate says so loudly at startup rather than
/// refusing to boot.
fn issuer_core(raw: &str) -> Result<String, (String, UrlFault)> {
    let u = raw.trim().trim_end_matches('/');
    let e = |fault| Err((raw.to_string(), fault));
    if u.is_empty() {
        return Ok(String::new());
    }
    if !u.bytes().all(|b| b.is_ascii_graphic()) {
        return e(UrlFault::NotPrintable);
    }
    let rest = match u.strip_prefix("https://") {
        Some(r) => r,
        None => return e(UrlFault::NotHttps),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return e(UrlFault::EmptyHost);
    }
    if authority.contains('@') || u.contains('\\') {
        return e(UrlFault::UserinfoOrBackslash);
    }
    if u.contains('?') || u.contains('#') {
        return e(UrlFault::QueryOrFragment);
    }
    Ok(u.to_string())
}

/// Validate the session cookie's `Domain`: a bare domain, optionally with the leading dot
/// RFC 6265 ignores, and never a scheme, a port or a path.
///
/// A single label is refused with a sentence of its own, because it is the mistake that looks
/// most like it should work: a browser will not store a cookie for `com` (a public suffix) and
/// has no use for one on a bare hostname that is not the request's own. What is wanted there
/// is the registrable domain the services share.
pub fn compile_cookie_domain(raw: &str) -> Result<String, String> {
    cookie_domain_core(raw).map_err(|r| r.sentence())
}

/// [`compile_cookie_domain`]'s checks, answering the typed refusal (§13.31 §3). The refusal
/// quotes `raw` **as given**, which is what today's sentence printed, and the value returned is
/// the trimmed, lowercased one. Empty is `Ok(String::new())`, the setting unset.
fn cookie_domain_core(raw: &str) -> Result<String, SettingsRefusal> {
    let d = raw.trim().to_ascii_lowercase();
    if d.is_empty() {
        return Ok(String::new());
    }
    let bare = d.strip_prefix('.').unwrap_or(&d);
    if bare.is_empty()
        || !bare
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || bare.starts_with('-')
        || bare.starts_with('.')
        || bare.ends_with('.')
        || bare.ends_with('-')
        || bare.contains("..")
    {
        return Err(SettingsRefusal::CookieDomainNotBare {
            raw: raw.to_string(),
        });
    }
    if !bare.contains('.') {
        return Err(SettingsRefusal::CookieDomainSingleLabel {
            raw: raw.to_string(),
        });
    }
    Ok(d)
}

/// The request headers an audit value may never be read from, because each carries a
/// credential. Compared case-insensitively, as header names are.
const CREDENTIAL_HEADERS: [&str; 3] = ["Authorization", "Proxy-Authorization", "Cookie"];

/// Validate the name of a request header the audit reads a value out of, for the setting
/// `what` names: empty, which is the setting switched off, or a header name that is not a
/// credential.
///
/// The charset is letters, digits and `-`, which is narrower than RFC 9110's token and is
/// every header name anybody actually writes. The underscore is the one that matters: nginx
/// drops a request header with one in its name unless `underscores_in_headers` says otherwise,
/// so a name that allowed it would allow a setting that reads nothing, in silence.
///
/// The credential headers are refused by name, and the reason is the request id rather than
/// the address. An address is parsed and whatever is not one is dropped, so naming
/// `Authorization` there would only record nothing; but a request id is written down as it
/// arrives, and naming a header that carries a credential would put that credential into a file
/// an administrator reads, which is the one thing this system never does with a bearer.
pub fn compile_audit_header(what: &str, raw: &str) -> Result<String, String> {
    // The caller's name in front of the shared tail: `bb-auth-adm` calls this leaf with its own
    // flag and the GUI with its own field name, and neither is a settings key, so the variant's
    // own sentence, which names `audit.client_ip_header`, is not what these callers print
    // (§13.31 §3).
    audit_header_core(raw).map_err(|(name, fault)| format!("{what}: '{name}' {fault}"))
}

/// [`compile_audit_header`]'s checks, answering the typed refusal's parts (§13.31 §3). The pair
/// it returns is the name **trimmed**, which is what today's sentence quoted, and the fault: the
/// setting's name belongs to the caller, which is why the CLI keeps its flag name in front of
/// the same tail. An empty value is the setting switched off, and is `Ok(String::new())`.
fn audit_header_core(raw: &str) -> Result<String, (String, HeaderFault)> {
    let name = raw.trim();
    if name.is_empty() {
        return Ok(String::new());
    }
    if name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err((name.to_string(), HeaderFault::NotAName));
    }
    if CREDENTIAL_HEADERS
        .iter()
        .any(|c| c.eq_ignore_ascii_case(name))
    {
        return Err((name.to_string(), HeaderFault::Credential));
    }
    Ok(name.to_string())
}

/// Compile `audit.rotation` and `audit.retention` into a policy, or say why not.
///
/// Empty is a default and not a refusal for both: a rotation nobody wrote is
/// [`AUDIT_MAX_BYTES`], and a retention nobody wrote is no limit beyond the rotation's own,
/// which is what the audit did before either was a setting. Each message names the setting it
/// is about, because the one sentence [`AuditPolicy::new`] can add is about the pair.
pub fn compile_audit_policy(rotation: &str, retention: &str) -> Result<AuditPolicy, String> {
    // `Display` is the prefixed sentence, which is byte for byte what this function printed
    // when it built the prefixes itself: `audit.rotation: …` / `audit.retention: …` for a limit,
    // `audit: …` for the pair, which is the prefix `bb-auth-adm` swaps for its own flags
    // (§13.31 §3).
    audit_section_core(rotation, retention).map_err(|r| r.to_string())
}

/// What a `Domain=` attribute actually reaches: the value without the optional leading dot,
/// which RFC 6265 ignores. The one place that dot is taken off, so nothing compares two
/// spellings of one domain and calls them different.
pub fn cookie_domain_host(domain: &str) -> &str {
    domain.strip_prefix('.').unwrap_or(domain)
}

/// Whether a cookie on `domain` is sent to every host `pattern` can match.
///
/// Textual rather than a glob intersection, and sound because a host pattern's suffix is
/// literal: everything `*.x.com` matches ends in `.x.com`, so a cookie on `x.com` reaches all
/// of it. The dot carries the whole check on both sides. `*x.com`, written without one, is
/// **not** covered and must not be, since it matches `evilx.com`, which no cookie on `x.com`
/// is ever sent to.
pub fn cookie_domain_covers(domain: &str, pattern: &str) -> bool {
    let d = cookie_domain_host(domain);
    let p = pattern.trim().to_ascii_lowercase();
    p == d || p.ends_with(&format!(".{d}"))
}

/// A setting whose change can stop people getting in, and which both editors therefore make a
/// **two-step** rather than a save.
///
/// Which fields these are is in this crate for the crate's own membership rule: two programs
/// edit this file, and one that wrote in silence what the other stopped to ask about would
/// make the guard a property of which editor you happened to open. The *wording* is not here.
/// That has an operator on the other end, so the CLI prints sentences and the GUI renders a
/// panel in two languages, and neither belongs in a library.
///
/// **It is five and not fifteen on purpose.** A confirmation that fires on every save is a
/// button people learn to click without reading, which is worse than no confirmation at all
/// because it is also an alibi. What earns a place here is the pair of properties that makes a
/// confirmation the right instrument in the first place: the value can stop a **new** login,
/// and it invalidates no cookie, so whoever made the edit still holds a session and can undo
/// it. The `ui` four cost a palette; the social wiring costs one way in of several; neither is
/// this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardedSetting {
    /// The pool. Every id_token is then checked against another issuer's `iss` and keys.
    Issuer,
    /// The email flow's app client. Every id_token is refused for its audience.
    ClientId,
    /// Where a `401` sends a browser. A wrong one is a sign-in page that is not there.
    LoginUrl,
    /// The cookie's `Domain`, and the only one here that does something worse than shut a
    /// door: see [`GateSettings::cookie_domain`].
    CookieDomain,
    /// Where a post-login redirect may land. Only a **removal** is guarded.
    AuthorizedHosts,
}

impl GuardedSetting {
    /// The field's name in the file, which is also the name both editors post it under.
    pub fn field(self) -> &'static str {
        match self {
            GuardedSetting::Issuer => "issuer",
            GuardedSetting::ClientId => "client_id",
            GuardedSetting::LoginUrl => "login_url",
            GuardedSetting::CookieDomain => "cookie_domain",
            GuardedSetting::AuthorizedHosts => "authorized_hosts",
        }
    }
}

/// Which guarded settings `new` changes relative to `old`: what an editor must confirm before
/// writing, and empty when there is nothing to stop for.
///
/// Two rules keep this quiet enough to be read, and both say the same thing: **a confirmation
/// is about what is taken away, never about what is set for the first time.** A field that was
/// empty and now is not can only be a deployment being finished, so it passes; a field that
/// had a value passes only if the value is unchanged. And for the host list, only a **removal**
/// counts: adding a host cannot stop a login, it widens where one may land, which is a
/// different conversation and one [`compile_settings`] already has with `cookie_domain`.
///
/// Comparison is on the normalised value, so a leading dot, a trailing slash, surrounding
/// space or a change of case is not a change. Two editors that disagreed about that would
/// disagree about when to ask.
pub fn guarded_changes(old: &GateSettings, new: &GateSettings) -> Vec<GuardedSetting> {
    let mut out = Vec::new();
    let scalar = |o: &str, n: &str| {
        let (o, n) = (o.trim(), n.trim());
        !o.is_empty() && o != n
    };
    if scalar(
        old.issuer.trim_end_matches('/'),
        new.issuer.trim().trim_end_matches('/'),
    ) {
        out.push(GuardedSetting::Issuer);
    }
    if scalar(&old.client_id, &new.client_id) {
        out.push(GuardedSetting::ClientId);
    }
    if scalar(&old.login_url, &new.login_url) {
        out.push(GuardedSetting::LoginUrl);
    }
    if scalar(
        cookie_domain_host(&old.cookie_domain.trim().to_ascii_lowercase()),
        cookie_domain_host(&new.cookie_domain.trim().to_ascii_lowercase()),
    ) {
        out.push(GuardedSetting::CookieDomain);
    }
    let host_set = |v: &[String]| -> Vec<String> {
        v.iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect()
    };
    let (before, after) = (
        host_set(&old.authorized_hosts),
        host_set(&new.authorized_hosts),
    );
    if before.iter().any(|h| !after.contains(h)) {
        out.push(GuardedSetting::AuthorizedHosts);
    }
    out
}

/// Validate the social sign-in buttons: a provider and an app client each.
///
/// **Fatal on a bad entry, like a claim name and for the same reason.** A silently skipped
/// entry here is a button an operator configured, cannot see, and has nowhere to look for:
/// there is no error, no log line at the moment it matters, and the page simply does not
/// offer what the file says it offers. Refusing the file says it once, in the editor, before
/// it is live. An entry with no app client is one of those: it could not draw a button, so it
/// is refused rather than dropped.
///
/// The charset is Cognito's own for an `identity_provider`: letters, digits, and `._-`. It is
/// not a list of known providers, because a user pool may federate a SAML or OIDC provider
/// under any name its administrator chose, and this file has no way to know which. What it
/// can refuse is a value that could never be one: a space, a quote, an angle bracket, a
/// percent sign. That value would land in a query parameter and in an HTML attribute, and
/// while both are escaped where they are emitted, a name that cannot work is worth catching
/// where it is written rather than where it fails.
///
/// Duplicates are refused rather than deduplicated: two buttons for one provider is not what
/// anybody meant, and quietly dropping one would hide a copy-paste from an operator who is
/// looking straight at the list.
///
/// This leaf answers the typed [`SettingsRefusal`] itself, with no `String` wrapper beside it:
/// `compile_settings` is its only caller, so the refusal built here is the refusal the file is
/// refused with, and there is no other caller whose words a wrapper would have to serve
/// (docs/ARCHITECTURE.md §13.31 §3).
pub fn compile_social_buttons(
    raw: &[SocialButtonSpec],
) -> Result<Vec<SocialButton>, SettingsRefusal> {
    let mut out: Vec<SocialButton> = Vec::with_capacity(raw.len());
    for entry in raw {
        let wired = match entry {
            SocialButtonSpec::Wired(w) => w,
            // The pre-2 shape, answered with the sentence a type error could not have said.
            SocialButtonSpec::Name(n) => {
                return Err(SettingsRefusal::ButtonBareName { name: n.clone() })
            }
        };
        let name = wired.idp.trim();
        if name.is_empty() {
            return Err(SettingsRefusal::ButtonNoIdp);
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        {
            return Err(SettingsRefusal::ButtonIdpCharset {
                idp: name.to_string(),
            });
        }
        if out.iter().any(|k| k.idp.eq_ignore_ascii_case(name)) {
            return Err(SettingsRefusal::ButtonTwice {
                idp: name.to_string(),
            });
        }
        // The shared app client core, with this button's name put on its refusal: the variant's
        // sentence spells `client_id`, which is the setting the core answers for, and a button's
        // audience is not that (§13.31 §3). Empty is `Ok("")` there, so the empty audience is
        // this leaf's own refusal, one check below.
        let audience = app_client_id_core(&wired.audience).map_err(|r| match r {
            SettingsRefusal::AppClientId { id, .. } => SettingsRefusal::AppClientId {
                button: Some(name.to_string()),
                id,
            },
            other => other,
        })?;
        if audience.is_empty() {
            return Err(SettingsRefusal::ButtonNoAudience {
                idp: name.to_string(),
            });
        }
        out.push(SocialButton {
            idp: name.to_string(),
            audience,
        });
    }
    Ok(out)
}

/// Why [`SettingsWrite::prepare`] will not put a settings document on the disk: the two serde
/// failures on our own structs, and the refusal [`compile_settings`] makes.
///
/// Its `Display` is the sentence `bb-auth-adm` prints today, `refusing to write:` included, and
/// [`From<PrepareError> for String`] is the one thing that lets that CLI print it without
/// changing a line (docs/ARCHITECTURE.md §13.31 §3). The GUI does not use the sentence: it maps
/// the refusal's [`SettingsRefusal::code`] to a `K` key, in slice S8.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrepareError {
    /// The document would not serialize: serde on our own structs, never seen.
    Serialize(String),
    /// The bytes it wrote do not re-parse: same, and the reason the check exists at all.
    Reparse(String),
    /// The compiled settings refuse these bytes, for a reason the settings file owns.
    Refused(SettingsRefusal),
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialize(e) => write!(f, "cannot serialize: {e}"),
            Self::Reparse(e) => write!(f, "serialized to invalid JSON: {e}"),
            Self::Refused(r) => write!(f, "refusing to write: {r}"),
        }
    }
}

impl From<PrepareError> for String {
    fn from(e: PrepareError) -> String {
        e.to_string()
    }
}

/// The `map_err` that turns a URL leaf's `(raw, fault)` pair into [`SettingsRefusal::Url`] for
/// one setting, so the six URL settings of this function name themselves without six copies of
/// the same arm (§13.31 §3).
fn url_refusal(key: SettingKey) -> impl FnOnce((String, UrlFault)) -> SettingsRefusal {
    move |(raw, fault)| SettingsRefusal::Url { key, raw, fault }
}

/// The `map_err` that turns the audit header leaf's `(name, fault)` pair into
/// [`SettingsRefusal::AuditHeader`] for one of the two audit settings, the sibling of
/// [`url_refusal`] (§13.31 §3).
fn header_refusal(key: SettingKey) -> impl FnOnce((String, HeaderFault)) -> SettingsRefusal {
    move |(name, fault)| SettingsRefusal::AuditHeader { key, name, fault }
}

/// Turn a settings document into the compiled settings, or say why it cannot be one.
///
/// Fatal, with the same reflex the access file's parser has: what changes behaviour is an
/// error, what merely drops one entry is a warning. So a bad claim name, an unknown identity
/// attribute, an empty attribute list, a wrong `version` and a nonsensical TTL all refuse the
/// file; a malformed admin email is warned about and skipped, which fails closed (one fewer
/// administrator) exactly as a malformed roster identifier does.
///
/// The gate reads only the `gate` half and the GUI only the `web` half, but both compile the
/// whole file: an editor that validated only its own section could write one the other
/// refuses, and the point of a shared parser is that it cannot.
pub fn compile_settings(file: &SettingsFile) -> Result<Settings, SettingsRefusal> {
    if file.version != SETTINGS_VERSION {
        // Explanatory for the one version that exists in the wild, terse for anything else:
        // a file that says 1 was written before the Cognito app clients moved into it, and
        // its `social_client_id` and bare-name buttons cannot be read into this shape without
        // guessing which client each button belonged to.
        return Err(SettingsRefusal::Version {
            found: file.version,
        });
    }
    let profile_claims = profile_claims_core(&file.gate.profile_claims)?;
    let identity_attrs = identity_attrs_core(&file.gate.identity_attrs)?;

    let ttl = file.gate.session_ttl_secs;
    if ttl < MIN_SESSION_TTL {
        return Err(SettingsRefusal::TtlBelowFloor { ttl });
    }
    if ttl > MAX_HONOURED_SESSION_TTL {
        eprintln!(
            "[bb-auth] WARNING: session_ttl_secs {ttl} exceeds the {MAX_HONOURED_SESSION_TTL}s \
             (400 day) cap browsers apply to Max-Age; the excess is fiction"
        );
    }
    if ttl > MAX_SESSION_TTL {
        // The floor is a refusal and the browser cap is a warning, which left the top end
        // with no refusal at all: this value is added to the wall clock for the cookie's
        // `exp` and cast to `i64` for its `Max-Age`, so far enough out it wraps and mints a
        // cookie that expired in the past. That is the login loop the floor exists to
        // prevent, arrived at from the other end, and it is reachable from a GUI field.
        return Err(SettingsRefusal::TtlAboveCeiling { ttl });
    }

    let providers: Vec<String> = file
        .gate
        .social_providers
        .iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    if !providers.is_empty() && !file.gate.allow_unverified_social {
        eprintln!(
            "[bb-auth] WARNING: social_providers lists {} provider(s) but \
             allow_unverified_social is off, so it narrows nothing",
            providers.len()
        );
    }

    // The app clients, and the audience list they derive. Nothing else in this system says
    // which app clients the gate is part of, which is what makes the derivation safe: there
    // is no second list to disagree with.
    let client_id = app_client_id_core(&file.gate.client_id)?;
    let login_url = match file.gate.login_url.trim() {
        "" => String::new(),
        raw => page_url_core(raw).map_err(url_refusal(SettingKey::LoginUrl))?,
    };
    let denied_url = match file.gate.denied_url.trim() {
        "" => String::new(),
        raw => page_url_core(raw).map_err(url_refusal(SettingKey::DeniedUrl))?,
    };
    let landing_url = match file.gate.landing_url.trim() {
        "" => String::new(),
        raw => page_url_core(raw).map_err(url_refusal(SettingKey::LandingUrl))?,
    };
    let issuer = issuer_core(&file.gate.issuer).map_err(url_refusal(SettingKey::Issuer))?;
    let cookie_domain = cookie_domain_core(&file.gate.cookie_domain)?;
    let mut authorized_hosts: Vec<UrlPattern> =
        Vec::with_capacity(file.gate.authorized_hosts.len());
    for raw in &file.gate.authorized_hosts {
        if raw.trim().is_empty() {
            continue;
        }
        authorized_hosts.push(host_pattern_core(raw)?);
    }
    // The check that only became possible once these two stopped living in different files,
    // and the reason the move is worth what it cost. A host the cookie cannot reach is not a
    // subtle misconfiguration: the login succeeds, the redirect lands, the browser sends no
    // session cookie, nginx answers 401, and the browser goes back to the sign-in page it
    // just came from, for ever, with nothing anywhere saying why.
    if !cookie_domain.is_empty() {
        let stray: Vec<String> = file
            .gate
            .authorized_hosts
            .iter()
            .map(|h| h.trim())
            .filter(|h| !h.is_empty() && !cookie_domain_covers(&cookie_domain, h))
            .map(str::to_string)
            .collect();
        if !stray.is_empty() {
            return Err(SettingsRefusal::HostsOutsideCookieDomain {
                hosts: stray,
                cookie_domain: cookie_domain.clone(),
            });
        }
    }
    // The same reflex one field along, and the reason `rd_url_allowed` lives in this library:
    // a landing page outside the redirect scope is refused by it at every login, so the login
    // falls back to the sign-in page, which is the loop this setting was added to end with a
    // setting standing beside it saying it is fixed. Silent is the half that costs an afternoon,
    // so the file refuses it on the way to disk, where both editors can still say so.
    if !landing_url.is_empty()
        && (authorized_hosts.is_empty() || !rd_url_allowed(&landing_url, &authorized_hosts))
    {
        return Err(SettingsRefusal::LandingOffHosts);
    }
    let oauth_domain = oauth_domain_core(&file.gate.oauth_domain)?;
    let social_callback_url = match asset_url_core(&file.gate.social_callback_url)
        .map_err(url_refusal(SettingKey::SocialCallbackUrl))?
    {
        Some(u) if !u.starts_with("https://") => return Err(SettingsRefusal::CallbackNotHttps),
        other => other,
    };
    let social_buttons = compile_social_buttons(&file.gate.social_buttons)?;
    // A button with nowhere to send the browser, or nowhere for it to come back to, is the
    // half-configured social sign-in that used to be a fatal startup when this lived in the
    // environment. It is still refused, one level earlier: in the editor, on the file.
    if !social_buttons.is_empty() && (oauth_domain.is_empty() || social_callback_url.is_none()) {
        return Err(SettingsRefusal::SocialHalfConfigured {
            buttons: social_buttons.len(),
        });
    }
    let mut audiences: Vec<String> = Vec::with_capacity(1 + social_buttons.len());
    if !client_id.is_empty() {
        audiences.push(client_id.clone());
    }
    for b in &social_buttons {
        if !audiences.contains(&b.audience) {
            audiences.push(b.audience.clone());
        }
    }

    // What the audit reads where a request came from out of. One header for both is refused
    // with a sentence rather than accepted: it could only ever be a slip, since no header
    // carries an address and an id at once, and one of the two settings would then record
    // nothing while looking configured.
    let client_ip_header = audit_header_core(&file.audit.client_ip_header)
        .map_err(header_refusal(SettingKey::ClientIpHeader))?;
    let request_id_header = audit_header_core(&file.audit.request_id_header)
        .map_err(header_refusal(SettingKey::RequestIdHeader))?;
    if !client_ip_header.is_empty() && client_ip_header.eq_ignore_ascii_case(&request_id_header) {
        return Err(SettingsRefusal::AuditHeadersSame {
            name: client_ip_header,
        });
    }
    let audit_policy = audit_section_core(&file.audit.rotation, &file.audit.retention)?;

    let mut admins: Vec<String> = Vec::new();
    for raw in &file.web.admins {
        let e = norm_email(raw);
        if e.is_empty() {
            continue;
        }
        // The same rule the roster's identifiers are held to, and skipped for the same reason:
        // an entry that could never match the identity nginx injects is one administrator
        // fewer, which is the safe direction to be wrong in.
        if !header_safe_email(&e) || !well_formed_email(&e) {
            eprintln!("[bb-auth] WARNING: web.admins: '{e}' is not an email, skipping");
            continue;
        }
        if !admins.contains(&e) {
            admins.push(e);
        }
    }

    // The look. Fatal on a bad value, with the same reflex the claim list is held to and for
    // the same reason: a stylesheet URL silently dropped is a deployment that goes on looking
    // wrong with nothing anywhere saying why. It cannot lock anybody out, which is what earns
    // it a place in this file at all, but "cannot lock anybody out" is not "may be wrong in
    // silence".
    let stylesheet_url =
        asset_url_core(&file.ui.stylesheet_url).map_err(url_refusal(SettingKey::StylesheetUrl))?;
    let logo_url = asset_url_core(&file.ui.logo_url).map_err(url_refusal(SettingKey::LogoUrl))?;
    let brand_name = brand_name_core(&file.ui.brand_name)?;
    let theme = UiTheme::parse(&file.ui.theme).ok_or_else(|| SettingsRefusal::ThemeUnknown {
        raw: file.ui.theme.trim().to_string(),
    })?;

    Ok(Settings {
        profile_claims,
        identity_attrs,
        allow_unverified_social: file.gate.allow_unverified_social,
        social_providers: (!providers.is_empty()).then_some(providers),
        client_id,
        audiences,
        login_url,
        denied_url,
        landing_url,
        oauth_domain: (!oauth_domain.is_empty()).then_some(oauth_domain),
        social_callback_url,
        social_buttons,
        session_ttl: ttl,
        issuer,
        cookie_domain: (!cookie_domain.is_empty()).then_some(cookie_domain),
        authorized_hosts,
        client_ip_header: (!client_ip_header.is_empty()).then_some(client_ip_header),
        request_id_header: (!request_id_header.is_empty()).then_some(request_id_header),
        audit_policy,
        admins,
        stylesheet_url,
        logo_url,
        brand_name,
        theme,
    })
}

/// Read and parse a settings file, without compiling it.
pub fn read_settings_file(path: &str) -> Result<SettingsFile, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("{path}: {e}"))
}

/// Read, parse and compile a settings file: what the gate does at startup and on every
/// SIGHUP, and what `--check-settings` reports on.
pub fn read_settings(path: &str) -> Result<Settings, String> {
    let file = read_settings_file(path)?;
    compile_settings(&file).map_err(|e| format!("{path}: {e}"))
}

/// Open a settings file for editing: the document to mutate, and what the services would make
/// of it as it stands.
///
/// A file either service would reject is refused here too, for the reason [`open_access_file`]
/// refuses one: an edit must start from a file that works, or a tool would cheerfully fix one
/// problem while carrying a fatal one to the disk.
pub fn open_settings_file(path: &str) -> Result<(SettingsFile, Settings), String> {
    let doc = read_settings_file(path)?;
    let settings = compile_settings(&doc)
        .map_err(|e| format!("{path}: the gate would reject this file as it stands: {e}"))?;
    Ok((doc, settings))
}

/// Serialize a settings document to the exact bytes it is written as: pretty JSON plus one
/// trailing newline, the same shape an access file is written in.
pub fn render_settings_file(doc: &SettingsFile) -> Result<String, String> {
    let mut json = serde_json::to_string_pretty(doc).map_err(|e| e.to_string())?;
    json.push('\n');
    Ok(json)
}

/// An edited settings document, rendered to the exact bytes it would be written as, and
/// already compiled.
///
/// [`AccessWrite`] for the other file, and the same rule made unskippable the same way:
/// [`SettingsWrite::prepare`] compiles, [`SettingsWrite::commit`] writes only what was
/// compiled, and `write_atomically` is private to this crate so there is no other door. The
/// stakes are lower than the access file's by exactly one step: a settings file the gate
/// refuses is a *reload* it declines, not a boot loop, because the running table survives,
/// but a restart would still meet it, so the check stays where it cannot be skipped.
#[derive(Debug)]
pub struct SettingsWrite {
    json: String,
    settings: Settings,
}

impl SettingsWrite {
    /// Render `doc`, then re-parse and compile the rendered text. `Err` means these bytes must
    /// not reach the disk, and says why: [`PrepareError`], whose `Display` is the sentence the
    /// CLI prints, prefix included.
    pub fn prepare(doc: &SettingsFile) -> Result<SettingsWrite, PrepareError> {
        let json = render_settings_file(doc).map_err(PrepareError::Serialize)?;
        let reparsed: SettingsFile =
            serde_json::from_str(&json).map_err(|e| PrepareError::Reparse(e.to_string()))?;
        let settings = compile_settings(&reparsed).map_err(PrepareError::Refused)?;
        Ok(SettingsWrite { json, settings })
    }

    /// The bytes: what a dry run prints, and exactly what [`SettingsWrite::commit`] writes.
    pub fn json(&self) -> &str {
        &self.json
    }

    /// What the services will make of those bytes.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Replace `path` with these bytes. The file must already exist: its mode and owner are
    /// what the replacement inherits.
    pub fn commit(&self, path: &str) -> Result<Written, String> {
        write_atomically(path, &self.json)
    }

    /// Create `path` with these bytes, and only if it does not exist yet. See
    /// [`AccessWrite::create`], which is the same operation on the other file and carries the
    /// reasoning.
    pub fn create(&self, path: &str) -> Result<(), String> {
        create_new_file(path, &self.json)
    }
}
