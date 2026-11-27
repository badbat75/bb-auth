use crate::*;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Runtime configuration, read once from the environment at startup. Mirrors the gate's
/// `Config::from_env`, down to the wording of a fatal exit: a missing required var has no
/// safe default, so the process refuses to start rather than guess.
pub(crate) struct Config {
    /// `BB_AUTH_WEB_LISTEN`. Loopback — see the trust model on the crate root.
    pub(crate) listen: String,
    /// `BB_AUTH_ACCESS_FILE`, the access file to render. The gate's variable name, on
    /// purpose: each service gets its own env file, and one name means one meaning.
    pub(crate) access_path: String,
    /// `BB_AUTH_SETTINGS_FILE`, the settings file this GUI reads **and writes**, defaulting
    /// to `settings.json` beside the access file exactly as the gate defaults it.
    ///
    /// Its `web.admins` is the administrator allowlist, and it is read **per request** rather
    /// than at startup: this is the one service that can edit it, and a change that needed a
    /// restart to take effect would be a change this GUI could make but not see.
    pub(crate) settings_path: String,
    /// `BB_AUTH_WEB_BASE_PATH`, normalised by [`normalize_base_path`]: `""` or `/admin`.
    /// Every internal href carries it and the router strips it.
    pub(crate) base_path: String,
    /// `BB_AUTH_WEB_DEFAULT_LANG`, used when a request expresses no preference at all.
    pub(crate) default_lang: Lang,
    /// `BB_AUTH_WEB_LOGOUT_URL`: where the Sign out control in the header points, or `None`
    /// for no control at all.
    ///
    /// **No control when it is unset**, rather than a guess. This GUI cannot know its own
    /// public URL: it speaks plain HTTP on loopback, so it knows neither the scheme nor the
    /// host, and the one thing it *is* handed, the `Host` header, is client-supplied and is
    /// exactly what the rest of this project refuses to let decide a redirect target. A
    /// button that logs an administrator out to an address an attacker chose would be a
    /// phishing gadget, so the address is the operator's to state.
    ///
    /// Normally the root-relative `/auth/logout`, which needs no hostname at all when the
    /// gate and this GUI are on one vhost, and an absolute `https://auth.example.com/auth/logout`
    /// when they are not.
    ///
    /// **It may carry the gate's `?rd=`**, and that is how "sign out, then sign back in, and
    /// be where you were" is expressed: the gate clears the cookie and redirects there, that
    /// address is gated, so the `401` sends the browser to the login page carrying it, and the
    /// login hands it back. Which makes the value the whole round trip, written once:
    ///
    /// ```text
    /// BB_AUTH_WEB_LOGOUT_URL=/auth/logout?rd=https%3A%2F%2Fauth.example.com%2Fadmin%2F
    /// ```
    ///
    /// The `rd` has to be **absolute**, and this is the reason rather than a preference: a
    /// relative one is resolved by the gate against the caller origin it reads from
    /// `BB_AUTH_ORIGINAL_URL_HEADER`, and the logout location is deliberately ungated, so
    /// nginx has no reason to set that header there and normally does not. Without it a
    /// relative `rd` falls back to the login page, which is fail-soft and silent, and silent
    /// is the bad half. It also stays the operator's to write for the same reason the address
    /// itself does: this GUI knows neither its scheme nor its host, and the one thing it is
    /// handed is a client-supplied `Host`.
    ///
    /// With no `rd` the browser lands on the login page and stops there, which is the honest
    /// destination for someone who just ended their session and is the right default for a
    /// deployment that has not said otherwise.
    pub(crate) logout_url: Option<String>,
    /// [`Self::logout_url`] with its `rd` query parameter removed, derived once at startup by
    /// [`logout_without_rd`] and `None` exactly when `logout_url` is. The self-service page's
    /// Sign out pill carries this (docs/ARCHITECTURE.md §13.17): the `rd` is the console's round
    /// trip to the administrator surface, and on `/account/` it would land a person who is not
    /// an administrator on a `403`. It is also the logout a completed deletion redirects
    /// through (§13.32 §1, [`delete_logout_location`]), which is why the value is derived once
    /// and never re-cut per request.
    pub(crate) account_logout_url: Option<String>,
    /// `BB_AUTH_AUDIT_FILE`, the authentication audit the gate appends to and this GUI reads.
    /// Default [`DEFAULT_AUDIT_FILE`], and **empty means there is no Audit tab at all**.
    ///
    /// The gate's variable name, on purpose, exactly as `BB_AUTH_ACCESS_FILE` is: each service
    /// has its own env file, one name means one thing, and unset on both sides means the same
    /// default on both sides. This end never writes it, and the unit that runs this end has no
    /// business being able to: an audit an administrator can edit is not one.
    pub(crate) audit_path: String,
    /// `BB_AUTH_WEB_PROXY_SECRET`: the shared secret nginx sets in `X-BB-Web-Secret` on every
    /// request it proxies here, and the only thing that tells this port "you came through the
    /// proxy" (docs/ARCHITECTURE.md §13.3).
    ///
    /// Required, and validated at startup by [`compile_proxy_secret`]. It is compared on every
    /// request, as the first check in [`handle`], through [`proxy_secret_matches`] and never
    /// with `==`; and it is never printed, logged or rendered, because a value that reaches
    /// the journal at boot is a secret for as long as the journal is kept.
    pub(crate) proxy_secret: String,
    /// `BB_AUTH_WEB_ACCOUNT_PATH`: the prefix the self-service page is mounted at
    /// (docs/ARCHITECTURE.md §13.2). Normalised and checked against `base_path` at startup by
    /// [`compile_account_path`], so a deployment where the two prefixes overlap is a refusal
    /// to start and not a page that answers the wrong half of its own URLs.
    pub(crate) account_path: String,
    /// `BB_AUTH_WEB_WORKERS`: the blocking request threads `main` spawns, validated at startup
    /// by [`compile_workers`] (docs/ARCHITECTURE.md §13.13).
    ///
    /// It bounds how many **handlers run at once**, not how many connections are open:
    /// `tiny_http` runs its own accept pool and pushes every parsed request onto one unbounded
    /// queue, so a request that finds every worker busy waits, it is not refused. Too few
    /// workers therefore shows up as latency for everybody, which is why the count is a
    /// deployment's to state and not a constant.
    pub(crate) workers: usize,
    /// The address the Cognito API calls go to, and set from the environment by nothing a
    /// deployment builds.
    ///
    /// `None` means "derive it from the settings file", which is what every real deployment does
    /// ([`Settings::cognito_endpoint`]). The field exists for the tests alone: `compile_issuer`
    /// is https-only, so a plain-HTTP fake pool cannot be named through `gate.issuer`, and a TLS
    /// fake would need a certificate authority the bundled Mozilla roots do not trust (the design
    /// of docs/ARCHITECTURE.md §13.22). No env var and no file sets it, so a host never points
    /// the sign-in flow at an address an operator wrote in a config. The one reader is the
    /// browser suite's harness, behind the `e2e-fake-cognito` feature and loopback only, through
    /// [`e2e_cognito_endpoint`]: a release that carries the feature does not compile
    /// (docs/ARCHITECTURE.md §13.24).
    pub(crate) cognito_endpoint: Option<String>,
    /// How long one Cognito call may take before this gives up and says so.
    ///
    /// [`COGNITO_TIMEOUT`] at startup, and the tests shorten it so the "pool that never answers"
    /// case is fast. It is a constant and not a setting because it is not a value an operator has
    /// a reason to tune per deployment, and because a setting that bounds a call nobody can
    /// reproduce is a setting nobody can debug.
    pub(crate) cognito_timeout: std::time::Duration,
    /// `BB_AUTH_WEB_DELETE_INTAKE`: the **origin** of the owner's deletion worker's intake, the
    /// service that queues a self-service account deletion (docs/ARCHITECTURE.md §13.29 W2).
    ///
    /// Validated at startup by [`compile_delete_intake`], which accepts only a plain-HTTP
    /// loopback origin. **Unset is the feature off**: no menu row, and the delete page is the
    /// `404` every unknown path gets, exactly as [`Self::logout_url`] unset already behaves. It
    /// is an env var and not a setting because it is read once and decides where an identity is
    /// sent: the settings file is editable from the console, and a field there would let a
    /// console session point every future deletion at another port.
    pub(crate) delete_intake: Option<String>,
    /// `BB_AUTH_WEB_DELETE_SECRET`: the value sent to the intake in `X-BB-Delete-Secret` on both
    /// of its calls, when one is set (docs/ARCHITECTURE.md §13.29 W2, W8 §1).
    ///
    /// **Optional for now**, and the reason is the intake's, not ours: today the intake checks no
    /// secret at all, so requiring one here would ship a half that enforces nothing while a
    /// missing one stops the GUI from starting. bb-auth ships its half once and the owner starts
    /// enforcing the header whenever they choose, with no release here. A **malformed** value is
    /// still fatal ([`compile_delete_secret`]): optional means "unset is allowed", never "a
    /// broken value is ignored". With the intake set and no secret the startup banner says so
    /// once, in the journal.
    ///
    /// Never printed, logged or rendered, for the proxy secret's reason: a value that reaches the
    /// journal at boot is a secret for as long as the journal is kept.
    pub(crate) delete_secret: Option<String>,
    /// How long one intake call may take before this gives up and says so (§13.29 W2).
    ///
    /// [`INTAKE_TIMEOUT`] at startup, and the tests shorten it as they do
    /// [`Self::cognito_timeout`], because the "intake that never answers" case has to be fast.
    /// It is a constant and not a setting for the same reason that one is. The startup banner
    /// names it beside the origin, so the bound a deployment runs with is something an operator
    /// can read out of the journal.
    pub(crate) intake_timeout: std::time::Duration,
}

/// The bound on one deletion-intake call, end to end (§13.29 W2).
///
/// The same wall as [`COGNITO_TIMEOUT`], for the same reason: `tiny_http` runs a fixed pool of
/// handler threads, so a call that hangs forever is a worker that never serves anybody again.
/// The intake answers from a spool append, so five seconds is generous, and the design promises
/// nothing longer.
const INTAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// The bound on one Cognito call, end to end (§13.22).
///
/// It is a wall on the **worker**, not a hint: `tiny_http` runs a fixed pool of handler threads,
/// so a call that hangs forever is a worker that never serves anybody again. Five seconds is
/// generous against the ~1 s a real `InitiateAuth` takes from rpi-01, and short enough that the
/// worst case is a slow page and not a wedged service. There is no retry: a start is one call and
/// the code step is two, so the most a request can spend is twice this.
pub(crate) const COGNITO_TIMEOUT: Duration = Duration::from_secs(5);

/// The Cognito address the browser suite's harness points this process at, and the reason no
/// release build has one (docs/ARCHITECTURE.md §13.24).
///
/// One function with two bodies, so the default build has a rule to test: without the
/// `e2e-fake-cognito` feature this answers `Ok(None)` for whatever `lookup` answers, and the
/// variable's name appears in no source that is compiled. With the feature,
/// `BB_AUTH_WEB_E2E_COGNITO_ENDPOINT` names the address and the address must be
/// `http://127.0.0.1:<port>`, optionally with a trailing `/`: the harness's fake is a plain-HTTP
/// server on loopback, and `compile_issuer` is https-only, so no real endpoint is ever spelled
/// like this. Anything else is an `Err` naming the variable, because a switch that accepted
/// `https://cognito-idp.eu-central-1.amazonaws.com/` is a switch a host can be pointed at an
/// upstream of the caller's choosing with, which is the §13.22 rule this feature exists to keep
/// unreachable outside a test.
///
/// A value that is read is announced on stderr in a line containing `E2E BUILD`, and
/// `e2e/lib/server.js` refuses to run against a process that did not print it: a walk that
/// silently reached no fake would read as a scene full of refusals.
#[cfg(feature = "e2e-fake-cognito")]
pub(crate) fn e2e_cognito_endpoint(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<String>, String> {
    const VAR: &str = "BB_AUTH_WEB_E2E_COGNITO_ENDPOINT";
    let Some(raw) = lookup(VAR) else {
        return Ok(None);
    };
    let refuse = || {
        format!(
            "{VAR} must be http://127.0.0.1:<port> (the e2e harness's fake Cognito); got '{raw}'"
        )
    };
    let Some(rest) = raw.strip_prefix("http://127.0.0.1:") else {
        return Err(refuse());
    };
    let port = rest.strip_suffix('/').unwrap_or(rest);
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refuse());
    }
    eprintln!("E2E BUILD: Cognito calls go to {raw}");
    Ok(Some(raw))
}

/// The same function with no switch: a build that does not carry `e2e-fake-cognito` reads
/// nothing, so the variable is inert on every host and its name is not in the binary. The
/// feature body above is the rule, and docs/ARCHITECTURE.md §13.24 is why it is behind one.
#[cfg(not(feature = "e2e-fake-cognito"))]
pub(crate) fn e2e_cognito_endpoint(
    _lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<String>, String> {
    Ok(None)
}

// The second lock of §13.24, on the source: the harness builds debug, so a release build that
// carries the feature does not compile at all, and the switch cannot meet a `.deb` (always
// `--release`) whatever flags somebody passes. The other two locks are the artifact check in
// scripts/package.sh and the harness's own `--target-dir target/e2e`, which keeps
// target/debug/bb-auth-web, the binary a developer copies by hand, free of the feature.
// (A `//` comment and not a doc comment: rustdoc documents no macro invocation, so `///` here
// is an unused-doc-comment warning.)
#[cfg(all(feature = "e2e-fake-cognito", not(debug_assertions)))]
compile_error!("e2e-fake-cognito is for the e2e harness's debug build only");

/// Read an env var, falling back to `default` when unset.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Read a required env var, or exit(1).
fn env_req(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        eprintln!("[bb-auth-web] FATAL: missing required env var {key}");
        std::process::exit(1);
    })
}

/// Normalise `BB_AUTH_WEB_BASE_PATH` — the prefix nginx mounts the GUI at.
///
/// Empty stays empty (mounted at the root). Otherwise a leading `/` is added if missing and
/// trailing ones are stripped, so `admin/` and `/admin` both become `/admin` and hrefs can
/// concatenate it with a route path without ever doubling a slash.
///
/// Rejects anything that is not printable ASCII, plus `?` and `#`: this string is prefixed
/// to every href *and* to the `Location:` of the language redirect, and that check at load
/// is what makes both emissions safe with no per-use escape — the same argument as the
/// gate's `compile_login_url`.
pub(crate) fn normalize_base_path(raw: &str) -> Result<String, String> {
    let p = raw.trim().trim_end_matches('/');
    if p.is_empty() {
        return Ok(String::new());
    }
    if !p.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "'{raw}': must be printable ASCII (no spaces, no control bytes)"
        ));
    }
    if p.contains('?') || p.contains('#') {
        return Err(format!("'{raw}': a path prefix cannot contain '?' or '#'"));
    }
    Ok(match p.strip_prefix('/') {
        Some(_) => p.to_string(),
        None => format!("/{p}"),
    })
}

/// The rule both of this program's shared secrets follow, named by the variable that carries
/// `raw`: at least 32 characters, all of `[A-Za-z0-9_-]`, so the value survives a shell, an env
/// file, an nginx `proxy_set_header` line and a header value with nothing to quote.
///
/// `hint` is the one sentence each secret has of its own, because the two are installed
/// differently: one is generated by the install, the other has to reach a file outside this
/// repository with the same bytes.
///
/// Every refusal names the variable and **never the value**. A startup message goes to the
/// journal, and a secret printed once at boot is a secret in the journal for as long as the
/// journal is kept; the length is safe to say, the bytes are not.
fn compile_secret_value(var: &str, raw: &str, hint: &str) -> Result<String, String> {
    if raw.chars().count() < 32 {
        return Err(format!(
            "{var} must be at least 32 characters of [A-Za-z0-9_-] (this one is {}); {hint}",
            raw.chars().count()
        ));
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(format!(
            "{var} holds a character outside [A-Za-z0-9_-], which cannot go into an env file, a \
             shell, an nginx `proxy_set_header` line or a header value without quoting it"
        ));
    }
    Ok(raw.to_string())
}

/// Validate `BB_AUTH_WEB_PROXY_SECRET` (docs/ARCHITECTURE.md §13.3), on the rule both of this
/// program's secrets share ([`compile_secret_value`]).
///
/// Required, with no default: a deployment that starts without a secret is a deployment where
/// the check is not running, and a generated one is one line of the install.
///
/// It is the first check [`handle`] makes, ahead of the self-service page's dispatch, so the
/// page is not a way around it (docs/ARCHITECTURE.md §13.2).
pub(crate) fn compile_proxy_secret(raw: &str) -> Result<String, String> {
    compile_secret_value(
        "BB_AUTH_WEB_PROXY_SECRET",
        raw,
        "the install generates one, so an env file that predates it needs the line appended once",
    )
}

/// Validate `BB_AUTH_WEB_DELETE_SECRET` (docs/ARCHITECTURE.md §13.29 W2): the value this program
/// sends to the deletion intake in `X-BB-Delete-Secret`, on the rule both of this program's
/// secrets share ([`compile_secret_value`]), and `Ok(None)` when unset.
///
/// **Optional for now**, and the reason is the intake's: it checks no secret today, so a required
/// one here would ship a half that enforces nothing while a missing one stopped the GUI from
/// starting. The user's answer to §13.29 W12 question 3, 2026-11-26: bb-auth ships its half once
/// and the owner starts enforcing the header when they choose, with no release here. With the
/// intake set and no secret the GUI starts and its banner says once, in the journal, that the
/// intake trusts any local caller until a secret is set on both sides.
///
/// Optional means "unset is allowed". A **malformed** value is fatal, because an operator who
/// wrote a secret and did not get one sent is a deployment that believes it is protected. The
/// rules are the proxy secret's so the one value can be written to this env file and to the
/// owner's unit file with nothing to quote.
pub(crate) fn compile_delete_secret(raw: &str) -> Result<Option<String>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    compile_secret_value(
        "BB_AUTH_WEB_DELETE_SECRET",
        raw,
        "the operator generates one and writes the same value here and where the intake's unit \
         reads it, so the install does not generate it",
    )
    .map(Some)
}

/// Validate `BB_AUTH_WEB_DELETE_INTAKE` (docs/ARCHITECTURE.md §13.29 W2): the deletion intake's
/// **origin**, and nothing more than an origin. Accepted: `http`, a loopback IP literal
/// (`127.0.0.0/8` or `[::1]`), a port, and nothing else. Empty is `Ok(None)`, the feature off.
///
/// The accepted value is returned **as written**, because the caller appends the intake's two
/// hard-coded paths to it, and a re-serialized origin is a second answer to what the operator
/// typed.
///
/// **Loopback only**, and the reason is the request, not the port: every call carries an identity
/// in clear, in `X-Auth-Email`, to a service whose one check is that header. To any other host
/// that is an identity sent unencrypted to something that deletes accounts on it, which is why a
/// plain-HTTP origin is accepted here and nowhere else in this estate.
///
/// Each refusal is its own reason, and each names the variable, because that is the only thing
/// an operator can go and edit:
///
/// - a **name**, `localhost` included: a name resolves to whatever the resolver says, and
///   "loopback" has to be a fact about the bytes the operator typed, not a guess the startup
///   made for them;
/// - a **non-loopback address**: the identity would leave the host;
/// - **`https`** or any other scheme: the intake speaks plain HTTP on loopback, so an https
///   origin names a host the operator did not name;
/// - a **path**, a query or a fragment: the intake hard-codes its two paths, so a base carrying
///   one appends them somewhere else;
/// - **userinfo**: an `@` is credentials in an origin;
/// - **no port**: the intake *is* a port, and the default one is not where it listens.
pub(crate) fn compile_delete_intake(raw: &str) -> Result<Option<String>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let refuse = |why: &str| -> Result<Option<String>, String> {
        Err(format!(
            "BB_AUTH_WEB_DELETE_INTAKE must be the deletion intake's origin: `http`, a loopback \
             IP literal (127.0.0.0/8 or [::1]) and a port, with no path, no query, no fragment \
             and no userinfo (docs/ARCHITECTURE.md §13.29 W2); '{raw}' {why}"
        ))
    };
    let Some(rest) = raw.strip_prefix("http://") else {
        return refuse("is not an http:// origin");
    };
    // The authority runs to the first delimiter, and there is nothing to accept after it: the
    // intake's paths are the caller's to append, so a base that already carries one is a base
    // that appends them somewhere else.
    let authority = match rest.find(['/', '?', '#']) {
        Some(_) => return refuse("carries a path, a query or a fragment"),
        None => rest,
    };
    if authority.contains('@') {
        return refuse("carries userinfo");
    }
    // An IPv6 literal is bracketed, and the brackets are not part of the address.
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => {
            let Some(close) = bracketed.find(']') else {
                return refuse("has an IPv6 literal with no closing bracket");
            };
            (
                &bracketed[..close],
                bracketed[close + 1..].strip_prefix(':').unwrap_or_default(),
            )
        }
        None => match authority.rsplit_once(':') {
            Some((h, p)) => (h, p),
            None => return refuse("names no port"),
        },
    };
    if port.is_empty()
        || !port.bytes().all(|b| b.is_ascii_digit())
        || !port.parse::<u16>().is_ok_and(|p| p > 0)
    {
        return refuse("names no port");
    }
    // A literal, both families, and nothing that has to be resolved to be known.
    let loopback = host
        .parse::<std::net::Ipv4Addr>()
        .map(|a| a.is_loopback())
        .or_else(|_| host.parse::<std::net::Ipv6Addr>().map(|a| a.is_loopback()))
        .unwrap_or(false);
    if !loopback {
        return refuse("is not a loopback IP literal");
    }
    Ok(Some(raw.to_string()))
}

/// The self-service page's prefix: `BB_AUTH_WEB_ACCOUNT_PATH`, normalised, checked against the
/// console's own [`Config::base_path`] (docs/ARCHITECTURE.md §13.2). The `/account` default is
/// the caller's, not this function's: a variable **set to empty** is a refusal, because an
/// operator who typed `BB_AUTH_WEB_ACCOUNT_PATH=` in an env file meant to say something, and a
/// prefix of nothing is the whole host.
///
/// The two prefixes are **siblings**, and that is what the checks are for. The page is the one
/// part of this program a person who is not an administrator reaches, so it is dispatched
/// *before* the `web.admins` allowlist, and a prefix nested inside the console's would put
/// `/admin/account/` in front of the console's own routes: the dispatch would answer those URLs
/// as the self-service page, and a person with no roster row would be standing inside the
/// administrator surface's URL space. So a prefix equal to the base, inside it, or containing
/// it, is a refusal to start, and the message names both.
///
/// The base is normalised the same way here as at startup, because the comparison is between
/// two prefixes and one of them arrives from the env file: `/admin` and `/admin/` are the same
/// prefix, and a check that read them as two strings would wave an overlapping deployment
/// through. A base that normalises to nothing is refused as well: `/` is every path, so a
/// console mounted at the root has no sibling space left to mount anything beside.
///
/// The prefix is checked for the same reason the base is: it is emitted into a `Location:` and
/// into a form's `action`, so printable ASCII with no quote, no backslash and no `@` is what
/// makes that safe with no per-request check.
pub(crate) fn compile_account_path(account: &str, base: &str) -> Result<String, String> {
    // Normalised with the console's own rule, so the comparison below is between two prefixes
    // in one spelling and `/account` and `/account/` are one answer, not two.
    let account =
        normalize_base_path(account).map_err(|e| format!("BB_AUTH_WEB_ACCOUNT_PATH: {e}"))?;
    if account.is_empty() {
        return Err(
            "BB_AUTH_WEB_ACCOUNT_PATH is empty: a prefix of nothing is the whole host, so the \
             self-service page would be dispatched ahead of the administrator allowlist for \
             every URL this program answers. Name a prefix, such as /account."
                .to_string(),
        );
    }
    let base = normalize_base_path(base)
        .map_err(|e| format!("BB_AUTH_WEB_ACCOUNT_PATH cannot be placed: {e}"))?;
    if base.is_empty() {
        return Err(
            "BB_AUTH_WEB_ACCOUNT_PATH cannot be placed: BB_AUTH_WEB_BASE_PATH is `/`, which is \
             every path, so a console mounted at the root has no prefix left beside it to mount \
             the self-service page on. Mount the console under a prefix."
                .to_string(),
        );
    }
    // Does `outer`'s area contain `inner`'s? At a path boundary, which is the rule
    // `bb_auth_core::base_covers` states for an application's area: `/accounts` beside
    // `/account` shares no boundary and is a legal neighbour, while `/admin/account` under
    // `/admin` is not.
    let contains =
        |outer: &str, inner: &str| inner == outer || inner.starts_with(&format!("{outer}/"));
    if contains(&base, &account) {
        return Err(format!(
            "BB_AUTH_WEB_ACCOUNT_PATH ({account}) is the console's own prefix ({base}) or sits \
             inside it: the self-service page is dispatched before the administrator allowlist, \
             so a prefix nested in the console's answers the console's URLs as the page. Choose \
             a prefix beside {base}, such as /account."
        ));
    }
    if contains(&account, &base) {
        return Err(format!(
            "BB_AUTH_WEB_ACCOUNT_PATH ({account}) contains the console's own prefix ({base}): \
             every administrator URL would be dispatched to the self-service page instead."
        ));
    }
    for (pos, ch) in account.char_indices() {
        if matches!(ch, '"' | '\'' | '\\' | '@') {
            return Err(format!(
                "BB_AUTH_WEB_ACCOUNT_PATH has a {ch:?} at offset {pos}: the prefix is emitted \
                 into a Location: and into a form action, so it carries no quote, no backslash \
                 and no userinfo."
            ));
        }
    }
    Ok(account)
}

/// Validate `BB_AUTH_WEB_WORKERS` (docs/ARCHITECTURE.md §13.13, plan step 4e): unset is
/// [`DEFAULT_WORKERS`], an exact decimal from 1 to [`MAX_WORKERS`] is accepted, and anything
/// else is a refusal naming the variable and the accepted range.
///
/// **Fatal, and not the gate's silent `unwrap_or`**: a fallback turns `BB_AUTH_WEB_WORKERS=800`
/// into 8 with nothing anywhere saying so, which is the operator's intent lost without a trace,
/// and every other value this binary reads from its env is already fatal on a bad one. The
/// boot-loop argument that makes the gate careful does not carry over here: a GUI that refuses
/// to start locks nobody out of any application, and `bb-auth-adm` over SSH is untouched.
///
/// **Digits only**, so ` 8` and `+8` are refusals rather than numbers with decoration: this
/// number is how many threads `main` spawns, and a parser that accepted one spelling's noise
/// would be a second answer to what the env file says. Empty is refused rather than defaulted,
/// because an empty assignment is somebody meaning to say something ([`compile_account_path`]
/// reads it the same way), and `0` is refused rather than raised to one, because a service that
/// binds its port and never answers is the worst of both. A refusal is **returned**, never a
/// panic: a panic in a startup parser is a `Restart=on-failure` boot loop.
pub(crate) fn compile_workers(raw: Option<&str>) -> Result<usize, String> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_WORKERS);
    };
    let n = if raw.bytes().all(|b| b.is_ascii_digit()) {
        raw.parse::<usize>().ok()
    } else {
        None
    };
    match n {
        Some(n) if (1..=MAX_WORKERS).contains(&n) => Ok(n),
        Some(n) => Err(format!(
            "BB_AUTH_WEB_WORKERS is {n}: the accepted range is 1 to {MAX_WORKERS}. Zero would \
             bind the port and never answer, and a count above {MAX_WORKERS} has nothing to do \
             in parallel (writes serialise on one lock and a read is milliseconds), so it reads \
             as a typo. Unset is {DEFAULT_WORKERS}."
        )),
        None => Err(format!(
            "BB_AUTH_WEB_WORKERS is {raw:?}: it must be a plain decimal number of request \
             threads from 1 to {MAX_WORKERS}, with no spaces, sign or trailing text. Unset is \
             {DEFAULT_WORKERS}."
        )),
    }
}

/// Does the secret this request carries match the one this process was started with
/// (docs/ARCHITECTURE.md §13.3)?
///
/// Both sides are hashed first, so the two inputs are always the same 32 bytes and the fold
/// over XOR reads every one of them: a plain `==` on strings stops at the first differing
/// byte, and a secret whose prefix can be probed one byte at a time is a secret with a search
/// attached to it. `sha2` is already in the tree (the cookie's HMAC, the form's `rev`), so
/// this buys the property for no dependency.
///
/// An absent header arrives as the empty string and fails like any other value: the refusal
/// for "no secret" and "wrong secret" is the same page, because a difference between them is
/// a probe that tells a local process when it has found the port.
pub(crate) fn proxy_secret_matches(sent: &str, expected: &str) -> bool {
    let sent = Sha256::digest(sent.as_bytes());
    let expected = Sha256::digest(expected.as_bytes());
    sent.iter()
        .zip(expected.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

impl Config {
    /// Build the config from the environment, exiting on the first fatal problem.
    pub(crate) fn from_env() -> Config {
        // The administrator allowlist is not read here: it lives in the settings file, where
        // this GUI can edit it and see the edit, and an empty or missing one is a refusal to
        // serve, per request, in `handle`.
        let base_path =
            normalize_base_path(&env_or("BB_AUTH_WEB_BASE_PATH", "")).unwrap_or_else(|e| {
                eprintln!("[bb-auth-web] FATAL: BB_AUTH_WEB_BASE_PATH: {e}");
                std::process::exit(1);
            });
        let raw_lang = env_or("BB_AUTH_WEB_DEFAULT_LANG", "en");
        let default_lang = parse_lang(&raw_lang).unwrap_or_else(|| {
            eprintln!(
                "[bb-auth-web] FATAL: BB_AUTH_WEB_DEFAULT_LANG: '{raw_lang}' is not en or it"
            );
            std::process::exit(1);
        });
        let access_path = env_req("BB_AUTH_ACCESS_FILE");
        let settings_path = std::env::var("BB_AUTH_SETTINGS_FILE")
            .ok()
            .filter(|p| !p.trim().is_empty())
            .unwrap_or_else(|| default_settings_path(&access_path));
        // Validated with the library's own asset-URL rule, which is the right one here for
        // the same reason it is right for a stylesheet: the value is emitted into an `href`,
        // and it may be either absolute https or a path on this host. Fatal on a bad one,
        // not skipped: a Sign out control that quietly went missing is one an administrator
        // would go on believing they had configured.
        let logout_url = compile_asset_url(
            "BB_AUTH_WEB_LOGOUT_URL",
            &env_or("BB_AUTH_WEB_LOGOUT_URL", ""),
        )
        .unwrap_or_else(|e| {
            eprintln!("[bb-auth-web] FATAL: {e}");
            std::process::exit(1);
        });
        // The self-service page's Sign out: the same link with only its `rd` removed (§13.17),
        // derived once here beside the value it comes from, so no page parses the operator's
        // value per request and the two surfaces cannot disagree about what was cut.
        let account_logout_url = logout_url.as_deref().map(logout_without_rd);
        // Required, and fatal here: a GUI that starts with no secret is a GUI whose check is
        // not running, and the one thing it is asked to protect is the header it trusts.
        let proxy_secret = compile_proxy_secret(&env_or("BB_AUTH_WEB_PROXY_SECRET", ""))
            .unwrap_or_else(|e| {
                eprintln!("[bb-auth-web] FATAL: {e}");
                std::process::exit(1);
            });
        // The self-service page's prefix, checked against the console's own: two prefixes that
        // overlap are a page answering the administrator surface's URLs, which is a refusal to
        // start, not a page that works on most of its own URLs.
        let account_path =
            compile_account_path(&env_or("BB_AUTH_WEB_ACCOUNT_PATH", "/account"), &base_path)
                .unwrap_or_else(|e| {
                    eprintln!("[bb-auth-web] FATAL: {e}");
                    std::process::exit(1);
                });
        // The worker count, fatal on a bad value like every other value read here. Read with
        // `var` and not `env_or` so an **unset** variable reaches `compile_workers` as `None`
        // (the default) while `BB_AUTH_WEB_WORKERS=` arrives as an empty value and is refused.
        let workers = compile_workers(std::env::var("BB_AUTH_WEB_WORKERS").ok().as_deref())
            .unwrap_or_else(|e| {
                eprintln!("[bb-auth-web] FATAL: {e}");
                std::process::exit(1);
            });
        // The deletion intake (§13.29 W2). Unset is the feature off, and off is a deployment:
        // no menu row, and the delete page is the `404` every unknown path gets. A malformed
        // value is fatal, like every other value read here, because a half-wired intake is a
        // menu row that leads to a page that cannot reach the worker.
        let delete_intake = compile_delete_intake(&env_or("BB_AUTH_WEB_DELETE_INTAKE", ""))
            .unwrap_or_else(|e| {
                eprintln!("[bb-auth-web] FATAL: {e}");
                std::process::exit(1);
            });
        let delete_secret = compile_delete_secret(&env_or("BB_AUTH_WEB_DELETE_SECRET", ""))
            .unwrap_or_else(|e| {
                eprintln!("[bb-auth-web] FATAL: {e}");
                std::process::exit(1);
            });
        Config {
            listen: env_or("BB_AUTH_WEB_LISTEN", "127.0.0.1:8091"),
            access_path,
            settings_path,
            base_path,
            account_path,
            workers,
            default_lang,
            logout_url,
            account_logout_url,
            proxy_secret,
            audit_path: env_or("BB_AUTH_AUDIT_FILE", DEFAULT_AUDIT_FILE)
                .trim()
                .to_string(),
            // The e2e switch (§13.24): `None` in every build that does not carry the feature,
            // which is every build a host runs. The feature build reads a loopback-only address
            // and says so on stderr; a bad value is fatal here, like every other value read
            // above, because a process that thinks it is talking to a fake and is not would
            // spend its whole request budget on the real pool.
            cognito_endpoint: e2e_cognito_endpoint(|k| std::env::var(k).ok()).unwrap_or_else(|e| {
                eprintln!("[bb-auth-web] FATAL: {e}");
                std::process::exit(1);
            }),
            // The production bound is the constant; only the tests shorten it.
            cognito_timeout: COGNITO_TIMEOUT,
            delete_intake,
            delete_secret,
            intake_timeout: INTAKE_TIMEOUT,
        }
    }
}

/// The operator's logout URL with its `rd` query parameter removed, and everything else exactly
/// as written: scheme, host, port, path, the other parameters in their order, and the fragment.
///
/// The `rd` on `BB_AUTH_WEB_LOGOUT_URL` is the console's round trip, the page a signed out
/// administrator comes back to, and it is written for the administrator surface. On `/account/`
/// that destination is a `403` for anybody who is not an administrator, so the self-service page
/// renders the same link with only that parameter dropped (docs/ARCHITECTURE.md §13.17). The
/// link can therefore only lose a parameter, never gain one: it names no landing place the
/// operator did not already write, and the gate's `safe_rd` against `gate.authorized_hosts`
/// still decides where any logout may land.
///
/// Textual, and deliberately: this program knows neither its scheme nor its host (the reason the
/// variable exists), so the value is cut, never parsed. A parameter goes when its name is
/// exactly `rd`, so `ord` and `rdx` stay; a percent-encoded value goes whole, because splitting
/// on `&` sees an encoded `&` as `%26` and not as a separator; the fragment is split off first,
/// so a `#` inside a value, which must be encoded, cannot be read as one; and the `?` leaves
/// with the last parameter, since a URL ending in `?` is a URL with an empty query.
pub(crate) fn logout_without_rd(url: &str) -> String {
    let (url, fragment) = match url.find('#') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, ""),
    };
    let Some((head, query)) = url.split_once('?') else {
        return format!("{url}{fragment}");
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| pair.split('=').next().unwrap_or_default() != "rd")
        .collect();
    if kept.is_empty() {
        format!("{head}{fragment}")
    } else {
        format!("{head}?{}{fragment}", kept.join("&"))
    }
}

/// The `Location:` of the `303` §13.32 §1 answers a **completed** deletion with: the operator's
/// logout URL ([`Config::account_logout_url`], already without the console's `rd`) with our `rd`
/// **added** to its query, ahead of any fragment.
///
/// A redirect and not a page because the gate is the only program that knows the session
/// cookie's name and builds the clearing `Set-Cookie`: a second builder would clear on a
/// `Domain` or `Path` that differs from the mint's, which "silently succeeds at nothing"
/// (`build_cookie`'s rustdoc, §13.32 §1's rejected option (b)). The `303` rides on the full
/// success **only**: every partial outcome above ends on a page that offers "Try again", and
/// that retry is a walk over the header's addresses which the gate admits by the session
/// cookie, so signing the browser out there strands the person on the page that tells them
/// to retry. With no logout URL there is nowhere to send the browser, so the done page stays.
///
/// The `rd` names the gate's **own** sign-in page and is built from the library's two
/// constants, never from the request: only that page understands the notice (the code is a
/// closed set of one, §13.32 §1), it is a location every deployment already routes ungated,
/// and the constants are the bytes the gate compiles its own `OWN_LOGIN_PATH` from, so the
/// two programs cannot disagree on the landing page. Fixed bytes also mean no request byte
/// ever rides into a `Location:` through this door. The value is percent-encoded with
/// [`pct_encode_segment`] (RFC 3986 unreserved set), which is what lets the `?` and the `=`
/// of the landing URL sit inside one parameter, and the fragment is kept **last**: a URL
/// ending `…#f&rd=…` sends the browser to the fragment and drops the notice.
pub(crate) fn delete_logout_location(logout: &str) -> String {
    let rd = pct_encode_segment(&format!(
        "{}?notice={}",
        bb_auth_core::GATE_LOGIN_PATH,
        bb_auth_core::LOGIN_NOTICE_ACCOUNT_DELETED
    ));
    let (url, fragment) = match logout.find('#') {
        Some(i) => (&logout[..i], &logout[i..]),
        None => (logout, ""),
    };
    let join = if url.contains('?') { '&' } else { '?' };
    format!("{url}{join}rd={rd}{fragment}")
}

/// Is this listen address on the loopback interface? The gate has the same function and the
/// same reason for it; this one is what makes a stray `0.0.0.0` fatal rather than merely
/// mentioned.
///
/// Textual on purpose: the value is a `host:port` string handed to `Server::http`, and what
/// matters is what an operator wrote in the env file. An unresolvable name is not loopback as
/// far as this is concerned, which errs towards refusing.
pub(crate) fn listen_is_loopback(listen: &str) -> bool {
    let host = match listen.rsplit_once(':') {
        // `[::1]:8091`, the only shape where the last colon is not the port separator's.
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => listen,
    };
    let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

/// An env var read as a deliberate yes: `1`, `true`, `yes`, in any case. Anything else,
/// including the variable being absent, is no.
pub(crate) fn env_flag(key: &str) -> bool {
    matches!(
        env_or(key, "").trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}
