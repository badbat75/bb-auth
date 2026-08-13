//! bb-auth-web — a server-rendered admin GUI over a bb-auth **access file**
//! (`BB_AUTH_USERS_FILE`, a.k.a. users.json).
//!
//! What `bb-auth-adm` shows on a terminal, this shows in a browser: the roster, the url
//! groups and who references them, the sites in the order that decides which one answers,
//! the `denied` veto, every api key's expiry, and the `can EMAIL URL` tester — answered, as
//! there, by the gate's own [`decide`]. And what `bb-auth-adm` *edits*, this edits: full
//! CRUD over every section, through the library's editing core and through nothing else.
//!
//! **Deployment.** Its own hardened unit (`deploy/bb-auth-web.service`) under a dedicated
//! `bb-auth-web` user, its own operator-owned env (`deploy/bb-auth-web.env.example`), and
//! `deploy/bb-auth-reload.path`, which turns any rewrite of the access file — this one's or
//! a `bb-auth-adm` over SSH — into a `systemctl reload bb-auth`. Optional in the deploy just
//! like `bb-auth-adm`: installed iff it was staged. Installing it is also what moves the
//! access file to `bb-auth-web:bb-auth 0640`, because the writer restores the owner it finds
//! and an unprivileged one may only chown to a uid it already owns and a group it is a
//! member of. See the README and `scripts/deploy.sh`.
//!
//! # Trust model
//!
//! This is **just another application bb-auth fronts**, and it is protected exactly the way
//! any other one is:
//!
//! * it binds **loopback** (`BB_AUTH_WEB_LISTEN`, default `127.0.0.1:8091`) and speaks plain
//!   HTTP, so nothing reaches it except through the reverse proxy;
//! * nginx gates its URL with `auth_request` against the gate, and injects the authorized
//!   email with `auth_request_set` + `proxy_set_header X-Auth-Email` — the contract
//!   documented on `bb-auth`'s `IDENTITY_HEADER`, unchanged and unextended;
//! * this binary reads that header and nothing else. It validates no token, holds no secret
//!   and mints no cookie — there is no credential here to steal.
//!
//! Trusting the header is sound for one reason only: `proxy_set_header` overwrites whatever
//! the client sent, on **every** gated location, and the service is unreachable except
//! through nginx. Both halves are load-bearing. Exposing this port directly, or gating it
//! from a location that forgets the `proxy_set_header`, would let anyone name themselves —
//! so a missing header is a `401` here rather than an anonymous session, which turns a
//! broken deployment into an error page instead of a silent open door.
//!
//! And the header is not the last word: the email must also be on **`BB_AUTH_WEB_ADMINS`**.
//! That allowlist is deliberate defense in depth: a `public_auth` site covering the GUI's
//! URL would otherwise open the admin surface to any Cognito account. It is required, and
//! must be non-empty — empty must never mean "everyone".
//!
//! Both checks are **route-global** and run before the router: there is no path — not a
//! `404`, not a `POST`, not a broken access file — that answers anything to someone nginx
//! did not vouch for and `BB_AUTH_WEB_ADMINS` does not name.
//!
//! # Mutations
//!
//! Every write goes through [`AccessWrite`], the same door `bb-auth-adm` uses: `prepare`
//! compiles the exact bytes with the gate's own parser, `commit` writes the bytes it
//! compiled, and the raw writer is private to the library. So this binary *cannot* save a
//! file the gate would reject — a rejected access file is a fatal startup, and under
//! `Restart=on-failure` a boot loop. A refusal is shown **verbatim**, in the English the
//! library says it in, on the form that caused it and with the submitted values still in
//! the fields; nothing is written on any error path.
//!
//! Four rules hold on every mutating route, and between them they are the whole mechanism:
//!
//! * **A `GET` never mutates.** Every mutation is a `POST`, to the same path that renders
//!   its form. The single redirect a `GET` performs is the `?lang=` one, which sets a
//!   display cookie and changes nothing else.
//! * **Strict same-origin on every `POST`** ([`csrf_ok`]). If `Sec-Fetch-Site` is present it
//!   must say `same-origin`: the browser sets it, a page cannot, so where it exists it is
//!   the whole answer. Otherwise `Origin`'s **host** must equal the `Host:` header's —
//!   hosts, not schemes, because this binary speaks plain HTTP behind a TLS-terminating
//!   nginx and would have to compare its own `http` against the browser's `https`, failing
//!   every honest request. Neither header present ⇒ refused with a `403`: that is not a
//!   browser submitting a form. There is deliberately **no CSRF token** — one needs
//!   per-session server state, which this binary does not have and the gate does not have
//!   either, and which nothing else here would use.
//! * **Optimistic concurrency.** Every form carries a hidden `rev`: the sha256 of the exact
//!   bytes of the access file as it was read to render that form. The `POST` re-reads the
//!   file and compares; a mismatch is a `409` that writes nothing and says to reload. This
//!   is what turns the lost-update race between this GUI and a `bb-auth-adm` over SSH — the
//!   two are expected to be used on the same file, the CLI is installed on the host for
//!   exactly that — into a visible error instead of a silently discarded edit.
//! * **POST-redirect-GET.** A successful mutation answers `303` to the page it belongs to
//!   with `?msg=<key>`, so a reload cannot repeat it. Only *known* keys render ([`Msg`]);
//!   an unknown one is ignored, and no free text ever travels through the query string.
//!
//! **Minting is the one exception to the redirect**, and deliberately: `key add` and
//! `key rotate` render their result page directly, because it carries the `bbk_` bearer,
//! which is shown once and stored nowhere. The order is the library's — [`SealedKey`]
//! opens only against the [`Written`] receipt of a completed write — so a bearer cannot be
//! handed out for a file that never landed. It never reaches a log line or a URL. A
//! re-submitted mint form cannot double-mint either, and pleasantly it is the `rev` rule
//! that stops it: the first write changed the file, so the second `POST` carries a stale
//! fingerprint and is refused.
//!
//! Destructive actions (`user rm`, `key rm`, `key rotate`, `site rm`, `url-group rm`,
//! `deny rm`) are a `GET` confirmation page whose `POST` does the deed — the no-JavaScript
//! form of "are you sure", and the only way to be sure a link never deletes anything.
//! Each successful mutation writes one audit line to stderr ([`audit`]): who, the verb as
//! `bb-auth-adm` spells it, and the target's name — never a bearer, never a hash, never a
//! submitted value beyond the name.
//!
//! An edit is not live until the gate re-reads the file: `systemctl reload bb-auth`. This
//! binary cannot send that signal (it is not the gate, and does not run in its namespace),
//! so every page says so in the footer.
//!
//! # Configuration
//!
//! | Var | Required | Default | Meaning |
//! |-----|----------|---------|---------|
//! | `BB_AUTH_USERS_FILE` | yes | — | the access file to render. Same name, same meaning as the gate's |
//! | `BB_AUTH_WEB_ADMINS` | yes | — | comma-separated emails allowed in. Empty is fatal |
//! | `BB_AUTH_WEB_LISTEN` | no | `127.0.0.1:8091` | bind address. Keep it on loopback |
//! | `BB_AUTH_WEB_BASE_PATH` | no | *(empty)* | URL prefix nginx mounts the GUI at, e.g. `/admin` |
//! | `BB_AUTH_WEB_DEFAULT_LANG` | no | `en` | `en` or `it`, when the request expresses no preference |
//!
//! Read once at startup, like the gate: a change needs a restart. A missing required var is
//! a fatal exit, in the same words and for the same reason — there is no safe default.
//!
//! # The file is read fresh on every request
//!
//! No cache, no watch, no server-side state: every page calls [`open_access_file`], renders,
//! and drops the result. The file is small, and always showing the live truth *is* the
//! feature — an edit made over SSH with `bb-auth-adm` a second ago is on the next page load,
//! with no reload signal and no coherency question between this binary and the gate. It also
//! keeps the process trivial: nothing here can go stale, and a restart loses nothing. The
//! `rev` fingerprint is what makes that safe for writing too: state a form needs about the
//! file travels in the form, not in the process.
//!
//! Two consequences worth knowing. Compiling is what emits the parser's warnings, so a file
//! that warns will warn once per request on this service's stderr — noisy, and the price of
//! having exactly one parser. And when the file does not compile at all, this GUI does not
//! die: it renders the library's message verbatim, which is the sentence an operator needs
//! ("the gate would reject this file as it stands"), on a page whose navigation still works.
//!
//! # Language
//!
//! English and Italian, from a table compiled into the binary ([`t`]). Prose and labels are
//! translated; the **file's vocabulary never is** — `public_auth`, `authorized_urls`,
//! `url_groups`, `sites`, `denied`, `bbk_`, an `@group` reference, and every name, email and
//! URL pattern read the same in both, because they are what an operator will type into
//! `bb-auth-adm` and into the file itself. Library error messages render verbatim, in the
//! English the gate and the CLI already say them in.

use bb_auth_core::{
    add_api_key, add_denied, add_site, add_url_group, add_user, decide, edit_urls, format_date,
    key_expiry, key_mut, move_site, norm_email, now, open_access_file, remove_api_key,
    remove_denied, remove_site, remove_url_group, remove_user, rename_site, rename_user,
    request_url, rotate_api_key, sha256_hex, site_name, site_pos, url_group_mut, url_group_refs,
    user_mut, user_pos, Access, AccessFile, AccessWrite, ApiKeySpec, Decision, SealedKey, SiteSpec,
    UserSpec, Written,
};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use std::io::Read;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

/// Request header naming the authenticated user, injected by nginx after the gate
/// authorized the request. The other end of `bb-auth`'s `IDENTITY_HEADER` contract — a fixed
/// constant there, so a fixed constant here.
const IDENTITY_HEADER: &str = "X-Auth-Email";

/// Cookie remembering the language choice. It carries no identity and no capability: the
/// worst an attacker who reads or rewrites it achieves is a page in the other language.
/// That is why it is not `Secure` — this binary speaks plain HTTP on loopback and cannot
/// know the scheme the browser used, and a display preference is not worth a flag that
/// would be a lie about half the deployments.
const LANG_COOKIE: &str = "lang";

/// A year. The preference is a preference, not a session.
const LANG_COOKIE_MAX_AGE: i64 = 31_536_000;

/// Blocking request threads. Fixed, and deliberately not an env var: this serves the
/// handful of people on `BB_AUTH_WEB_ADMINS`, not the public.
const WORKERS: usize = 2;

/// The whole stylesheet, inlined. No external request of any kind — no font, no script, no
/// image — so the page renders identically on a laptop, on a phone, and on a host with no
/// route to the internet.
///
/// Light and dark come from `prefers-color-scheme` over a handful of custom properties;
/// there is no theme toggle, and no JavaScript on any page — not for a form, not for a
/// confirmation, not for reordering a site.
const CSS: &str = r"
*,*::before,*::after{box-sizing:border-box}
:root{color-scheme:light dark;
  --bg:#f7f7fa;--panel:#fff;--fg:#1c1c21;--muted:#65656f;--line:#e2e2ea;
  --accent:#3350c8;--ok:#1c6b40;--warn:#8a5a00;--bad:#b3261e;--chip:#eeeef4}
@media (prefers-color-scheme:dark){:root{
  --bg:#16161b;--panel:#1e1e25;--fg:#e8e8ee;--muted:#9a9aa8;--line:#30303b;
  --accent:#8aa0ff;--ok:#5fd08a;--warn:#e3b341;--bad:#ff8a80;--chip:#292933}}
body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;font-size:.92em}
header.top{background:var(--panel);border-bottom:1px solid var(--line);padding:10px 16px}
.bar{max-width:1000px;margin:0 auto;display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.brand{font-weight:600;letter-spacing:.02em}
.brand .v{color:var(--muted);font-weight:400;font-size:.85em;margin-left:6px}
nav{display:flex;flex-wrap:wrap;gap:4px;flex:1 1 auto}
nav a{padding:4px 10px;border-radius:6px;text-decoration:none;color:var(--fg)}
nav a:hover{background:var(--chip)}
nav a.on{background:var(--accent);color:#fff}
.lang{display:flex;gap:6px;align-items:center;color:var(--muted);font-size:.85em}
main{max-width:1000px;margin:0 auto;padding:18px 16px 40px}
h1{font-size:1.25rem;margin:0 0 4px}
h2{font-size:1rem;margin:26px 0 8px}
p.lede{color:var(--muted);margin:0 0 18px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:14px 16px;margin:0 0 16px;overflow-x:auto}
table{border-collapse:collapse;width:100%;min-width:420px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}
ul.plain{list-style:none;margin:0;padding:0}
ul.plain li{padding:2px 0}
ol.sites{margin:0;padding-left:22px}
ol.sites li{margin:0 0 14px}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:12px 16px;min-width:110px;flex:1 1 110px}
.card .n{font-size:1.6rem;font-weight:600;line-height:1.1}
.card .l{color:var(--muted);font-size:.82rem}
.tag{display:inline-block;padding:1px 7px;border-radius:999px;background:var(--chip);
  font-size:.78rem;white-space:nowrap}
.tag.bad{background:var(--bad);color:#fff}
.tag.warn{background:var(--warn);color:#fff}
.tag.ok{background:var(--ok);color:#fff}
.muted{color:var(--muted)}
.bad{color:var(--bad)}
form.can{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end}
form.can label{display:flex;flex-direction:column;gap:4px;flex:1 1 240px;font-size:.82rem;
  text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
input[type=text]{font:inherit;padding:7px 9px;border:1px solid var(--line);border-radius:7px;
  background:var(--bg);color:var(--fg);width:100%}
button{font:inherit;padding:8px 18px;border:0;border-radius:7px;background:var(--accent);
  color:#fff;cursor:pointer}
.verdict{font-size:1.05rem;font-weight:600;margin:0 0 6px}
.verdict.yes{color:var(--ok)}
.verdict.no{color:var(--bad)}
footer{max-width:1000px;margin:0 auto;padding:0 16px 30px;color:var(--muted);font-size:.82rem;
  display:flex;flex-wrap:wrap;gap:10px;justify-content:space-between}
form.edit label{display:block;margin:0 0 14px}
form.edit .lbl{display:block;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;
  color:var(--muted);margin:0 0 4px}
form.edit .hint{display:block;color:var(--muted);font-size:.82rem;margin:4px 0 0}
textarea{font-family:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;font-size:.92em;
  padding:7px 9px;border:1px solid var(--line);border-radius:7px;background:var(--bg);
  color:var(--fg);width:100%;line-height:1.5}
form.edit .radio{display:flex;gap:8px;align-items:baseline;margin:0 0 6px}
form.edit .radio input{margin:0}
.actions{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin:18px 0 0}
button.danger{background:var(--bad)}
a.cancel{color:var(--muted)}
.rowacts{display:flex;flex-wrap:wrap;gap:8px;align-items:center;white-space:nowrap}
.rowacts form{display:inline}
.rowacts button.mv{background:none;color:var(--accent);padding:2px 7px;border:1px solid var(--line);
  border-radius:6px;font-size:.85rem}
.rowacts button.mv[disabled]{color:var(--muted);cursor:default}
.flash{background:var(--panel);border:1px solid var(--ok);border-left:4px solid var(--ok);
  border-radius:8px;padding:10px 14px;margin:0 0 16px}
.err{background:var(--panel);border:1px solid var(--bad);border-left:4px solid var(--bad);
  border-radius:8px;padding:10px 14px;margin:0 0 16px;white-space:pre-wrap}
.secret{border:1px solid var(--warn);border-left:4px solid var(--warn);border-radius:8px;
  padding:12px 14px;margin:0 0 16px;background:var(--panel)}
.secret code{display:block;margin:8px 0 0;padding:10px;background:var(--chip);border-radius:6px;
  word-break:break-all;user-select:all}
";

// ---------------------------------------------------------------------------
// Language
// ---------------------------------------------------------------------------

/// The two languages the binary carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lang {
    En,
    It,
}

impl Lang {
    /// The `lang=` attribute, the cookie value, and the query parameter — one spelling.
    fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::It => "it",
        }
    }

    /// The one the switch in the header offers.
    fn other(self) -> Lang {
        match self {
            Lang::En => Lang::It,
            Lang::It => Lang::En,
        }
    }
}

/// Parse a language name, from the query, the cookie or `BB_AUTH_WEB_DEFAULT_LANG`.
/// `None` for anything else — an unknown value is simply not a preference.
fn parse_lang(s: &str) -> Option<Lang> {
    match s.trim().to_ascii_lowercase().as_str() {
        "en" => Some(Lang::En),
        "it" => Some(Lang::It),
        _ => None,
    }
}

/// Every translatable string in the GUI, as a variant.
///
/// An enum rather than a string key so that [`t`]'s match is **exhaustive**: adding a key
/// without translating it does not fall back at runtime, it fails to compile. And because
/// each arm names both spellings on one line, no key can be half-translated either.
///
/// What is *not* here is as deliberate as what is: `users`, `url_groups`, `sites`, `denied`,
/// `authorized_urls`, `public_auth`, `login_url`, `api_keys`, `released`, `duration`,
/// `notes`, `can`, `bbk_` and every `@group` reference are the access file's own vocabulary.
/// They stay in both languages because they are what an operator types into the file and
/// into `bb-auth-adm`; translating them would invent a second name for a thing that has one.
#[derive(Clone, Copy)]
enum K {
    Dashboard,
    Back,
    None,
    Counts,
    KeyExpiry,
    ColOwner,
    ColExpiry,
    Expired,
    ExpiresSoon,
    NeverExpires,
    KeyInvalid,
    Expires,
    Warnings,
    NoWarnings,
    WarnNoScope,
    WarnEnrolledAndDenied,
    ReferencedBy,
    ReferencedByNothing,
    Patterns,
    Inherits,
    ReachesNothing,
    NoSuchUser,
    UsersIntro,
    GroupsIntro,
    SitesIntro,
    DeniedIntro,
    AlsoEnrolled,
    CanIntro,
    Submit,
    Authorized,
    VerdictDenied,
    WhySiteGrant,
    WhyRosterGrant,
    WhyVetoed,
    WhyOutOfScope,
    WhyNotEnrolled,
    AppSees,
    NoIdentityTitle,
    NoIdentityBody,
    NotAdminTitle,
    NotAdminBody,
    NotFoundTitle,
    NotFoundBody,
    FileErrorTitle,
    FileErrorHint,
    SignedInAs,
    ReloadHint,
    // --- actions, buttons, form furniture ---
    Add,
    Edit,
    Remove,
    Rotate,
    Save,
    Create,
    Cancel,
    MoveUp,
    MoveDown,
    ScopeHelp,
    ScopeEmptyMeans,
    KeyScopeInherit,
    KeyScopeOwn,
    KeyScopeOwnEmpty,
    SiteUrlsHelp,
    PublicAuthWarn,
    GroupUrlsHelp,
    GroupNoRename,
    NewEmail,
    NewName,
    // --- what a destructive page warns about ---
    ConfirmUserRm,
    ConfirmKeyRm,
    ConfirmKeyRotate,
    ConfirmSiteRm,
    ConfirmGroupRm,
    ConfirmDenyRm,
    // --- the minted bearer ---
    BearerHeading,
    BearerOnce,
    // --- refusals a form makes on its own ---
    EmailRequired,
    NameRequired,
    KeyIdRequired,
    BadKeyWindow,
    AlreadyDenied,
    NoSuchKey,
    NoSuchSite,
    NoSuchGroup,
    NoSuchDenied,
    // --- whole-request refusals ---
    ConflictTitle,
    ConflictBody,
    ConflictBack,
    CsrfTitle,
    CsrfBody,
    NotAllowedTitle,
    NotAllowedBody,
    // --- what a redirect says it did ---
    MsgUserAdded,
    MsgUserSaved,
    MsgUserRemoved,
    MsgKeySaved,
    MsgKeyRemoved,
    MsgSiteAdded,
    MsgSiteSaved,
    MsgSiteRemoved,
    MsgSiteMoved,
    MsgGroupAdded,
    MsgGroupSaved,
    MsgGroupRemoved,
    MsgDeniedAdded,
    MsgDeniedRemoved,
}

/// Pick one of a key's two spellings.
fn m(lang: Lang, en: &'static str, it: &'static str) -> &'static str {
    match lang {
        Lang::En => en,
        Lang::It => it,
    }
}

/// The translation table. See [`K`] for why it is a match and what is deliberately absent
/// from it.
fn t(lang: Lang, key: K) -> &'static str {
    match key {
        K::Dashboard => m(lang, "Dashboard", "Cruscotto"),
        K::Back => m(lang, "back", "indietro"),
        K::None => m(lang, "none", "nessuno"),
        K::Counts => m(lang, "What is in the file", "Cosa c'è nel file"),
        K::KeyExpiry => m(lang, "Key expiry", "Scadenza delle chiavi"),
        K::ColOwner => m(lang, "owner", "proprietario"),
        K::ColExpiry => m(lang, "expiry", "scadenza"),
        K::Expired => m(lang, "expired", "scaduta"),
        K::ExpiresSoon => m(lang, "expires soon", "scade a breve"),
        K::NeverExpires => m(lang, "never expires", "non scade mai"),
        K::KeyInvalid => m(
            lang,
            "invalid released/duration — the gate skips this key",
            "released/duration non validi — il gate salta questa chiave",
        ),
        K::Expires => m(lang, "expires", "scade il"),
        K::Warnings => m(lang, "Warnings", "Avvisi"),
        K::NoWarnings => m(lang, "nothing to report", "nulla da segnalare"),
        K::WarnNoScope => m(
            lang,
            "reaches nothing — no authorized_urls",
            "non raggiunge nulla — nessun authorized_urls",
        ),
        K::WarnEnrolledAndDenied => m(
            lang,
            "is in users and in denied — denied wins, on every credential",
            "è in users e in denied — vince denied, su ogni credenziale",
        ),
        K::ReferencedBy => m(lang, "referenced by", "referenziato da"),
        K::ReferencedByNothing => m(lang, "referenced by nothing", "referenziato da nulla"),
        K::Patterns => m(lang, "patterns", "pattern"),
        K::Inherits => m(lang, "inherits the user's", "eredita quello dell'utente"),
        K::ReachesNothing => m(lang, "reaches nothing", "non raggiunge nulla"),
        K::NoSuchUser => m(lang, "no such user", "utente inesistente"),
        K::UsersIntro => m(
            lang,
            "The roster: who is enrolled, and what they may reach.",
            "Il roster: chi è iscritto e cosa può raggiungere.",
        ),
        K::GroupsIntro => m(
            lang,
            "Named sets of URL patterns. A group is abbreviation, never a grant: defining \
             one authorizes nobody until some list names it.",
            "Insiemi di pattern di URL con un nome. Un gruppo è un'abbreviazione, mai una \
             concessione: definirne uno non autorizza nessuno finché una lista non lo nomina.",
        ),
        K::SitesIntro => m(
            lang,
            "URL areas, in file order. First match wins: the first site whose urls cover a \
             request answers for it, even if it grants nothing. Specific sites go first.",
            "Aree di URL, nell'ordine del file. Vince la prima corrispondenza: risponde il \
             primo site le cui urls coprono la richiesta, anche se non concede nulla. I \
             site specifici vanno prima.",
        ),
        K::DeniedIntro => m(
            lang,
            "A veto by email. It outranks every grant, on every credential — and it is not \
             the same as deleting the user's row.",
            "Un veto per email. Batte ogni concessione, su ogni credenziale — e non equivale \
             a cancellare la riga dell'utente.",
        ),
        K::AlsoEnrolled => m(lang, "also in users", "anche in users"),
        K::CanIntro => m(
            lang,
            "Would this credential reach this URL? Answered by the gate's own decision \
             function, on the file as it is on disk right now.",
            "Questa credenziale raggiungerebbe questo URL? Risponde la funzione di decisione \
             del gate, sul file così com'è su disco adesso.",
        ),
        K::Submit => m(lang, "Check", "Verifica"),
        K::Authorized => m(lang, "AUTHORIZED", "AUTORIZZATO"),
        K::VerdictDenied => m(lang, "DENIED", "NEGATO"),
        K::WhySiteGrant => m(
            lang,
            "is public_auth: any identity Cognito vouches for reaches this URL, enrolled or \
             not. The roster is not consulted.",
            "è public_auth: ogni identità garantita da Cognito raggiunge questo URL, iscritta \
             o no. Il roster non viene consultato.",
        ),
        K::WhyRosterGrant => m(
            lang,
            "is enrolled, and this URL is inside their authorized_urls.",
            "è iscritto e questo URL è dentro i suoi authorized_urls.",
        ),
        K::WhyVetoed => m(
            lang,
            "is on the denied list, which outranks every grant.",
            "è nella lista denied, che batte ogni concessione.",
        ),
        K::WhyOutOfScope => m(
            lang,
            "is outside their authorized_urls, and no public_auth site covers it.",
            "è fuori dai loro authorized_urls, e nessun site public_auth lo copre.",
        ),
        K::WhyNotEnrolled => m(
            lang,
            "is not in users, and no public_auth site covers this URL.",
            "non è in users, e nessun site public_auth copre questo URL.",
        ),
        K::AppSees => m(lang, "the application sees", "l'applicazione vede"),
        K::NoIdentityTitle => m(lang, "No identity header", "Nessun header di identità"),
        K::NoIdentityBody => m(
            lang,
            "identity header missing — is nginx auth_request wiring in front of this service?",
            "header di identità mancante — c'è il wiring nginx auth_request davanti a questo \
             servizio?",
        ),
        K::NotAdminTitle => m(lang, "Not an administrator", "Non sei un amministratore"),
        K::NotAdminBody => m(
            lang,
            "is authenticated, but is not on BB_AUTH_WEB_ADMINS.",
            "è autenticato, ma non è in BB_AUTH_WEB_ADMINS.",
        ),
        K::NotFoundTitle => m(lang, "Not found", "Non trovato"),
        K::NotFoundBody => m(
            lang,
            "there is no page at this address.",
            "non c'è nessuna pagina a questo indirizzo.",
        ),
        K::FileErrorTitle => m(
            lang,
            "The access file cannot be read",
            "L'access file non è leggibile",
        ),
        K::FileErrorHint => m(
            lang,
            "Every page here re-reads the file on each request, so fixing it takes effect at \
             once — no restart, no reload.",
            "Ogni pagina qui rilegge il file a ogni richiesta, quindi correggerlo ha effetto \
             subito — senza riavvio né reload.",
        ),
        K::SignedInAs => m(lang, "signed in as", "accesso come"),
        K::ReloadHint => m(
            lang,
            "an edit is live when the gate re-reads the file:",
            "una modifica è attiva quando il gate rilegge il file:",
        ),

        K::Add => m(lang, "add", "aggiungi"),
        K::Edit => m(lang, "edit", "modifica"),
        K::Remove => m(lang, "remove", "rimuovi"),
        K::Rotate => m(lang, "rotate", "rigenera"),
        K::Save => m(lang, "Save", "Salva"),
        K::Create => m(lang, "Create", "Crea"),
        K::Cancel => m(lang, "cancel", "annulla"),
        K::MoveUp => m(lang, "move up", "sposta su"),
        K::MoveDown => m(lang, "move down", "sposta giù"),
        K::ScopeHelp => m(
            lang,
            "One URL pattern per line. A group reference is a line of its own, written \
             '@name' exactly as in the file. Blank lines are dropped.",
            "Un pattern di URL per riga. Un riferimento a un gruppo è una riga a sé, scritta \
             '@nome' esattamente come nel file. Le righe vuote vengono scartate.",
        ),
        K::ScopeEmptyMeans => m(
            lang,
            "Empty reaches nothing — access is enumerated, never assumed. Everything is the \
             explicit pattern",
            "Vuoto non raggiunge nulla — l'accesso si enumera, non si presume. Tutto è il \
             pattern esplicito",
        ),
        K::KeyScopeInherit => m(
            lang,
            "inherit the user's scope",
            "eredita lo scope dell'utente",
        ),
        K::KeyScopeOwn => m(lang, "its own scope", "scope proprio"),
        K::KeyScopeOwnEmpty => m(
            lang,
            "An own scope with no patterns is not the same as inheriting: it reaches nothing.",
            "Uno scope proprio senza pattern non equivale a ereditare: non raggiunge nulla.",
        ),
        K::SiteUrlsHelp => m(
            lang,
            "The URL area this record answers for. First match wins, so a broad site listed \
             early silences the ones below it.",
            "L'area di URL per cui risponde questo record. Vince la prima corrispondenza, \
             quindi un site ampio messo presto zittisce quelli sotto.",
        ),
        K::PublicAuthWarn => m(
            lang,
            "any identity Cognito vouches for reaches these urls, enrolled or not, and the \
             roster is not consulted. Self-signup is open, so that means anyone who can \
             register: the right grant for an onboarding area, the wrong one for anything else.",
            "ogni identità garantita da Cognito raggiunge questi urls, iscritta o no, e il \
             roster non viene consultato. La registrazione è aperta, quindi vuol dire chiunque \
             possa registrarsi: la concessione giusta per un'area di onboarding, sbagliata per \
             tutto il resto.",
        ),
        K::GroupUrlsHelp => m(
            lang,
            "The patterns this name stands for. A group cannot reference another group.",
            "I pattern per cui sta questo nome. Un gruppo non può referenziarne un altro.",
        ),
        K::GroupNoRename => m(
            lang,
            "There is deliberately no rename: a reference names a group by its exact \
             spelling. Add the new name, move the references, then remove the old one.",
            "La rinomina non esiste di proposito: un riferimento nomina il gruppo con la sua \
             esatta grafia. Aggiungi il nuovo nome, sposta i riferimenti, poi rimuovi il \
             vecchio.",
        ),
        K::NewEmail => m(lang, "email (rename)", "email (rinomina)"),
        K::NewName => m(lang, "name (rename)", "nome (rinomina)"),

        K::ConfirmUserRm => m(
            lang,
            "The roster row goes, and every api key it owns with it. It does NOT keep them \
             off a public_auth site — the roster is not consulted there; that is what denied \
             is for.",
            "Sparisce la riga del roster, e con essa ogni sua api key. NON li tiene fuori da \
             un site public_auth — lì il roster non viene consultato; per quello c'è denied.",
        ),
        K::ConfirmKeyRm => m(
            lang,
            "The bearer stops working the moment the gate reloads. It cannot be restored — \
             only a new key can be minted.",
            "Il bearer smette di funzionare appena il gate ricarica. Non è recuperabile — si \
             può solo generare una chiave nuova.",
        ),
        K::ConfirmKeyRotate => m(
            lang,
            "A new bearer is minted and shown once, here. The old one stops working at the \
             next reload — which is what makes this the answer to a leak.",
            "Viene generato un nuovo bearer, mostrato una volta sola, qui. Il vecchio smette \
             di funzionare al prossimo reload — ed è per questo che è la risposta a una fuga.",
        ),
        K::ConfirmSiteRm => m(
            lang,
            "If it was public_auth, the identities it let in with no roster entry now reach \
             nothing.",
            "Se era public_auth, le identità che entravano senza riga nel roster ora non \
             raggiungono nulla.",
        ),
        K::ConfirmGroupRm => m(
            lang,
            "A group is abbreviation, not a grant. Removing one is refused while any list \
             still names it.",
            "Un gruppo è un'abbreviazione, non una concessione. Rimuoverlo viene rifiutato \
             finché una lista lo nomina.",
        ),
        K::ConfirmDenyRm => m(
            lang,
            "The veto is lifted. Whatever the roster and the sites grant them applies again.",
            "Il veto viene tolto. Torna a valere quanto gli concedono il roster e i site.",
        ),

        K::BearerHeading => m(
            lang,
            "The bearer — copy it now",
            "Il bearer — copialo adesso",
        ),
        K::BearerOnce => m(
            lang,
            "Shown once, here, and stored nowhere: the file keeps only its sha256, and that \
             lookup is the whole verification. It cannot be recovered — only replaced by a \
             rotation.",
            "Mostrato una volta sola, qui, e non memorizzato da nessuna parte: il file tiene \
             solo il suo sha256, e quel lookup è tutta la verifica. Non è recuperabile — si \
             può solo sostituire con una rotazione.",
        ),

        K::EmailRequired => m(lang, "an email is required", "serve un'email"),
        K::NameRequired => m(lang, "a name is required", "serve un nome"),
        K::KeyIdRequired => m(
            lang,
            "a key needs an id — it is what names it in a log and in a rotation",
            "una chiave ha bisogno di un id — è ciò che la nomina in un log e in una rotazione",
        ),
        K::BadKeyWindow => m(
            lang,
            "released + duration is not a valid window: a date is YYYY-MM-DD, a duration is \
             <n>d, <n>h or never. The gate would skip this key.",
            "released + duration non sono una finestra valida: una data è YYYY-MM-DD, una \
             durata è <n>d, <n>h o never. Il gate salterebbe questa chiave.",
        ),
        K::AlreadyDenied => m(
            lang,
            "that email is already on denied",
            "quell'email è già in denied",
        ),
        K::NoSuchKey => m(lang, "no such api key", "api key inesistente"),
        K::NoSuchSite => m(lang, "no such site", "site inesistente"),
        K::NoSuchGroup => m(lang, "no such url group", "url group inesistente"),
        K::NoSuchDenied => m(
            lang,
            "that email is not on denied",
            "quell'email non è in denied",
        ),

        K::ConflictTitle => m(lang, "The file changed", "Il file è cambiato"),
        K::ConflictBody => m(
            lang,
            "The access file was written by someone else after this form was loaded — a \
             bb-auth-adm over SSH, or another tab. Nothing was written here: reload the page \
             and make the change again, on what the file says now.",
            "L'access file è stato scritto da qualcun altro dopo il caricamento di questa \
             form — un bb-auth-adm via SSH, o un'altra scheda. Qui non è stato scritto \
             nulla: ricarica la pagina e rifai la modifica su ciò che il file dice adesso.",
        ),
        K::ConflictBack => m(lang, "reload the page", "ricarica la pagina"),
        K::CsrfTitle => m(lang, "Request refused", "Richiesta rifiutata"),
        K::CsrfBody => m(
            lang,
            "this POST did not come from a page of this site. Only a same-origin form \
             submission is accepted.",
            "questo POST non arriva da una pagina di questo sito. Si accetta solo l'invio di \
             una form dalla stessa origine.",
        ),
        K::NotAllowedTitle => m(lang, "Not allowed here", "Non ammesso qui"),
        K::NotAllowedBody => m(
            lang,
            "this address does not answer that method.",
            "questo indirizzo non risponde a quel metodo.",
        ),

        K::MsgUserAdded => m(lang, "user added", "utente aggiunto"),
        K::MsgUserSaved => m(lang, "user saved", "utente salvato"),
        K::MsgUserRemoved => m(lang, "user removed", "utente rimosso"),
        K::MsgKeySaved => m(lang, "api key saved", "api key salvata"),
        K::MsgKeyRemoved => m(lang, "api key removed", "api key rimossa"),
        K::MsgSiteAdded => m(lang, "site added", "site aggiunto"),
        K::MsgSiteSaved => m(lang, "site saved", "site salvato"),
        K::MsgSiteRemoved => m(lang, "site removed", "site rimosso"),
        K::MsgSiteMoved => m(lang, "site moved", "site spostato"),
        K::MsgGroupAdded => m(lang, "url group added", "url group aggiunto"),
        K::MsgGroupSaved => m(lang, "url group saved", "url group salvato"),
        K::MsgGroupRemoved => m(lang, "url group removed", "url group rimosso"),
        K::MsgDeniedAdded => m(lang, "email denied", "email negata"),
        K::MsgDeniedRemoved => m(lang, "veto lifted", "veto tolto"),
    }
}

/// What a successful mutation says on the page it redirects to.
///
/// A closed set, and that is the point: the `303` puts `?msg=<key>` in the URL, so what
/// comes back is request data. Only these keys render, through [`t`]; anything else is
/// dropped silently. No free text ever travels through the query string, which is what
/// keeps the banner from being a place to inject prose into an admin's page.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Msg {
    UserAdded,
    UserSaved,
    UserRemoved,
    KeySaved,
    KeyRemoved,
    SiteAdded,
    SiteSaved,
    SiteRemoved,
    SiteMoved,
    GroupAdded,
    GroupSaved,
    GroupRemoved,
    DeniedAdded,
    DeniedRemoved,
}

impl Msg {
    /// The spelling in the query string — printable ASCII, so it goes into a `Location:`
    /// with no encoding.
    fn key(self) -> &'static str {
        match self {
            Msg::UserAdded => "user-added",
            Msg::UserSaved => "user-saved",
            Msg::UserRemoved => "user-removed",
            Msg::KeySaved => "key-saved",
            Msg::KeyRemoved => "key-removed",
            Msg::SiteAdded => "site-added",
            Msg::SiteSaved => "site-saved",
            Msg::SiteRemoved => "site-removed",
            Msg::SiteMoved => "site-moved",
            Msg::GroupAdded => "group-added",
            Msg::GroupSaved => "group-saved",
            Msg::GroupRemoved => "group-removed",
            Msg::DeniedAdded => "denied-added",
            Msg::DeniedRemoved => "denied-removed",
        }
    }

    /// The inverse. `None` for anything this binary does not say itself.
    fn parse(s: &str) -> Option<Msg> {
        [
            Msg::UserAdded,
            Msg::UserSaved,
            Msg::UserRemoved,
            Msg::KeySaved,
            Msg::KeyRemoved,
            Msg::SiteAdded,
            Msg::SiteSaved,
            Msg::SiteRemoved,
            Msg::SiteMoved,
            Msg::GroupAdded,
            Msg::GroupSaved,
            Msg::GroupRemoved,
            Msg::DeniedAdded,
            Msg::DeniedRemoved,
        ]
        .into_iter()
        .find(|m| m.key() == s)
    }

    fn text(self, lang: Lang) -> &'static str {
        t(
            lang,
            match self {
                Msg::UserAdded => K::MsgUserAdded,
                Msg::UserSaved => K::MsgUserSaved,
                Msg::UserRemoved => K::MsgUserRemoved,
                Msg::KeySaved => K::MsgKeySaved,
                Msg::KeyRemoved => K::MsgKeyRemoved,
                Msg::SiteAdded => K::MsgSiteAdded,
                Msg::SiteSaved => K::MsgSiteSaved,
                Msg::SiteRemoved => K::MsgSiteRemoved,
                Msg::SiteMoved => K::MsgSiteMoved,
                Msg::GroupAdded => K::MsgGroupAdded,
                Msg::GroupSaved => K::MsgGroupSaved,
                Msg::GroupRemoved => K::MsgGroupRemoved,
                Msg::DeniedAdded => K::MsgDeniedAdded,
                Msg::DeniedRemoved => K::MsgDeniedRemoved,
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Runtime configuration, read once from the environment at startup. Mirrors the gate's
/// `Config::from_env`, down to the wording of a fatal exit: a missing required var has no
/// safe default, so the process refuses to start rather than guess.
struct Config {
    /// `BB_AUTH_WEB_LISTEN`. Loopback — see the trust model on the crate root.
    listen: String,
    /// `BB_AUTH_USERS_FILE`, the access file to render. The gate's variable name, on
    /// purpose: each service gets its own env file, and one name means one meaning.
    access_path: String,
    /// `BB_AUTH_WEB_ADMINS`, normalised with [`norm_email`] — the emails allowed in, and
    /// never empty ([`compile_admins`]).
    admins: Vec<String>,
    /// `BB_AUTH_WEB_BASE_PATH`, normalised by [`normalize_base_path`]: `""` or `/admin`.
    /// Every internal href carries it and the router strips it.
    base_path: String,
    /// `BB_AUTH_WEB_DEFAULT_LANG`, used when a request expresses no preference at all.
    default_lang: Lang,
}

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

/// Compile `BB_AUTH_WEB_ADMINS` — comma-separated emails — into the allowlist. Entries are
/// trimmed, lowercased ([`norm_email`], so a login's capitalisation cannot matter) and
/// deduplicated; blank entries are dropped, which is what makes a trailing comma harmless.
///
/// **An empty result is an error**, never "everyone". This list is the only thing standing
/// between a `public_auth` site that happens to cover the GUI's URL and an admin surface
/// open to any Cognito account — and Cognito self-signup is open.
///
/// Pure and fallible so it can be tested; [`Config::from_env`] turns an `Err` into the usual
/// fatal exit.
fn compile_admins(spec: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for email in spec.split(',').map(norm_email).filter(|e| !e.is_empty()) {
        if !out.contains(&email) {
            out.push(email);
        }
    }
    if out.is_empty() {
        return Err("no admin emails — this must never mean 'everyone'".into());
    }
    Ok(out)
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
fn normalize_base_path(raw: &str) -> Result<String, String> {
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

impl Config {
    /// Build the config from the environment, exiting on the first fatal problem.
    fn from_env() -> Config {
        let admins = compile_admins(&env_req("BB_AUTH_WEB_ADMINS")).unwrap_or_else(|e| {
            eprintln!("[bb-auth-web] FATAL: BB_AUTH_WEB_ADMINS: {e}");
            std::process::exit(1);
        });
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
        Config {
            listen: env_or("BB_AUTH_WEB_LISTEN", "127.0.0.1:8091"),
            access_path: env_req("BB_AUTH_USERS_FILE"),
            admins,
            base_path,
            default_lang,
        }
    }

    /// Whether `email` (already [`norm_email`]-normalised) may use the GUI.
    fn is_admin(&self, email: &str) -> bool {
        self.admins.iter().any(|a| a == email)
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// A page. The four section routes are the access file's four sections, which is the whole
/// navigation: what the file has, the GUI has a tab for. Everything else is a form, a
/// confirmation, or the one `POST`-only route ([`Route::SiteMove`]).
///
/// A route that mutates is reached by `POST` on **the same path** that renders its form by
/// `GET`, which is what makes "re-render this form with the library's refusal" a matter of
/// calling the same page function again. The names a route carries — an email, a key id, a
/// site or group name — are already percent-**decoded**.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Route {
    Dashboard,
    Groups,
    Sites,
    Denied,
    Users,
    /// One roster row.
    User(String),
    Can,

    UserAdd,
    UserEdit(String),
    UserRm(String),
    KeyAdd(String),
    KeyEdit(String, String),
    KeyRotate(String, String),
    KeyRm(String, String),

    SiteAdd,
    SiteEdit(String),
    SiteRm(String),
    /// `POST` only: a per-row button, so there is nothing to render on a `GET`.
    SiteMove(String),

    GroupAdd,
    GroupEdit(String),
    GroupRm(String),

    DenyAdd,
    DenyRm(String),
}

/// The segment that marks an action rather than a name, in a position where a name could
/// also appear (`/users/+add` vs `/users/bob@x.com`).
///
/// A `+` is what makes the two unambiguous, and by construction rather than by luck:
/// [`pct_encode_segment`] escapes everything outside the unreserved set, `+` included, so
/// no href this binary builds for a name can ever spell one — whatever the roster holds.
const ACTION_ADD: &str = "+add";

impl Route {
    /// This route's path below the base — the canonical spelling, which is also what every
    /// href, the language redirect and the post-mutation `Location:` are built from. Nothing
    /// a client sent survives into one: names are re-encoded by [`pct_encode_segment`], so
    /// the result is printable ASCII whatever the access file contains.
    fn path(&self) -> String {
        let seg = pct_encode_segment;
        match self {
            Route::Dashboard => "/".to_string(),
            Route::Groups => "/groups".to_string(),
            Route::Sites => "/sites".to_string(),
            Route::Denied => "/denied".to_string(),
            Route::Users => "/users".to_string(),
            Route::User(e) => format!("/users/{}", seg(e)),
            Route::Can => "/can".to_string(),

            Route::UserAdd => format!("/users/{ACTION_ADD}"),
            Route::UserEdit(e) => format!("/users/{}/edit", seg(e)),
            Route::UserRm(e) => format!("/users/{}/rm", seg(e)),
            Route::KeyAdd(e) => format!("/users/{}/keys/{ACTION_ADD}", seg(e)),
            Route::KeyEdit(e, i) => format!("/users/{}/keys/{}/edit", seg(e), seg(i)),
            Route::KeyRotate(e, i) => format!("/users/{}/keys/{}/rotate", seg(e), seg(i)),
            Route::KeyRm(e, i) => format!("/users/{}/keys/{}/rm", seg(e), seg(i)),

            Route::SiteAdd => format!("/sites/{ACTION_ADD}"),
            Route::SiteEdit(n) => format!("/sites/{}/edit", seg(n)),
            Route::SiteRm(n) => format!("/sites/{}/rm", seg(n)),
            Route::SiteMove(n) => format!("/sites/{}/move", seg(n)),

            Route::GroupAdd => format!("/groups/{ACTION_ADD}"),
            Route::GroupEdit(n) => format!("/groups/{}/edit", seg(n)),
            Route::GroupRm(n) => format!("/groups/{}/rm", seg(n)),

            Route::DenyAdd => format!("/denied/{ACTION_ADD}"),
            Route::DenyRm(e) => format!("/denied/{}/rm", seg(e)),
        }
    }

    /// Which nav tab to mark current for this route — everything about a user belongs to
    /// the `users` tab, and so on down the four sections.
    fn tab(&self) -> Route {
        match self {
            Route::User(_)
            | Route::UserAdd
            | Route::UserEdit(_)
            | Route::UserRm(_)
            | Route::KeyAdd(_)
            | Route::KeyEdit(..)
            | Route::KeyRotate(..)
            | Route::KeyRm(..) => Route::Users,
            Route::SiteAdd | Route::SiteEdit(_) | Route::SiteRm(_) | Route::SiteMove(_) => {
                Route::Sites
            }
            Route::GroupAdd | Route::GroupEdit(_) | Route::GroupRm(_) => Route::Groups,
            Route::DenyAdd | Route::DenyRm(_) => Route::Denied,
            other => other.clone(),
        }
    }

    /// Where a form's `cancel` link goes, and where a `409` offers to send the browser
    /// back: the page this route was reached *from*.
    fn parent(&self) -> Route {
        match self {
            Route::UserEdit(e)
            | Route::UserRm(e)
            | Route::KeyAdd(e)
            | Route::KeyEdit(e, _)
            | Route::KeyRotate(e, _)
            | Route::KeyRm(e, _) => Route::User(e.clone()),
            Route::UserAdd => Route::Users,
            Route::SiteAdd | Route::SiteEdit(_) | Route::SiteRm(_) | Route::SiteMove(_) => {
                Route::Sites
            }
            Route::GroupAdd | Route::GroupEdit(_) | Route::GroupRm(_) => Route::Groups,
            Route::DenyAdd | Route::DenyRm(_) => Route::Denied,
            other => other.clone(),
        }
    }

    /// The `<title>` and the tab label this route lives under — the section's own name,
    /// untranslated, because that is the word an operator types.
    fn title(&self) -> &'static str {
        match self.tab() {
            Route::Groups => "url_groups",
            Route::Sites => "sites",
            Route::Denied => "denied",
            Route::Users => "users",
            Route::Can => "can",
            _ => "bb-auth-web",
        }
    }
}

/// Resolve a request path to a page, or `None` for a 404.
///
/// `base` is [`normalize_base_path`]'s output. A request outside it is not this service's —
/// it 404s rather than falling through to the dashboard, so a misconfigured `location` in
/// nginx shows up as a missing page instead of a GUI that silently answers everywhere.
///
/// Segments are decoded one by one, so a name containing a `/` (a key id may) round-trips
/// through [`Route::path`] and back. Literal arms come before the ones that capture a name;
/// [`ACTION_ADD`] is why that is unambiguous rather than a precedence a future name could
/// steal.
fn route(path: &str, base: &str) -> Option<Route> {
    let rest = if base.is_empty() {
        path
    } else {
        match path.strip_prefix(base) {
            // `/admin` and `/admin/…` are ours; `/administrivia` is not.
            Some("") => "/",
            Some(r) if r.starts_with('/') => r,
            _ => return None,
        }
    };
    let decoded: Vec<String> = rest
        .trim_end_matches('/')
        .split('/')
        .skip(1)
        .map(pct_decode)
        .collect();
    let segs: Vec<&str> = decoded.iter().map(String::as_str).collect();
    let s = |x: &&str| x.to_string();
    match segs.as_slice() {
        [] | [""] => Some(Route::Dashboard),
        ["can"] => Some(Route::Can),

        ["users"] => Some(Route::Users),
        ["users", ACTION_ADD] => Some(Route::UserAdd),
        ["users", e] if !e.is_empty() => Some(Route::User(s(e))),
        ["users", e, "edit"] if !e.is_empty() => Some(Route::UserEdit(s(e))),
        ["users", e, "rm"] if !e.is_empty() => Some(Route::UserRm(s(e))),
        ["users", e, "keys", ACTION_ADD] if !e.is_empty() => Some(Route::KeyAdd(s(e))),
        ["users", e, "keys", i, "edit"] if !e.is_empty() => Some(Route::KeyEdit(s(e), s(i))),
        ["users", e, "keys", i, "rotate"] if !e.is_empty() => Some(Route::KeyRotate(s(e), s(i))),
        ["users", e, "keys", i, "rm"] if !e.is_empty() => Some(Route::KeyRm(s(e), s(i))),

        ["sites"] => Some(Route::Sites),
        ["sites", ACTION_ADD] => Some(Route::SiteAdd),
        ["sites", n, "edit"] if !n.is_empty() => Some(Route::SiteEdit(s(n))),
        ["sites", n, "rm"] if !n.is_empty() => Some(Route::SiteRm(s(n))),
        ["sites", n, "move"] if !n.is_empty() => Some(Route::SiteMove(s(n))),

        ["groups"] => Some(Route::Groups),
        ["groups", ACTION_ADD] => Some(Route::GroupAdd),
        ["groups", n, "edit"] if !n.is_empty() => Some(Route::GroupEdit(s(n))),
        ["groups", n, "rm"] if !n.is_empty() => Some(Route::GroupRm(s(n))),

        ["denied"] => Some(Route::Denied),
        ["denied", ACTION_ADD] => Some(Route::DenyAdd),
        ["denied", e, "rm"] if !e.is_empty() => Some(Route::DenyRm(s(e))),

        _ => None,
    }
}

/// Percent-encode one path segment per RFC 3986: everything outside the unreserved set
/// becomes `%XX`.
///
/// Hand-rolled for the same reason the gate hand-rolls its own: `form_urlencoded` is the
/// wrong grammar here. It spells a space `+`, which would make `a+tag@x.com` — a perfectly
/// ordinary address — ambiguous with `a tag@x.com` in a path segment. Encoding and decoding
/// are exact inverses, and the output is printable ASCII for **any** input, which is what
/// lets a route path go into a `Location:` header unchecked.
fn pct_encode_segment(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// The inverse of [`pct_encode_segment`]: `%XX` decoded, every other byte literal — a `+`
/// is a `+`. Invalid UTF-8 is replaced rather than rejected; the result is only ever
/// compared against roster emails, and a mangled one simply matches nobody.
fn pct_decode(s: &str) -> String {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (
            b[i],
            b.get(i + 1).copied().and_then(hex),
            b.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(hi), Some(lo)) => {
                out.push(hi * 16 + lo);
                i += 3;
            }
            _ => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// First request header matching `name`, compared case-insensitively.
fn header_value<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

/// Pull one cookie's value out of a `Cookie:` header.
fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header
        .split(';')
        .filter_map(|p| p.trim().strip_prefix(name))
        .find_map(|rest| rest.strip_prefix('='))
}

/// The value of query parameter `name`. `form_urlencoded` **is** the right grammar here —
/// this is what a browser puts in the query string when it submits the `can` form.
fn query_param(query: &str, name: &str) -> Option<String> {
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// Build a response header. Panics only on a caller-side bug; every call site passes a
/// constant or a value that is printable ASCII by construction.
fn h(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("valid header")
}

/// Is this `POST` a same-origin form submission?
///
/// Two questions, in the order the browser answers them best:
///
/// * **`Sec-Fetch-Site`** is set by the browser on every request and cannot be set by a
///   page, so where it exists it is the whole answer: `same-origin` passes, anything else
///   (`cross-site`, `same-site`, `none`) does not.
/// * **`Origin`** is the fallback, and only its **host** is compared — against the `Host:`
///   header's. Not the scheme: this binary speaks plain HTTP behind a TLS-terminating
///   nginx, so the browser's `https://…` origin can never equal a scheme reconstructed
///   here, and comparing one would refuse every honest request. The port travels with the
///   host in both headers, so comparing the authority as written is right in the
///   default-port case *and* the explicit-port one.
///
/// Neither header present ⇒ **refused**. That is not a browser submitting a form, and no
/// token in the page would help against a client that sends neither.
fn csrf_ok(sec_fetch_site: Option<&str>, origin: Option<&str>, host: Option<&str>) -> bool {
    if let Some(sfs) = sec_fetch_site {
        return sfs.trim().eq_ignore_ascii_case("same-origin");
    }
    match (origin, host) {
        (Some(o), Some(hst)) => {
            let authority = o
                .trim()
                .split_once("://")
                .map(|(_, rest)| rest.trim_end_matches('/'));
            authority.is_some_and(|a| !a.is_empty() && a.eq_ignore_ascii_case(hst.trim()))
        }
        _ => false,
    }
}

/// The most a form body may be. Every field here is an email, a name or a handful of URL
/// patterns; anything past this is not one of our forms, and reading it would be a way to
/// make a 2-thread server chew memory.
const MAX_BODY: usize = 256 * 1024;

/// Read a request body, capped. A truncated read is not distinguished from a short one on
/// purpose: what comes out is parsed as a form, and a form missing its `rev` is refused by
/// the concurrency check anyway.
fn read_body(req: &mut Request) -> String {
    let mut body = String::new();
    let _ = req
        .as_reader()
        .take(MAX_BODY as u64)
        .read_to_string(&mut body);
    body
}

/// A submitted form, parsed once. `form_urlencoded` is exactly the right grammar here: this
/// is what a browser sends for a `<form method="post">` with no `enctype`.
///
/// The content type is deliberately not checked. A body in another grammar simply does not
/// produce the fields a handler asks for — starting with `rev`, whose absence is a refusal —
/// so there is nothing a wrong `Content-Type` buys that the same-origin check does not
/// already deny.
struct Form(Vec<(String, String)>);

impl Form {
    fn parse(body: &str) -> Form {
        Form(
            form_urlencoded::parse(body.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect(),
        )
    }

    /// The first value of `name`, or `""`. Nothing is trimmed here — a field that must be
    /// trimmed says so at its use.
    fn get(&self, name: &str) -> &str {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map_or("", |(_, v)| v.as_str())
    }

    /// A checkbox: present at all ⇒ ticked. Browsers omit an unticked box entirely.
    fn checked(&self, name: &str) -> bool {
        self.0.iter().any(|(k, _)| k == name)
    }

    /// A textarea of URL patterns, one per line: trimmed, blanks dropped. `@refs` are left
    /// exactly as typed — the file's own spelling, which is what the library expands.
    fn lines(&self, name: &str) -> Vec<String> {
        self.get(name)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    }
}

/// Send a rendered page.
///
/// `Response::from_data` rather than `from_string` because the latter installs its own
/// `Content-Type: text/plain` header that `with_header` would then *append* to rather than
/// replace, putting two of them on the wire.
///
/// Three headers on every response, and they are the same three every time: `no-store`
/// because a page is a snapshot of a file that changes under it, `nosniff` because a browser
/// guessing at a content type is a browser deciding something we already know, and the
/// charset because the roster is full of names that are not ASCII.
fn respond_page(req: Request, status: u16, page: Markup) {
    let resp = Response::from_data(page.into_string().into_bytes())
        .with_status_code(StatusCode(status))
        .with_header(h("Content-Type", "text/html; charset=utf-8"))
        .with_header(h("Cache-Control", "no-store"))
        .with_header(h("X-Content-Type-Options", "nosniff"));
    let _ = req.respond(resp);
}

/// `302` to `location`, setting the language cookie. `location` is built from a [`Route`]
/// and re-encoded query parameters, so it is printable ASCII by construction and [`h`]
/// cannot panic on it.
fn respond_lang_redirect(req: Request, location: &str, lang: Lang) {
    let cookie = format!(
        "{LANG_COOKIE}={}; Max-Age={LANG_COOKIE_MAX_AGE}; Path=/; HttpOnly; SameSite=Lax",
        lang.code()
    );
    let resp = Response::empty(StatusCode(302))
        .with_header(h("Location", location))
        .with_header(h("Set-Cookie", &cookie[..]))
        .with_header(h("Cache-Control", "no-store"));
    let _ = req.respond(resp);
}

/// `303` to `location` — the redirect half of POST-redirect-GET, so a reload of the result
/// page cannot repeat the mutation.
///
/// `303` and not `302`: it is the status that tells every browser to follow with a `GET`,
/// which is the entire point. `location` is a [`Route::path`] under the base plus a
/// [`Msg::key`], both printable ASCII by construction, so [`h`] cannot panic on it — and
/// nothing request-supplied is in it.
fn respond_redirect(req: Request, location: &str) {
    let resp = Response::empty(StatusCode(303))
        .with_header(h("Location", location))
        .with_header(h("Cache-Control", "no-store"));
    let _ = req.respond(resp);
}

/// Which language to render in. Query, then cookie, then `Accept-Language`, then the
/// configured default — most explicit wins.
///
/// The `Accept-Language` check is deliberately crude: does the header start with `it`? A
/// full RFC 4647 negotiation over two languages would be more code than the question is
/// worth, and both wrong answers are one click from being right (and then remembered).
fn negotiate_lang(
    query: Option<&str>,
    cookie: Option<&str>,
    accept: Option<&str>,
    default: Lang,
) -> Lang {
    if let Some(l) = query.and_then(parse_lang) {
        return l;
    }
    if let Some(l) = cookie.and_then(parse_lang) {
        return l;
    }
    if accept.is_some_and(|a| a.trim().to_ascii_lowercase().starts_with("it")) {
        return Lang::It;
    }
    default
}

/// This request's URL with the `lang` parameter dropped, or set to `to`.
///
/// Used for both the language switch link and the redirect that follows one. Every byte of
/// the result is a constant, a [`Route::path`] or a re-encoded query parameter — nothing the
/// client sent survives verbatim, which is what makes the same string safe in an `href` and
/// in a `Location:` header.
fn lang_href(cfg: &Config, at: &Route, query: &str, to: Option<Lang>) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, v) in form_urlencoded::parse(query.as_bytes()) {
        if k != "lang" {
            ser.append_pair(&k, &v);
        }
    }
    if let Some(l) = to {
        ser.append_pair("lang", l.code());
    }
    let q = ser.finish();
    let path = format!("{}{}", cfg.base_path, at.path());
    if q.is_empty() {
        path
    } else {
        format!("{path}?{q}")
    }
}

// ---------------------------------------------------------------------------
// The shell
// ---------------------------------------------------------------------------

/// Everything the page shell needs that is not the page.
struct View<'a> {
    cfg: &'a Config,
    lang: Lang,
    /// The signed-in administrator, when there is one. `None` suppresses the navigation:
    /// a visitor who got a `401` or a `403` has nowhere to go but the login page.
    admin: Option<&'a str>,
    /// The route being rendered, for the current tab and the language switch.
    at: Route,
    /// The query as received, so switching language keeps the `can` form filled in.
    query: &'a str,
    /// sha256 of the access file's exact bytes as this request read them. Every form on the
    /// page carries it, and the `POST` that comes back must still match — see [`mutate`].
    /// Empty when the file could not be read, in which case there is no form to render.
    rev: &'a str,
    /// What the redirect that landed here says it did, if this binary said it ([`Msg`]).
    msg: Option<Msg>,
}

impl View<'_> {
    fn t(&self, key: K) -> &'static str {
        t(self.lang, key)
    }

    /// An absolute href for one of our own routes.
    fn href(&self, at: &Route) -> String {
        format!("{}{}", self.cfg.base_path, at.path())
    }
}

/// The chrome around every page: the tabs, the language switch, the footer.
///
/// The tabs are the access file's four sections **in file order** — `url_groups`, `sites`,
/// `denied`, `users` — with the dashboard in front and the tester at the end. Reading the
/// nav left to right is reading the file top to bottom, and the labels are the section names
/// themselves, untranslated, because those are the words an operator types.
fn shell(v: &View, title: &str, content: Markup) -> Markup {
    let tabs = [
        (Route::Dashboard, v.t(K::Dashboard)),
        (Route::Groups, "url_groups"),
        (Route::Sites, "sites"),
        (Route::Denied, "denied"),
        (Route::Users, "users"),
        (Route::Can, "can"),
    ];
    let current = v.at.tab();
    html! {
        (DOCTYPE)
        html lang=(v.lang.code()) {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { "bb-auth-web · " (title) }
                // The one deliberately raw emission on any page: a compile-time constant,
                // never request data and never anything read out of the access file.
                style { (PreEscaped(CSS)) }
            }
            body {
                header class="top" {
                    div class="bar" {
                        span class="brand" {
                            "bb-auth-web"
                            span class="v" { "v" (env!("CARGO_PKG_VERSION")) }
                        }
                        @if v.admin.is_some() {
                            nav {
                                @for (r, label) in &tabs {
                                    a class=@if *r == current { "on" } @else { "" }
                                      href=(v.href(r)) { (label) }
                                }
                            }
                        } @else {
                            nav {}
                        }
                        span class="lang" {
                            span { (v.lang.code()) }
                            "·"
                            a href=(lang_href(v.cfg, &v.at, v.query, Some(v.lang.other()))) {
                                (v.lang.other().code())
                            }
                        }
                    }
                }
                main {
                    // The one thing a redirect is allowed to say, from a closed set.
                    @if let Some(msg) = v.msg {
                        div class="flash" { (msg.text(v.lang)) }
                    }
                    (content)
                }
                footer {
                    span { (v.t(K::ReloadHint)) " " code { "systemctl reload bb-auth" } }
                    @if let Some(a) = v.admin {
                        span { (v.t(K::SignedInAs)) " " code { (a) } }
                    }
                }
            }
        }
    }
}

/// A rounded label — a `denied` badge, an expiry state, `public_auth`.
fn tag(class: &str, text: &str) -> Markup {
    html! { span class=(format!("tag {class}")) { (text) } }
}

/// A URL-pattern list as the file stores it. `@group` references are shown **raw, never
/// expanded**: the file is what an operator edits and what `bb-auth-adm` prints, so a page
/// that quietly substituted a group's patterns would be showing something nobody wrote.
fn url_list(lang: Lang, urls: Option<&Vec<String>>, absent: &str) -> Markup {
    html! {
        @match urls {
            None => span class="muted" { (absent) },
            Some(l) if l.is_empty() => span class="bad" { "[] — " (t(lang, K::ReachesNothing)) },
            Some(l) => ul class="plain mono" { @for u in l { li { (u) } } },
        }
    }
}

// ---------------------------------------------------------------------------
// Form furniture
// ---------------------------------------------------------------------------

/// The scaffold every editing form shares: the `POST` back to the route that rendered it,
/// the `rev` the concurrency check reads, the refusal above the fields it is about, and a
/// way out that changes nothing.
///
/// The action is always [`View::at`] — a form posts to the path it was served from — which
/// is what makes a re-render after a refusal literally the same call with an error added.
fn form_shell(v: &View, err: Option<&str>, fields: Markup, submit: &str, danger: bool) -> Markup {
    html! {
        form class="edit" method="post" action=(v.href(&v.at)) {
            // The library's words, verbatim: the sentence `bb-auth-adm` prints for the same
            // refusal, so an operator who has read one recognises the other.
            @if let Some(e) = err { div class="err" { (e) } }
            input type="hidden" name="rev" value=(v.rev);
            (fields)
            div class="actions" {
                button type="submit" class=@if danger { "danger" } @else { "" } { (submit) }
                a class="cancel" href=(v.href(&v.at.parent())) { (v.t(K::Cancel)) }
            }
        }
    }
}

/// A one-line text field. The label is the file's own field name wherever there is one.
fn text_field(
    label: &str,
    name: &str,
    value: &str,
    placeholder: &str,
    hint: Option<&str>,
) -> Markup {
    html! {
        label {
            span class="lbl" { (label) }
            input type="text" name=(name) value=(value) placeholder=(placeholder)
                  autocapitalize="off" spellcheck="false";
            @if let Some(h) = hint { span class="hint" { (h) } }
        }
    }
}

/// A URL-pattern list: one per line, `@refs` written literally. The same shape for a user's
/// scope, a key's, a site's `urls` and a group's patterns — one grammar, as in the file.
fn urls_field(label: &str, name: &str, value: &str, hint: Markup) -> Markup {
    html! {
        label {
            // An empty label is a field whose heading is already above it (the key form's
            // scope radios) — not a blank line to leave in the page.
            @if !label.is_empty() { span class="lbl" { (label) } }
            textarea name=(name) rows="6" spellcheck="false" autocapitalize="off" { (value) }
            span class="hint" { (hint) }
        }
    }
}

/// The lines of a pattern list, as a textarea's value.
fn urls_text(urls: Option<&Vec<String>>) -> String {
    urls.map(|l| l.join("\n")).unwrap_or_default()
}

/// A small `add` / `edit` / `remove` link beside the thing it acts on.
fn act(v: &View, at: &Route, label: &str) -> Markup {
    html! { a href=(v.href(at)) { (label) } }
}

/// A confirmation page: what is about to go, what that means, and a `POST` that does it.
/// The `GET` that renders this changes nothing, which is the whole reason destructive
/// actions are two steps and not a link.
fn page_confirm(
    v: &View,
    heading: Markup,
    what: Markup,
    why: &str,
    button: &str,
    err: Option<&str>,
) -> Markup {
    html! {
        h1 { (heading) }
        p class="lede" { (why) }
        div class="panel" {
            (what)
            (form_shell(v, err, html! {}, button, true))
        }
    }
}

/// "no such user / api key / site / url group" — a `GET` for a name the file does not have.
fn page_missing(v: &View, what: &str, name: &str, back: &Route) -> Markup {
    html! {
        h1 { (what) }
        p class="lede" { code { (name) } }
        p { a href=(v.href(back)) { "← " (v.t(K::Back)) } }
    }
}

// ---------------------------------------------------------------------------
// Key expiry
// ---------------------------------------------------------------------------

/// A key's validity window, resolved against the wall clock — the library's [`key_expiry`]
/// plus the "is that in the past?" the gate applies on every request.
enum Expiry {
    /// `released`/`duration` do not parse: the gate skips this key entirely.
    Invalid,
    Never,
    /// Unix seconds, and the days from now (negative once past).
    At(u64, i64),
}

/// Anything closer than this is called out on the dashboard. A month is the window in which
/// re-minting a key is a chore rather than an incident.
const SOON_DAYS: i64 = 30;

fn expiry_of(k: &ApiKeySpec, now: u64) -> Expiry {
    match key_expiry(&k.released, &k.duration) {
        None => Expiry::Invalid,
        Some(None) => Expiry::Never,
        Some(Some(exp)) => Expiry::At(exp, (exp as i64 - now as i64) / 86_400),
    }
}

impl Expiry {
    /// Sort rank for the dashboard table: what expires soonest first, then the broken ones
    /// (which need attention but have no date to sort by), then the ones that never expire.
    fn rank(&self) -> (u8, i64) {
        match self {
            Expiry::At(_, days) => (0, *days),
            Expiry::Invalid => (1, 0),
            Expiry::Never => (2, 0),
        }
    }
}

fn expiry_markup(lang: Lang, e: &Expiry) -> Markup {
    html! {
        @match e {
            Expiry::Invalid => (tag("bad", t(lang, K::KeyInvalid))),
            Expiry::Never => (tag("", t(lang, K::NeverExpires))),
            Expiry::At(exp, days) if *days < 0 => {
                (tag("bad", t(lang, K::Expired)))
                " " span class="mono muted" { (format_date(*exp)) }
            }
            Expiry::At(exp, days) if *days <= SOON_DAYS => {
                (tag("warn", t(lang, K::ExpiresSoon)))
                " " span class="mono muted" { (format_date(*exp)) " (" (days) "d)" }
            }
            Expiry::At(exp, days) => {
                span class="muted" { (t(lang, K::Expires)) " " }
                span class="mono" { (format_date(*exp)) }
                span class="muted" { " (" (days) "d)" }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

/// The emails on `denied`, normalised — every page that marks one needs this set.
fn denied_set(doc: &AccessFile) -> Vec<String> {
    doc.denied.iter().map(|d| norm_email(d)).collect()
}

/// Whether a scope grants nothing: absent, empty, or nothing but blank entries (which
/// `compile_access` drops).
fn scope_is_empty(urls: Option<&Vec<String>>) -> bool {
    urls.is_none_or(|l| l.iter().all(|u| u.trim().is_empty()))
}

/// `/` — the counts, what expires next, and everything the file says that an operator would
/// rather hear now than at 3am.
///
/// The warnings are computed from library data only ([`url_group_refs`], the scopes, the
/// `denied` list). `bb-auth-adm check`'s site-shadowing lint deliberately stays in the CLI:
/// it is a heuristic with an operator to explain itself to, and duplicating it here would
/// mean two implementations of a judgement call.
fn page_dashboard(v: &View, doc: &AccessFile) -> Markup {
    let n = now();
    let key_count: usize = doc.users.iter().map(|u| u.api_keys.len()).sum();

    // Every key in the file, soonest expiry first.
    let mut keys: Vec<(String, &ApiKeySpec, Expiry)> = doc
        .users
        .iter()
        .flat_map(|u| {
            u.api_keys
                .iter()
                .map(move |k| (norm_email(&u.email), k, expiry_of(k, n)))
        })
        .collect();
    keys.sort_by_key(|(_, _, e)| e.rank());

    let denied = denied_set(doc);
    let mut warnings: Vec<Markup> = Vec::new();
    for u in &doc.users {
        if scope_is_empty(u.authorized_urls.as_ref()) {
            let email = norm_email(&u.email);
            warnings.push(html! { code { (email) } " " (v.t(K::WarnNoScope)) });
        }
    }
    for name in doc.url_groups.keys() {
        if url_group_refs(doc, name).is_empty() {
            warnings.push(html! { code { "@" (name) } " " (v.t(K::ReferencedByNothing)) });
        }
    }
    for u in &doc.users {
        let email = norm_email(&u.email);
        if denied.contains(&email) {
            warnings.push(html! { code { (email) } " " (v.t(K::WarnEnrolledAndDenied)) });
        }
    }

    html! {
        h1 { (v.t(K::Dashboard)) }
        p class="lede" { code { (v.cfg.access_path) } }

        h2 { (v.t(K::Counts)) }
        div class="cards" {
            @for (label, count) in [
                ("users", doc.users.len()),
                ("api_keys", key_count),
                ("sites", doc.sites.len()),
                ("url_groups", doc.url_groups.len()),
                ("denied", doc.denied.len()),
            ] {
                div class="card" {
                    div class="n" { (count) }
                    div class="l mono" { (label) }
                }
            }
        }

        h2 { (v.t(K::KeyExpiry)) }
        div class="panel" {
            @if keys.is_empty() {
                span class="muted" { (v.t(K::None)) }
            } @else {
                table {
                    thead { tr {
                        th { (v.t(K::ColOwner)) }
                        th { "id" }
                        th { (v.t(K::ColExpiry)) }
                    } }
                    tbody {
                        @for (email, k, e) in &keys {
                            tr {
                                td { a href=(v.href(&Route::User(email.clone()))) { (email) } }
                                td class="mono" { (k.id.trim()) }
                                td { (expiry_markup(v.lang, e)) }
                            }
                        }
                    }
                }
            }
        }

        h2 { (v.t(K::Warnings)) }
        div class="panel" {
            @if warnings.is_empty() {
                span class="muted" { (v.t(K::NoWarnings)) }
            } @else {
                ul class="plain" { @for w in &warnings { li { (*w) } } }
            }
        }
    }
}

/// `/users` — the roster.
fn page_users(v: &View, doc: &AccessFile) -> Markup {
    let denied = denied_set(doc);
    html! {
        h1 { "users" }
        p class="lede" { (v.t(K::UsersIntro)) }
        p { (act(v, &Route::UserAdd, &format!("+ {}", v.t(K::Add)))) }
        div class="panel" {
            @if doc.users.is_empty() {
                span class="muted" { (v.t(K::None)) }
            } @else {
                table {
                    thead { tr {
                        th { "email" }
                        th { "authorized_urls" }
                        th { "api_keys" }
                        th {}
                    } }
                    tbody {
                        @for u in &doc.users {
                            @let email = norm_email(&u.email);
                            tr {
                                td {
                                    a href=(v.href(&Route::User(email.clone()))) { (email) }
                                    @if denied.contains(&email) {
                                        " " (tag("bad", "denied"))
                                    }
                                }
                                // Raw entries, so an `@group` reference counts as the one
                                // line it is in the file.
                                td {
                                    @if scope_is_empty(u.authorized_urls.as_ref()) {
                                        span class="bad" { (v.t(K::ReachesNothing)) }
                                    } @else {
                                        (u.authorized_urls.as_ref().map_or(0, Vec::len))
                                    }
                                }
                                td { (u.api_keys.len()) }
                                td class="rowacts" {
                                    (act(v, &Route::UserEdit(email.clone()), v.t(K::Edit)))
                                    (act(v, &Route::UserRm(email.clone()), v.t(K::Remove)))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// `/users/{email}` — one roster row, as the file stores it.
fn page_user(v: &View, doc: &AccessFile, email: &str) -> (u16, Markup) {
    let u: &UserSpec = match user_pos(doc, email).map(|i| &doc.users[i]) {
        Some(u) => u,
        None => {
            return (
                404,
                page_missing(v, v.t(K::NoSuchUser), email, &Route::Users),
            )
        }
    };
    let n = now();
    let normalised = norm_email(&u.email);
    let denied = denied_set(doc).contains(&normalised);
    let notes = u.extra.get("notes").and_then(|n| n.as_str());

    (
        200,
        html! {
            h1 {
                (normalised)
                @if denied { " " (tag("bad", "denied")) }
            }
            p class="lede" {
                a href=(v.href(&Route::Users)) { "← " (v.t(K::Back)) }
            }
            p class="rowacts" {
                (act(v, &Route::UserEdit(normalised.clone()), v.t(K::Edit)))
                (act(v, &Route::UserRm(normalised.clone()), v.t(K::Remove)))
            }

            @if let Some(notes) = notes {
                div class="panel" { span class="muted mono" { "notes " } (notes) }
            }

            h2 { "authorized_urls" }
            div class="panel" {
                (url_list(v.lang, u.authorized_urls.as_ref(), t(v.lang, K::ReachesNothing)))
            }

            h2 { "api_keys" }
            p { (act(v, &Route::KeyAdd(normalised.clone()), &format!("+ {}", v.t(K::Add)))) }
            div class="panel" {
                @if u.api_keys.is_empty() {
                    span class="muted" { (v.t(K::None)) }
                } @else {
                    table {
                        thead { tr {
                            th { "id" }
                            th { "released" }
                            th { "duration" }
                            th { (v.t(K::ColExpiry)) }
                            th { "authorized_urls" }
                            th {}
                        } }
                        tbody {
                            @for k in &u.api_keys {
                                @let id = k.id.trim().to_string();
                                tr {
                                    td class="mono" { (id) }
                                    td class="mono" { (k.released.trim()) }
                                    td class="mono" { (k.duration.trim()) }
                                    td { (expiry_markup(v.lang, &expiry_of(k, n))) }
                                    td {
                                        (url_list(
                                            v.lang,
                                            k.authorized_urls.as_ref(),
                                            t(v.lang, K::Inherits),
                                        ))
                                    }
                                    td class="rowacts" {
                                        (act(v, &Route::KeyEdit(normalised.clone(), id.clone()),
                                             v.t(K::Edit)))
                                        (act(v, &Route::KeyRotate(normalised.clone(), id.clone()),
                                             v.t(K::Rotate)))
                                        (act(v, &Route::KeyRm(normalised.clone(), id.clone()),
                                             v.t(K::Remove)))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

/// `/groups` — each `url_groups` entry and everything that names it.
fn page_groups(v: &View, doc: &AccessFile) -> Markup {
    html! {
        h1 { "url_groups" }
        p class="lede" { (v.t(K::GroupsIntro)) }
        p { (act(v, &Route::GroupAdd, &format!("+ {}", v.t(K::Add)))) }
        @if doc.url_groups.is_empty() {
            div class="panel" { span class="muted" { (v.t(K::None)) } }
        } @else {
            @for (name, urls) in &doc.url_groups {
                @let refs = url_group_refs(doc, name);
                div class="panel" {
                    h2 style="margin-top:0" {
                        code { "@" (name) }
                        " "
                        span class="rowacts" style="display:inline-flex;font-size:.8rem" {
                            (act(v, &Route::GroupEdit(name.clone()), v.t(K::Edit)))
                            (act(v, &Route::GroupRm(name.clone()), v.t(K::Remove)))
                        }
                    }
                    p class="muted" {
                        @if refs.is_empty() {
                            (v.t(K::ReferencedByNothing))
                        } @else {
                            (v.t(K::ReferencedBy)) " "
                            @for (i, r) in refs.iter().enumerate() {
                                @if i > 0 { ", " }
                                code { (r) }
                            }
                        }
                    }
                    p class="muted" { (v.t(K::Patterns)) }
                    ul class="plain mono" { @for u in urls { li { (u) } } }
                }
            }
        }
    }
}

/// `/sites` — the site table, **numbered, in file order**.
///
/// An ordered list and not a grid, because the number *is* the meaning: `Sites::resolve` is
/// first-match-wins, so position 1 shadows position 2 for any URL both cover. A layout that
/// let the eye wander would be hiding the one property this section has.
fn page_sites(v: &View, doc: &AccessFile) -> Markup {
    let last = doc.sites.len().saturating_sub(1);
    html! {
        h1 { "sites" }
        p class="lede" { (v.t(K::SitesIntro)) }
        p { (act(v, &Route::SiteAdd, &format!("+ {}", v.t(K::Add)))) }
        div class="panel" {
            @if doc.sites.is_empty() {
                span class="muted" { (v.t(K::None)) }
            } @else {
                ol class="sites" {
                    @for (i, s) in doc.sites.iter().enumerate() {
                        li { (site_block(v, s, i, last)) }
                    }
                }
            }
        }
    }
}

/// One `POST` button that moves a site one place. Order is meaning — `Sites::resolve` is
/// first-match-wins — so this is a mutation like any other: same `rev`, same audit line,
/// and a `303` back to this page. It is a button and not a link because a `GET` never
/// mutates, and it is per row because two buttons beat a position field an operator has to
/// count out.
fn move_button(
    v: &View,
    name: &str,
    dir: &str,
    label: &str,
    glyph: &str,
    disabled: bool,
) -> Markup {
    html! {
        form method="post" action=(v.href(&Route::SiteMove(name.to_string()))) {
            input type="hidden" name="rev" value=(v.rev);
            input type="hidden" name="dir" value=(dir);
            button type="submit" class="mv" title=(label) disabled[disabled] { (glyph) }
        }
    }
}

fn site_block(v: &View, s: &SiteSpec, i: usize, last: usize) -> Markup {
    let name = site_name(s);
    html! {
        div {
            strong { (name) }
            " "
            @if s.public_auth {
                (tag("warn", "public_auth"))
            } @else {
                (tag("", "public_auth: false"))
            }
            " "
            span class="rowacts" style="display:inline-flex" {
                (act(v, &Route::SiteEdit(name.clone()), v.t(K::Edit)))
                (act(v, &Route::SiteRm(name.clone()), v.t(K::Remove)))
                (move_button(v, &name, "up", v.t(K::MoveUp), "↑", i == 0))
                (move_button(v, &name, "down", v.t(K::MoveDown), "↓", i >= last))
            }
        }
        @if let Some(l) = &s.login_url {
            div class="muted" { "login_url " span class="mono" { (l) } }
        }
        @if s.urls.is_empty() {
            div class="bad" { "urls: [] — " (v.t(K::ReachesNothing)) }
        } @else {
            ul class="plain mono" { @for u in &s.urls { li { (u) } } }
        }
    }
}

/// `/denied` — the veto list.
fn page_denied(v: &View, doc: &AccessFile) -> Markup {
    html! {
        h1 { "denied" }
        p class="lede" { (v.t(K::DeniedIntro)) }
        p { (act(v, &Route::DenyAdd, &format!("+ {}", v.t(K::Add)))) }
        div class="panel" {
            @if doc.denied.is_empty() {
                span class="muted" { (v.t(K::None)) }
            } @else {
                ul class="plain" {
                    @for d in &doc.denied {
                        @let email = norm_email(d);
                        li class="rowacts" {
                            code { (email) }
                            @if user_pos(doc, &email).is_some() {
                                a href=(v.href(&Route::User(email.clone()))) {
                                    (tag("", t(v.lang, K::AlsoEnrolled)))
                                }
                            }
                            (act(v, &Route::DenyRm(email.clone()), v.t(K::Remove)))
                        }
                    }
                }
            }
        }
    }
}

/// `/can` — the tester. A `GET` form, and the gate's own [`decide`] behind it.
///
/// Only the two Cognito-backed credentials are asked about here: an id_token bearer and a
/// session cookie resolve to nothing but an email, which is exactly what the form collects.
/// (`bb-auth-adm can --key ID` also evaluates a `bbk_` key. It stays on the terminal for
/// now: naming a key means picking one, which is a second field and a listing, and a key's
/// verdict is one `bb-auth-adm` invocation away on the host that has the file.)
fn page_can(v: &View, access: &Access, query: &str) -> Markup {
    let email_in = query_param(query, "email").unwrap_or_default();
    let url_in = query_param(query, "url").unwrap_or_default();
    let asked = !email_in.trim().is_empty() && !url_in.trim().is_empty();
    let email = norm_email(&email_in);
    let url = request_url(&url_in);

    html! {
        h1 { "can" }
        p class="lede" { (v.t(K::CanIntro)) }
        div class="panel" {
            form class="can" method="get" action=(v.href(&Route::Can)) {
                label {
                    "email"
                    input type="text" name="email" value=(email_in)
                          placeholder="bob@x.com" autocapitalize="off" spellcheck="false";
                }
                label {
                    "url"
                    input type="text" name="url" value=(url_in)
                          placeholder="https://app.x.com/reports" autocapitalize="off"
                          spellcheck="false";
                }
                // Keep the language across a submit: the form replaces the whole query.
                input type="hidden" name="lang" value=(v.lang.code());
                button type="submit" { (v.t(K::Submit)) }
            }
        }
        @if asked {
            div class="panel" { (verdict(v, access, &email, &url)) }
        }
    }
}

/// One verdict, with the reason the gate would have. The wording follows `bb-auth-adm can`'s
/// — same decision, same explanation, so an operator who has read one recognises the other.
fn verdict(v: &View, access: &Access, email: &str, url: &str) -> Markup {
    let decision = decide(access, email, Some(url));
    html! {
        p class=@if decision.granted() { "verdict yes" } @else { "verdict no" } {
            @if decision.granted() { (v.t(K::Authorized)) } @else { (v.t(K::VerdictDenied)) }
        }
        p {
            @match &decision {
                Decision::SiteGrant(site) => {
                    "site " code { (site) } " " (v.t(K::WhySiteGrant))
                }
                Decision::RosterGrant => { code { (email) } " " (v.t(K::WhyRosterGrant)) }
                Decision::Vetoed => { code { (email) } " " (v.t(K::WhyVetoed)) }
                Decision::OutOfScope => { code { (url) } " " (v.t(K::WhyOutOfScope)) }
                Decision::NotEnrolled => { code { (email) } " " (v.t(K::WhyNotEnrolled)) }
            }
        }
        @if decision.granted() {
            p class="muted" {
                (v.t(K::AppSees)) " " code { (IDENTITY_HEADER) ": " (email) }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Editing pages
// ---------------------------------------------------------------------------
//
// One struct and one page function per form. The struct is what the fields hold, and it is
// filled from two places — the access file, when the form is first rendered, and the
// submitted body, when a refusal sends the same form back. That is what "the submitted
// values are preserved" is: the same page function, one error string later.

/// The `users` form: an address and a scope.
#[derive(Default)]
struct UserForm {
    email: String,
    urls: String,
}

impl UserForm {
    fn of(u: &UserSpec) -> UserForm {
        UserForm {
            email: norm_email(&u.email),
            urls: urls_text(u.authorized_urls.as_ref()),
        }
    }
    fn read(f: &Form) -> UserForm {
        UserForm {
            email: f.get("email").to_string(),
            urls: f.get("urls").to_string(),
        }
    }
}

/// `users · add` and `users · edit`. One form for both: the difference is whether the
/// address names a row that already exists, which is also the difference between
/// [`add_user`] and [`rename_user`].
///
/// A user's scope has no absent-vs-empty distinction to express — absent and empty both
/// deny — so it is a plain textarea, and an emptied one collapses to absent.
fn page_user_form(v: &View, existing: Option<&str>, f: &UserForm, err: Option<&str>) -> Markup {
    let editing = existing.is_some();
    html! {
        h1 { "users · " (if editing { v.t(K::Edit) } else { v.t(K::Add) }) }
        @if let Some(e) = existing { p class="lede" { code { (e) } } }
        div class="panel" {
            (form_shell(v, err, html! {
                (text_field(
                    if editing { v.t(K::NewEmail) } else { "email" },
                    "email", &f.email, "bob@x.com", None))
                (urls_field("authorized_urls", "urls", &f.urls, html! {
                    (v.t(K::ScopeHelp)) " " (v.t(K::ScopeEmptyMeans)) " " code { "*://*/*" } "."
                }))
            }, if editing { v.t(K::Save) } else { v.t(K::Create) }, false))
        }
    }
}

/// The `api_keys` form: a label, a window, and a scope that may be its own or the user's.
#[derive(Default)]
struct KeyForm {
    id: String,
    duration: String,
    /// `true` = this key carries its own `authorized_urls`; `false` = the field is absent
    /// and the key inherits the user's. Two different things in the file, so two radios.
    own: bool,
    urls: String,
}

impl KeyForm {
    fn of(k: &ApiKeySpec) -> KeyForm {
        KeyForm {
            id: k.id.trim().to_string(),
            duration: k.duration.trim().to_string(),
            own: k.authorized_urls.is_some(),
            urls: urls_text(k.authorized_urls.as_ref()),
        }
    }
    fn read(f: &Form) -> KeyForm {
        KeyForm {
            id: f.get("id").to_string(),
            duration: f.get("duration").to_string(),
            own: f.get("scope") == "own",
            urls: f.get("urls").to_string(),
        }
    }
    /// The field as the file spells it: `None` is *absent* (inherit), `Some(vec![])` is a
    /// present-but-empty own scope, which denies. Collapsing the two would quietly hand a
    /// key its owner's access.
    fn scope(&self, lines: Vec<String>) -> Option<Vec<String>> {
        if self.own {
            Some(lines)
        } else {
            None
        }
    }
}

/// `api_keys · add` / `· edit`. `released` is not editable: on an add it is today, and on an
/// edit it is what the file says — a key's issue date is a fact about a secret that exists,
/// not a setting. (`bb-auth-adm key set --released` is there for a repair; a GUI that
/// offered it would mostly be a way to move an expiry by accident.)
fn page_key_form(
    v: &View,
    owner: &str,
    existing: Option<&str>,
    released: &str,
    f: &KeyForm,
    err: Option<&str>,
) -> Markup {
    let editing = existing.is_some();
    html! {
        h1 { (owner) " · api_keys · " (if editing { v.t(K::Edit) } else { v.t(K::Add) }) }
        @if let Some(id) = existing { p class="lede" { code { (id) } } }
        div class="panel" {
            (form_shell(v, err, html! {
                @if !editing {
                    (text_field("id", "id", &f.id, "laptop", None))
                }
                (text_field("duration", "duration", &f.duration, "365d",
                            Some("<n>d · <n>h · never")))
                label {
                    span class="lbl" { "released" }
                    span class="mono" { (released) }
                }
                div {
                    span class="lbl" { "authorized_urls" }
                    label class="radio" {
                        input type="radio" name="scope" value="inherit" checked[!f.own];
                        span { (v.t(K::KeyScopeInherit)) }
                    }
                    label class="radio" {
                        input type="radio" name="scope" value="own" checked[f.own];
                        span { (v.t(K::KeyScopeOwn)) }
                    }
                }
                (urls_field("", "urls", &f.urls, html! {
                    (v.t(K::ScopeHelp)) " " (v.t(K::KeyScopeOwnEmpty))
                }))
            }, if editing { v.t(K::Save) } else { v.t(K::Create) }, false))
        }
    }
}

/// The `sites` form. There is no field here that names a user, and there never may be one:
/// a site describes a **place**, and grants to named users live in `users[].authorized_urls`
/// alone.
#[derive(Default)]
struct SiteForm {
    name: String,
    urls: String,
    public_auth: bool,
    login_url: String,
}

impl SiteForm {
    fn of(s: &SiteSpec) -> SiteForm {
        SiteForm {
            name: site_name(s),
            urls: s.urls.join("\n"),
            public_auth: s.public_auth,
            login_url: s.login_url.clone().unwrap_or_default(),
        }
    }
    fn read(f: &Form) -> SiteForm {
        SiteForm {
            name: f.get("name").to_string(),
            urls: f.get("urls").to_string(),
            public_auth: f.checked("public_auth"),
            login_url: f.get("login_url").to_string(),
        }
    }
}

fn page_site_form(v: &View, existing: Option<&str>, f: &SiteForm, err: Option<&str>) -> Markup {
    let editing = existing.is_some();
    html! {
        h1 { "sites · " (if editing { v.t(K::Edit) } else { v.t(K::Add) }) }
        @if let Some(n) = existing { p class="lede" { code { (n) } } }
        div class="panel" {
            (form_shell(v, err, html! {
                (text_field(if editing { v.t(K::NewName) } else { "name" },
                            "name", &f.name, "app1", None))
                (urls_field("urls", "urls", &f.urls, html! { (v.t(K::SiteUrlsHelp)) }))
                label class="radio" {
                    input type="checkbox" name="public_auth" value="on" checked[f.public_auth];
                    span { "public_auth" " — " (v.t(K::PublicAuthWarn)) }
                }
                (text_field("login_url", "login_url", &f.login_url, "https://login.x.com/", None))
            }, if editing { v.t(K::Save) } else { v.t(K::Create) }, false))
        }
    }
}

/// The `url_groups` form — a name and its patterns.
#[derive(Default)]
struct GroupForm {
    name: String,
    urls: String,
}

impl GroupForm {
    fn read(f: &Form) -> GroupForm {
        GroupForm {
            name: f.get("name").to_string(),
            urls: f.get("urls").to_string(),
        }
    }
}

fn page_group_form(v: &View, existing: Option<&str>, f: &GroupForm, err: Option<&str>) -> Markup {
    let editing = existing.is_some();
    html! {
        h1 { "url_groups · " (if editing { v.t(K::Edit) } else { v.t(K::Add) }) }
        @if let Some(n) = existing { p class="lede" { code { "@" (n) } } }
        div class="panel" {
            (form_shell(v, err, html! {
                // No rename: the library refuses to have one, and says why.
                @if editing {
                    p class="muted" { (v.t(K::GroupNoRename)) }
                } @else {
                    (text_field("name", "name", &f.name, "mcp", None))
                }
                (urls_field("urls", "urls", &f.urls, html! { (v.t(K::GroupUrlsHelp)) }))
            }, if editing { v.t(K::Save) } else { v.t(K::Create) }, false))
        }
    }
}

/// The `denied` form — one address, and the veto that outranks every grant.
#[derive(Default)]
struct DenyForm {
    email: String,
}

impl DenyForm {
    fn read(f: &Form) -> DenyForm {
        DenyForm {
            email: f.get("email").to_string(),
        }
    }
}

fn page_deny_form(v: &View, f: &DenyForm, err: Option<&str>) -> Markup {
    html! {
        h1 { "denied · " (v.t(K::Add)) }
        p class="lede" { (v.t(K::DeniedIntro)) }
        div class="panel" {
            (form_shell(v, err, html! {
                (text_field("email", "email", &f.email, "spammer@x.com", None))
            }, v.t(K::Create), false))
        }
    }
}

/// The page a mint answers with — and the one place a `bbk_` bearer is ever rendered.
///
/// Rendered **directly**, not after a redirect: a `303` would put the result behind a fresh
/// `GET` that has no bearer to show, and the bearer exists nowhere else — the file keeps
/// only its sha256. It is not logged and never travels in a URL.
fn page_minted(v: &View, owner: &str, id: &str, bearer: &str) -> Markup {
    html! {
        h1 { (owner) " · api_keys · " (id) }
        div class="secret" {
            div { strong { (v.t(K::BearerHeading)) } }
            p { (v.t(K::BearerOnce)) }
            code { "Authorization: Bearer " (bearer) }
        }
        p { a href=(v.href(&Route::User(owner.to_string()))) { "← " (v.t(K::Back)) } }
    }
}

/// The `409`: the file moved under the form. Nothing was written, and the way out is a
/// fresh read of what the file says now.
fn page_conflict(v: &View) -> Markup {
    // A `POST`-only route has no form to reload, so it goes back to its section.
    let back = match &v.at {
        Route::SiteMove(_) => v.at.parent(),
        other => other.clone(),
    };
    html! {
        h1 { (v.t(K::ConflictTitle)) }
        div class="panel" {
            p { (v.t(K::ConflictBody)) }
            p { a href=(v.href(&back)) { "← " (v.t(K::ConflictBack)) } }
        }
    }
}

/// A page that is only a message: the `401`, the `403`, the `404`, the `405` and the
/// broken-file page. Content only — the caller wraps it in [`shell`], as it does any page.
fn notice(title: &str, body: Markup) -> Markup {
    html! {
        h1 { (title) }
        div class="panel" { (body) }
    }
}

/// The page for an access file the gate would refuse. The library's message goes out
/// **verbatim** — it is the same sentence `bb-auth --check-users` and a failed startup
/// print, and an operator who can match those three is an operator who can fix the file.
fn page_file_error(v: &View, err: &str) -> Markup {
    notice(
        v.t(K::FileErrorTitle),
        html! {
            p class="mono bad" { (err) }
            p class="muted" { (v.t(K::FileErrorHint)) }
        },
    )
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

/// What a `POST` came to: either it happened, and the browser is sent to the page it
/// belongs to, or there is a page to render right here.
enum Outcome {
    /// POST-redirect-GET: `303` to this route with `?msg=`, so a reload cannot repeat it.
    Done(Route, Msg),
    /// A form re-rendered with a refusal, the `409`, or the one page that carries a freshly
    /// minted bearer and therefore cannot be behind a redirect.
    Page(u16, &'static str, Markup),
}

/// One line per successful mutation, on stderr, in the shape the gate logs in.
///
/// The acting administrator, the verb spelled as `bb-auth-adm` spells the equivalent
/// command, and the target's name. Never a bearer, never a `key_hash`, and no submitted
/// value beyond the name of the thing that changed — a scope full of URLs is in the file,
/// and the file keeps a `.bak` of what it was.
fn audit(admin: &str, verb: &str, target: &str) {
    eprintln!("[bb-auth-web] {admin}: {verb} {target}");
}

/// Check the edit with the gate's own parser, write it, and log the line.
///
/// [`AccessWrite`] is the only door: `prepare` compiles the exact bytes, `commit` writes the
/// bytes it compiled. An `Err` is the library's own sentence and means the file on disk was
/// not touched — which is what every error path in [`mutate`] relies on.
fn commit(v: &View, doc: &AccessFile, verb: &str, target: &str) -> Result<Written, String> {
    let written = AccessWrite::prepare(doc)?.commit(&v.cfg.access_path)?;
    audit(v.admin.unwrap_or("?"), verb, target);
    Ok(written)
}

/// Apply one `POST`.
///
/// Three things happen before any mutation is even looked at, and they are the load-bearing
/// order:
///
/// 1. the access file is re-read, and its sha256 must equal the `rev` the form carries —
///    otherwise the file moved under the form (a `bb-auth-adm` over SSH, another tab) and
///    this is a `409` that writes nothing;
/// 2. the document is opened with [`open_access_file`], which refuses to start from a file
///    the gate would reject — an edit must begin from a file that works;
/// 3. only then does the arm for this route run, and every one of them ends in [`commit`].
///
/// (1) and (2) are two reads of the same file, so a writer landing exactly between them is
/// still not seen — the same window `bb-auth-adm` has had all along, since nothing here
/// locks. What the `rev` removes is the interesting case, the one measured in minutes: a
/// form loaded, read, thought about, and submitted onto a file that has since moved.
///
/// A refusal — from a form's own check or from the library — re-renders the very form that
/// caused it, with the submitted values still in the fields and the message verbatim. On
/// every one of those paths nothing has been written: `prepare` fails before `commit`, and
/// `commit` is atomic.
///
/// The status for a refused submission is `400`, and a failed write is reported the same
/// way. From the browser's side the two say the same thing — nothing happened, here is the
/// sentence that says why — and the sentence itself is what distinguishes them.
fn mutate(v: &View, form: &Form) -> Outcome {
    let path = &v.cfg.access_path;
    let title = v.at.title();

    // (1) The file as it is right now, byte for byte.
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("read {path}: {e}");
            return Outcome::Page(500, title, page_file_error(v, &msg));
        }
    };
    if form.get("rev").trim() != sha256_hex(&raw) {
        return Outcome::Page(409, title, page_conflict(v));
    }

    // (2) And as the gate would read it. A file that does not compile is not a file to edit.
    let (mut doc, _) = match open_access_file(path) {
        Ok(pair) => pair,
        Err(e) => return Outcome::Page(500, title, page_file_error(v, &e)),
    };

    // (3) The mutation itself. Each arm: read the form, ask the library, write, say where
    // the browser goes — or hand the refusal back to the form it came from.
    match &v.at {
        Route::UserAdd => {
            let f = UserForm::read(form);
            let r = (|| -> Result<String, String> {
                let email = norm_email(&f.email);
                if email.is_empty() {
                    return Err(v.t(K::EmailRequired).to_string());
                }
                let urls = form.lines("urls");
                add_user(
                    &mut doc,
                    UserSpec {
                        email: email.clone(),
                        authorized_urls: if urls.is_empty() { None } else { Some(urls) },
                        ..Default::default()
                    },
                )?;
                commit(v, &doc, "user add", &email)?;
                Ok(email)
            })();
            match r {
                Ok(email) => Outcome::Done(Route::User(email), Msg::UserAdded),
                Err(e) => Outcome::Page(400, title, page_user_form(v, None, &f, Some(&e))),
            }
        }

        Route::UserEdit(target) => {
            let f = UserForm::read(form);
            let r = (|| -> Result<String, String> {
                let email = norm_email(&f.email);
                if email.is_empty() {
                    return Err(v.t(K::EmailRequired).to_string());
                }
                rename_user(&mut doc, target, &email)?;
                let u = user_mut(&mut doc, &email)?;
                // A user's scope has no "inherit": an emptied list collapses to absent, and
                // both mean the same thing — reaches nothing.
                let urls = form.lines("urls");
                let clear = urls.is_empty();
                edit_urls(&mut u.authorized_urls, urls, Vec::new(), Vec::new(), clear);
                commit(v, &doc, "user set", &email)?;
                Ok(email)
            })();
            match r {
                Ok(email) => Outcome::Done(Route::User(email), Msg::UserSaved),
                Err(e) => Outcome::Page(400, title, page_user_form(v, Some(target), &f, Some(&e))),
            }
        }

        Route::UserRm(target) => {
            let r = (|| -> Result<(), String> {
                let u = remove_user(&mut doc, target)?;
                commit(v, &doc, "user rm", &norm_email(&u.email))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Users, Msg::UserRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { "users · " (v.t(K::Remove)) },
                        html! { p { code { (norm_email(target)) } } },
                        v.t(K::ConfirmUserRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::KeyAdd(owner) => {
            let f = KeyForm::read(form);
            // Today, and not a field: a key's issue date is a fact about a secret that is
            // being created right now.
            let released = format_date(now());
            let r = (|| -> Result<(String, String), String> {
                let id = f.id.trim().to_string();
                if id.is_empty() {
                    return Err(v.t(K::KeyIdRequired).to_string());
                }
                let duration = f.duration.trim().to_string();
                // Fail before minting: a key the file would reject is a secret handed out
                // for nothing.
                if key_expiry(&released, &duration).is_none() {
                    return Err(v.t(K::BadKeyWindow).to_string());
                }
                let sealed: SealedKey = add_api_key(
                    &mut doc,
                    owner,
                    ApiKeySpec {
                        id: id.clone(),
                        released: released.clone(),
                        duration,
                        authorized_urls: f.scope(form.lines("urls")),
                        ..Default::default()
                    },
                )?;
                // The bearer opens only against the receipt of a completed write, so this
                // order is the library's and not a convention this file could get wrong.
                let written = commit(v, &doc, "key add", &format!("{}/{id}", norm_email(owner)))?;
                Ok((id, sealed.reveal(&written)))
            })();
            match r {
                Ok((id, bearer)) => {
                    Outcome::Page(200, title, page_minted(v, &norm_email(owner), &id, &bearer))
                }
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_key_form(v, &norm_email(owner), None, &released, &f, Some(&e)),
                ),
            }
        }

        Route::KeyEdit(owner, id) => {
            let f = KeyForm::read(form);
            let released = key_mut(&mut doc, owner, id)
                .map(|k| k.released.trim().to_string())
                .unwrap_or_default();
            let r = (|| -> Result<(), String> {
                let k = key_mut(&mut doc, owner, id)?;
                k.duration = f.duration.trim().to_string();
                if key_expiry(&k.released, &k.duration).is_none() {
                    return Err(v.t(K::BadKeyWindow).to_string());
                }
                // Absent vs present-and-empty is the whole point of the radio: absent
                // inherits the owner's scope, empty is an own scope that reaches nothing.
                k.authorized_urls = f.scope(form.lines("urls"));
                commit(v, &doc, "key set", &format!("{}/{id}", norm_email(owner)))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::User(norm_email(owner)), Msg::KeySaved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_key_form(v, &norm_email(owner), Some(id), &released, &f, Some(&e)),
                ),
            }
        }

        Route::KeyRotate(owner, id) => {
            let r = (|| -> Result<String, String> {
                let sealed = rotate_api_key(&mut doc, owner, id)?;
                let written = commit(
                    v,
                    &doc,
                    "key rotate",
                    &format!("{}/{id}", norm_email(owner)),
                )?;
                Ok(sealed.reveal(&written))
            })();
            match r {
                Ok(bearer) => {
                    Outcome::Page(200, title, page_minted(v, &norm_email(owner), id, &bearer))
                }
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (norm_email(owner)) " · api_keys · " (v.t(K::Rotate)) },
                        html! { p { code { (id) } } },
                        v.t(K::ConfirmKeyRotate),
                        v.t(K::Rotate),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::KeyRm(owner, id) => {
            let r = (|| -> Result<(), String> {
                remove_api_key(&mut doc, owner, id)?;
                commit(v, &doc, "key rm", &format!("{}/{id}", norm_email(owner)))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::User(norm_email(owner)), Msg::KeyRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { (norm_email(owner)) " · api_keys · " (v.t(K::Remove)) },
                        html! { p { code { (id) } } },
                        v.t(K::ConfirmKeyRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::SiteAdd => {
            let f = SiteForm::read(form);
            let r = (|| -> Result<(), String> {
                let name = f.name.trim().to_string();
                add_site(&mut doc, site_spec(&f, form.lines("urls")), None)?;
                commit(v, &doc, "site add", &name)?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Sites, Msg::SiteAdded),
                Err(e) => Outcome::Page(400, title, page_site_form(v, None, &f, Some(&e))),
            }
        }

        Route::SiteEdit(target) => {
            let f = SiteForm::read(form);
            let r = (|| -> Result<(), String> {
                let name = f.name.trim().to_string();
                if name.is_empty() {
                    return Err(v.t(K::NameRequired).to_string());
                }
                // The rename first, then the record is addressed by the name it now has.
                rename_site(&mut doc, target, &name)?;
                let i =
                    site_pos(&doc, &name).ok_or_else(|| format!("no site '{}'", target.trim()))?;
                let spec = site_spec(&f, form.lines("urls"));
                doc.sites[i] = spec;
                commit(v, &doc, "site set", &name)?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Sites, Msg::SiteSaved),
                Err(e) => Outcome::Page(400, title, page_site_form(v, Some(target), &f, Some(&e))),
            }
        }

        Route::SiteMove(target) => {
            let r = (|| -> Result<(), String> {
                let i =
                    site_pos(&doc, target).ok_or_else(|| format!("no site '{}'", target.trim()))?;
                let to = match form.get("dir") {
                    "up" => i.checked_sub(1),
                    "down" => Some(i + 1).filter(|j| *j < doc.sites.len()),
                    _ => None,
                };
                // A move off either end is not an error, it is a button that was already
                // disabled: nothing changes, and nothing is written.
                if let Some(to) = to {
                    move_site(&mut doc, i, to);
                    commit(v, &doc, "site mv", &format!("{} --at {to}", target.trim()))?;
                }
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Sites, Msg::SiteMoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    notice(v.t(K::NotFoundTitle), html! { p { (e) } }),
                ),
            }
        }

        Route::SiteRm(target) => {
            let r = (|| -> Result<(), String> {
                let s = remove_site(&mut doc, target)?;
                commit(v, &doc, "site rm", &site_name(&s))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Sites, Msg::SiteRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { "sites · " (v.t(K::Remove)) },
                        html! { p { code { (target) } } },
                        v.t(K::ConfirmSiteRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::GroupAdd => {
            let f = GroupForm::read(form);
            let r = (|| -> Result<(), String> {
                let name = f.name.trim().to_string();
                add_url_group(&mut doc, &name, form.lines("urls"))?;
                commit(v, &doc, "url-group add", &format!("@{name}"))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Groups, Msg::GroupAdded),
                Err(e) => Outcome::Page(400, title, page_group_form(v, None, &f, Some(&e))),
            }
        }

        Route::GroupEdit(target) => {
            let f = GroupForm::read(form);
            let r = (|| -> Result<(), String> {
                // No rename: a reference names a group by its exact spelling, so the
                // library does not offer one and neither does this form.
                *url_group_mut(&mut doc, target)? = form.lines("urls");
                commit(v, &doc, "url-group set", &format!("@{}", target.trim()))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Groups, Msg::GroupSaved),
                Err(e) => Outcome::Page(400, title, page_group_form(v, Some(target), &f, Some(&e))),
            }
        }

        Route::GroupRm(target) => {
            let r = (|| -> Result<(), String> {
                // The library refuses while anything still references the group, and its
                // refusal names every referrer — which is the list of places to go and fix.
                remove_url_group(&mut doc, target)?;
                commit(v, &doc, "url-group rm", &format!("@{}", target.trim()))?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Groups, Msg::GroupRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { "url_groups · " (v.t(K::Remove)) },
                        html! { p { code { "@" (target) } } },
                        v.t(K::ConfirmGroupRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        Route::DenyAdd => {
            let f = DenyForm::read(form);
            let r = (|| -> Result<(), String> {
                let email = norm_email(&f.email);
                if email.is_empty() {
                    return Err(v.t(K::EmailRequired).to_string());
                }
                if !add_denied(&mut doc, &email) {
                    return Err(v.t(K::AlreadyDenied).to_string());
                }
                commit(v, &doc, "deny add", &email)?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Denied, Msg::DeniedAdded),
                Err(e) => Outcome::Page(400, title, page_deny_form(v, &f, Some(&e))),
            }
        }

        Route::DenyRm(target) => {
            let email = norm_email(target);
            let r = (|| -> Result<(), String> {
                if remove_denied(&mut doc, std::slice::from_ref(&email)) == 0 {
                    return Err(v.t(K::NoSuchDenied).to_string());
                }
                commit(v, &doc, "deny rm", &email)?;
                Ok(())
            })();
            match r {
                Ok(()) => Outcome::Done(Route::Denied, Msg::DeniedRemoved),
                Err(e) => Outcome::Page(
                    400,
                    title,
                    page_confirm(
                        v,
                        html! { "denied · " (v.t(K::Remove)) },
                        html! { p { code { (email) } } },
                        v.t(K::ConfirmDenyRm),
                        v.t(K::Remove),
                        Some(&e),
                    ),
                ),
            }
        }

        // Everything else is a page, and a page does not take a POST.
        _ => Outcome::Page(
            405,
            title,
            notice(
                v.t(K::NotAllowedTitle),
                html! { p { (v.t(K::NotAllowedBody)) } },
            ),
        ),
    }
}

/// The record a site form describes. `login_url` is absent when the field is blank —
/// absent means "use `BB_AUTH_LOGIN_URL`", and an empty string would be a malformed URL
/// the gate refuses.
fn site_spec(f: &SiteForm, urls: Vec<String>) -> SiteSpec {
    SiteSpec {
        name: f.name.trim().to_string(),
        urls,
        public_auth: f.public_auth,
        login_url: match f.login_url.trim() {
            "" => None,
            l => Some(l.to_string()),
        },
    }
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

/// Serve one request: identify, authorize, route, then either render or mutate.
///
/// The order is the point. Identity and the admin allowlist come **before** the router and
/// before the file is opened, so there is no path — not a 404, not a `POST`, not a broken
/// access file — that answers anything to someone nginx did not vouch for. The two guards
/// are route-global and method-blind by construction: they are here, above everything.
fn handle(mut req: Request, cfg: &Config) {
    let target = req.url().to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let posting = *req.method() == Method::Post;
    let lang = negotiate_lang(
        query_param(&query, "lang").as_deref(),
        header_value(&req, "Cookie").and_then(|c| cookie_value(c, LANG_COOKIE)),
        header_value(&req, "Accept-Language"),
        cfg.default_lang,
    );
    // Nothing is routed yet, so the language switch on an error page points at the root.
    let anon = |at: Route| View {
        cfg,
        lang,
        admin: None,
        at,
        query: "",
        rev: "",
        msg: None,
    };

    // Identity comes from nginx and from nowhere else. A missing header is a broken
    // deployment, not an anonymous visitor — say so, and fail closed.
    let raw_email = match header_value(&req, IDENTITY_HEADER) {
        Some(e) if !e.trim().is_empty() => e.to_string(),
        _ => {
            let v = anon(Route::Dashboard);
            let page = notice(
                v.t(K::NoIdentityTitle),
                html! { p { (v.t(K::NoIdentityBody)) } },
            );
            respond_page(req, 401, shell(&v, v.t(K::NoIdentityTitle), page));
            return;
        }
    };
    let email = norm_email(&raw_email);
    if !cfg.is_admin(&email) {
        let v = anon(Route::Dashboard);
        let page = notice(
            v.t(K::NotAdminTitle),
            html! { p { code { (email) } " " (v.t(K::NotAdminBody)) } },
        );
        respond_page(req, 403, shell(&v, v.t(K::NotAdminTitle), page));
        return;
    }

    let at = match route(&path, &cfg.base_path) {
        Some(r) => r,
        None => {
            let v = View {
                cfg,
                lang,
                admin: Some(&email),
                at: Route::Dashboard,
                query: "",
                rev: "",
                msg: None,
            };
            let page = notice(
                v.t(K::NotFoundTitle),
                html! { p { (v.t(K::NotFoundBody)) } },
            );
            respond_page(req, 404, shell(&v, v.t(K::NotFoundTitle), page));
            return;
        }
    };

    // ----- POST: the mutating half -----------------------------------------
    if posting {
        // Same-origin or nothing, and before the body is even read.
        let allowed = csrf_ok(
            header_value(&req, "Sec-Fetch-Site"),
            header_value(&req, "Origin"),
            header_value(&req, "Host"),
        );
        let v = View {
            cfg,
            lang,
            admin: Some(&email),
            at: at.clone(),
            query: "",
            rev: "",
            msg: None,
        };
        if !allowed {
            let page = notice(v.t(K::CsrfTitle), html! { p { (v.t(K::CsrfBody)) } });
            respond_page(req, 403, shell(&v, v.t(K::CsrfTitle), page));
            return;
        }
        let form = Form::parse(&read_body(&mut req));
        match mutate(&v, &form) {
            Outcome::Done(to, msg) => {
                let location = format!("{}{}?msg={}", cfg.base_path, to.path(), msg.key());
                respond_redirect(req, &location);
            }
            Outcome::Page(status, title, content) => {
                respond_page(req, status, shell(&v, title, content))
            }
        }
        return;
    }

    // ----- GET: the rendering half -----------------------------------------

    // An explicit `?lang=` is a choice: remember it, then send the browser to the same page
    // without the parameter, so a bookmark or a reload does not carry it around forever.
    // The rest of the query survives, which is what keeps a `can` result on screen.
    if query_param(&query, "lang")
        .and_then(|l| parse_lang(&l))
        .is_some()
    {
        respond_lang_redirect(req, &lang_href(cfg, &at, &query, None), lang);
        return;
    }

    // Fresh off disk, every request, and hashed: `rev` is what every form on this page will
    // carry, and what the `POST` that comes back has to still match.
    let raw = std::fs::read_to_string(&cfg.access_path).unwrap_or_default();
    let rev = sha256_hex(&raw);
    let v = View {
        cfg,
        lang,
        admin: Some(&email),
        at: at.clone(),
        query: &query,
        rev: &rev,
        msg: query_param(&query, "msg").as_deref().and_then(Msg::parse),
    };

    let (doc, access) = match open_access_file(&cfg.access_path) {
        Ok(pair) => pair,
        Err(e) => {
            respond_page(
                req,
                500,
                shell(&v, v.t(K::FileErrorTitle), page_file_error(&v, &e)),
            );
            return;
        }
    };

    let title = at.title();
    let (status, content, title) = match &at {
        Route::Dashboard => (200, page_dashboard(&v, &doc), v.t(K::Dashboard)),
        Route::Groups => (200, page_groups(&v, &doc), title),
        Route::Sites => (200, page_sites(&v, &doc), title),
        Route::Denied => (200, page_denied(&v, &doc), title),
        Route::Users => (200, page_users(&v, &doc), title),
        Route::User(e) => {
            let (status, content) = page_user(&v, &doc, e);
            (status, content, title)
        }
        Route::Can => (200, page_can(&v, &access, &query), title),

        Route::UserAdd => (
            200,
            page_user_form(&v, None, &UserForm::default(), None),
            title,
        ),
        Route::UserEdit(e) => match user_pos(&doc, e) {
            Some(i) => {
                let f = UserForm::of(&doc.users[i]);
                let email = norm_email(&doc.users[i].email);
                (200, page_user_form(&v, Some(&email), &f, None), title)
            }
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchUser), e, &Route::Users),
                title,
            ),
        },
        Route::UserRm(e) => match user_pos(&doc, e) {
            Some(i) => {
                let u = &doc.users[i];
                let email = norm_email(&u.email);
                let keys = u.api_keys.len();
                (
                    200,
                    page_confirm(
                        &v,
                        html! { "users · " (v.t(K::Remove)) },
                        html! {
                            p { code { (email) } }
                            @if keys > 0 {
                                p class="muted" { (keys) " api_keys" }
                            }
                        },
                        v.t(K::ConfirmUserRm),
                        v.t(K::Remove),
                        None,
                    ),
                    title,
                )
            }
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchUser), e, &Route::Users),
                title,
            ),
        },
        Route::KeyAdd(e) => match user_pos(&doc, e) {
            Some(i) => {
                let owner = norm_email(&doc.users[i].email);
                let f = KeyForm {
                    duration: "365d".to_string(),
                    ..Default::default()
                };
                (
                    200,
                    page_key_form(&v, &owner, None, &format_date(now()), &f, None),
                    title,
                )
            }
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchUser), e, &Route::Users),
                title,
            ),
        },
        Route::KeyEdit(e, id) => match find_key(&doc, e, id) {
            Some((owner, k)) => (
                200,
                page_key_form(
                    &v,
                    &owner,
                    Some(id),
                    k.released.trim(),
                    &KeyForm::of(k),
                    None,
                ),
                title,
            ),
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchKey), id, &Route::User(norm_email(e))),
                title,
            ),
        },
        Route::KeyRotate(e, id) => match find_key(&doc, e, id) {
            Some((owner, _)) => (
                200,
                page_confirm(
                    &v,
                    html! { (owner) " · api_keys · " (v.t(K::Rotate)) },
                    html! { p { code { (id) } } },
                    v.t(K::ConfirmKeyRotate),
                    v.t(K::Rotate),
                    None,
                ),
                title,
            ),
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchKey), id, &Route::User(norm_email(e))),
                title,
            ),
        },
        Route::KeyRm(e, id) => match find_key(&doc, e, id) {
            Some((owner, _)) => (
                200,
                page_confirm(
                    &v,
                    html! { (owner) " · api_keys · " (v.t(K::Remove)) },
                    html! { p { code { (id) } } },
                    v.t(K::ConfirmKeyRm),
                    v.t(K::Remove),
                    None,
                ),
                title,
            ),
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchKey), id, &Route::User(norm_email(e))),
                title,
            ),
        },

        Route::SiteAdd => (
            200,
            page_site_form(&v, None, &SiteForm::default(), None),
            title,
        ),
        Route::SiteEdit(n) => match site_pos(&doc, n) {
            Some(i) => {
                let f = SiteForm::of(&doc.sites[i]);
                let name = site_name(&doc.sites[i]);
                (200, page_site_form(&v, Some(&name), &f, None), title)
            }
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchSite), n, &Route::Sites),
                title,
            ),
        },
        Route::SiteRm(n) => match site_pos(&doc, n) {
            Some(i) => {
                let s = &doc.sites[i];
                (
                    200,
                    page_confirm(
                        &v,
                        html! { "sites · " (v.t(K::Remove)) },
                        html! {
                            p { code { (site_name(s)) } }
                            @if s.public_auth { p { (tag("warn", "public_auth")) } }
                        },
                        v.t(K::ConfirmSiteRm),
                        v.t(K::Remove),
                        None,
                    ),
                    title,
                )
            }
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchSite), n, &Route::Sites),
                title,
            ),
        },
        // A button, not a page: there is nothing to render for it, and a GET must not move
        // a site any more than it may delete a user.
        Route::SiteMove(_) => (
            405,
            notice(
                v.t(K::NotAllowedTitle),
                html! { p { (v.t(K::NotAllowedBody)) } },
            ),
            title,
        ),

        Route::GroupAdd => (
            200,
            page_group_form(&v, None, &GroupForm::default(), None),
            title,
        ),
        Route::GroupEdit(n) => match doc.url_groups.get(n.trim()) {
            Some(urls) => {
                let f = GroupForm {
                    name: n.trim().to_string(),
                    urls: urls.join("\n"),
                };
                (200, page_group_form(&v, Some(n.trim()), &f, None), title)
            }
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchGroup), n, &Route::Groups),
                title,
            ),
        },
        Route::GroupRm(n) => match doc.url_groups.get(n.trim()) {
            Some(_) => (
                200,
                page_confirm(
                    &v,
                    html! { "url_groups · " (v.t(K::Remove)) },
                    html! {
                        p { code { "@" (n.trim()) } }
                        @let refs = url_group_refs(&doc, n.trim());
                        @if !refs.is_empty() {
                            p class="muted" {
                                (v.t(K::ReferencedBy)) " "
                                @for (i, r) in refs.iter().enumerate() {
                                    @if i > 0 { ", " }
                                    code { (r) }
                                }
                            }
                        }
                    },
                    v.t(K::ConfirmGroupRm),
                    v.t(K::Remove),
                    None,
                ),
                title,
            ),
            None => (
                404,
                page_missing(&v, v.t(K::NoSuchGroup), n, &Route::Groups),
                title,
            ),
        },

        Route::DenyAdd => (200, page_deny_form(&v, &DenyForm::default(), None), title),
        Route::DenyRm(e) => {
            let email = norm_email(e);
            if doc.denied.iter().any(|d| norm_email(d) == email) {
                (
                    200,
                    page_confirm(
                        &v,
                        html! { "denied · " (v.t(K::Remove)) },
                        html! { p { code { (email) } } },
                        v.t(K::ConfirmDenyRm),
                        v.t(K::Remove),
                        None,
                    ),
                    title,
                )
            } else {
                (
                    404,
                    page_missing(&v, v.t(K::NoSuchDenied), &email, &Route::Denied),
                    title,
                )
            }
        }
    };
    respond_page(req, status, shell(&v, title, content));
}

/// One user's key, by owner and id — what a key form and its two confirmations need before
/// there is anything to render. The owner comes back normalised, as every page spells it.
fn find_key<'a>(doc: &'a AccessFile, email: &str, id: &str) -> Option<(String, &'a ApiKeySpec)> {
    let i = user_pos(doc, email)?;
    let u = &doc.users[i];
    let k = u.api_keys.iter().find(|k| k.id.trim() == id.trim())?;
    Some((norm_email(&u.email), k))
}

/// Read the config, bind, and serve forever on a fixed pool of blocking threads — the gate's
/// shape, minus everything the gate needs and this does not.
fn main() {
    let cfg = Config::from_env();

    // Read once at startup so a broken file is heard about immediately, and so the banner
    // can say what is in it. Not fatal: the GUI's job is to *show* a broken file.
    match open_access_file(&cfg.access_path) {
        Ok((doc, _)) => eprintln!(
            "[bb-auth-web] {}: {} users, {} sites, {} url_groups, {} denied",
            cfg.access_path,
            doc.users.len(),
            doc.sites.len(),
            doc.url_groups.len(),
            doc.denied.len()
        ),
        Err(e) => eprintln!("[bb-auth-web] WARNING: {e}"),
    }

    let server = Server::http(&cfg.listen).unwrap_or_else(|e| {
        eprintln!("[bb-auth-web] FATAL: cannot bind {}: {e}", cfg.listen);
        std::process::exit(1);
    });
    let base = if cfg.base_path.is_empty() {
        "/".to_string()
    } else {
        cfg.base_path.clone()
    };
    eprintln!(
        "[bb-auth-web] listening on {} | file={} | admins={} | base={base} | lang={}",
        cfg.listen,
        cfg.access_path,
        cfg.admins.len(),
        cfg.default_lang.code()
    );
    eprintln!(
        "[bb-auth-web] identity comes from the {IDENTITY_HEADER} header — this port must be \
         reachable ONLY through nginx, behind bb-auth's own auth_request"
    );
    eprintln!(
        "[bb-auth-web] this instance WRITES {} — every edit is validated with the gate's own \
         parser first, and goes live on: systemctl reload bb-auth",
        cfg.access_path
    );

    let server = std::sync::Arc::new(server);
    let cfg = std::sync::Arc::new(cfg);
    let mut handles = Vec::new();
    for _ in 0..WORKERS {
        let server = std::sync::Arc::clone(&server);
        let cfg = std::sync::Arc::clone(&cfg);
        handles.push(std::thread::spawn(move || loop {
            match server.recv() {
                Ok(req) => handle(req, &cfg),
                Err(e) => eprintln!("[bb-auth-web] recv error: {e}"),
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A file with one of everything, so a rendering test has something to render.
    const SAMPLE: &str = r#"{
      "url_groups": { "mcp": ["https://mcp.x.com/mcp/*"], "unused": ["https://old.x.com/*"] },
      "sites": [
        { "name": "onboarding", "urls": ["https://app.x.com/hello/*"], "public_auth": true }
      ],
      "denied": ["spammer@x.com"],
      "users": [
        { "email": "Bob@X.com", "authorized_urls": ["@mcp"], "notes": "the bot",
          "api_keys": [ { "id": "laptop",
            "key_hash": "1111111111111111111111111111111111111111111111111111111111111111",
            "released": "1970-01-01", "duration": "1d" } ] },
        { "email": "nowhere@x.com" }
      ]
    }"#;

    /// Two sites, so a reorder has somewhere to go.
    const TWO_SITES: &str = r#"{
      "sites": [
        { "name": "first", "urls": ["https://app.x.com/a/*"], "public_auth": false },
        { "name": "second", "urls": ["https://app.x.com/b/*"], "public_auth": true }
      ],
      "users": [ { "email": "bob@x.com", "authorized_urls": ["https://app.x.com/*"] } ]
    }"#;

    fn cfg_for(path: &str, base: &str) -> Config {
        Config {
            listen: String::new(),
            access_path: path.to_string(),
            admins: vec!["admin@x.com".to_string()],
            base_path: base.to_string(),
            default_lang: Lang::En,
        }
    }

    /// Write `json` to a uniquely-named temp file so tests can run in parallel.
    fn scratch(name: &str, json: &str) -> String {
        let p = std::env::temp_dir().join(format!("bb-auth-web-{name}.json"));
        std::fs::write(&p, json).unwrap();
        p.to_string_lossy().into_owned()
    }

    /// The scratch file and the backup a write leaves beside it.
    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.bak"));
    }

    fn read(path: &str) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    /// The fingerprint a form rendered from this file would carry.
    fn rev_of(path: &str) -> String {
        sha256_hex(&read(path))
    }

    fn body_of(fields: &[(&str, &str)]) -> String {
        let mut ser = form_urlencoded::Serializer::new(String::new());
        for (k, v) in fields {
            ser.append_pair(k, v);
        }
        ser.finish()
    }

    /// What a `POST` came to, as a test wants to read it.
    #[derive(Debug)]
    enum Got {
        /// The `Location:` a `303` would carry, base path and `?msg=` included.
        Redirect(String),
        /// A status and the whole rendered page.
        Page(u16, String),
    }

    impl Got {
        fn page(&self) -> (u16, &str) {
            match self {
                Got::Page(s, h) => (*s, h.as_str()),
                Got::Redirect(l) => panic!("expected a page, got a redirect to {l}"),
            }
        }
        fn location(&self) -> &str {
            match self {
                Got::Redirect(l) => l.as_str(),
                Got::Page(s, _) => panic!("expected a redirect, got a {s} page"),
            }
        }
    }

    /// Drive one `POST` exactly as [`handle`] does, minus the HTTP: parse the body, build
    /// the view, call [`mutate`], and turn the outcome into what a browser would see.
    fn post(cfg: &Config, at: Route, fields: &[(&str, &str)]) -> Got {
        let v = view(cfg, at, "");
        let form = Form::parse(&body_of(fields));
        match mutate(&v, &form) {
            Outcome::Done(to, msg) => {
                Got::Redirect(format!("{}{}?msg={}", cfg.base_path, to.path(), msg.key()))
            }
            Outcome::Page(status, title, content) => {
                Got::Page(status, shell(&v, title, content).into_string())
            }
        }
    }

    /// The `rev` a rendered page's forms carry, lifted out the way a browser would.
    fn rev_in(html: &str) -> String {
        const NEEDLE: &str = "name=\"rev\" value=\"";
        let at = html.find(NEEDLE).expect("a form carrying a rev");
        html[at + NEEDLE.len()..]
            .split('"')
            .next()
            .unwrap()
            .to_string()
    }

    // --- config -------------------------------------------------------------

    #[test]
    fn compile_admins_trims_lowercases_and_dedupes() {
        assert_eq!(
            compile_admins("  Alice@X.com , bob@x.com ,, ALICE@x.com ,").unwrap(),
            vec!["alice@x.com".to_string(), "bob@x.com".to_string()]
        );
        assert_eq!(compile_admins("one@x.com").unwrap(), vec!["one@x.com"]);
    }

    #[test]
    fn compile_admins_rejects_an_empty_list() {
        // Empty must never mean "everyone" — it is the whole point of the allowlist.
        for spec in ["", "   ", ",", " , , "] {
            assert!(compile_admins(spec).is_err(), "{spec:?} must be rejected");
        }
    }

    #[test]
    fn normalize_base_path_normalizes_and_rejects() {
        assert_eq!(normalize_base_path("").unwrap(), "");
        assert_eq!(normalize_base_path("  ").unwrap(), "");
        assert_eq!(normalize_base_path("/").unwrap(), "");
        assert_eq!(normalize_base_path("/admin").unwrap(), "/admin");
        assert_eq!(normalize_base_path("admin").unwrap(), "/admin");
        assert_eq!(normalize_base_path("/admin/").unwrap(), "/admin");
        assert_eq!(normalize_base_path(" /a/b// ").unwrap(), "/a/b");
        // It reaches a Location: header, so the same reflex as compile_login_url.
        assert!(normalize_base_path("/a b").is_err());
        assert!(normalize_base_path("/a\r\nX: 1").is_err());
        assert!(normalize_base_path("/a?b").is_err());
        assert!(normalize_base_path("/a#b").is_err());
    }

    #[test]
    fn parse_lang_accepts_only_the_two() {
        assert_eq!(parse_lang("en"), Some(Lang::En));
        assert_eq!(parse_lang(" IT "), Some(Lang::It));
        assert_eq!(parse_lang("fr"), None);
        assert_eq!(parse_lang(""), None);
    }

    // --- routing ------------------------------------------------------------

    #[test]
    fn route_without_a_base_path() {
        assert_eq!(route("/", ""), Some(Route::Dashboard));
        assert_eq!(route("", ""), Some(Route::Dashboard));
        assert_eq!(route("/users", ""), Some(Route::Users));
        assert_eq!(route("/users/", ""), Some(Route::Users));
        assert_eq!(route("/groups", ""), Some(Route::Groups));
        assert_eq!(route("/sites", ""), Some(Route::Sites));
        assert_eq!(route("/denied", ""), Some(Route::Denied));
        assert_eq!(route("/can", ""), Some(Route::Can));
        assert_eq!(route("/nope", ""), None);
        assert_eq!(route("/users/a/b", ""), None);
    }

    #[test]
    fn route_strips_the_base_path_and_404s_outside_it() {
        assert_eq!(route("/admin", "/admin"), Some(Route::Dashboard));
        assert_eq!(route("/admin/", "/admin"), Some(Route::Dashboard));
        assert_eq!(route("/admin/users", "/admin"), Some(Route::Users));
        // Outside the prefix, and the near-misses that a plain `starts_with` would admit.
        assert_eq!(route("/users", "/admin"), None);
        assert_eq!(route("/administrivia", "/admin"), None);
        assert_eq!(route("/adminusers", "/admin"), None);
        assert_eq!(route("/", "/admin"), None);
    }

    #[test]
    fn route_decodes_the_email_segment() {
        assert_eq!(
            route("/users/a%2Btag%40x.com", ""),
            Some(Route::User("a+tag@x.com".to_string()))
        );
    }

    #[test]
    fn email_path_segment_round_trips() {
        // A `+` is a literal plus, not a space — which is why this is not form_urlencoded.
        for email in [
            "bob@x.com",
            "a+tag@sub.example.co.uk",
            "n.o'brien@x.com",
            "béatrice@x.com",
            "<script>alert(1)</script>@x.com",
            "a b@x.com",
        ] {
            let enc = pct_encode_segment(email);
            assert!(
                enc.bytes().all(|b| b.is_ascii_graphic()),
                "{enc} must be printable ASCII"
            );
            assert!(!enc.contains('/'), "{enc} must stay one path segment");
            assert_eq!(pct_decode(&enc), email);
            assert_eq!(
                route(&format!("/users/{enc}"), ""),
                Some(Route::User(email.to_string()))
            );
        }
    }

    #[test]
    fn route_path_is_the_href_and_survives_a_hostile_email() {
        let r = Route::User("<script>@x.com".to_string());
        assert_eq!(r.path(), "/users/%3Cscript%3E%40x.com");
        assert_eq!(r.tab(), Route::Users);
    }

    // --- language -----------------------------------------------------------

    #[test]
    fn negotiate_lang_prefers_query_then_cookie_then_header_then_default() {
        // query beats everything
        assert_eq!(
            negotiate_lang(Some("it"), Some("en"), Some("en-GB"), Lang::En),
            Lang::It
        );
        // cookie beats the header
        assert_eq!(
            negotiate_lang(None, Some("it"), Some("en-GB"), Lang::En),
            Lang::It
        );
        // header beats the default
        assert_eq!(
            negotiate_lang(None, None, Some("it-IT,it;q=0.9"), Lang::En),
            Lang::It
        );
        // and the default is the floor
        assert_eq!(
            negotiate_lang(None, None, Some("de-DE"), Lang::En),
            Lang::En
        );
        assert_eq!(negotiate_lang(None, None, None, Lang::It), Lang::It);
        // an unparseable preference is not a preference
        assert_eq!(
            negotiate_lang(Some("fr"), Some("it"), None, Lang::En),
            Lang::It
        );
    }

    #[test]
    fn lang_href_swaps_the_parameter_and_keeps_the_rest() {
        let cfg = cfg_for("x.json", "/admin");
        let q = "email=bob%40x.com&lang=en";
        assert_eq!(
            lang_href(&cfg, &Route::Can, q, Some(Lang::It)),
            "/admin/can?email=bob%40x.com&lang=it"
        );
        assert_eq!(
            lang_href(&cfg, &Route::Can, q, None),
            "/admin/can?email=bob%40x.com"
        );
        assert_eq!(lang_href(&cfg, &Route::Dashboard, "", None), "/admin/");
    }

    #[test]
    fn lang_href_never_carries_client_bytes_verbatim() {
        // Everything a client sent is re-encoded, so this string is safe in a Location:.
        let cfg = cfg_for("x.json", "");
        let href = lang_href(&cfg, &Route::Can, "url=https://x/%0d%0aX:+1&lang=it", None);
        assert!(href.bytes().all(|b| b.is_ascii_graphic()), "{href}");
        assert!(!href.contains('\r') && !href.contains('\n'));
    }

    #[test]
    fn cookie_value_parses_the_language_cookie() {
        assert_eq!(cookie_value("lang=it", LANG_COOKIE), Some("it"));
        assert_eq!(cookie_value("a=1; lang=en; b=2", LANG_COOKIE), Some("en"));
        assert_eq!(cookie_value("mylang=it", LANG_COOKIE), None);
        assert_eq!(cookie_value("a=1", LANG_COOKIE), None);
    }

    // --- rendering ----------------------------------------------------------

    /// A view over `cfg` at `at`, as a request would build one.
    fn view<'a>(cfg: &'a Config, at: Route, rev: &'a str) -> View<'a> {
        View {
            cfg,
            lang: Lang::En,
            admin: Some("admin@x.com"),
            at,
            query: "",
            rev,
            msg: None,
        }
    }

    /// Render one read-only page of `SAMPLE` and hand back the HTML.
    fn render(name: &str, at: Route) -> String {
        let path = scratch(name, SAMPLE);
        let cfg = cfg_for(&path, "");
        let (doc, access) = open_access_file(&cfg.access_path).unwrap();
        let v = view(&cfg, at.clone(), "REV");
        let content = match &at {
            Route::Dashboard => page_dashboard(&v, &doc),
            Route::Groups => page_groups(&v, &doc),
            Route::Sites => page_sites(&v, &doc),
            Route::Denied => page_denied(&v, &doc),
            Route::Users => page_users(&v, &doc),
            Route::User(e) => page_user(&v, &doc, e).1,
            Route::Can => page_can(&v, &access, "email=bob@x.com&url=https://mcp.x.com/mcp/a"),
            other => panic!("{other:?} is not a read-only page"),
        };
        let html = shell(&v, "t", content).into_string();
        let _ = std::fs::remove_file(&path);
        html
    }

    #[test]
    fn dashboard_counts_expiries_and_warnings() {
        let html = render("dash", Route::Dashboard);
        assert!(html.contains("url_groups"));
        // the 1970 key is long past
        assert!(html.contains("expired"), "{html}");
        // a scope-less user, an unreferenced group
        assert!(html.contains("no authorized_urls"));
        assert!(html.contains("@unused"));
        assert!(html.contains("referenced by nothing"));
    }

    #[test]
    fn user_page_shows_group_refs_raw_and_never_expanded() {
        let html = render("user", Route::User("bob@x.com".to_string()));
        assert!(html.contains("@mcp"), "the reference is shown as stored");
        assert!(
            !html.contains("https://mcp.x.com/mcp/*"),
            "a group must never be expanded on the page"
        );
        assert!(html.contains("the bot"), "notes come from extra");
        assert!(
            html.contains("inherits the user's"),
            "the key declares no scope"
        );
    }

    #[test]
    fn sites_page_is_numbered_in_file_order() {
        let html = render("sites", Route::Sites);
        assert!(
            html.contains("<ol"),
            "order is meaning, so it is an ordered list"
        );
        assert!(html.contains("onboarding") && html.contains("public_auth"));
    }

    #[test]
    fn can_page_renders_the_gates_own_verdict() {
        let html = render("can", Route::Can);
        assert!(html.contains("AUTHORIZED"), "{html}");
        assert!(html.contains("X-Auth-Email"));
    }

    #[test]
    fn groups_page_names_who_references_a_group() {
        let html = render("groups", Route::Groups);
        assert!(html.contains("referenced by"));
        assert!(html.contains("bob@x.com"));
    }

    #[test]
    fn denied_page_marks_the_enrolled() {
        let html = render("denied", Route::Denied);
        assert!(html.contains("spammer@x.com"));
    }

    #[test]
    fn hostile_values_from_the_file_come_out_escaped() {
        // The access file is operator-owned, but it is also a text file that anything with
        // root can write, and half of it ends up in a page. maud escapes on the way in;
        // this pins that it stays that way.
        let json = r#"{ "users": [ { "email": "<script>alert(1)</script>@x.com",
                          "authorized_urls": ["https://x.com/\"><img src=x onerror=alert(1)>/*"],
                          "notes": "<b>bold</b>" } ] }"#;
        let path = scratch("xss", json);
        let cfg = cfg_for(&path, "");
        let (doc, _) = open_access_file(&cfg.access_path).unwrap();
        let v = view(&cfg, Route::Users, "REV");
        let email = "<script>alert(1)</script>@x.com";
        for html in [
            shell(&v, "t", page_users(&v, &doc)).into_string(),
            shell(&v, "t", page_user(&v, &doc, email).1).into_string(),
        ] {
            assert!(
                html.contains("&lt;script&gt;alert(1)&lt;/script&gt;@x.com"),
                "{html}"
            );
            assert!(!html.contains("<script>alert(1)"), "{html}");
            assert!(!html.contains("<img src=x"), "{html}");
            assert!(!html.contains("<b>bold</b>"), "{html}");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_broken_file_renders_the_librarys_message_verbatim() {
        let path = scratch(
            "broken",
            r#"{ "users": [ { "email": "b@x", "authorized_urls": ["@nope"] } ] }"#,
        );
        let cfg = cfg_for(&path, "");
        // `Access` has no `Debug` on purpose (a table of live credentials), so no unwrap_err.
        let err = match open_access_file(&cfg.access_path) {
            Ok(_) => panic!("a dangling @group reference must be refused"),
            Err(e) => e,
        };
        let v = view(&cfg, Route::Dashboard, "REV");
        let html = page_file_error(&v, &err).into_string();
        assert!(
            html.contains("the gate would reject this file as it stands"),
            "{html}"
        );
        assert!(html.contains("unknown url group"), "{html}");
        let _ = std::fs::remove_file(&path);
    }

    // --- mutations ----------------------------------------------------------

    #[test]
    fn csrf_accepts_only_a_same_origin_submission() {
        // Sec-Fetch-Site is the whole answer where the browser sends it.
        assert!(csrf_ok(Some("same-origin"), None, None));
        assert!(csrf_ok(Some(" Same-Origin "), None, None));
        for bad in ["cross-site", "same-site", "none", ""] {
            assert!(!csrf_ok(Some(bad), None, None), "{bad:?} must be refused");
        }
        // A hostile Origin does not rescue a cross-site Sec-Fetch-Site.
        assert!(!csrf_ok(
            Some("cross-site"),
            Some("https://x.com"),
            Some("x.com")
        ));
        // Origin is the fallback, and only the host is compared — the scheme cannot be,
        // since this binary speaks http behind a TLS-terminating nginx.
        assert!(csrf_ok(
            None,
            Some("https://admin.x.com"),
            Some("admin.x.com")
        ));
        assert!(csrf_ok(
            None,
            Some("http://admin.x.com:8091"),
            Some("admin.x.com:8091")
        ));
        assert!(!csrf_ok(
            None,
            Some("https://evil.com"),
            Some("admin.x.com")
        ));
        assert!(!csrf_ok(None, Some("null"), Some("admin.x.com")));
        // Neither header is not a browser posting a form.
        assert!(!csrf_ok(None, None, Some("admin.x.com")));
        assert!(!csrf_ok(None, None, None));
    }

    #[test]
    fn a_user_add_writes_through_and_redirects() {
        let path = scratch("m-useradd", SAMPLE);
        let cfg = cfg_for(&path, "");
        let got = post(
            &cfg,
            Route::UserAdd,
            &[
                ("rev", &rev_of(&path)),
                ("email", " New@X.com "),
                ("urls", "https://app.x.com/*\n\n  @mcp  \n"),
            ],
        );
        assert_eq!(got.location(), "/users/new%40x.com?msg=user-added");
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        let u = &doc.users[doc.users.len() - 1];
        assert_eq!(
            u.email, "new@x.com",
            "the email is normalised on the way in"
        );
        assert_eq!(
            u.authorized_urls.as_deref().unwrap(),
            ["https://app.x.com/*", "@mcp"],
            "lines are trimmed, blanks dropped, @refs kept literal"
        );
        cleanup(&path);
    }

    #[test]
    fn a_rev_mismatch_is_a_409_and_writes_nothing() {
        let path = scratch("m-rev", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(
            &cfg,
            Route::UserAdd,
            &[
                (
                    "rev",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                ),
                ("email", "new@x.com"),
                ("urls", "*://*/*"),
            ],
        );
        let (status, html) = got.page();
        assert_eq!(status, 409);
        assert!(html.contains("The file changed"), "{html}");
        assert_eq!(read(&path), before, "nothing may be written on a conflict");
        // A form with no rev at all is the same refusal, not a bypass.
        let got = post(&cfg, Route::UserAdd, &[("email", "new@x.com")]);
        assert_eq!(got.page().0, 409);
        assert_eq!(read(&path), before);
        cleanup(&path);
    }

    #[test]
    fn a_refused_edit_re_renders_the_form_with_the_librarys_words() {
        let path = scratch("m-refused", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(
            &cfg,
            Route::UserEdit("bob@x.com".to_string()),
            &[
                ("rev", &rev_of(&path)),
                ("email", "bob@x.com"),
                ("urls", "@nope"),
            ],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        // Verbatim, in the English the CLI says it in.
        assert!(html.contains("refusing to write"), "{html}");
        assert!(html.contains("unknown url group '@nope'"), "{html}");
        // And the submitted values are still in the fields.
        assert!(html.contains("@nope</textarea>"), "{html}");
        assert!(html.contains("value=\"bob@x.com\""), "{html}");
        assert_eq!(read(&path), before, "a refusal writes nothing");
        cleanup(&path);
    }

    #[test]
    fn hostile_submitted_values_come_back_escaped() {
        let path = scratch("m-hostile", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(
            &cfg,
            Route::UserAdd,
            &[
                ("rev", &rev_of(&path)),
                ("email", "<script>alert(1)</script>@x.com"),
                ("urls", "@nope\n\"><img src=x onerror=alert(1)>"),
            ],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;@x.com"),
            "{html}"
        );
        assert!(!html.contains("<script>alert(1)"), "{html}");
        assert!(!html.contains("<img src=x"), "{html}");
        assert_eq!(read(&path), before);
        cleanup(&path);
    }

    #[test]
    fn minting_shows_the_bearer_once_and_files_only_its_hash() {
        let path = scratch("m-mint", SAMPLE);
        let cfg = cfg_for(&path, "");
        let stale = rev_of(&path);
        let got = post(
            &cfg,
            Route::KeyAdd("bob@x.com".to_string()),
            &[
                ("rev", &stale),
                ("id", "ci"),
                ("duration", "365d"),
                ("scope", "inherit"),
            ],
        );
        let (status, html) = got.page();
        assert_eq!(
            status, 200,
            "a mint renders its result, it does not redirect"
        );
        let bearer = html
            .split("Authorization: Bearer ")
            .nth(1)
            .and_then(|r| r.split('<').next())
            .expect("the bearer, once")
            .to_string();
        assert!(bearer.starts_with("bbk_"), "{bearer}");
        assert!(html.contains("stored nowhere"), "{html}");

        // The file carries the hash and never the bearer.
        let on_disk = read(&path);
        assert!(on_disk.contains(&sha256_hex(&bearer)), "the hash is filed");
        assert!(!on_disk.contains(&bearer), "the raw key is never stored");
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        let k = &doc.users[0].api_keys;
        assert_eq!(k.len(), 2);
        assert!(
            k[1].authorized_urls.is_none(),
            "'inherit' is the field being absent"
        );

        // A re-submitted form cannot double-mint: the write moved the file, so the rev the
        // browser still holds is stale.
        let replay = post(
            &cfg,
            Route::KeyAdd("bob@x.com".to_string()),
            &[
                ("rev", &stale),
                ("id", "ci2"),
                ("duration", "365d"),
                ("scope", "inherit"),
            ],
        );
        assert_eq!(replay.page().0, 409);
        assert_eq!(read(&path), on_disk, "the replay wrote nothing");
        cleanup(&path);
    }

    #[test]
    fn a_key_scope_is_inherited_or_its_own_and_empty_is_not_absent() {
        let path = scratch("m-keyscope", SAMPLE);
        let cfg = cfg_for(&path, "");
        let key = || Route::KeyEdit("bob@x.com".to_string(), "laptop".to_string());
        let scope = || {
            bb_auth_core::read_access_file(&path).unwrap().users[0].api_keys[0]
                .authorized_urls
                .clone()
        };
        assert_eq!(scope(), None, "the sample key inherits");

        // "own scope" with an empty textarea is a present, empty list: it denies.
        let got = post(
            &cfg,
            key(),
            &[
                ("rev", &rev_of(&path)),
                ("duration", "1d"),
                ("scope", "own"),
                ("urls", "   \n  "),
            ],
        );
        assert_eq!(got.location(), "/users/bob%40x.com?msg=key-saved");
        assert_eq!(scope(), Some(Vec::new()));

        // And back: "inherit" is the field being absent, not an empty one.
        let got = post(
            &cfg,
            key(),
            &[
                ("rev", &rev_of(&path)),
                ("duration", "1d"),
                ("scope", "inherit"),
                ("urls", "https://x.com/*"),
            ],
        );
        assert_eq!(got.location(), "/users/bob%40x.com?msg=key-saved");
        assert_eq!(scope(), None, "inherit drops the field, textarea and all");
        cleanup(&path);
    }

    #[test]
    fn a_bad_key_window_is_refused_before_anything_is_minted() {
        let path = scratch("m-window", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(
            &cfg,
            Route::KeyAdd("bob@x.com".to_string()),
            &[
                ("rev", &rev_of(&path)),
                ("id", "ci"),
                ("duration", "forever"),
                ("scope", "inherit"),
            ],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        assert!(html.contains("not a valid window"), "{html}");
        assert!(!html.contains("bbk_"), "no secret is handed out: {html}");
        assert_eq!(read(&path), before);
        // The same for a key with no id.
        let got = post(
            &cfg,
            Route::KeyAdd("bob@x.com".to_string()),
            &[("rev", &rev_of(&path)), ("id", "  "), ("duration", "365d")],
        );
        assert!(got.page().1.contains("a key needs an id"));
        assert_eq!(read(&path), before);
        cleanup(&path);
    }

    #[test]
    fn removing_a_referenced_url_group_is_refused_with_its_referrers() {
        let path = scratch("m-grouprm", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(
            &cfg,
            Route::GroupRm("mcp".to_string()),
            &[("rev", &rev_of(&path))],
        );
        let (status, html) = got.page();
        assert_eq!(status, 400);
        assert!(html.contains("is still referenced by"), "{html}");
        assert!(html.contains("bob@x.com"), "the referrer is named: {html}");
        assert_eq!(read(&path), before);

        // The unreferenced one goes.
        let got = post(
            &cfg,
            Route::GroupRm("unused".to_string()),
            &[("rev", &rev_of(&path))],
        );
        assert_eq!(got.location(), "/groups?msg=group-removed");
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        assert!(!doc.url_groups.contains_key("unused"));
        assert!(doc.url_groups.contains_key("mcp"));
        cleanup(&path);
    }

    #[test]
    fn a_site_is_edited_and_reordered_by_its_buttons() {
        let path = scratch("m-sites", TWO_SITES);
        let cfg = cfg_for(&path, "");
        let names = || {
            bb_auth_core::read_access_file(&path)
                .unwrap()
                .sites
                .iter()
                .map(site_name)
                .collect::<Vec<_>>()
        };

        // Editing replaces the record wholesale — urls, public_auth and login_url.
        let got = post(
            &cfg,
            Route::SiteEdit("second".to_string()),
            &[
                ("rev", &rev_of(&path)),
                ("name", "second"),
                ("urls", "https://app.x.com/b\nhttps://app.x.com/b/*"),
                ("public_auth", "on"),
                ("login_url", "https://login.x.com/"),
            ],
        );
        assert_eq!(got.location(), "/sites?msg=site-saved");
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        assert_eq!(doc.sites[1].urls.len(), 2);
        assert!(doc.sites[1].public_auth);
        assert_eq!(
            doc.sites[1].login_url.as_deref(),
            Some("https://login.x.com/")
        );

        // An unticked checkbox is a field the browser does not send at all.
        let got = post(
            &cfg,
            Route::SiteEdit("second".to_string()),
            &[
                ("rev", &rev_of(&path)),
                ("name", "second"),
                ("urls", "https://app.x.com/b/*"),
                ("login_url", ""),
            ],
        );
        assert_eq!(got.location(), "/sites?msg=site-saved");
        let doc = bb_auth_core::read_access_file(&path).unwrap();
        assert!(!doc.sites[1].public_auth);
        assert_eq!(doc.sites[1].login_url, None, "a blank login_url is absent");

        // Order is meaning, so a move is a mutation like any other.
        assert_eq!(names(), ["first", "second"]);
        let got = post(
            &cfg,
            Route::SiteMove("second".to_string()),
            &[("rev", &rev_of(&path)), ("dir", "up")],
        );
        assert_eq!(got.location(), "/sites?msg=site-moved");
        assert_eq!(names(), ["second", "first"]);
        // And a move off the end changes nothing rather than erroring.
        let before = read(&path);
        post(
            &cfg,
            Route::SiteMove("second".to_string()),
            &[("rev", &rev_of(&path)), ("dir", "up")],
        );
        assert_eq!(read(&path), before);
        cleanup(&path);
    }

    #[test]
    fn a_denied_email_is_added_once_and_lifted() {
        let path = scratch("m-deny", TWO_SITES);
        let cfg = cfg_for(&path, "");
        let got = post(
            &cfg,
            Route::DenyAdd,
            &[("rev", &rev_of(&path)), ("email", " Bob@X.com ")],
        );
        assert_eq!(got.location(), "/denied?msg=denied-added");
        assert_eq!(
            bb_auth_core::read_access_file(&path).unwrap().denied,
            ["bob@x.com"]
        );
        // Twice is a refusal, not a second row.
        let got = post(
            &cfg,
            Route::DenyAdd,
            &[("rev", &rev_of(&path)), ("email", "bob@x.com")],
        );
        assert!(got.page().1.contains("already on denied"));
        // And the veto lifts.
        let got = post(
            &cfg,
            Route::DenyRm("bob@x.com".to_string()),
            &[("rev", &rev_of(&path))],
        );
        assert_eq!(got.location(), "/denied?msg=denied-removed");
        assert!(bb_auth_core::read_access_file(&path)
            .unwrap()
            .denied
            .is_empty());
        cleanup(&path);
    }

    #[test]
    fn a_page_route_does_not_take_a_post() {
        let path = scratch("m-405", SAMPLE);
        let cfg = cfg_for(&path, "");
        let before = read(&path);
        let got = post(&cfg, Route::Users, &[("rev", &rev_of(&path))]);
        assert_eq!(got.page().0, 405);
        assert_eq!(read(&path), before);
        cleanup(&path);
    }

    #[test]
    fn a_mutation_under_a_base_path_redirects_under_it() {
        let path = scratch("m-base", SAMPLE);
        let cfg = cfg_for(&path, "/admin");
        let got = post(
            &cfg,
            Route::UserAdd,
            &[
                ("rev", &rev_of(&path)),
                ("email", "new@x.com"),
                ("urls", "*://*/*"),
            ],
        );
        assert_eq!(got.location(), "/admin/users/new%40x.com?msg=user-added");
        cleanup(&path);
    }

    #[test]
    fn a_known_msg_key_renders_and_an_unknown_one_is_dropped() {
        assert_eq!(Msg::parse("user-added"), Some(Msg::UserAdded));
        assert_eq!(Msg::parse("site-moved"), Some(Msg::SiteMoved));
        assert_eq!(Msg::parse("<script>"), None);
        assert_eq!(Msg::parse(""), None);
        assert_eq!(Msg::UserRemoved.text(Lang::It), "utente rimosso");
        // Every key round-trips, so a redirect can never name a banner that does not exist.
        for m in [
            Msg::UserAdded,
            Msg::KeySaved,
            Msg::GroupRemoved,
            Msg::DeniedAdded,
        ] {
            assert_eq!(Msg::parse(m.key()), Some(m));
        }
    }

    // --- the server ---------------------------------------------------------

    #[test]
    fn serving_enforces_the_identity_header_and_the_admin_allowlist() {
        let path = scratch("serve", SAMPLE);
        let cfg = cfg_for(&path, "");
        let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
        let port = server.server_addr().to_ip().expect("an ip address").port();
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                handle(req, &cfg);
            }
        });
        let at = |p: &str| format!("http://127.0.0.1:{port}{p}");

        // No header at all: a broken deployment, not an anonymous visitor.
        match ureq::get(&at("/")).call() {
            Err(ureq::Error::Status(401, r)) => {
                assert!(r.into_string().unwrap().contains("auth_request"));
            }
            other => panic!("expected 401, got {other:?}"),
        }
        // Authenticated, but not on the allowlist.
        match ureq::get(&at("/"))
            .set(IDENTITY_HEADER, "someone@x.com")
            .call()
        {
            Err(ureq::Error::Status(403, r)) => {
                assert!(r.into_string().unwrap().contains("someone@x.com"));
            }
            other => panic!("expected 403, got {other:?}"),
        }
        // An administrator gets the dashboard, in the configured language.
        let body = ureq::get(&at("/"))
            .set(IDENTITY_HEADER, "Admin@X.com") // normalised, so capitalisation is fine
            .call()
            .expect("200")
            .into_string()
            .unwrap();
        assert!(
            body.contains("url_groups") && body.contains("Warnings"),
            "{body}"
        );
        // And an unknown path is a 404, not a fall-through to the dashboard.
        match ureq::get(&at("/nope"))
            .set(IDENTITY_HEADER, "admin@x.com")
            .call()
        {
            Err(ureq::Error::Status(404, _)) => {}
            other => panic!("expected 404, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    /// The whole `POST` contract over real HTTP, under a base path: a confirmation page that
    /// changes nothing, the same-origin check, the `rev`, the `303`, and the replay that
    /// the `rev` turns into a `409`.
    #[test]
    fn serving_a_post_checks_the_origin_the_rev_and_then_redirects() {
        let path = scratch("serve-post", SAMPLE);
        let cfg = cfg_for(&path, "/admin");
        let server = Server::http("127.0.0.1:0").expect("bind an ephemeral port");
        let port = server.server_addr().to_ip().expect("an ip address").port();
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                handle(req, &cfg);
            }
        });
        let url = format!("http://127.0.0.1:{port}/admin/users/bob%40x.com/rm");
        // 303s must be visible, not followed.
        let agent = ureq::builder().redirects(0).build();
        let post = || agent.post(&url).set(IDENTITY_HEADER, "admin@x.com");

        // The confirmation page is a GET, and a GET changes nothing.
        let before = read(&path);
        let page = ureq::get(&url)
            .set(IDENTITY_HEADER, "admin@x.com")
            .call()
            .expect("200")
            .into_string()
            .unwrap();
        assert!(
            page.contains("denied is for"),
            "the consequence is spelled out"
        );
        assert_eq!(read(&path), before, "a GET never mutates");
        let rev = rev_in(&page);
        assert_eq!(rev, rev_of(&path));

        // The identity header and the allowlist guard a POST exactly as they guard a GET:
        // they are above the router, so no method reaches a mutation without them.
        match agent
            .post(&url)
            .set("Sec-Fetch-Site", "same-origin")
            .send_form(&[("rev", &rev)])
        {
            Err(ureq::Error::Status(401, _)) => {}
            other => panic!("expected 401 with no identity header, got {other:?}"),
        }
        match agent
            .post(&url)
            .set(IDENTITY_HEADER, "someone@x.com")
            .set("Sec-Fetch-Site", "same-origin")
            .send_form(&[("rev", &rev)])
        {
            Err(ureq::Error::Status(403, r)) => {
                assert!(r.into_string().unwrap().contains("BB_AUTH_WEB_ADMINS"));
            }
            other => panic!("expected 403 for a non-admin POST, got {other:?}"),
        }
        assert_eq!(read(&path), before, "neither may have written anything");

        // No Sec-Fetch-Site and no Origin: not a browser posting a form.
        match post().send_form(&[("rev", &rev)]) {
            Err(ureq::Error::Status(403, r)) => {
                assert!(r.into_string().unwrap().contains("same-origin"));
            }
            other => panic!("expected 403, got {other:?}"),
        }
        assert_eq!(read(&path), before);

        // Cross-site is a refusal too, whatever the Origin claims.
        match post()
            .set("Sec-Fetch-Site", "cross-site")
            .set("Origin", &format!("http://127.0.0.1:{port}"))
            .send_form(&[("rev", &rev)])
        {
            Err(ureq::Error::Status(403, _)) => {}
            other => panic!("expected 403, got {other:?}"),
        }
        assert_eq!(read(&path), before);

        // Same-origin, current rev: it happens, and answers a 303 under the base path.
        let resp = post()
            .set("Sec-Fetch-Site", "same-origin")
            .send_form(&[("rev", &rev)])
            .expect("a 303 is not an error");
        assert_eq!(resp.status(), 303);
        assert_eq!(
            resp.header("Location"),
            Some("/admin/users?msg=user-removed")
        );
        let after = read(&path);
        assert!(!after.contains("Bob@X.com"), "bob is gone: {after}");

        // The browser still holds the old rev — a resubmission cannot repeat the deed.
        match post()
            .set("Sec-Fetch-Site", "same-origin")
            .send_form(&[("rev", &rev)])
        {
            Err(ureq::Error::Status(409, r)) => {
                assert!(r.into_string().unwrap().contains("The file changed"));
            }
            other => panic!("expected 409, got {other:?}"),
        }
        assert_eq!(read(&path), after);

        // And the redirect target renders the banner it was sent with.
        let landed = ureq::get(&format!(
            "http://127.0.0.1:{port}/admin/users?msg=user-removed"
        ))
        .set(IDENTITY_HEADER, "admin@x.com")
        .call()
        .expect("200")
        .into_string()
        .unwrap();
        assert!(landed.contains("user removed"), "{landed}");
        cleanup(&path);
    }
}
