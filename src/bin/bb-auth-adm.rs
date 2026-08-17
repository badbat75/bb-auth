//! bb-auth-adm — edit a bb-auth **access file** (`BB_AUTH_USERS_FILE`, a.k.a. users.json).
//!
//! CRUD over every section of the file the gate actually enforces: `applications` and their
//! scopes, `user_groups`, `denied`, `users` and their `api_keys`. Plus the three things an
//! operator otherwise has to do by hand and by eye: minting a `bbk_` key, answering "would
//! this credential reach that URL?", and converting a file older than 3.0.
//!
//! It shares [`bb_auth_core`] with the gate, and that is the whole design:
//!
//! * **It cannot write a file the gate would reject.** Every mutation goes through
//!   [`AccessWrite`], which serializes, re-parses and compiles with the same parser
//!   `bb-auth --check-users` and the running gate use, *before* anything reaches the disk.
//!   A file the gate refuses at startup is a boot loop under `Restart=on-failure`, so the
//!   only safe place to catch it is here.
//! * **It cannot disagree with the gate about who may reach what.** `can` calls
//!   [`decide`] / [`decide_api_key`], the very functions `/auth/validate` calls.
//! * **It does not eat what it does not understand.** `_comment` and `notes` round-trip
//!   untouched; an unknown field in an application or a scope is still a hard error,
//!   exactly as in the gate.
//!
//! Every document edit below is a call into the library too: the lookups, the duplicate
//! refusals, the mint, the write. What is left here is what a *command-line* program owes
//! its operator: flags, warnings, and the exact words of a verdict.
//!
//! The write is atomic (temp file + rename) and preserves the file's mode and owner, which
//! matters more than it sounds: the live file is `bb-auth-web:bb-auth 0640`, and a rewrite
//! that left it `root:root` would make the gate unable to read its own access list at the
//! next restart.
//!
//! ```text
//! bb-auth-adm -f deploy/users.json app add mpa --base 'https://app.x.com/mpa'
//! bb-auth-adm -f deploy/users.json scope add mpa admin --url 'https://app.x.com/mpa/admin/*' \
//!     --access restricted --user bob@x.com
//! bb-auth-adm -f deploy/users.json key add bob@x.com --id laptop --duration 365d
//! bb-auth-adm -f deploy/users.json can bob@x.com https://app.x.com/mpa/admin/panel
//! ```
//!
//! Editing the file is not enough to change anything: the gate re-reads it on `systemctl
//! reload bb-auth` (SIGHUP) or a restart.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::process::ExitCode;

use bb_auth_core::{
    add_api_key, add_application, add_denied, add_scope, add_user, add_user_email, add_user_group,
    app_mut, app_pos, base_covers, decide, decide_api_key, edit_url_list, edit_urls, format_date,
    key_expiry, key_mut, mint_uuid, move_scope, norm_email, now, open_access_file, remove_api_key,
    remove_application, remove_denied, remove_scope, remove_user, remove_user_email,
    remove_user_group, rename_application, rename_scope, render_access_file, request_url,
    rotate_api_key, scope_pos, user_group_mut, user_group_refs, user_label, user_pos,
    well_formed_uuid, Access, AccessFile, AccessWrite, ApiKeySpec, AppSpec, Decision, KeyDecision,
    ScopeSpec, SealedKey, Subject, UrlScope, UserSpec, Written, ACCESS_FILE_VERSION,
};

const USAGE: &str = "\
bb-auth-adm — edit a bb-auth access file (users.json)

usage: bb-auth-adm [-f FILE] [--dry-run] <command> [args]

  -f, --file FILE   the access file (default: $BB_AUTH_USERS_FILE)
  --dry-run         print the resulting file to stdout, write nothing

file
  init                          create an empty access file (refuses to clobber one)
  show                          the file as the gate resolves it
  check                         validate with the gate's own parser, then lint
  can WHO URL [--as login|api_key] [--key ID]
                                would this credential reach this URL? (exit 0 = yes)
  migrate [-o OUT]              convert a pre-3.0 file, and prove nothing changed

applications                    the places. Areas do not overlap, so their order is nothing
  app list
  app add NAME --base URL... [--login-url URL] [--note TEXT]
  app set NAME [--base U]... [--add-base U]... [--rm-base U]... [--login-url URL]
               [--no-login-url] [--note TEXT]
  app rename NAME NEW
  app rm NAME

scopes                          inside one application. FIRST MATCH WINS: narrow ones first
  scope list APP
  scope add APP NAME --url U... --access anonymous|authenticated|restricted
                     [--user WHO]... [--group @G]... [--credentials login,api_key]
                     [--exclude WHO]... [--note TEXT] [--at N]
  scope set APP NAME [--url U]... [--add-url U]... [--rm-url U]... [--access A]
                     [--user WHO]... [--add-user WHO]... [--rm-user WHO]...
                     [--group @G]... [--credentials C] [--no-credentials]
                     [--exclude WHO]... [--add-exclude WHO]... [--rm-exclude WHO]...
                     [--no-exclude] [--note TEXT]
  --exclude keeps somebody OUT of this one scope, ahead of its own grant: a user, a
  '@group', or a stranger's email. It beats a group membership and it beats
  'authenticated'. Not on 'anonymous', which needs no credential to grant.
  scope mv APP NAME --at N      reorder (0 = first). Order is meaning.
  scope rename APP NAME NEW
  scope rm APP NAME

users                           the roster: an identity, its emails, its keys
  user list
  user show WHO                 WHO is an email or a uuid, everywhere
  user add EMAIL [--note TEXT]  mints the uuid and prints it
  user email add WHO EMAIL
  user email rm WHO EMAIL
  user rm WHO                   also sweeps every scope and group that named them

user groups                     named sets of people, written '@NAME' in a scope's groups
  group list
  group add NAME --member WHO...
  group set NAME [--member WHO]... [--add-member WHO]... [--rm-member WHO]...
  group rm NAME                 refused while a scope still references it

api keys                        static bbk_ bearers, tied to a user
  key list [--user WHO]
  key add WHO --id ID [--duration 365d] [--released YYYY-MM-DD] [--scope APP/SCOPE]...
  key set WHO ID [--duration D] [--released DATE] [--scope S]... [--add-scope S]...
                 [--rm-scope S]... [--no-scopes] [--note TEXT]
  key rotate WHO ID             mint a new secret for an existing key (old one dies)
  key rm WHO ID
  The raw bearer is printed ONCE, on stdout, and never stored: only its sha256.

denied                          a veto. Outranks EVERY grant, on every credential
  deny list
  deny add WHO...               an enrolled user is written down by uuid, a stranger by email
  deny rm WHO...

--url takes a <scheme>://<host>/<path> glob; repeat it, or comma-separate. `*` never
crosses '/' unless it is the pattern's last character; blanket coverage is '*://*/*'.
A --base is LITERAL (no wildcards): it is the area an application owns, and every scope
pattern must lie inside it. Access is enumerated, never assumed: a URL no application
covers is reachable by nobody.

An edit takes effect when the gate re-reads the file: systemctl reload bb-auth.
";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[bb-auth-adm] {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() || argv.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }

    // Global options first, so `-f` may sit anywhere.
    let mut file: Option<String> = None;
    let mut dry_run = false;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "-f" | "--file" => {
                let v = argv
                    .get(i + 1)
                    .cloned()
                    .ok_or("-f/--file needs a path".to_string())?;
                file = Some(v);
                argv.drain(i..=i + 1);
            }
            "--dry-run" => {
                dry_run = true;
                argv.remove(i);
            }
            // `-o` is `migrate`'s alone, but it is rewritten here so the short form does
            // not have to fight the one-dash rule in `parse_args`.
            "-o" => {
                argv[i] = "--out".to_string();
                i += 1;
            }
            _ => i += 1,
        }
    }
    let path = match file.or_else(|| std::env::var("BB_AUTH_USERS_FILE").ok()) {
        Some(p) => p,
        None => return Err("no access file: pass -f FILE or set BB_AUTH_USERS_FILE".into()),
    };

    let (words, flags) = parse_args(&argv)?;
    let cmd: Vec<&str> = words.iter().map(String::as_str).collect();
    let ctx = Ctx {
        path,
        dry_run,
        flags,
    };

    match cmd.as_slice() {
        ["init"] => cmd_init(ctx),
        ["show"] => cmd_show(ctx),
        ["check"] => cmd_check(ctx),
        ["can", who, url] => cmd_can(ctx, who, url),
        ["migrate"] => cmd_migrate(ctx),

        ["app", "list"] => cmd_app_list(ctx),
        ["app", "add", name] => cmd_app_add(ctx, name),
        ["app", "set", name] => cmd_app_set(ctx, name),
        ["app", "rename", name, new] => cmd_app_rename(ctx, name, new),
        ["app", "rm", name] => cmd_app_rm(ctx, name),

        ["scope", "list", app] => cmd_scope_list(ctx, app),
        ["scope", "add", app, name] => cmd_scope_add(ctx, app, name),
        ["scope", "set", app, name] => cmd_scope_set(ctx, app, name),
        ["scope", "mv", app, name] => cmd_scope_mv(ctx, app, name),
        ["scope", "rename", app, name, new] => cmd_scope_rename(ctx, app, name, new),
        ["scope", "rm", app, name] => cmd_scope_rm(ctx, app, name),

        ["user", "list"] => cmd_user_list(ctx),
        ["user", "show", who] => cmd_user_show(ctx, who),
        ["user", "add", email] => cmd_user_add(ctx, email),
        ["user", "email", "add", who, email] => cmd_user_email_add(ctx, who, email),
        ["user", "email", "rm", who, email] => cmd_user_email_rm(ctx, who, email),
        ["user", "rm", who] => cmd_user_rm(ctx, who),

        ["group", "list"] => cmd_group_list(ctx),
        ["group", "add", name] => cmd_group_add(ctx, name),
        ["group", "set", name] => cmd_group_set(ctx, name),
        ["group", "rm", name] => cmd_group_rm(ctx, name),

        ["key", "list"] => cmd_key_list(ctx),
        ["key", "add", who] => cmd_key_add(ctx, who),
        ["key", "set", who, id] => cmd_key_set(ctx, who, id),
        ["key", "rotate", who, id] => cmd_key_rotate(ctx, who, id),
        ["key", "rm", who, id] => cmd_key_rm(ctx, who, id),

        ["deny", "list"] => cmd_deny_list(ctx),
        ["deny", "add", rest @ ..] if !rest.is_empty() => cmd_deny_add(ctx, rest),
        ["deny", "rm", rest @ ..] if !rest.is_empty() => cmd_deny_rm(ctx, rest),

        [] => Err("no command (see --help)".into()),
        other => Err(format!(
            "unknown command '{}' (see --help)",
            other.join(" ")
        )),
    }
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/// Everything a command needs: where the file is, whether it may write, and the flags it
/// has not consumed yet. [`Flags::finish`] then rejects the ones nobody claimed: a typo
/// in `--access` must not be silently ignored by a tool whose job is to keep typos out of
/// the access file.
struct Ctx {
    path: String,
    dry_run: bool,
    flags: Flags,
}

/// Parsed `--flag [value]` options, in order. A flag with no value (the next token is
/// another flag, or the end) is a boolean.
struct Flags(Vec<(String, Option<String>)>);

/// Split argv into positional words and flags. `--name=value` and `--name value` are
/// equivalent; `--name` alone is a boolean.
fn parse_args(argv: &[String]) -> Result<(Vec<String>, Flags), String> {
    let mut words = Vec::new();
    let mut flags = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if let Some(name) = a.strip_prefix("--") {
            if let Some((n, v)) = name.split_once('=') {
                flags.push((n.to_string(), Some(v.to_string())));
            } else {
                let next = argv.get(i + 1);
                match next {
                    Some(v) if !v.starts_with("--") => {
                        flags.push((name.to_string(), Some(v.clone())));
                        i += 1;
                    }
                    _ => flags.push((name.to_string(), None)),
                }
            }
        } else if a.starts_with('-') && a.len() > 1 {
            return Err(format!("unknown option '{a}' (see --help)"));
        } else {
            words.push(a.clone());
        }
        i += 1;
    }
    Ok((words, Flags(flags)))
}

impl Flags {
    /// The single value of `name`, or `None`. Repeated means an error, since silently
    /// keeping one of two contradictory values is how an access file ends up not saying
    /// what its author thought.
    fn take_one(&mut self, name: &str) -> Result<Option<String>, String> {
        let mut found: Option<String> = None;
        let mut n = 0;
        self.0.retain(|(k, v)| {
            if k != name {
                return true;
            }
            n += 1;
            found = v.clone();
            false
        });
        match (n, &found) {
            (0, _) => Ok(None),
            (1, Some(_)) => Ok(found),
            (1, None) => Err(format!("--{name} needs a value")),
            _ => Err(format!("--{name} given more than once")),
        }
    }

    /// Every value of `name`, comma-split and trimmed: `--url a,b --url c` gives `[a, b, c]`.
    fn take_many(&mut self, name: &str) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        let mut missing = false;
        self.0.retain(|(k, v)| {
            if k != name {
                return true;
            }
            match v {
                Some(v) => out.extend(
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string),
                ),
                None => missing = true,
            }
            false
        });
        if missing {
            return Err(format!("--{name} needs a value"));
        }
        Ok(out)
    }

    /// A boolean flag: present (bare, or `=true`/`=false`).
    fn take_flag(&mut self, name: &str) -> Result<bool, String> {
        match self.take_one(name) {
            Ok(None) => Ok(false),
            Ok(Some(v)) => match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => Ok(true),
                "0" | "false" | "no" | "off" => Ok(false),
                other => Err(format!("--{name}: expected true/false, got '{other}'")),
            },
            // a bare `--flag` lands here: take_one calls a valueless flag an error
            Err(e) if e.contains("needs a value") => Ok(true),
            Err(e) => Err(e),
        }
    }

    /// Reject anything nobody claimed. A typo in `--access` must not be shrugged off by the
    /// one tool whose job is keeping typos out of the access file.
    fn finish(&self) -> Result<(), String> {
        match self.0.first() {
            None => Ok(()),
            Some((k, _)) => Err(format!("unknown option '--{k}' for this command")),
        }
    }
}

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

/// The document, and the table the gate would build from it: [`open_access_file`] with the
/// path this invocation is working on.
fn load(ctx: &Ctx) -> Result<(AccessFile, Access), String> {
    open_access_file(&ctx.path)
}

/// Check the edit with the gate's own parser and write it, or, under `--dry-run`, print the
/// bytes and write nothing.
///
/// `Ok(None)` means nothing was written. That is also what denies a freshly minted bearer
/// its way out: [`SealedKey::reveal`] wants the receipt of a real write, and a dry run has
/// none to give it.
fn save(ctx: &Ctx, doc: &AccessFile) -> Result<Option<Written>, String> {
    let pending = AccessWrite::prepare(doc)?;

    if ctx.dry_run {
        print!("{}", pending.json());
        eprintln!("[bb-auth-adm] --dry-run: {} NOT written", ctx.path);
        return Ok(None);
    }

    let written = pending.commit(&ctx.path)?;
    eprintln!(
        "[bb-auth-adm] previous file kept at {}",
        written.backup.display()
    );
    let access = pending.access();
    let scopes: usize = access.apps.iter().map(|a| a.scopes.len()).sum();
    eprintln!(
        "[bb-auth-adm] wrote {}: {} applications, {scopes} scopes, {} users, {} api keys, {} denied",
        ctx.path,
        access.apps.len(),
        access.by_uuid.len(),
        access.by_key_hash.len(),
        access.denied_users.len() + access.denied_identifiers.len()
    );
    eprintln!("[bb-auth-adm] the gate re-reads it on: systemctl reload bb-auth");
    Ok(Some(written))
}

/// `init` — a new, empty access file: a version and nothing else, which is a valid file
/// that grants nobody anything. It refuses to overwrite an existing one, because every
/// other command here starts by reading the file, and the only way to lose a roster with
/// this tool would be to let `init` land on top of one.
///
/// `0640` on unix: the gate reads its access file as a group member and must not be the
/// only one that can, but nobody else has any business reading it.
fn cmd_init(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    if std::path::Path::new(&ctx.path).exists() {
        return Err(format!(
            "{} already exists: refusing to overwrite an access file",
            ctx.path
        ));
    }
    let doc = AccessFile {
        version: ACCESS_FILE_VERSION,
        ..Default::default()
    };
    let json = render_access_file(&doc)?;
    if ctx.dry_run {
        print!("{json}");
        eprintln!("[bb-auth-adm] --dry-run: {} NOT created", ctx.path);
        return Ok(ExitCode::SUCCESS);
    }
    std::fs::write(&ctx.path, &json).map_err(|e| format!("write {}: {e}", ctx.path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ctx.path, std::fs::Permissions::from_mode(0o640))
            .map_err(|e| format!("chmod {}: {e}", ctx.path))?;
    }
    eprintln!(
        "[bb-auth-adm] created {}: it grants nobody anything yet",
        ctx.path
    );
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// Rendering the document
// ---------------------------------------------------------------------------

/// A key's expiry, rendered: `never`, a date, or `EXPIRED`.
fn expiry_str(k: &ApiKeySpec) -> String {
    match key_expiry(&k.released, &k.duration) {
        None => "INVALID released/duration — the gate SKIPS this key".to_string(),
        Some(None) => "never expires".to_string(),
        Some(Some(exp)) => {
            let n = now();
            if exp <= n {
                format!("EXPIRED on {}", format_date(exp))
            } else {
                format!("expires {} (in {}d)", format_date(exp), (exp - n) / 86_400)
            }
        }
    }
}

/// How a user is named back to an operator, resolved through the document: their primary
/// email if they have one, else the uuid. Never make somebody read a uuid they did not
/// have to type.
fn who_is(doc: &AccessFile, uuid: &str) -> String {
    match user_pos(doc, uuid) {
        Some(i) => {
            let u = &doc.users[i];
            let label = user_label(u);
            if label == uuid {
                uuid.to_string()
            } else {
                format!("{label} ({uuid})")
            }
        }
        None => format!("{uuid} (IN NO users ENTRY)"),
    }
}

/// Resolve what an operator typed (an email or a uuid) to the uuid the file stores.
fn to_uuid(doc: &AccessFile, who: &str) -> Result<String, String> {
    match user_pos(doc, who) {
        Some(i) => Ok(doc.users[i].uuid.trim().to_ascii_lowercase()),
        None => Err(format!(
            "no user '{}' (add them with: user add {})",
            who.trim(),
            who.trim()
        )),
    }
}

/// Resolve a list of `--user`/`--member` values to uuids, in order.
fn to_uuids(doc: &AccessFile, who: &[String]) -> Result<Vec<String>, String> {
    who.iter().map(|w| to_uuid(doc, w)).collect()
}

/// Resolve a list of `--exclude` values the way `excluded` is written: an enrolled person
/// becomes their **uuid**, a group stays `@name`, and an email the roster has never heard of
/// stays itself.
///
/// The last case is why this is not [`to_uuids`], which refuses an unknown email. Excluding
/// a stranger is the only exclusion that exists on an `authenticated` scope, and that scope
/// is precisely the one that admits people who are in no roster row — so refusing to name
/// them here would make the field useless where it is needed most. An enrolled person is
/// still written as a uuid, so an exclusion covers every identifier they have.
fn to_exclusions(doc: &AccessFile, who: &[String]) -> Result<Vec<String>, String> {
    who.iter()
        .map(|w| {
            let w = w.trim();
            if w.starts_with('@') {
                return Ok(w.to_string());
            }
            if let Some(i) = user_pos(doc, w) {
                return Ok(doc.users[i].uuid.trim().to_ascii_lowercase());
            }
            if w.contains('@') {
                return Ok(norm_email(w));
            }
            Err(format!(
                "--exclude '{w}': not a uuid, not '@group', and no user of that name. Give an \
                 email (a stranger's is fine) or a group as '@name'"
            ))
        })
        .collect()
}

fn print_scope(app: &str, i: usize, s: &ScopeSpec, doc: &AccessFile) {
    let access = s.access.trim();
    println!("  {i}. {app}/{}  [access: {access}]", s.name.trim());
    for u in &s.urls {
        println!("       {u}");
    }
    if let Some(c) = &s.credentials {
        println!("       credentials: {}", c.join(", "));
    }
    let members: Vec<String> = s.users.iter().flatten().map(|u| who_is(doc, u)).collect();
    if !members.is_empty() {
        println!("       users: {}", members.join(", "));
    }
    if let Some(g) = &s.groups {
        if !g.is_empty() {
            println!("       groups: {}", g.join(", "));
        }
    }
    let excluded: Vec<String> = s
        .excluded
        .iter()
        .flatten()
        .map(|e| {
            let e = e.trim();
            // A bare email that resolves to nobody is a *stranger*, which is the one thing
            // this field can say that `users` cannot, so it prints as itself rather than
            // through `who_is`, whose "IN NO users ENTRY" would read as a mistake here.
            match (e.starts_with('@'), user_pos(doc, e)) {
                (true, _) => e.to_string(),
                (false, Some(_)) => who_is(doc, e),
                (false, None) if e.contains('@') => format!("{e} (a stranger)"),
                (false, None) => who_is(doc, e),
            }
        })
        .collect();
    if !excluded.is_empty() {
        println!("       excluded: {}", excluded.join(", "));
    }
    if let Some(n) = &s.notes {
        if !n.is_empty() {
            println!("       notes: {n}");
        }
    }
}

fn print_app(a: &AppSpec, doc: &AccessFile) {
    println!("{}  base: {}", a.name.trim(), a.base.join(", "));
    if let Some(l) = &a.login_url {
        println!("     login_url: {l}");
    }
    if let Some(n) = &a.notes {
        if !n.is_empty() {
            println!("     notes: {n}");
        }
    }
    if a.scopes.is_empty() {
        println!("  (no scopes: every URL in this area is denied to everyone)");
    }
    for (i, s) in a.scopes.iter().enumerate() {
        print_scope(a.name.trim(), i, s, doc);
    }
}

/// One roster row, plus what it reaches, which is the question the inversion made harder
/// to answer by eye: the grants are on the side of the place now, so the tool computes it.
fn print_user(u: &UserSpec, _doc: &AccessFile, access: &Access) {
    let uuid = u.uuid.trim().to_ascii_lowercase();
    let denied = access.denied_users.contains(&uuid)
        || u.emails
            .iter()
            .any(|e| access.denied_identifiers.contains(&norm_email(e)));
    let tag = if denied { "  [DENIED]" } else { "" };
    println!("  {}{tag}", user_label(u));
    println!("      uuid: {uuid}");
    println!(
        "      emails: {}",
        if u.emails.is_empty() {
            "none — no credential can resolve to this user".to_string()
        } else {
            u.emails
                .iter()
                .map(|e| norm_email(e))
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    let reaches: Vec<String> = access
        .scopes_for(&uuid)
        .iter()
        .map(|(a, s)| format!("{}/{}", a.name, s.name))
        .collect();
    println!(
        "      scopes: {}",
        if reaches.is_empty() {
            "none — this user reaches nothing".to_string()
        } else {
            reaches.join(", ")
        }
    );
    if let Some(n) = u.extra.get("notes").and_then(|v| v.as_str()) {
        if !n.is_empty() {
            println!("      notes: {n}");
        }
    }
    for k in &u.api_keys {
        println!(
            "      key '{}' — {} — released {}, duration {}",
            k.id,
            expiry_str(k),
            k.released,
            k.duration
        );
        println!(
            "          scopes: {}",
            match &k.scopes {
                None => "everything its owner reaches".to_string(),
                Some(l) if l.is_empty() => "[] — reaches NOTHING".to_string(),
                Some(l) => l.join(", "),
            }
        );
    }
}

// ---------------------------------------------------------------------------
// show / check / can
// ---------------------------------------------------------------------------

fn cmd_show(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, access) = load(&ctx)?;

    if doc.applications.is_empty() {
        println!("applications: none — every gated URL is denied to everyone");
    } else {
        println!("applications (areas do not overlap; scopes are FIRST MATCH WINS):");
        for a in &doc.applications {
            print_app(a, &doc);
        }
    }

    println!();
    if doc.user_groups.is_empty() {
        println!("user groups: none");
    } else {
        println!("user groups (name one as '@NAME' in a scope's groups):");
        for (name, members) in &doc.user_groups {
            println!("  @{name}  ({} members)", members.len());
            for m in members {
                println!("       {}", who_is(&doc, m));
            }
        }
    }

    println!();
    if doc.denied.is_empty() {
        println!("denied: none");
    } else {
        println!("denied (outranks EVERY grant, on every credential):");
        for e in &doc.denied {
            let e = norm_email(e);
            if well_formed_uuid(&e) {
                println!("  {}", who_is(&doc, &e));
            } else {
                println!("  {e}  (an identity the roster does not know)");
            }
        }
    }

    println!();
    println!("users:");
    for u in &doc.users {
        print_user(u, &doc, &access);
    }
    Ok(ExitCode::SUCCESS)
}

/// `check` — the gate's parser (already run by [`load`]), then the lints only a tool that
/// sees the *document* can do. The parser reports what would be fatal or skipped; these are
/// the things that parse fine and still mean something other than what was intended.
fn cmd_check(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, access) = load(&ctx)?;

    let scopes: usize = access.apps.iter().map(|a| a.scopes.len()).sum();
    println!(
        "[bb-auth-adm] {}: OK: {} applications, {scopes} scopes, {} users, {} api keys, {} denied",
        ctx.path,
        access.apps.len(),
        access.by_uuid.len(),
        access.by_key_hash.len(),
        access.denied_users.len() + access.denied_identifiers.len()
    );

    let mut lints = Vec::new();
    let known_scopes: HashSet<String> = doc
        .applications
        .iter()
        .flat_map(|a| {
            a.scopes
                .iter()
                .map(move |s| format!("{}/{}", a.name.trim(), s.name.trim()))
        })
        .collect();

    // Places that answer for nobody, or never answer at all.
    for a in &doc.applications {
        let name = a.name.trim();
        if a.scopes.is_empty() {
            lints.push(format!(
                "application '{name}' has no scopes: every URL in its area is denied to everyone"
            ));
        }
        for (i, s) in a.scopes.iter().enumerate() {
            let at = format!("{name}/{}", s.name.trim());
            if s.urls.is_empty() {
                lints.push(format!("{at} has no urls: it answers for nothing"));
            }
            if let Some(j) = shadowed_by(&a.scopes, i) {
                lints.push(format!(
                    "{at} is listed after '{}', which already answers for its urls: first match \
                     wins, so {at} never speaks. Move it earlier: scope mv {name} {} --at {j}",
                    a.scopes[j].name.trim(),
                    s.name.trim(),
                ));
            }
            if s.access.trim() == "restricted" {
                let named = s.users.iter().flatten().count() + s.groups.iter().flatten().count();
                if named == 0 {
                    lints.push(format!(
                        "{at} is restricted and lists nobody: it admits no one"
                    ));
                }
            }
            for u in s.users.iter().flatten() {
                if user_pos(&doc, u).is_none() {
                    lints.push(format!(
                        "{at} lists {u}, which is in no users entry: that reference grants nothing"
                    ));
                }
            }
        }
    }

    // People who reach nothing, or cannot sign in.
    for u in &doc.users {
        let uuid = u.uuid.trim().to_ascii_lowercase();
        let label = user_label(u);
        if u.emails.is_empty() {
            lints.push(format!(
                "{label}: no emails, so no credential can ever resolve to this user"
            ));
        }
        if access.scopes_for(&uuid).is_empty() {
            lints.push(format!(
                "{label} is in no scope: they reach nothing (an anonymous or authenticated scope \
                 may still let them in, but nothing lists them)"
            ));
        }
        let mut ids = HashSet::new();
        for k in &u.api_keys {
            if !ids.insert(k.id.trim().to_string()) {
                lints.push(format!(
                    "{label}: two api keys share the id '{}'",
                    k.id.trim()
                ));
            }
            match key_expiry(&k.released, &k.duration) {
                Some(Some(exp)) if exp <= now() => lints.push(format!(
                    "{label}: key '{}' expired on {}: the gate rejects it",
                    k.id,
                    format_date(exp)
                )),
                _ => {}
            }
            // A restriction naming a scope its owner is not admitted to can never be used.
            for r in k.scopes.iter().flatten() {
                let r = r.trim();
                if !known_scopes.contains(r) {
                    continue; // the parser already refuses this one
                }
                let owner_reaches = access
                    .scopes_for(&uuid)
                    .iter()
                    .any(|(a, s)| format!("{}/{}", a.name, s.name) == r);
                if !owner_reaches {
                    lints.push(format!(
                        "{label}: key '{}' is restricted to {r}, which does not list {label}: the \
                         key can never use it",
                        k.id.trim()
                    ));
                }
            }
        }
    }

    // A veto written as a stranger's email while the roster holds that same address: the
    // parser folds it onto the uuid, so it works, but the file reads as if it did not.
    for d in &doc.denied {
        let d = norm_email(d);
        if !well_formed_uuid(&d) {
            if let Some(i) = user_pos(&doc, &d) {
                lints.push(format!(
                    "denied lists the email {d}, which belongs to {}: it works, but writing the \
                     uuid says plainly that every address of theirs is vetoed",
                    user_label(&doc.users[i])
                ));
            }
        }
    }

    for name in doc.user_groups.keys() {
        if user_group_refs(&doc, name).is_empty() {
            lints.push(format!(
                "user group '@{name}' is defined but no scope references it: it grants nobody \
                 anything"
            ));
        }
    }

    if lints.is_empty() {
        println!("[bb-auth-adm] lint: nothing to report");
        return Ok(ExitCode::SUCCESS);
    }
    for l in &lints {
        println!("[bb-auth-adm] LINT: {l}");
    }
    Ok(ExitCode::SUCCESS)
}

/// The index of an earlier scope that already answers for scope `i`'s urls, if any.
///
/// A heuristic, and deliberately so: matching one glob against another has no exact answer
/// (`https://x.com/*` vs `*://x.com/app1` cover each other partially). Feeding the later
/// scope's pattern *text* to the earlier scope's matcher catches the case that actually
/// happens, a broad scope listed first, and stays quiet otherwise. It only ever warns.
fn shadowed_by(scopes: &[ScopeSpec], i: usize) -> Option<usize> {
    let mine = &scopes[i];
    if mine.urls.is_empty() {
        return None;
    }
    for (j, earlier) in scopes.iter().enumerate().take(i) {
        let scope = match UrlScope::compile(&earlier.urls) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if mine.urls.iter().all(|u| scope.allows(Some(u))) {
            return Some(j);
        }
    }
    None
}

/// `can WHO URL [--as CLASS] [--key ID]` — put the question to the gate's own decision
/// function, and exit 0 only if it says yes. What `--check-users` is to the file, this is
/// to a grant.
fn cmd_can(mut ctx: Ctx, who: &str, url: &str) -> Result<ExitCode, String> {
    let key_id = ctx.flags.take_one("key")?;
    let as_class = ctx.flags.take_one("as")?;
    ctx.flags.finish()?;
    let (doc, access) = load(&ctx)?;

    let url = request_url(url);
    let at = Some(url.as_str());

    // The API-key path: a key is looked up by the sha256 of the bearer, and the file keeps
    // exactly that, so the record can be evaluated without ever holding the secret.
    let key_id = match (key_id, as_class.as_deref()) {
        (Some(id), _) => Some(id),
        (None, Some("api_key")) => {
            let i = user_pos(&doc, who).ok_or_else(|| format!("no user '{who}'"))?;
            match doc.users[i].api_keys.first() {
                Some(k) => Some(k.id.clone()),
                None => return Err(format!("{who} has no api key to try (--as api_key)")),
            }
        }
        (None, Some("login")) | (None, None) => None,
        (None, Some(other)) => {
            return Err(format!("--as: expected login or api_key, got '{other}'"))
        }
    };

    if let Some(id) = key_id {
        let i = user_pos(&doc, who).ok_or_else(|| format!("no user '{who}'"))?;
        let k = doc.users[i]
            .api_keys
            .iter()
            .find(|k| k.id.trim() == id.trim())
            .ok_or_else(|| format!("{}: no api key '{id}'", user_label(&doc.users[i])))?;
        let hash = k.key_hash.trim().to_ascii_lowercase();

        let rec = match decide_api_key(&access, &hash, now()) {
            KeyDecision::Granted(rec) => rec,
            KeyDecision::Unknown => {
                println!(
                    "DENIED — the gate has no key with this hash: it was skipped at load (bad \
                     key_hash '{}')",
                    k.key_hash.trim()
                );
                return Ok(ExitCode::FAILURE);
            }
            KeyDecision::OwnerDenied(_) => {
                println!("DENIED — its owner is on the denied list");
                return Ok(ExitCode::FAILURE);
            }
            KeyDecision::Expired(_) => {
                println!("DENIED — the key is expired ({})", expiry_str(k));
                return Ok(ExitCode::FAILURE);
            }
        };
        return Ok(verdict(&access, &doc, &Subject::Key(rec), at, &url));
    }

    let subject = Subject::Identifier(who);
    Ok(verdict(&access, &doc, &subject, at, &url))
}

/// Print the gate's decision in the gate's own words, and turn it into an exit code.
fn verdict(
    access: &Access,
    doc: &AccessFile,
    subject: &Subject,
    at: Option<&str>,
    url: &str,
) -> ExitCode {
    let d = decide(access, subject, at);
    let sees = |uuid: Option<&str>| match uuid.and_then(|u| user_pos(doc, u)) {
        Some(i) => format!(
            "  the application sees X-Auth-Email: {}",
            user_label(&doc.users[i])
        ),
        None => match subject {
            Subject::Identifier(id) => format!("  the application sees X-Auth-Email: {id}"),
            _ => "  the application sees no identity".to_string(),
        },
    };
    let uuid = match subject {
        Subject::Identifier(id) => access.uuid_of(id).map(str::to_string),
        Subject::Key(rec) => Some(rec.uuid.clone()),
        Subject::Anonymous => None,
    };
    match &d {
        Decision::Anonymous { app, scope } => {
            println!("AUTHORIZED — {app}/{scope} is anonymous: {url} is open to everyone");
            println!("  the 204 names nobody");
            ExitCode::SUCCESS
        }
        Decision::Granted { app, scope } => {
            println!("AUTHORIZED — {app}/{scope} admits this credential for {url}");
            println!("{}", sees(uuid.as_deref()));
            ExitCode::SUCCESS
        }
        Decision::Vetoed => {
            println!("DENIED — on the denied list, which outranks every grant");
            ExitCode::FAILURE
        }
        Decision::Excluded { app, scope } => {
            println!("DENIED — {app}/{scope} excludes this identity, ahead of its own grant");
            println!("  this is local: another scope may still admit them");
            ExitCode::FAILURE
        }
        Decision::NoApplication => {
            println!("DENIED — no application's base covers {url}, so nobody reaches it");
            ExitCode::FAILURE
        }
        Decision::NoScope { app } => {
            println!("DENIED — application '{app}' owns {url} but has no scope covering it");
            ExitCode::FAILURE
        }
        Decision::Unauthenticated { app, scope } => {
            println!("DENIED — {app}/{scope} wants an identity and none was given");
            ExitCode::FAILURE
        }
        Decision::CredentialRefused { app, scope } => {
            println!("DENIED — {app}/{scope} does not admit this class of credential");
            ExitCode::FAILURE
        }
        Decision::NotEnrolled { app, scope } => {
            println!(
                "DENIED — {app}/{scope} is restricted, and this identity is in no users entry"
            );
            ExitCode::FAILURE
        }
        Decision::NotMember { app, scope } => {
            println!("DENIED — {app}/{scope} does not list this user");
            ExitCode::FAILURE
        }
        Decision::KeyOutOfScope { app, scope } => {
            println!("DENIED — this key restricted itself to other scopes, not {app}/{scope}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// applications
// ---------------------------------------------------------------------------

fn cmd_app_list(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, _) = load(&ctx)?;
    for a in &doc.applications {
        println!(
            "{}  base: {}  ({} scopes){}",
            a.name.trim(),
            a.base.join(", "),
            a.scopes.len(),
            match &a.login_url {
                Some(l) => format!("  login_url={l}"),
                None => String::new(),
            }
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_app_add(mut ctx: Ctx, name: &str) -> Result<ExitCode, String> {
    let base = ctx.flags.take_many("base")?;
    let login_url = ctx.flags.take_one("login-url")?;
    let note = ctx.flags.take_one("note")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    if base.is_empty() {
        return Err("app add needs --base URL: it is the area the application owns".into());
    }
    add_application(
        &mut doc,
        AppSpec {
            name: name.trim().to_string(),
            base,
            login_url,
            notes: note,
            ..Default::default()
        },
    )?;
    eprintln!(
        "[bb-auth-adm] '{}' owns that area now, and nothing in it is reachable until it has a \
         scope: scope add {} NAME --url ... --access ...",
        name.trim(),
        name.trim()
    );
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_app_set(mut ctx: Ctx, name: &str) -> Result<ExitCode, String> {
    let set = ctx.flags.take_many("base")?;
    let add = ctx.flags.take_many("add-base")?;
    let rm = ctx.flags.take_many("rm-base")?;
    let login_url = ctx.flags.take_one("login-url")?;
    let no_login = ctx.flags.take_flag("no-login-url")?;
    let note = ctx.flags.take_one("note")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let a = app_mut(&mut doc, name)?;
    let mut changed = edit_url_list(&mut a.base, set, add, rm, false);
    if no_login {
        a.login_url = None;
        changed = true;
    }
    if let Some(l) = login_url {
        a.login_url = Some(l);
        changed = true;
    }
    if let Some(n) = note {
        a.notes = Some(n);
        changed = true;
    }
    if !changed {
        return Err("nothing to change (see --help)".into());
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

/// `app rename` — and every key restriction that named `app/scope` moves with it, because
/// a restriction is a string and one left behind would silently point at nothing.
fn cmd_app_rename(ctx: Ctx, name: &str, new: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    rename_application(&mut doc, name, new)?;
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_app_rm(ctx: Ctx, name: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    let gone = remove_application(&mut doc, name)?;
    eprintln!(
        "[bb-auth-adm] removed '{}' and its {} scope(s): every URL in {} is now reachable by \
         nobody",
        gone.name.trim(),
        gone.scopes.len(),
        gone.base.join(", ")
    );
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// scopes
// ---------------------------------------------------------------------------

fn cmd_scope_list(ctx: Ctx, app: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, _) = load(&ctx)?;
    let i = app_pos(&doc, app).ok_or_else(|| format!("no application '{}'", app.trim()))?;
    print_app(&doc.applications[i], &doc);
    Ok(ExitCode::SUCCESS)
}

/// A scope's three membership fields, as the document holds them: the uuids, the group
/// references, and the credential classes. Absent everywhere but under `restricted`.
type Membership = (
    Option<Vec<String>>,
    Option<Vec<String>>,
    Option<Vec<String>>,
);

/// Build a scope's membership fields from what an operator typed, resolving emails to
/// uuids. `users`/`groups`/`credentials` only exist under `restricted`, so they are left
/// absent otherwise and the parser refuses them if they were given anyway.
fn scope_membership(
    doc: &AccessFile,
    access: &str,
    users: Vec<String>,
    groups: Vec<String>,
    credentials: Vec<String>,
) -> Result<Membership, String> {
    if access != "restricted" {
        if !users.is_empty() || !groups.is_empty() || !credentials.is_empty() {
            return Err(format!(
                "--user/--group/--credentials belong to --access restricted, not to '{access}'"
            ));
        }
        return Ok((None, None, None));
    }
    let users = to_uuids(doc, &users)?;
    let groups: Vec<String> = groups
        .iter()
        .map(|g| {
            let g = g.trim();
            if g.starts_with('@') {
                g.to_string()
            } else {
                format!("@{g}")
            }
        })
        .collect();
    Ok((
        Some(users),
        if groups.is_empty() {
            None
        } else {
            Some(groups)
        },
        if credentials.is_empty() {
            None
        } else {
            Some(credentials)
        },
    ))
}

fn cmd_scope_add(mut ctx: Ctx, app: &str, name: &str) -> Result<ExitCode, String> {
    let urls = ctx.flags.take_many("url")?;
    let access = ctx
        .flags
        .take_one("access")?
        .ok_or("scope add needs --access anonymous|authenticated|restricted")?;
    let users = ctx.flags.take_many("user")?;
    let groups = ctx.flags.take_many("group")?;
    let credentials = ctx.flags.take_many("credentials")?;
    let exclude = ctx.flags.take_many("exclude")?;
    let note = ctx.flags.take_one("note")?;
    let at = ctx.flags.take_one("at")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let access = access.trim().to_string();
    let (users, groups, credentials) = scope_membership(&doc, &access, users, groups, credentials)?;
    let excluded = if exclude.is_empty() {
        None
    } else {
        if access == "anonymous" {
            return Err(
                "--exclude means nothing on --access anonymous: that scope grants with no \
                 credential at all, so an excluded client would simply send none"
                    .into(),
            );
        }
        Some(to_exclusions(&doc, &exclude)?)
    };
    let at = match at {
        Some(v) => Some(
            v.trim()
                .parse::<usize>()
                .map_err(|_| format!("--at wants a position, got '{v}'"))?,
        ),
        None => None,
    };
    let landed = add_scope(
        &mut doc,
        app,
        ScopeSpec {
            name: name.trim().to_string(),
            urls,
            access: access.clone(),
            users,
            groups,
            credentials,
            excluded,
            notes: note,
        },
        at,
    )?;
    if access != "restricted" {
        eprintln!(
            "[bb-auth-adm] WARNING: {}/{} is '{access}': it grants without listing anybody",
            app.trim(),
            name.trim()
        );
    }
    eprintln!(
        "[bb-auth-adm] {}/{} is scope #{landed}: first match wins, so a broader scope before it \
         would silence it (check)",
        app.trim(),
        name.trim()
    );
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_scope_set(mut ctx: Ctx, app: &str, name: &str) -> Result<ExitCode, String> {
    let set = ctx.flags.take_many("url")?;
    let add = ctx.flags.take_many("add-url")?;
    let rm = ctx.flags.take_many("rm-url")?;
    let access = ctx.flags.take_one("access")?;
    let users = ctx.flags.take_many("user")?;
    let add_users = ctx.flags.take_many("add-user")?;
    let rm_users = ctx.flags.take_many("rm-user")?;
    let groups = ctx.flags.take_many("group")?;
    let credentials = ctx.flags.take_many("credentials")?;
    let no_credentials = ctx.flags.take_flag("no-credentials")?;
    let exclude = ctx.flags.take_many("exclude")?;
    let add_exclude = ctx.flags.take_many("add-exclude")?;
    let rm_exclude = ctx.flags.take_many("rm-exclude")?;
    let no_exclude = ctx.flags.take_flag("no-exclude")?;
    let note = ctx.flags.take_one("note")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    // Resolve people before taking the mutable borrow: the lookup needs the document.
    let users = to_uuids(&doc, &users)?;
    let add_users = to_uuids(&doc, &add_users)?;
    let rm_users = to_uuids(&doc, &rm_users)?;
    let exclude = to_exclusions(&doc, &exclude)?;
    let add_exclude = to_exclusions(&doc, &add_exclude)?;
    let rm_exclude = to_exclusions(&doc, &rm_exclude)?;
    let groups: Vec<String> = groups
        .iter()
        .map(|g| {
            let g = g.trim();
            if g.starts_with('@') {
                g.to_string()
            } else {
                format!("@{g}")
            }
        })
        .collect();

    let s = bb_auth_core::scope_mut(&mut doc, app, name)?;
    let mut changed = edit_url_list(&mut s.urls, set, add, rm, false);
    if let Some(a) = access {
        s.access = a.trim().to_string();
        changed = true;
    }
    changed |= edit_urls(&mut s.users, users, add_users, rm_users, false);
    if !groups.is_empty() {
        s.groups = Some(groups);
        changed = true;
    }
    if no_credentials {
        s.credentials = None;
        changed = true;
    }
    if !credentials.is_empty() {
        s.credentials = Some(credentials);
        changed = true;
    }
    // Same set/add/rm shape as every other list. Then the collapse: absent and empty both
    // mean nobody is kept out, so the file says it one way, and `"excluded": []` never
    // survives to be refused by a later `--access anonymous`.
    changed |= edit_urls(
        &mut s.excluded,
        exclude,
        add_exclude,
        rm_exclude,
        no_exclude,
    );
    if s.excluded.as_ref().is_some_and(Vec::is_empty) {
        s.excluded = None;
    }
    if let Some(n) = note {
        s.notes = Some(n);
        changed = true;
    }
    if !changed {
        return Err("nothing to change (see --help)".into());
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

/// `scope mv` — the one edit that changes behaviour without changing a field: scopes are
/// first match wins, so this decides which requests a scope ever sees.
fn cmd_scope_mv(mut ctx: Ctx, app: &str, name: &str) -> Result<ExitCode, String> {
    let at = ctx
        .flags
        .take_one("at")?
        .ok_or("scope mv needs --at N (0 = first)")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let to: usize = at
        .trim()
        .parse()
        .map_err(|_| format!("--at wants a position, got '{at}'"))?;
    let i = app_pos(&doc, app).ok_or_else(|| format!("no application '{}'", app.trim()))?;
    let from = scope_pos(&doc.applications[i], name)
        .ok_or_else(|| format!("{}/{}: no such scope", app.trim(), name.trim()))?;
    move_scope(&mut doc, app, from, to)?;
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_scope_rename(ctx: Ctx, app: &str, name: &str, new: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    rename_scope(&mut doc, app, name, new)?;
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_scope_rm(ctx: Ctx, app: &str, name: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    remove_scope(&mut doc, app, name)?;
    eprintln!(
        "[bb-auth-adm] the scope after it now answers for the urls it covered: scope list {}",
        app.trim()
    );
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

fn cmd_user_list(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, access) = load(&ctx)?;
    for u in &doc.users {
        print_user(u, &doc, &access);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_user_show(ctx: Ctx, who: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, access) = load(&ctx)?;
    match user_pos(&doc, who) {
        Some(i) => {
            print_user(&doc.users[i], &doc, &access);
            Ok(ExitCode::SUCCESS)
        }
        None => Err(format!("no user '{}'", who.trim())),
    }
}

/// `user add EMAIL` — mints the uuid, which is the identity every reference in the file
/// will use. The email is the identifier Cognito vouches for.
fn cmd_user_add(mut ctx: Ctx, email: &str) -> Result<ExitCode, String> {
    let note = ctx.flags.take_one("note")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let uuid = mint_uuid()?;
    let mut u = UserSpec {
        uuid: uuid.clone(),
        emails: vec![norm_email(email)],
        ..Default::default()
    };
    if let Some(n) = note {
        u.extra.insert("notes".into(), n.into());
    }
    add_user(&mut doc, u)?;
    eprintln!(
        "[bb-auth-adm] {} is {uuid}. They reach nothing until a scope lists them: \
         scope set APP NAME --add-user {}",
        norm_email(email),
        norm_email(email)
    );
    println!("{uuid}");
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_user_email_add(ctx: Ctx, who: &str, email: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    if !add_user_email(&mut doc, who, email)? {
        eprintln!(
            "[bb-auth-adm] {} already has {}",
            who.trim(),
            norm_email(email)
        );
        return Ok(ExitCode::SUCCESS);
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_user_email_rm(ctx: Ctx, who: &str, email: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    if !remove_user_email(&mut doc, who, email)? {
        return Err(format!(
            "{} does not have {}",
            who.trim(),
            norm_email(email)
        ));
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

/// `user rm` — the row goes, and with it every key it owned and **every reference to it**.
/// The sweep is the point: with grants written on the side of the place, a row can be named
/// by any number of scopes and groups, and a leftover reference is a member who does not
/// exist.
fn cmd_user_rm(ctx: Ctx, who: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, access) = load(&ctx)?;
    let (u, swept) = remove_user(&mut doc, who)?;
    let label = user_label(&u);
    if !u.api_keys.is_empty() {
        eprintln!(
            "[bb-auth-adm] {label}: also removed {} api key(s): {}",
            u.api_keys.len(),
            u.api_keys
                .iter()
                .map(|k| k.id.trim())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !swept.is_empty() {
        eprintln!(
            "[bb-auth-adm] {label}: also removed from {}",
            swept.join(", ")
        );
    }
    if access.any_authenticated_scope() {
        eprintln!(
            "[bb-auth-adm] WARNING: this file has an authenticated scope, and removing {label} \
             does NOT keep them out of it: the roster is not consulted there. To lock them out: \
             deny add {label}"
        );
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// user groups
// ---------------------------------------------------------------------------

fn cmd_group_list(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, _) = load(&ctx)?;
    for (name, members) in &doc.user_groups {
        let refs = user_group_refs(&doc, name);
        let by = if refs.is_empty() {
            "referenced by NOTHING".to_string()
        } else {
            format!("referenced by {}", refs.join(", "))
        };
        println!("@{name}  ({} members, {by})", members.len());
        for m in members {
            println!("     {}", who_is(&doc, m));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `group add` — a group is abbreviation, not a grant: defining one authorizes nobody until
/// a scope names it.
fn cmd_group_add(mut ctx: Ctx, name: &str) -> Result<ExitCode, String> {
    let members = ctx.flags.take_many("member")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let members = to_uuids(&doc, &members)?;
    let empty = members.is_empty();
    add_user_group(&mut doc, name, members)?;
    if empty {
        eprintln!(
            "[bb-auth-adm] WARNING: '@{}' has no --member: a scope naming it admits nobody \
             through it",
            name.trim()
        );
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

/// `group set` — there is deliberately no rename: a reference names a group by its exact
/// spelling, so renaming one would silently re-point every scope that used it. Add the new
/// name, move the references, drop the old one: three edits the gate re-validates one by
/// one.
fn cmd_group_set(mut ctx: Ctx, name: &str) -> Result<ExitCode, String> {
    let set = ctx.flags.take_many("member")?;
    let add = ctx.flags.take_many("add-member")?;
    let rm = ctx.flags.take_many("rm-member")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let set = to_uuids(&doc, &set)?;
    let add = to_uuids(&doc, &add)?;
    let rm = to_uuids(&doc, &rm)?;
    let changed = edit_url_list(user_group_mut(&mut doc, name)?, set, add, rm, false);
    if !changed {
        return Err("nothing to change (see --help)".into());
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_group_rm(ctx: Ctx, name: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    remove_user_group(&mut doc, name)?;
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// api keys
// ---------------------------------------------------------------------------

fn cmd_key_list(mut ctx: Ctx) -> Result<ExitCode, String> {
    let only = ctx.flags.take_one("user")?;
    ctx.flags.finish()?;
    let (doc, _) = load(&ctx)?;
    let only = match only {
        Some(w) => Some(to_uuid(&doc, &w)?),
        None => None,
    };
    for u in &doc.users {
        let uuid = u.uuid.trim().to_ascii_lowercase();
        if only.as_ref().is_some_and(|o| o != &uuid) {
            continue;
        }
        for k in &u.api_keys {
            println!(
                "{}  key '{}'  {}",
                user_label(u),
                k.id.trim(),
                expiry_str(k)
            );
            println!(
                "      scopes: {}",
                match &k.scopes {
                    None => "everything its owner reaches".to_string(),
                    Some(l) if l.is_empty() => "[] — reaches NOTHING".to_string(),
                    Some(l) => l.join(", "),
                }
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Hand the freshly minted bearer to its owner, which `written` is what makes possible: a
/// [`SealedKey`] only opens against the receipt of a completed write, so there is no order
/// in which this prints a credential the file never got.
///
/// It goes to **stdout**, alone, so it can be piped into a secret store; everything a human
/// reads is on stderr. It is not recoverable: the file keeps the hash, and the hash *is*
/// the verification.
fn hand_over(key: SealedKey, what: &str, written: Option<&Written>) {
    let receipt = match written {
        Some(w) => w,
        None => {
            eprintln!("[bb-auth-adm] --dry-run: nothing was written, so this key is void");
            return;
        }
    };
    let raw = key.reveal(receipt);
    eprintln!("=== {what} — not stored anywhere, and it cannot be recovered ===");
    eprintln!("Authorization: Bearer {raw}");
    eprintln!("===");
    println!("{raw}");
}

/// `key add` — mint a `bbk_` bearer, store only its sha256, print the raw key once.
fn cmd_key_add(mut ctx: Ctx, who: &str) -> Result<ExitCode, String> {
    let id = ctx
        .flags
        .take_one("id")?
        .ok_or("key add needs --id LABEL (it names the key for logs and revocation)")?;
    let duration = ctx.flags.take_one("duration")?.unwrap_or("365d".into());
    let released = ctx
        .flags
        .take_one("released")?
        .unwrap_or_else(|| format_date(now()));
    let scopes = ctx.flags.take_many("scope")?;
    let note = ctx.flags.take_one("note")?;
    ctx.flags.finish()?;
    let (mut doc, access) = load(&ctx)?;

    let id = id.trim().to_string();
    if id.is_empty() {
        return Err("--id must not be empty".into());
    }
    // Fail before minting: a key the file would reject is a secret handed out for nothing.
    if key_expiry(&released, &duration).is_none() {
        return Err(format!(
            "bad --released '{released}' / --duration '{duration}' (YYYY-MM-DD, and <n>d / <n>h \
             / never)"
        ));
    }
    let uuid = to_uuid(&doc, who)?;
    if access.denied_users.contains(&uuid) {
        eprintln!("[bb-auth-adm] WARNING: this user is denied: every key of theirs is rejected");
    }
    let unrestricted = scopes.is_empty();
    let mut k = ApiKeySpec {
        id: id.clone(),
        released,
        duration,
        scopes: if unrestricted { None } else { Some(scopes) },
        ..Default::default()
    };
    if let Some(n) = note {
        k.extra.insert("notes".into(), n.into());
    }
    // The mint is in here, and the bearer comes back sealed until the write below.
    let sealed = add_api_key(&mut doc, who, k)?;

    if access.scopes_for(&uuid).is_empty() {
        eprintln!(
            "[bb-auth-adm] WARNING: no scope lists this user, so the key reaches nothing that \
             asks for an identity"
        );
    }
    let written = save(&ctx, &doc)?;
    hand_over(
        sealed,
        &format!("the bearer for '{id}' — give it to the client ONCE"),
        written.as_ref(),
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_key_set(mut ctx: Ctx, who: &str, id: &str) -> Result<ExitCode, String> {
    let duration = ctx.flags.take_one("duration")?;
    let released = ctx.flags.take_one("released")?;
    let set = ctx.flags.take_many("scope")?;
    let add = ctx.flags.take_many("add-scope")?;
    let rm = ctx.flags.take_many("rm-scope")?;
    let clear = ctx.flags.take_flag("no-scopes")?;
    let note = ctx.flags.take_one("note")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let k = key_mut(&mut doc, who, id)?;
    let mut changed = false;
    if let Some(d) = duration {
        k.duration = d;
        changed = true;
    }
    if let Some(r) = released {
        k.released = r;
        changed = true;
    }
    if key_expiry(&k.released, &k.duration).is_none() {
        return Err(format!(
            "released '{}' + duration '{}' is not a valid window: the gate would skip this key",
            k.released, k.duration
        ));
    }
    // `--no-scopes` clears the restriction, which means "everything its owner reaches".
    changed |= edit_urls(&mut k.scopes, set, add, rm, clear);
    if let Some(n) = note {
        k.extra.insert("notes".into(), n.into());
        changed = true;
    }
    if !changed {
        return Err("nothing to change (see --help)".into());
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

/// `key rotate` — same row, same restriction, new secret. The old bearer stops working the
/// moment the gate reloads, which is exactly what makes this the answer to a leaked key.
fn cmd_key_rotate(ctx: Ctx, who: &str, id: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    let sealed = rotate_api_key(&mut doc, who, id)?;
    let written = save(&ctx, &doc)?;
    hand_over(
        sealed,
        &format!("the NEW bearer for '{id}' — the old one dies at the next reload"),
        written.as_ref(),
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_key_rm(ctx: Ctx, who: &str, id: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    remove_api_key(&mut doc, who, id)?;
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// denied
// ---------------------------------------------------------------------------

fn cmd_deny_list(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, _) = load(&ctx)?;
    for e in &doc.denied {
        let e = norm_email(e);
        if well_formed_uuid(&e) {
            println!("{}", who_is(&doc, &e));
        } else {
            println!("{e}  (an identity the roster does not know)");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `deny add` — the veto. An enrolled user is written down by **uuid**, whichever way they
/// were named, so every email they hold goes with it; a stranger is written down as the
/// email itself, which on an `authenticated` scope is the only denial there is.
fn cmd_deny_add(ctx: Ctx, who: &[&str]) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    let mut changed = false;
    for w in who {
        let w = w.trim();
        if w.is_empty() {
            continue;
        }
        let enrolled = user_pos(&doc, w).is_some();
        if !add_denied(&mut doc, w)? {
            eprintln!("[bb-auth-adm] {w} is already denied");
            continue;
        }
        changed = true;
        if enrolled {
            eprintln!(
                "[bb-auth-adm] {w} stays in users: the veto wins on every credential, and their \
                 group memberships and keys survive the lockout"
            );
        }
    }
    if !changed {
        return Err("nothing to deny".into());
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_deny_rm(ctx: Ctx, who: &[&str]) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    let want: Vec<String> = who.iter().map(|w| w.trim().to_string()).collect();
    if remove_denied(&mut doc, &want) == 0 {
        return Err(format!("none of {} were denied", want.join(", ")));
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// migrate: a pre-3.0 file to this format
// ---------------------------------------------------------------------------

/// One old grant, as the pre-3.0 rules expressed it.
struct OldUser {
    email: String,
    urls: Vec<String>,
    keys: Vec<serde_json::Value>,
}

/// The literal prefix of a pattern: everything before the first wildcard, trimmed back to
/// the last `/`. `https://x.com/app/*` gives `https://x.com/app`; a pattern whose authority
/// carries a wildcard has none, and cannot be placed in an area.
fn literal_prefix(pattern: &str) -> Option<String> {
    let p = pattern.trim();
    let cut = p.find(['*', '&']).unwrap_or(p.len());
    let head = &p[..cut];
    let sep = head.find("://")?;
    if head[sep + 3..].is_empty() {
        return None; // the wildcard is in the authority
    }
    let path_at = head[sep + 3..].find('/').map(|i| sep + 3 + i)?;
    if cut == p.len() {
        return Some(p.to_string()); // wholly literal
    }
    let end = head.rfind('/').unwrap_or(path_at);
    let out = &head[..end.max(path_at)];
    Some(out.to_string())
}

/// Replace every wildcard with a literal token, so a pattern becomes one representative URL
/// the old and the new rules can both be asked about.
fn representative(pattern: &str) -> String {
    pattern.trim().replace(['*', '&'], "x")
}

/// `migrate` — convert a pre-3.0 access file, and refuse to write unless every grant
/// survives.
///
/// The conversion is mechanical and the result is correct, not tidy: it invents one
/// application per URL area it can find, and renaming those is a separate, unhurried edit.
/// What it will not do is guess. Every old grant it cannot place is reported, and any
/// (identity, URL) pair whose answer changed stops the write entirely.
fn cmd_migrate(mut ctx: Ctx) -> Result<ExitCode, String> {
    let out = ctx.flags.take_one("out")?;
    ctx.flags.finish()?;

    let raw = std::fs::read_to_string(&ctx.path).map_err(|e| format!("read {}: {e}", ctx.path))?;
    let old: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", ctx.path))?;
    if old.get("applications").is_some() || old.get("version").is_some() {
        return Err(format!(
            "{} already looks like a version {ACCESS_FILE_VERSION} file: nothing to migrate",
            ctx.path
        ));
    }

    // --- read the old shape -------------------------------------------------
    let groups: BTreeMap<String, Vec<String>> = old
        .get("url_groups")
        .and_then(|g| g.as_object())
        .map(|o| {
            o.iter()
                .map(|(k, v)| {
                    let list = v
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    (k.clone(), list)
                })
                .collect()
        })
        .unwrap_or_default();
    let expand = |list: &[String]| -> Vec<String> {
        let mut out = Vec::new();
        for e in list {
            match e.trim().strip_prefix('@') {
                Some(g) => out.extend(groups.get(g).cloned().unwrap_or_default()),
                None => out.push(e.trim().to_string()),
            }
        }
        out
    };
    let strings = |v: Option<&serde_json::Value>| -> Vec<String> {
        v.and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                    .collect()
            })
            .unwrap_or_default()
    };

    let denied: Vec<String> = strings(old.get("denied"))
        .iter()
        .map(|e| norm_email(e))
        .collect();
    let old_sites: Vec<serde_json::Value> = old
        .get("sites")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();
    let old_users: Vec<OldUser> = old
        .get("users")
        .and_then(|u| u.as_array())
        .map(|a| {
            a.iter()
                .map(|u| OldUser {
                    email: norm_email(u.get("email").and_then(|e| e.as_str()).unwrap_or("")),
                    urls: expand(&strings(u.get("authorized_urls"))),
                    keys: u
                        .get("api_keys")
                        .and_then(|k| k.as_array())
                        .cloned()
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();

    // --- the areas ----------------------------------------------------------
    let mut every_pattern: Vec<String> = Vec::new();
    for s in &old_sites {
        every_pattern.extend(expand(&strings(s.get("urls"))));
    }
    for u in &old_users {
        every_pattern.extend(u.urls.clone());
        for k in &u.keys {
            every_pattern.extend(expand(&strings(k.get("authorized_urls"))));
        }
    }
    let mut bases: Vec<String> = Vec::new();
    let mut unplaceable: Vec<String> = Vec::new();
    for p in &every_pattern {
        match literal_prefix(p) {
            Some(b) => {
                if !bases.iter().any(|x| base_covers(x, &b)) {
                    bases.retain(|x| !base_covers(&b, x));
                    bases.push(b);
                }
            }
            None => unplaceable.push(p.clone()),
        }
    }
    bases.sort();
    if bases.is_empty() {
        return Err("nothing to migrate: this file has no URL pattern with a literal area".into());
    }

    // --- the new document ---------------------------------------------------
    let mut doc = AccessFile {
        version: ACCESS_FILE_VERSION,
        ..Default::default()
    };
    // Keep the operator's own comment, if any: it is theirs, not ours.
    if let Some(c) = old.get("_comment") {
        doc.extra.insert("_comment".into(), c.clone());
    }
    let app_name = |base: &str| -> String {
        let tail = base.rsplit('/').next().unwrap_or("app");
        let host = base
            .split("://")
            .nth(1)
            .and_then(|r| r.split('/').next())
            .unwrap_or("app");
        let raw = if tail.is_empty() || tail.contains('.') {
            host
        } else {
            tail
        };
        let cleaned: String = raw
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        cleaned.trim_matches('-').to_string()
    };
    let mut names: HashSet<String> = HashSet::new();
    let mut app_of: HashMap<String, String> = HashMap::new(); // base -> application name
    for b in &bases {
        let mut n = app_name(b);
        if n.is_empty() {
            n = "app".into();
        }
        let mut candidate = n.clone();
        let mut i = 2;
        while !names.insert(candidate.clone()) {
            candidate = format!("{n}-{i}");
            i += 1;
        }
        app_of.insert(b.clone(), candidate.clone());
        doc.applications.push(AppSpec {
            name: candidate,
            base: vec![b.clone()],
            ..Default::default()
        });
    }
    let app_for = |p: &str| -> Option<String> {
        let b = literal_prefix(p)?;
        bases
            .iter()
            .find(|x| base_covers(x, &b))
            .and_then(|x| app_of.get(x).cloned())
    };

    // Mint an identity per old user, keeping their email as the one identifier.
    let mut uuid_of: HashMap<String, String> = HashMap::new();
    for u in &old_users {
        if u.email.is_empty() {
            continue;
        }
        let uuid = mint_uuid()?;
        uuid_of.insert(u.email.clone(), uuid.clone());
        let keys: Vec<ApiKeySpec> = u
            .keys
            .iter()
            .map(|k| ApiKeySpec {
                id: k
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                key_hash: k
                    .get("key_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                released: k
                    .get("released")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                duration: k
                    .get("duration")
                    .and_then(|v| v.as_str())
                    .unwrap_or("never")
                    .to_string(),
                ..Default::default()
            })
            .collect();
        doc.users.push(UserSpec {
            uuid,
            emails: vec![u.email.clone()],
            api_keys: keys,
            ..Default::default()
        });
    }
    doc.denied = denied
        .iter()
        .map(|d| match uuid_of.get(d) {
            Some(u) => u.clone(),
            None => d.clone(),
        })
        .collect();

    // The sites become scopes first, because a `public_auth` site grants to more people
    // than any roster entry does, and first match wins.
    for s in &old_sites {
        let urls = expand(&strings(s.get("urls")));
        let public = s
            .get("public_auth")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let login = s.get("login_url").and_then(|v| v.as_str());
        let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("site");
        let mut by_app: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for u in &urls {
            match app_for(u) {
                Some(a) => by_app.entry(a).or_default().push(u.clone()),
                None => unplaceable.push(u.clone()),
            }
        }
        for (app, urls) in by_app {
            let i = app_pos(&doc, &app).ok_or("internal: application vanished")?;
            if let Some(l) = login {
                doc.applications[i].login_url = Some(l.to_string());
            }
            let scope = ScopeSpec {
                name: sanitize(name),
                urls,
                access: if public {
                    "authenticated"
                } else {
                    "restricted"
                }
                .into(),
                users: if public { None } else { Some(Vec::new()) },
                ..Default::default()
            };
            add_scope(&mut doc, &app, scope, None)?;
        }
    }

    // Then the roster, one scope per distinct set of patterns, listing the users that had
    // it. That is the smallest conversion that keeps every grant.
    let mut by_urls: BTreeMap<Vec<String>, Vec<String>> = BTreeMap::new();
    for u in &old_users {
        if u.email.is_empty() || u.urls.is_empty() {
            continue;
        }
        let mut key = u.urls.clone();
        key.sort();
        key.dedup();
        by_urls.entry(key).or_default().push(u.email.clone());
    }
    for (n, (urls, emails)) in by_urls.iter().enumerate() {
        let mut by_app: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for u in urls {
            match app_for(u) {
                Some(a) => by_app.entry(a).or_default().push(u.clone()),
                None => unplaceable.push(u.clone()),
            }
        }
        for (app, urls) in by_app {
            let members: Vec<String> = emails
                .iter()
                .filter_map(|e| uuid_of.get(e).cloned())
                .collect();
            add_scope(
                &mut doc,
                &app,
                ScopeSpec {
                    name: format!("roster-{}", n + 1),
                    urls,
                    access: "restricted".into(),
                    users: Some(members),
                    ..Default::default()
                },
                None,
            )?;
        }
    }

    // --- prove it -----------------------------------------------------------
    let pending = AccessWrite::prepare(&doc)?;
    let new = pending.access();
    let mut diffs: Vec<String> = Vec::new();
    let urls: Vec<String> = every_pattern.iter().map(|p| representative(p)).collect();
    for u in &old_users {
        for url in &urls {
            let before = old_grants(u, &old_sites, &denied, &expand, url);
            let after = decide(new, &Subject::Identifier(&u.email), Some(url)).granted();
            if before != after {
                diffs.push(format!(
                    "{} -> {url}: was {}, now {}",
                    u.email,
                    if before { "AUTHORIZED" } else { "denied" },
                    if after { "AUTHORIZED" } else { "denied" }
                ));
            }
        }
    }

    unplaceable.sort();
    unplaceable.dedup();
    for p in &unplaceable {
        eprintln!(
            "[bb-auth-adm] COULD NOT PLACE '{p}': it has no literal area, so no application can \
             own it. Split it by hand."
        );
    }
    if !diffs.is_empty() {
        for d in &diffs {
            eprintln!("[bb-auth-adm] CHANGED: {d}");
        }
        return Err(format!(
            "refusing to write: {} (identity, URL) pair(s) would answer differently. The \
             conversion is not safe as it stands",
            diffs.len()
        ));
    }

    let target = out.unwrap_or_else(|| format!("{}.v3", ctx.path));
    if ctx.dry_run {
        print!("{}", pending.json());
        eprintln!("[bb-auth-adm] --dry-run: {target} NOT written");
        return Ok(ExitCode::SUCCESS);
    }
    std::fs::write(&target, pending.json()).map_err(|e| format!("write {target}: {e}"))?;
    eprintln!(
        "[bb-auth-adm] wrote {target}: {} applications, {} users. Every grant the old file made \
         still resolves the same way.",
        doc.applications.len(),
        doc.users.len()
    );
    eprintln!(
        "[bb-auth-adm] the names are invented: read it, rename what deserves a name, then \
         install it. Do NOT restart the gate before the new binary is in place."
    );
    Ok(ExitCode::SUCCESS)
}

/// A name the new format accepts: `[A-Za-z0-9_-]`, never empty.
fn sanitize(raw: &str) -> String {
    let s: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() {
        "scope".into()
    } else {
        s
    }
}

/// The pre-3.0 rules, reimplemented here and nowhere else: denied first, then a `public_auth`
/// site covering the URL, then the user's own patterns. This is the oracle the conversion
/// is checked against, so it has to say what the old gate said, not what the new one does.
fn old_grants(
    u: &OldUser,
    sites: &[serde_json::Value],
    denied: &[String],
    expand: &dyn Fn(&[String]) -> Vec<String>,
    url: &str,
) -> bool {
    if denied.contains(&u.email) {
        return false;
    }
    for s in sites {
        let urls = expand(
            &s.get("urls")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        );
        let scope = match UrlScope::compile(&urls) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if scope.allows(Some(url)) {
            // First match wins, exactly as `Sites::resolve` did.
            return s
                .get("public_auth")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
        }
    }
    UrlScope::compile(&u.urls)
        .map(|s| s.allows(Some(url)))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_prefix_stops_at_the_first_wildcard() {
        assert_eq!(
            literal_prefix("https://x.com/app/*").as_deref(),
            Some("https://x.com/app")
        );
        assert_eq!(
            literal_prefix("https://x.com/app").as_deref(),
            Some("https://x.com/app")
        );
        assert_eq!(
            literal_prefix("https://x.com/a/b/*/c").as_deref(),
            Some("https://x.com/a/b")
        );
        // A wildcard in the authority leaves no area to own.
        assert_eq!(literal_prefix("*://*/*"), None);
        assert_eq!(literal_prefix("https://*.x.com/a"), None);
    }

    #[test]
    fn to_exclusions_keeps_a_stranger_and_resolves_a_user() {
        let doc: AccessFile = serde_json::from_str(
            r#"{ "version": 3, "user_groups": { "admins": [] },
                 "users": [ { "uuid": "11111111-1111-4111-8111-111111111111",
                              "emails": ["bob@x.com"] } ] }"#,
        )
        .unwrap();
        let got = to_exclusions(
            &doc,
            &[
                "BOB@x.com".to_string(),
                "@admins".to_string(),
                "Stranger@X.com".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(
            got,
            [
                "11111111-1111-4111-8111-111111111111",
                "@admins",
                "stranger@x.com"
            ]
        );
        // Something that is none of the three is refused rather than written down as a
        // string nothing will ever equal.
        assert!(to_exclusions(&doc, &["nonsense".to_string()]).is_err());
    }

    #[test]
    fn representative_turns_a_pattern_into_one_url() {
        assert_eq!(representative("https://x.com/a/*"), "https://x.com/a/x");
        assert_eq!(representative("https://x.com/v&/y"), "https://x.com/vx/y");
    }

    #[test]
    fn sanitize_makes_a_name_the_format_accepts() {
        assert_eq!(sanitize("app 1"), "app-1");
        assert_eq!(sanitize("  --  "), "scope");
        assert_eq!(sanitize("keep_this-1"), "keep_this-1");
    }

    #[test]
    fn shadowed_by_finds_the_broad_scope_listed_first() {
        let broad = ScopeSpec {
            name: "broad".into(),
            urls: vec!["https://x.com/a/*".into()],
            access: "authenticated".into(),
            ..Default::default()
        };
        let narrow = ScopeSpec {
            name: "narrow".into(),
            urls: vec!["https://x.com/a/deep/*".into()],
            access: "authenticated".into(),
            ..Default::default()
        };
        let scopes = vec![broad, narrow];
        assert_eq!(shadowed_by(&scopes, 1), Some(0));
        assert_eq!(shadowed_by(&scopes, 0), None);
    }

    /// The old rules, on the shape the old file had. This is what `migrate` checks itself
    /// against, so it is worth pinning on its own.
    #[test]
    fn old_grants_is_the_pre_3_0_rule() {
        let sites: Vec<serde_json::Value> = vec![serde_json::json!({
            "name": "signup",
            "urls": ["https://x.com/welcome/*"],
            "public_auth": true
        })];
        let expand = |l: &[String]| l.to_vec();
        let bob = OldUser {
            email: "bob@x.com".into(),
            urls: vec!["https://x.com/app/*".into()],
            keys: vec![],
        };
        let denied = vec!["spammer@x.com".to_string()];

        assert!(old_grants(
            &bob,
            &sites,
            &denied,
            &expand,
            "https://x.com/app/x"
        ));
        // The public_auth site grants without consulting the roster.
        assert!(old_grants(
            &bob,
            &sites,
            &denied,
            &expand,
            "https://x.com/welcome/x"
        ));
        assert!(!old_grants(
            &bob,
            &sites,
            &denied,
            &expand,
            "https://x.com/other"
        ));
        let spammer = OldUser {
            email: "spammer@x.com".into(),
            urls: vec!["*://*/*".into()],
            keys: vec![],
        };
        assert!(!old_grants(
            &spammer,
            &sites,
            &denied,
            &expand,
            "https://x.com/app/x"
        ));
    }
}
