//! bb-auth-adm — edit a bb-auth **access file** (`BB_AUTH_USERS_FILE`, a.k.a. users.json).
//!
//! CRUD over every section of the file the gate actually enforces — `url_groups`, `sites`,
//! `denied`, `users` and their `api_keys` — plus the two things an operator otherwise has
//! to do by hand and by eye: minting a `bbk_` key, and answering "would this credential
//! reach that URL?".
//!
//! It shares [`bb_auth_core`] with the gate, and that is the whole design:
//!
//! * **It cannot write a file the gate would reject.** Every mutation is serialized,
//!   re-parsed, and compiled with [`compile_access`] — the same parser `bb-auth
//!   --check-users` and the running gate use — *before* anything reaches the disk. A file
//!   the gate refuses at startup is a boot loop under `Restart=on-failure`, so the only
//!   safe place to catch it is here.
//! * **It cannot disagree with the gate about who may reach what.** `can` calls
//!   [`decide`] / [`decide_api_key`], the very functions `/auth/validate` calls.
//! * **It does not eat what it does not understand.** `_comment` and `notes` round-trip
//!   untouched; a site's unknown field is still a hard error, exactly as in the gate.
//!
//! The write is atomic (temp file + rename) and preserves the file's mode and owner, which
//! matters more than it sounds: the live file is `root:bb-auth 0640`, and a rewrite that
//! left it `root:root` would make the gate unable to read its own access list at the next
//! restart.
//!
//! ```text
//! bb-auth-adm -f deploy/users.json user add bob@x.com --url 'https://app.x.com/*'
//! bb-auth-adm -f deploy/users.json key add bob@x.com --id laptop --duration 365d
//! bb-auth-adm -f deploy/users.json can bob@x.com https://app.x.com/reports
//! ```
//!
//! Editing the file is not enough to change anything: the gate re-reads it on `systemctl
//! reload bb-auth` (SIGHUP) or a restart.

use std::process::ExitCode;

use bb_auth_core::{
    compile_access, decide, decide_api_key, format_date, group_ref, key_expiry, lower_authority,
    mint_api_key, now, read_access_file, Access, AccessFile, ApiKeySpec, Decision, KeyDecision,
    SiteSpec, UrlScope, UserSpec,
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
  can EMAIL URL [--key ID]      would this credential reach this URL? (exit 0 = yes)

users                           the roster: who is enrolled, and what they may reach
  user list
  user show EMAIL
  user add EMAIL [--url U]... [--note TEXT]
  user set EMAIL [--email NEW] [--url U]... [--add-url U]... [--rm-url U]...
                 [--no-urls] [--note TEXT]
  user rm EMAIL

api keys                        static bbk_ bearers, tied to a user
  key list [--user EMAIL]
  key add EMAIL --id ID [--duration 365d] [--released YYYY-MM-DD] [--url U]... [--note T]
  key set EMAIL ID [--duration D] [--released DATE] [--url U]... [--add-url U]...
                   [--rm-url U]... [--inherit-urls] [--note TEXT]
  key rotate EMAIL ID           mint a new secret for an existing key (old one dies)
  key rm EMAIL ID
  The raw bearer is printed ONCE, on stdout, and never stored — only its sha256.

sites                           URL areas. FIRST MATCH WINS: specific sites go first
  site list
  site add NAME [--url U]... [--public-auth] [--login-url URL] [--at N]
  site set NAME [--name NEW] [--url U]... [--add-url U]... [--rm-url U]...
                [--public-auth] [--no-public-auth] [--login-url URL] [--no-login-url]
  site mv NAME --at N           reorder (0 = first). Order is meaning.
  site rm NAME

url groups                      named pattern sets, written '@NAME' in any urls list
  url-group list
  url-group add NAME --url U...
  url-group set NAME [--url U]... [--add-url U]... [--rm-url U]... [--no-urls]
  url-group rm NAME             refused while anything still references it

denied                          a veto by email. Outranks EVERY grant, on every credential
  deny list
  deny add EMAIL...
  deny rm EMAIL...

--url takes a <scheme>://<host>/<path> glob; repeat it, or comma-separate. `*` never
crosses '/' unless it is the pattern's last character; blanket access is '*://*/*'.
An entry '@NAME' stands for the url group NAME — in a user's urls, a key's or a site's.
Access is enumerated, never assumed: no authorized_urls means no access at all.

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
        ["can", email, url] => cmd_can(ctx, email, url),

        ["user", "list"] => cmd_user_list(ctx),
        ["user", "show", email] => cmd_user_show(ctx, email),
        ["user", "add", email] => cmd_user_add(ctx, email),
        ["user", "set", email] => cmd_user_set(ctx, email),
        ["user", "rm", email] => cmd_user_rm(ctx, email),

        ["key", "list"] => cmd_key_list(ctx),
        ["key", "add", email] => cmd_key_add(ctx, email),
        ["key", "set", email, id] => cmd_key_set(ctx, email, id),
        ["key", "rotate", email, id] => cmd_key_rotate(ctx, email, id),
        ["key", "rm", email, id] => cmd_key_rm(ctx, email, id),

        ["site", "list"] => cmd_site_list(ctx),
        ["site", "add", name] => cmd_site_add(ctx, name),
        ["site", "set", name] => cmd_site_set(ctx, name),
        ["site", "mv", name] => cmd_site_mv(ctx, name),
        ["site", "rm", name] => cmd_site_rm(ctx, name),

        ["url-group", "list"] => cmd_url_group_list(ctx),
        ["url-group", "add", name] => cmd_url_group_add(ctx, name),
        ["url-group", "set", name] => cmd_url_group_set(ctx, name),
        ["url-group", "rm", name] => cmd_url_group_rm(ctx, name),

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
/// has not consumed yet. [`Flags::finish`] then rejects the ones nobody claimed — a typo
/// in `--public-auth` must not be silently ignored by a tool whose job is to keep typos
/// out of the access file.
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
    /// The single value of `name`, or `None`. Repeated ⇒ error, since silently keeping one
    /// of two contradictory values is how an access file ends up not saying what its author
    /// thought.
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

    /// Every value of `name`, comma-split and trimmed — `--url a,b --url c` ⇒ `[a, b, c]`.
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

    /// Reject anything nobody claimed. A typo in `--public-auth` must not be shrugged off
    /// by the one tool whose job is keeping typos out of the access file.
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

/// Load the document, and the table the gate would build from it.
///
/// A file the gate would reject is refused here too: an edit must start from a file that
/// works, or the tool would cheerfully fix one problem while carrying a fatal one to the
/// disk. Both halves come back because compiling is also what *prints* the parser's
/// warnings ("this user reaches nothing"), and an operator should hear each of those once,
/// not once per look.
fn load(ctx: &Ctx) -> Result<(AccessFile, Access), String> {
    let doc = read_access_file(&ctx.path)?;
    let access = compile_access(&doc).map_err(|e| {
        format!(
            "{}: the gate would reject this file as it stands: {e}",
            ctx.path
        )
    })?;
    Ok((doc, access))
}

/// Serialize, re-parse, compile with the gate's parser, and only then write — atomically,
/// preserving the file's mode and owner.
///
/// The round-trip is not paranoia: what is compiled is the exact byte string that is about
/// to land on disk, so nothing can slip in between the check and the write. `compile_access`
/// is the same function the gate runs at startup and on SIGHUP, so a file this accepts is a
/// file the gate accepts — which is what keeps a bad edit from becoming a `Restart=on-failure`
/// boot loop.
fn save(ctx: &Ctx, doc: &AccessFile) -> Result<(), String> {
    let mut json =
        serde_json::to_string_pretty(doc).map_err(|e| format!("cannot serialize: {e}"))?;
    json.push('\n');

    let reparsed: AccessFile =
        serde_json::from_str(&json).map_err(|e| format!("serialized to invalid JSON: {e}"))?;
    let access = compile_access(&reparsed).map_err(|e| format!("refusing to write: {e}"))?;

    if ctx.dry_run {
        print!("{json}");
        eprintln!("[bb-auth-adm] --dry-run: {} NOT written", ctx.path);
        return Ok(());
    }

    write_atomically(&ctx.path, &json)?;
    eprintln!(
        "[bb-auth-adm] wrote {} — {} users, {} api keys, {} sites, {} denied",
        ctx.path,
        access.by_email.len(),
        access.by_key_hash.len(),
        access.sites.entries.len(),
        access.denied.len()
    );
    eprintln!("[bb-auth-adm] the gate re-reads it on: systemctl reload bb-auth");
    Ok(())
}

/// Write `content` to `path` atomically: a temp file in the same directory, then a rename.
///
/// Mode and owner are copied from the file being replaced, and that is not cosmetic. The
/// live access file is `root:bb-auth 0640`; a rewrite by root that left it `root:root`
/// would be unreadable to the service, and the gate would die on its next start — a
/// lockout dressed up as a successful edit. If the owner cannot be restored, nothing is
/// renamed: the old file stays, intact.
fn write_atomically(path: &str, content: &str) -> Result<(), String> {
    let p = std::path::Path::new(path);
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty());
    let tmp = match dir {
        Some(d) => d.join(format!(
            ".{}.bb-auth-adm.tmp",
            p.file_name().unwrap_or_default().to_string_lossy()
        )),
        None => std::path::PathBuf::from(format!(".{path}.bb-auth-adm.tmp")),
    };

    let meta = std::fs::metadata(p).map_err(|e| format!("stat {path}: {e}"))?;
    // Keep one step back. The gate is stateless, but a roster is not reconstructible.
    let bak = format!("{path}.bak");
    std::fs::copy(p, &bak).map_err(|e| format!("backup {bak}: {e}"))?;

    std::fs::write(&tmp, content).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    let restore = |e: String| {
        let _ = std::fs::remove_file(&tmp);
        e
    };
    std::fs::set_permissions(&tmp, meta.permissions())
        .map_err(|e| restore(format!("chmod {}: {e}", tmp.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (uid, gid) = (meta.uid(), meta.gid());
        let c = std::ffi::CString::new(tmp.to_string_lossy().as_bytes())
            .map_err(|e| restore(format!("path: {e}")))?;
        // SAFETY: a NUL-terminated path we just created, and two ids read off the file we
        // are replacing.
        if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
            return Err(restore(format!(
                "cannot restore owner {uid}:{gid} on {} ({}) — not writing, the old file is \
                 untouched. Re-run as root.",
                tmp.display(),
                std::io::Error::last_os_error()
            )));
        }
    }
    std::fs::rename(&tmp, p).map_err(|e| restore(format!("rename onto {path}: {e}")))?;
    eprintln!("[bb-auth-adm] previous file kept at {bak}");
    Ok(())
}

/// `init` — a new, empty access file: `{"users": []}`, which is a valid file that grants
/// nobody anything. It refuses to overwrite an existing one, because every other command
/// here starts by reading the file, and the only way to lose a roster with this tool would
/// be to let `init` land on top of one.
///
/// `0640` on unix: the gate reads its access file as a group member and must not be the
/// only one that can, but nobody else has any business reading it.
fn cmd_init(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    if std::path::Path::new(&ctx.path).exists() {
        return Err(format!(
            "{} already exists — refusing to overwrite an access file",
            ctx.path
        ));
    }
    let doc = AccessFile::default();
    let json = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())? + "\n";
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
        "[bb-auth-adm] created {} — it grants nobody anything yet",
        ctx.path
    );
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// Lookups over the document
// ---------------------------------------------------------------------------

/// Emails are matched the way the gate matches them: trimmed and lowercased.
fn norm_email(e: &str) -> String {
    e.trim().to_ascii_lowercase()
}

fn user_pos(doc: &AccessFile, email: &str) -> Option<usize> {
    let want = norm_email(email);
    doc.users.iter().position(|u| norm_email(&u.email) == want)
}

fn user_mut<'a>(doc: &'a mut AccessFile, email: &str) -> Result<&'a mut UserSpec, String> {
    match user_pos(doc, email) {
        Some(i) => Ok(&mut doc.users[i]),
        None => Err(format!(
            "no user '{}' (add them with: user add {})",
            email.trim(),
            email.trim()
        )),
    }
}

fn key_mut<'a>(
    doc: &'a mut AccessFile,
    email: &str,
    id: &str,
) -> Result<&'a mut ApiKeySpec, String> {
    let u = user_mut(doc, email)?;
    match u.api_keys.iter().position(|k| k.id.trim() == id.trim()) {
        Some(i) => Ok(&mut u.api_keys[i]),
        None => Err(format!("{}: no api key '{id}'", norm_email(email))),
    }
}

fn site_pos(doc: &AccessFile, name: &str) -> Option<usize> {
    doc.sites.iter().position(|s| s.name.trim() == name.trim())
}

/// Apply the standard scope edits to a `authorized_urls` field: a full `--url` replacement,
/// then `--add-url` / `--rm-url`. Returns `true` if anything changed.
///
/// `None` means "absent". For a user that is deny-all; for a key it means "inherit the
/// owner's" — two different things, so the caller says which one an empty result should
/// collapse to.
fn edit_urls(
    urls: &mut Option<Vec<String>>,
    set: Vec<String>,
    add: Vec<String>,
    rm: Vec<String>,
    clear: bool,
) -> bool {
    let mut changed = false;
    if clear {
        *urls = None;
        changed = true;
    }
    if !set.is_empty() {
        *urls = Some(set);
        changed = true;
    }
    if !add.is_empty() {
        let list = urls.get_or_insert_with(Vec::new);
        for u in add {
            if !list.iter().any(|x| x == &u) {
                list.push(u);
                changed = true;
            }
        }
    }
    if !rm.is_empty() {
        if let Some(list) = urls.as_mut() {
            let before = list.len();
            list.retain(|x| !rm.iter().any(|r| r == x));
            changed |= list.len() != before;
        }
    }
    changed
}

/// The URL as the gate will see it on `/auth/validate`: query and fragment stripped (nginx
/// sends `$uri`), authority lowercased. Comparing anything else would be answering a
/// different question from the one the gate answers.
fn request_url(url: &str) -> String {
    lower_authority(url.split(['?', '#']).next().unwrap_or(""))
}

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

fn urls_of(urls: &Option<Vec<String>>, absent: &str) -> String {
    match urls {
        None => absent.to_string(),
        Some(l) if l.is_empty() => "[] — reaches NOTHING".to_string(),
        Some(l) => l.join(", "),
    }
}

// ---------------------------------------------------------------------------
// show / check / can
// ---------------------------------------------------------------------------

fn cmd_show(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, _) = load(&ctx)?;

    // Definitions before uses, and the lists below print '@name' as stored: what the
    // file says is what an operator has to be able to read back.
    if doc.url_groups.is_empty() {
        println!("url groups: none");
    } else {
        println!("url groups (name one as '@NAME' in any urls list):");
        for (name, urls) in &doc.url_groups {
            println!("  @{name}  ({} urls)", urls.len());
            for u in urls {
                println!("       {u}");
            }
        }
    }

    println!();
    if doc.sites.is_empty() {
        println!("sites: none — every grant comes from the roster below");
    } else {
        println!("sites (FIRST MATCH WINS, in this order):");
        for (i, s) in doc.sites.iter().enumerate() {
            let open = if s.public_auth {
                "public_auth: ANY authenticated identity, enrolled or not"
            } else {
                "public_auth: no — grants nothing today"
            };
            println!("  {}. {}  [{open}]", i, name_of(s));
            if let Some(l) = &s.login_url {
                println!("       login_url: {l}");
            }
            for u in &s.urls {
                println!("       {u}");
            }
        }
    }

    println!();
    if doc.denied.is_empty() {
        println!("denied: none");
    } else {
        println!("denied (outranks EVERY grant, on every credential):");
        for e in &doc.denied {
            println!("  {}", norm_email(e));
        }
    }

    println!();
    println!("users:");
    for u in &doc.users {
        print_user(u, &doc);
    }
    Ok(ExitCode::SUCCESS)
}

fn print_user(u: &UserSpec, doc: &AccessFile) {
    let denied = doc
        .denied
        .iter()
        .any(|d| norm_email(d) == norm_email(&u.email));
    let tag = if denied { "  [DENIED]" } else { "" };
    println!("  {}{tag}", norm_email(&u.email));
    println!(
        "      urls: {}",
        urls_of(&u.authorized_urls, "none — reaches NOTHING")
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
            "          urls: {}",
            urls_of(&k.authorized_urls, "inherits the user's")
        );
    }
}

fn name_of(s: &SiteSpec) -> String {
    match s.name.trim() {
        "" => "?".to_string(),
        n => n.to_string(),
    }
}

/// `check` — the gate's parser (already run by [`load`]), then the lints only a tool that
/// sees the *document* can do. The parser reports what would be fatal or skipped; these are
/// the things that parse fine and still mean something other than what was intended.
fn cmd_check(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, access) = load(&ctx)?;

    println!(
        "[bb-auth-adm] {}: OK — {} users, {} api keys, {} sites, {} denied",
        ctx.path,
        access.by_email.len(),
        access.by_key_hash.len(),
        access.sites.entries.len(),
        access.denied.len()
    );

    let mut lints = Vec::new();

    // Duplicates. The gate builds HashMaps, so a duplicate is not an error there — the last
    // one silently wins, and the row an operator is reading may not be the row in force.
    let mut seen = std::collections::HashSet::new();
    for u in &doc.users {
        let e = norm_email(&u.email);
        if !seen.insert(e.clone()) {
            lints.push(format!(
                "user {e} appears more than once — the LAST entry wins, the others are dead"
            ));
        }
        let mut ids = std::collections::HashSet::new();
        for k in &u.api_keys {
            if !ids.insert(k.id.trim().to_string()) {
                lints.push(format!("{e}: two api keys share the id '{}'", k.id.trim()));
            }
        }
    }
    let mut hashes: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
    for u in &doc.users {
        for k in &u.api_keys {
            let h = k.key_hash.trim();
            if h.is_empty() {
                continue;
            }
            if let Some(other) = hashes.insert(h, format!("{} '{}'", norm_email(&u.email), k.id)) {
                lints.push(format!(
                    "the same key_hash is on {other} and on {} '{}' — one bearer, two rows, and \
                     only one of them is in force",
                    norm_email(&u.email),
                    k.id
                ));
            }
        }
    }

    // Grants that are not grants.
    for u in &doc.users {
        let e = norm_email(&u.email);
        for k in &u.api_keys {
            match key_expiry(&k.released, &k.duration) {
                Some(Some(exp)) if exp <= now() => lints.push(format!(
                    "{e}: key '{}' expired on {} — the gate rejects it",
                    k.id,
                    format_date(exp)
                )),
                _ => {}
            }
        }
    }
    for name in doc.url_groups.keys() {
        if refs_to(&doc, name).is_empty() {
            lints.push(format!(
                "url group '@{name}' is defined but nothing references it — it grants nobody \
                 anything until some urls list names it"
            ));
        }
    }
    for (i, s) in doc.sites.iter().enumerate() {
        if let Some(j) = shadowed_by(&doc.sites, i) {
            lints.push(format!(
                "site '{}' is listed after '{}', which already answers for its urls — first \
                 match wins, so '{}' never speaks. Move it earlier: site mv {} --at {j}",
                name_of(s),
                name_of(&doc.sites[j]),
                name_of(s),
                name_of(s),
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

/// The index of an earlier site that already answers for site `i`'s urls, if any.
///
/// A heuristic, and deliberately so: matching one glob against another has no exact answer
/// (`https://x.com/*` vs `*://x.com/app1` cover each other partially). Feeding the later
/// site's pattern *text* to the earlier site's matcher catches the case that actually
/// happens — a broad site listed first — and stays quiet otherwise. It only ever warns.
fn shadowed_by(sites: &[SiteSpec], i: usize) -> Option<usize> {
    let mine = &sites[i];
    if mine.urls.is_empty() {
        return None;
    }
    for (j, earlier) in sites.iter().enumerate().take(i) {
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

/// `can EMAIL URL [--key ID]` — put the question to the gate's own decision function, and
/// exit 0 only if it says yes. What `--check-users` is to the file, this is to a grant.
fn cmd_can(mut ctx: Ctx, email: &str, url: &str) -> Result<ExitCode, String> {
    let key_id = ctx.flags.take_one("key")?;
    ctx.flags.finish()?;
    let (doc, access) = load(&ctx)?;

    let email = norm_email(email);
    let url = request_url(url);
    let at = Some(url.as_str());

    // The API-key path: a key is looked up by the sha256 of the bearer, and the file keeps
    // exactly that — so the record can be evaluated without ever holding the secret.
    if let Some(id) = key_id {
        let user = doc
            .users
            .iter()
            .find(|u| norm_email(&u.email) == email)
            .ok_or_else(|| format!("no user '{email}'"))?;
        let k = user
            .api_keys
            .iter()
            .find(|k| k.id.trim() == id.trim())
            .ok_or_else(|| format!("{email}: no api key '{id}'"))?;
        let hash = k.key_hash.trim().to_ascii_lowercase();

        let verdict = match decide_api_key(&access, &hash, at, now()) {
            KeyDecision::Granted(rec) => {
                println!("AUTHORIZED — key '{id}' is in scope for {url}");
                println!("  the application sees X-Auth-Email: {}", rec.email);
                return Ok(ExitCode::SUCCESS);
            }
            KeyDecision::Unknown => format!(
                "the gate has no key with this hash — it was skipped at load (bad key_hash: \
                 '{}')",
                k.key_hash.trim()
            ),
            KeyDecision::OwnerDenied(_) => format!("its owner {email} is on the denied list"),
            KeyDecision::Expired(_) => format!("the key is expired ({})", expiry_str(k)),
            KeyDecision::OutOfScope(_) => format!(
                "{url} is outside the key's scope ({})",
                urls_of(&k.authorized_urls, "inherited from the user")
            ),
        };
        println!("DENIED — {verdict}");
        return Ok(ExitCode::FAILURE);
    }

    // The two Cognito-backed credentials (id_token bearer, session cookie) — same rule for
    // both, since both resolve to nothing but an email.
    match decide(&access, &email, at) {
        Decision::SiteGrant(site) => {
            println!("AUTHORIZED — site '{site}' is public_auth: any identity Cognito vouches");
            println!("  for reaches {url}, enrolled or not. The roster is not consulted.");
            println!("  the application sees X-Auth-Email: {email}");
            Ok(ExitCode::SUCCESS)
        }
        Decision::RosterGrant => {
            println!("AUTHORIZED — {email} is enrolled and {url} is in their authorized_urls");
            println!("  the application sees X-Auth-Email: {email}");
            Ok(ExitCode::SUCCESS)
        }
        Decision::Vetoed => {
            println!("DENIED — {email} is on the denied list, which outranks every grant");
            Ok(ExitCode::FAILURE)
        }
        Decision::OutOfScope => {
            println!("DENIED — {url} is outside {email}'s authorized_urls, and no public_auth");
            println!("  site covers it");
            Ok(ExitCode::FAILURE)
        }
        Decision::NotEnrolled => {
            println!("DENIED — {email} is not in users, and no public_auth site covers {url}");
            Ok(ExitCode::FAILURE)
        }
    }
}

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

fn cmd_user_list(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, _) = load(&ctx)?;
    for u in &doc.users {
        print_user(u, &doc);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_user_show(ctx: Ctx, email: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, _) = load(&ctx)?;
    match user_pos(&doc, email) {
        Some(i) => {
            print_user(&doc.users[i], &doc);
            Ok(ExitCode::SUCCESS)
        }
        None => Err(format!("no user '{}'", norm_email(email))),
    }
}

fn cmd_user_add(mut ctx: Ctx, email: &str) -> Result<ExitCode, String> {
    let urls = ctx.flags.take_many("url")?;
    let note = ctx.flags.take_one("note")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let email = norm_email(email);
    if user_pos(&doc, &email).is_some() {
        return Err(format!(
            "{email} is already in users (edit them: user set {email})"
        ));
    }
    if urls.is_empty() {
        eprintln!(
            "[bb-auth-adm] WARNING: {email} has no --url, so they reach NOTHING. Access is \
             enumerated, never assumed; grant everything with --url '*://*/*'."
        );
    }
    if doc.denied.iter().any(|d| norm_email(d) == email) {
        eprintln!("[bb-auth-adm] WARNING: {email} is on the denied list — the veto wins anyway");
    }

    let mut u = UserSpec {
        email: email.clone(),
        authorized_urls: if urls.is_empty() { None } else { Some(urls) },
        ..Default::default()
    };
    if let Some(n) = note {
        u.extra.insert("notes".into(), n.into());
    }
    doc.users.push(u);
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_user_set(mut ctx: Ctx, email: &str) -> Result<ExitCode, String> {
    let new_email = ctx.flags.take_one("email")?;
    let set = ctx.flags.take_many("url")?;
    let add = ctx.flags.take_many("add-url")?;
    let rm = ctx.flags.take_many("rm-url")?;
    let clear = ctx.flags.take_flag("no-urls")?;
    let note = ctx.flags.take_one("note")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    // Renaming has to see the whole roster, so resolve the collision before borrowing.
    if let Some(new) = &new_email {
        let new = norm_email(new);
        if new != norm_email(email) && user_pos(&doc, &new).is_some() {
            return Err(format!("{new} is already in users"));
        }
    }
    let u = user_mut(&mut doc, email)?;
    let mut changed = false;
    if let Some(new) = new_email {
        u.email = norm_email(&new);
        changed = true;
    }
    changed |= edit_urls(&mut u.authorized_urls, set, add, rm, clear);
    if let Some(n) = note {
        u.extra.insert("notes".into(), n.into());
        changed = true;
    }
    if !changed {
        return Err("nothing to change (see --help)".into());
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

/// `user rm` — the row goes, and with it every key it owned (a key is a grant *tied to a
/// user*; an orphan key would be a credential with no one to answer for it).
///
/// Removing a user does **not** keep them off a `public_auth` site: there the roster is
/// never consulted. That is what `denied` is for, and it is the one thing an operator has
/// to be told here, because "I deleted them" reads like it should be enough.
fn cmd_user_rm(ctx: Ctx, email: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, access) = load(&ctx)?;
    let i = user_pos(&doc, email).ok_or_else(|| format!("no user '{}'", norm_email(email)))?;

    let u = doc.users.remove(i);
    let email = norm_email(&u.email);
    if !u.api_keys.is_empty() {
        eprintln!(
            "[bb-auth-adm] {email}: also removed {} api key(s): {}",
            u.api_keys.len(),
            u.api_keys
                .iter()
                .map(|k| k.id.trim())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if access.sites.any_public_auth() && !doc.denied.iter().any(|d| norm_email(d) == email) {
        eprintln!(
            "[bb-auth-adm] WARNING: this file has a public_auth site, and removing {email} does \
             NOT keep them out of it — the roster is not consulted there. To lock them out: \
             deny add {email}"
        );
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// api keys
// ---------------------------------------------------------------------------

fn cmd_key_list(mut ctx: Ctx) -> Result<ExitCode, String> {
    let only = ctx.flags.take_one("user")?.map(|e| norm_email(&e));
    ctx.flags.finish()?;
    let (doc, _) = load(&ctx)?;
    for u in &doc.users {
        let e = norm_email(&u.email);
        if only.as_ref().is_some_and(|o| o != &e) {
            continue;
        }
        for k in &u.api_keys {
            println!("{e}  key '{}'  {}", k.id.trim(), expiry_str(k));
            println!(
                "      urls: {}",
                urls_of(&k.authorized_urls, "inherits the user's")
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Hand the freshly minted bearer to its owner — **after** the file that carries its hash
/// is safely on disk. The other order would print a credential that authorizes nothing if
/// the write then failed, and the raw key exists nowhere else to try again with.
///
/// It goes to **stdout**, alone, so it can be piped into a secret store; everything a human
/// reads is on stderr. It is not recoverable: the file keeps the hash, and the hash *is* the
/// verification.
fn hand_over(raw: &str, what: &str, dry_run: bool) {
    if dry_run {
        eprintln!("[bb-auth-adm] --dry-run: nothing was written, so this key is void");
        return;
    }
    eprintln!("=== {what} — not stored anywhere, and it cannot be recovered ===");
    eprintln!("Authorization: Bearer {raw}");
    eprintln!("===");
    println!("{raw}");
}

/// `key add` — mint a `bbk_` bearer, store only its sha256, print the raw key once.
fn cmd_key_add(mut ctx: Ctx, email: &str) -> Result<ExitCode, String> {
    let id = ctx
        .flags
        .take_one("id")?
        .ok_or("key add needs --id LABEL (it names the key for logs and revocation)")?;
    let duration = ctx.flags.take_one("duration")?.unwrap_or("365d".into());
    let released = ctx
        .flags
        .take_one("released")?
        .unwrap_or_else(|| format_date(now()));
    let urls = ctx.flags.take_many("url")?;
    let note = ctx.flags.take_one("note")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

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
    let email = norm_email(email);
    if doc.denied.iter().any(|d| norm_email(d) == email) {
        eprintln!("[bb-auth-adm] WARNING: {email} is denied — every key of theirs is rejected");
    }
    let (raw, hash) = mint_api_key()?;
    {
        let u = user_mut(&mut doc, &email)?;
        if u.api_keys.iter().any(|k| k.id.trim() == id) {
            return Err(format!(
                "{email} already has a key '{id}' (replace its secret: key rotate {email} {id})"
            ));
        }
        let inherits = urls.is_empty();
        if inherits && u.authorized_urls.as_ref().is_none_or(|l| l.is_empty()) {
            eprintln!(
                "[bb-auth-adm] WARNING: with no --url the key inherits {email}'s scope, which is \
                 empty — it will reach nothing. Give it --url, or give the user one."
            );
        }
        let mut k = ApiKeySpec {
            id: id.clone(),
            key_hash: hash,
            released,
            duration,
            authorized_urls: if inherits { None } else { Some(urls) },
            ..Default::default()
        };
        if let Some(n) = note {
            k.extra.insert("notes".into(), n.into());
        }
        u.api_keys.push(k);
    }
    save(&ctx, &doc)?;
    hand_over(
        &raw,
        &format!("the bearer for '{id}' — give it to the client ONCE"),
        ctx.dry_run,
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_key_set(mut ctx: Ctx, email: &str, id: &str) -> Result<ExitCode, String> {
    let duration = ctx.flags.take_one("duration")?;
    let released = ctx.flags.take_one("released")?;
    let set = ctx.flags.take_many("url")?;
    let add = ctx.flags.take_many("add-url")?;
    let rm = ctx.flags.take_many("rm-url")?;
    let inherit = ctx.flags.take_flag("inherit-urls")?;
    let note = ctx.flags.take_one("note")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let k = key_mut(&mut doc, email, id)?;
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
            "released '{}' + duration '{}' is not a valid window — the gate would skip this key",
            k.released, k.duration
        ));
    }
    changed |= edit_urls(&mut k.authorized_urls, set, add, rm, inherit);
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

/// `key rotate` — same row, same scope, new secret. The old bearer stops working the moment
/// the gate reloads, which is exactly what makes this the answer to a leaked key.
fn cmd_key_rotate(ctx: Ctx, email: &str, id: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    let (raw, hash) = mint_api_key()?;
    {
        let k = key_mut(&mut doc, email, id)?;
        k.key_hash = hash;
        k.released = format_date(now());
    }
    save(&ctx, &doc)?;
    hand_over(
        &raw,
        &format!("the NEW bearer for '{id}' — the old one dies at the next reload"),
        ctx.dry_run,
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_key_rm(ctx: Ctx, email: &str, id: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    let u = user_mut(&mut doc, email)?;
    let i = u
        .api_keys
        .iter()
        .position(|k| k.id.trim() == id.trim())
        .ok_or_else(|| format!("{}: no api key '{id}'", norm_email(email)))?;
    u.api_keys.remove(i);
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// sites
// ---------------------------------------------------------------------------

fn cmd_site_list(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, _) = load(&ctx)?;
    for (i, s) in doc.sites.iter().enumerate() {
        println!(
            "{i}. {}  public_auth={}{}",
            name_of(s),
            if s.public_auth { "YES" } else { "no" },
            match &s.login_url {
                Some(l) => format!("  login_url={l}"),
                None => String::new(),
            }
        );
        for u in &s.urls {
            println!("     {u}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `site add` — a site describes a **place**, never a person: there is no flag here that
/// names a user, and there never may be. Grants to named users live in exactly one place,
/// `users[].authorized_urls`.
fn cmd_site_add(mut ctx: Ctx, name: &str) -> Result<ExitCode, String> {
    let urls = ctx.flags.take_many("url")?;
    let public_auth = ctx.flags.take_flag("public-auth")?;
    let login_url = ctx.flags.take_one("login-url")?;
    let at = ctx.flags.take_one("at")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("a site needs a name".into());
    }
    if site_pos(&doc, &name).is_some() {
        return Err(format!(
            "site '{name}' already exists (edit it: site set {name})"
        ));
    }
    if urls.is_empty() {
        eprintln!("[bb-auth-adm] WARNING: site '{name}' has no --url — it matches nothing");
    }
    if public_auth {
        eprintln!(
            "[bb-auth-adm] WARNING: '{name}' is public_auth — ANY identity Cognito vouches for \
             reaches it, enrolled or not. Cognito self-signup is open, so that means anyone who \
             can register. The right grant for an onboarding area, the wrong one for anything \
             else."
        );
    }

    let site = SiteSpec {
        name: name.clone(),
        urls,
        public_auth,
        login_url,
    };
    let at = match at {
        Some(n) => n
            .parse::<usize>()
            .map_err(|_| format!("--at: '{n}' is not a position"))?
            .min(doc.sites.len()),
        None => doc.sites.len(),
    };
    doc.sites.insert(at, site);

    if let Some(j) = shadowed_by(&doc.sites, at) {
        eprintln!(
            "[bb-auth-adm] WARNING: site '{}' is listed first and already answers for these \
             urls — first match wins, so '{name}' will never speak. Put it earlier: \
             site mv {name} --at {j}",
            name_of(&doc.sites[j])
        );
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_site_set(mut ctx: Ctx, name: &str) -> Result<ExitCode, String> {
    let new_name = ctx.flags.take_one("name")?;
    let set = ctx.flags.take_many("url")?;
    let add = ctx.flags.take_many("add-url")?;
    let rm = ctx.flags.take_many("rm-url")?;
    let public_auth = ctx.flags.take_flag("public-auth")?;
    let no_public_auth = ctx.flags.take_flag("no-public-auth")?;
    let login_url = ctx.flags.take_one("login-url")?;
    let no_login_url = ctx.flags.take_flag("no-login-url")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    if public_auth && no_public_auth {
        return Err("--public-auth and --no-public-auth contradict each other".into());
    }
    let i = site_pos(&doc, name).ok_or_else(|| format!("no site '{}'", name.trim()))?;
    if let Some(n) = &new_name {
        if site_pos(&doc, n).is_some_and(|j| j != i) {
            return Err(format!("site '{}' already exists", n.trim()));
        }
    }
    let s = &mut doc.sites[i];
    let mut changed = false;
    if let Some(n) = new_name {
        s.name = n.trim().to_string();
        changed = true;
    }
    // `urls` is a plain Vec here (a site with no urls matches nothing — there is no
    // "inherit" to fall back to), so run the same edits over an Option and unwrap.
    let mut urls = Some(std::mem::take(&mut s.urls));
    changed |= edit_urls(&mut urls, set, add, rm, false);
    s.urls = urls.unwrap_or_default();
    if public_auth || no_public_auth {
        s.public_auth = public_auth;
        changed = true;
    }
    if let Some(l) = login_url {
        s.login_url = Some(l);
        changed = true;
    }
    if no_login_url {
        s.login_url = None;
        changed = true;
    }
    if !changed {
        return Err("nothing to change (see --help)".into());
    }
    if s.public_auth {
        eprintln!(
            "[bb-auth-adm] WARNING: '{}' is public_auth — ANY authenticated identity reaches it, \
             enrolled or not",
            name_of(s)
        );
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

/// `site mv` — order is meaning: [`Sites::resolve`](bb_auth_core::Sites::resolve) is
/// first-match-wins, so moving a record changes who answers for a URL — and so who gets in.
fn cmd_site_mv(mut ctx: Ctx, name: &str) -> Result<ExitCode, String> {
    let at = ctx
        .flags
        .take_one("at")?
        .ok_or("site mv needs --at N (0 = first; the first site whose urls match answers)")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let i = site_pos(&doc, name).ok_or_else(|| format!("no site '{}'", name.trim()))?;
    let at: usize = at
        .parse()
        .map_err(|_| format!("--at: '{at}' is not a position"))?;
    if at >= doc.sites.len() {
        return Err(format!(
            "--at {at}: there are {} sites (0..={})",
            doc.sites.len(),
            doc.sites.len().saturating_sub(1)
        ));
    }
    let s = doc.sites.remove(i);
    doc.sites.insert(at, s);
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_site_rm(ctx: Ctx, name: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    let i = site_pos(&doc, name).ok_or_else(|| format!("no site '{}'", name.trim()))?;
    let s = doc.sites.remove(i);
    if s.public_auth {
        eprintln!(
            "[bb-auth-adm] '{}' was public_auth — the identities it let in with no roster entry \
             now reach nothing",
            name_of(&s)
        );
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// url groups
// ---------------------------------------------------------------------------

/// Everything that names `@name`: users by email, keys as `email/id`, sites as
/// `site 'NAME'`.
///
/// [`group_ref`] is what decides whether an entry is a reference, so this cannot drift
/// from what the gate expands. The gate would refuse a
/// file with a dangling reference anyway — [`save`] compiles before it writes — and this
/// is what turns that refusal into a list of places to go and fix.
fn refs_to(doc: &AccessFile, name: &str) -> Vec<String> {
    let names = |urls: &[String]| urls.iter().any(|u| group_ref(u) == Some(name));
    let mut out = Vec::new();
    for s in &doc.sites {
        if names(&s.urls) {
            out.push(format!("site '{}'", name_of(s)));
        }
    }
    for u in &doc.users {
        if u.authorized_urls.as_deref().is_some_and(names) {
            out.push(norm_email(&u.email));
        }
        for k in &u.api_keys {
            if k.authorized_urls.as_deref().is_some_and(names) {
                out.push(format!("{}/{}", norm_email(&u.email), k.id.trim()));
            }
        }
    }
    out
}

fn cmd_url_group_list(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (doc, _) = load(&ctx)?;
    for (name, urls) in &doc.url_groups {
        let refs = refs_to(&doc, name);
        let by = if refs.is_empty() {
            "referenced by NOTHING".to_string()
        } else {
            format!("referenced by {}", refs.join(", "))
        };
        println!("@{name}  ({} urls, {by})", urls.len());
        for u in urls {
            println!("     {u}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `url-group add` — a group is abbreviation, not a grant: defining one authorizes nobody
/// until some urls list names it.
fn cmd_url_group_add(mut ctx: Ctx, name: &str) -> Result<ExitCode, String> {
    let urls = ctx.flags.take_many("url")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("a url group needs a name".into());
    }
    if doc.url_groups.contains_key(&name) {
        return Err(format!(
            "url group '@{name}' already exists (edit it: url-group set {name})"
        ));
    }
    if urls.is_empty() {
        eprintln!(
            "[bb-auth-adm] WARNING: url group '@{name}' has no --url — a reference to it grants \
             nothing"
        );
    }
    doc.url_groups.insert(name, urls);
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

/// `url-group set` — the same url edits as `user set`. There is deliberately no rename: a
/// reference names a group by its exact spelling, so renaming one would be a silent
/// re-pointing of every list that used it. Add the new name, move the references, drop
/// the old one — three steps the gate re-validates one by one.
fn cmd_url_group_set(mut ctx: Ctx, name: &str) -> Result<ExitCode, String> {
    let set = ctx.flags.take_many("url")?;
    let add = ctx.flags.take_many("add-url")?;
    let rm = ctx.flags.take_many("rm-url")?;
    let clear = ctx.flags.take_flag("no-urls")?;
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let name = name.trim().to_string();
    let changed = {
        let entry = doc
            .url_groups
            .get_mut(&name)
            .ok_or_else(|| format!("no url group '@{name}'"))?;
        // A group's patterns are a plain Vec — there is no "inherit" to fall back to, so
        // --no-urls empties the group rather than deleting it (that is `url-group rm`).
        let mut urls = Some(std::mem::take(entry));
        let changed = edit_urls(&mut urls, set, add, rm, clear);
        *entry = urls.unwrap_or_default();
        changed
    };
    if !changed {
        return Err("nothing to change (see --help)".into());
    }
    if doc.url_groups[&name].is_empty() {
        eprintln!(
            "[bb-auth-adm] WARNING: url group '@{name}' now has no urls — every list that \
             references it loses those patterns"
        );
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_url_group_rm(ctx: Ctx, name: &str) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;

    let name = name.trim().to_string();
    if !doc.url_groups.contains_key(&name) {
        return Err(format!("no url group '@{name}'"));
    }
    let refs = refs_to(&doc, &name);
    if !refs.is_empty() {
        return Err(format!(
            "url group '@{name}' is still referenced by {} — the gate would reject the file. \
             Change those lists first, then remove the group.",
            refs.join(", ")
        ));
    }
    doc.url_groups.remove(&name);
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
        println!("{}", norm_email(e));
    }
    Ok(ExitCode::SUCCESS)
}

/// `deny add` — the veto. It is not the same as deleting the user's row: on a `public_auth`
/// site the roster is never consulted, so for an un-enrolled identity this is the only
/// denial there is; and for an enrolled one it is a suspension, not a deletion — scope and
/// keys survive, so re-enabling is one `deny rm`.
fn cmd_deny_add(ctx: Ctx, emails: &[&str]) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    let mut changed = false;
    for e in emails {
        let e = norm_email(e);
        if e.is_empty() {
            continue;
        }
        if doc.denied.iter().any(|d| norm_email(d) == e) {
            eprintln!("[bb-auth-adm] {e} is already denied");
            continue;
        }
        doc.denied.push(e.clone());
        changed = true;
        if user_pos(&doc, &e).is_some() {
            eprintln!(
                "[bb-auth-adm] {e} stays in users — the veto wins on every credential, and their \
                 scope and keys survive the lockout"
            );
        }
    }
    if !changed {
        return Err("nothing to deny".into());
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_deny_rm(ctx: Ctx, emails: &[&str]) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (mut doc, _) = load(&ctx)?;
    let before = doc.denied.len();
    let want: Vec<String> = emails.iter().map(|e| norm_email(e)).collect();
    doc.denied.retain(|d| !want.contains(&norm_email(d)));
    if doc.denied.len() == before {
        return Err(format!("none of {} were denied", want.join(", ")));
    }
    save(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}
