//! bb-auth-adm — edit a bb-auth **access file** (`BB_AUTH_ACCESS_FILE`, a.k.a. access.json).
//!
//! CRUD over every section of the file the gate actually enforces: `applications` and their
//! scopes, `user_groups`, `denied`, `users` and their `api_keys`. Plus the two things an
//! operator otherwise has to do by hand and by eye: minting a `bbk_` key, and answering
//! "would this credential reach that URL?".
//!
//! It shares [`bb_auth_core`] with the gate, and that is the whole design:
//!
//! * **It cannot write a file the gate would reject.** Every mutation goes through
//!   [`AccessWrite`], which serializes, re-parses and compiles with the same parser
//!   `bb-auth --check-access` and the running gate use, *before* anything reaches the disk.
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
//! bb-auth-adm -f deploy/access.json app add mpa --base 'https://app.x.com/mpa'
//! bb-auth-adm -f deploy/access.json scope add mpa admin --url 'https://app.x.com/mpa/admin/*' \
//!     --access restricted --user bob@x.com
//! bb-auth-adm -f deploy/access.json key add bob@x.com --id laptop --duration 365d
//! bb-auth-adm -f deploy/access.json can bob@x.com https://app.x.com/mpa/admin/panel
//! ```
//!
//! Editing the file is not enough to change anything: the gate re-reads it on `systemctl
//! reload bb-auth` (SIGHUP) or a restart.

use std::collections::HashSet;
use std::process::ExitCode;

use bb_auth_core::{
    add_api_key, add_application, add_denied, add_scope, add_user, add_user_email, add_user_group,
    app_mut, app_pos, compile_app_client_id, compile_asset_url, compile_brand_name,
    compile_login_url, compile_oauth_domain, decide, decide_api_key, default_settings_path,
    edit_url_list, edit_urls, format_date, key_expiry, key_mut, mint_uuid, move_scope, norm_email,
    now, open_access_file, open_settings_file, parse_exclusion, remove_api_key, remove_application,
    remove_denied, remove_scope, remove_user, remove_user_email, remove_user_group,
    rename_application, rename_scope, request_url, rotate_api_key, scope_pos, shadowing_scope,
    user_group_mut, user_group_refs, user_label, user_pos, version_line, well_formed_uuid, Access,
    AccessFile, AccessWrite, ApiKeySpec, AppSpec, Decision, KeyDecision, ScopeSpec, SealedKey,
    SettingsFile, SettingsWrite, SocialButtonSpec, Subject, UiTheme, UserSpec, WiredButton,
    Written, ACCESS_FILE_VERSION, SETTINGS_VERSION,
};

const USAGE: &str = "\
bb-auth-adm — edit a bb-auth access file (access.json)

usage: bb-auth-adm [-f FILE] [--dry-run] <command> [args]

  -f, --file FILE   the access file (default: $BB_AUTH_ACCESS_FILE)
  -s, --settings-file FILE
                    the settings file (default: $BB_AUTH_SETTINGS_FILE, else settings.json
                    beside the access file)
  --dry-run         print the resulting file to stdout, write nothing

file
  init                          create an empty access file (refuses to clobber one)
  show                          the file as the gate resolves it
  check [--strict]              validate with the gate's own parser, then lint
                                (--strict: exit 1 if anything was linted)
  can WHO URL [--as login|api_key] [--key ID]
                                would this credential reach this URL?
                                (exit 0 = yes, 1 = no, 2 = the question was unanswerable)

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

settings                        the OTHER file: what takes effect with no restart at all
  settings init                 create a settings file (refuses to clobber one)
  settings show                 what the gate and the GUI read from it
  settings set [--claims LIST] [--identity LIST] [--session-ttl SECS]
               [--unverified-social true|false] [--providers LIST] [--no-providers]
               [--login-url URL] [--client-id ID] [--oauth-domain HOST]
               [--social-callback-url URL]
               [--social-buttons IDP=APPCLIENT,...] [--no-social-buttons]
               [--brand NAME] [--stylesheet URL] [--logo URL] [--theme system|light|dark]
  settings admin add EMAIL...   who may use bb-auth-web. NEVER empty, never 'everyone'
  settings admin rm EMAIL...
  Default path: settings.json beside the access file; -s/--settings-file, or
  $BB_AUTH_SETTINGS_FILE. These are hot BECAUSE they are in a file: a process cannot
  re-read its own environment, so an env var could never be one.
  The Cognito app clients live here and nowhere else. --client-id is the one the email
  flow uses; every --social-buttons entry is `provider=app client`, because Cognito
  federates per app client and two providers may sit on two of them. Together they ARE the
  accepted audiences: an id_token carries the app client it was minted for in `aud`, so
  naming an app client here is what makes the gate accept its tokens. The pool they must
  belong to is BB_AUTH_COGNITO_ISSUER, which stays in the env file, so this file chooses
  among the app clients of one pool and can never reach another.
  The last four are the `ui` section, and they are the look of every page BOTH programs
  emit: the gate's login page and bb-auth-web itself. --stylesheet loads after the built-in
  stylesheet and is meant to redefine its custom properties, so a deployment restyles both
  surfaces with one file; unset, or unreachable, and each page keeps the look it was
  compiled with. Pass an empty value to unset any of them.

--url takes a <scheme>://<host>/<path> glob; repeat it, or comma-separate. `*` never
crosses '/' unless it is the pattern's last character; blanket coverage is '*://*/*'.
A --base is LITERAL (no wildcards): it is the area an application owns, and every scope
pattern must lie inside it. Access is enumerated, never assumed: a URL no application
covers is reachable by nobody.

An edit takes effect when the gate re-reads the file: systemctl reload bb-auth.
";

/// Exit codes, and there are three because a caller has to be able to tell them apart.
///
/// `0` yes, `1` no, **`2` I could not tell**. Everything used to be `0` or `1`, so a script
/// running `can` could not distinguish "the gate would refuse this request" from "you passed
/// a URL I could not parse" or "that file does not exist": the same code for the answer being
/// no and for there being no answer. `2` is the shell's own convention for a usage error and
/// is what `bb-auth --check-access` already exits with on a bad invocation.
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[bb-auth-adm] {e}");
            // Every `Err` out of `run` is one of two things: a bad invocation, or a file this
            // tool could not read or write. Neither is a verdict about a request, and `can`
            // is the command that makes the difference matter.
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    // Which build this is, before anything else is parsed. All three programs answer it the
    // same way and with the same string: a package version cannot tell a tagged release from
    // a working tree somebody built by hand, and on a host that is the first question.
    if argv.iter().any(|a| a == "--version") {
        println!("{}", version_line("bb-auth-adm"));
        return Ok(ExitCode::SUCCESS);
    }
    if argv.is_empty() || argv.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }

    // Global options first, so `-f` may sit anywhere.
    let mut file: Option<String> = None;
    let mut settings_file: Option<String> = None;
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
            "-s" | "--settings-file" => {
                let v = argv
                    .get(i + 1)
                    .cloned()
                    .ok_or("-s/--settings-file needs a path".to_string())?;
                settings_file = Some(v);
                argv.drain(i..=i + 1);
            }
            "--dry-run" => {
                dry_run = true;
                argv.remove(i);
            }
            _ => i += 1,
        }
    }
    let access = file
        .or_else(|| std::env::var("BB_AUTH_ACCESS_FILE").ok())
        .filter(|p| !p.trim().is_empty());

    // Derived from the access file's own path when nothing names it, exactly as the gate
    // derives it: the two files live together, and an operator who moved one moved both.
    let settings = settings_file
        .or_else(|| std::env::var("BB_AUTH_SETTINGS_FILE").ok())
        .filter(|p| !p.trim().is_empty())
        .or_else(|| access.as_deref().map(default_settings_path));

    let (words, flags) = parse_args(&argv)?;
    let cmd: Vec<&str> = words.iter().map(String::as_str).collect();

    // Which file this invocation is missing depends on which file it is about. A `settings`
    // command that refused because nobody named the *access* file would send an operator to
    // look at the wrong one, which is the whole reason this is not a single check.
    let about_settings = cmd.first() == Some(&"settings");
    let ctx = Ctx {
        path: match (&access, about_settings) {
            (Some(p), _) => p.clone(),
            // Never read: every `settings` arm works on `settings_path`. Empty rather than
            // an `Option` so the forty arms that do use it stay as they read now.
            (None, true) => String::new(),
            (None, false) => {
                return Err("no access file: pass -f FILE or set BB_AUTH_ACCESS_FILE".into())
            }
        },
        settings_path: match settings {
            Some(p) => p,
            None => {
                return Err(
                    "no settings file: pass -s FILE, or -f FILE to take the one \
                            beside it, or set BB_AUTH_SETTINGS_FILE"
                        .into(),
                )
            }
        },
        dry_run,
        flags,
    };

    match cmd.as_slice() {
        ["init"] => cmd_init(ctx),
        ["show"] => cmd_show(ctx),
        ["check"] => cmd_check(ctx),
        ["can", who, url] => cmd_can(ctx, who, url),

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

        ["settings", "init"] => cmd_settings_init(ctx),
        ["settings", "show"] => cmd_settings_show(ctx),
        ["settings", "set"] => cmd_settings_set(ctx),
        ["settings", "admin", "add", rest @ ..] if !rest.is_empty() => {
            cmd_settings_admin(ctx, rest, true)
        }
        ["settings", "admin", "rm", rest @ ..] if !rest.is_empty() => {
            cmd_settings_admin(ctx, rest, false)
        }

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
    /// The access file. Empty on a `settings` invocation that named no access file, which is
    /// the one case where there is nothing to name: those commands read `settings_path` and
    /// never this.
    path: String,
    /// The settings file, which only the `settings` commands touch. Resolved for every
    /// invocation rather than only for those, so that `--help` and an error message can name
    /// it without the caller having had to ask for it.
    settings_path: String,
    dry_run: bool,
    flags: Flags,
}

/// Parsed `--flag [value]` options, in order. A flag with no value (the next token is
/// another flag, or the end) is a boolean.
#[derive(Debug)]
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

/// What one lookup of a flag found. Three states, and they are three because a flag can be
/// **absent**, **bare** (`--force`), or **valued** (`--force=no`), and the difference between
/// the last two is what six clearing flags in this tool are built on.
///
/// It exists because that difference used to be carried by an error *string*:
/// [`Flags::take_flag`] asked [`Flags::take_one`] for a value and read `e.contains("needs a
/// value")` off the refusal to decide that the flag was bare. Rewording one message would
/// have turned every `--no-scopes`, `--clear` and `--force` into a hard error, and nothing in
/// `cargo test` would have noticed, in the tool that writes the production access file as
/// root over SSH.
#[derive(Debug, PartialEq, Eq)]
enum Taken {
    Absent,
    Bare,
    Valued(String),
}

impl Flags {
    /// What `name` was given as, consuming it. Repeated means an error, since silently
    /// keeping one of two contradictory values is how an access file ends up not saying
    /// what its author thought.
    fn take(&mut self, name: &str) -> Result<Taken, String> {
        let mut found: Option<Option<String>> = None;
        let mut n = 0;
        self.0.retain(|(k, v)| {
            if k != name {
                return true;
            }
            n += 1;
            found = Some(v.clone());
            false
        });
        match (n, found) {
            (0, _) => Ok(Taken::Absent),
            (1, Some(Some(v))) => Ok(Taken::Valued(v)),
            (1, _) => Ok(Taken::Bare),
            _ => Err(format!("--{name} given more than once")),
        }
    }

    /// The single value of `name`, or `None`. A bare `--name` is an error here: a flag that
    /// takes a value and was given none is a typo, not a boolean.
    fn take_one(&mut self, name: &str) -> Result<Option<String>, String> {
        match self.take(name)? {
            Taken::Absent => Ok(None),
            Taken::Bare => Err(format!("--{name} needs a value")),
            Taken::Valued(v) => Ok(Some(v)),
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
    ///
    /// The bare case is read off [`Taken`] and not off the text of an error, which is what it
    /// used to be: see that type for what depended on the wording of a string.
    fn take_flag(&mut self, name: &str) -> Result<bool, String> {
        match self.take(name)? {
            Taken::Absent => Ok(false),
            Taken::Bare => Ok(true),
            Taken::Valued(v) => match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => Ok(true),
                "0" | "false" | "no" | "off" => Ok(false),
                other => Err(format!("--{name}: expected true/false, got '{other}'")),
            },
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
    let doc = AccessFile {
        version: ACCESS_FILE_VERSION,
        ..Default::default()
    };
    // Through the library's writer like every other command here, and not a `std::fs::write`
    // of its own: the bytes are compiled with the gate's parser before they land, the file is
    // `0640` from its first byte, and "only if absent" is the filesystem's answer rather than
    // an `exists()` this function asked a moment earlier.
    let write = AccessWrite::prepare(&doc)?;
    if ctx.dry_run {
        print!("{}", write.json());
        eprintln!("[bb-auth-adm] --dry-run: {} NOT created", ctx.path);
        return Ok(ExitCode::SUCCESS);
    }
    write.create(&ctx.path)?;
    eprintln!(
        "[bb-auth-adm] created {}: it grants nobody anything yet",
        ctx.path
    );
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// The settings file
// ---------------------------------------------------------------------------
//
// The other file, and the only one whose values need no restart. Everything below goes
// through the library exactly as the access-file commands do: one parser, one writer, one
// answer to "would the gate accept this?", so an edit made here and one made in the GUI are
// the same edit.

/// A tri-state boolean flag: absent (leave the setting alone), or an explicit value.
///
/// [`Flags::take_flag`] cannot serve here, because it reads an absent flag as `false`, and
/// on a `set` command that would turn every unrelated edit into a silent
/// `allow_unverified_social = false`.
fn take_tristate(flags: &mut Flags, name: &str) -> Result<Option<bool>, String> {
    match flags.take_one(name) {
        Ok(None) => Ok(None),
        Ok(Some(v)) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(Some(true)),
            "0" | "false" | "no" | "off" => Ok(Some(false)),
            other => Err(format!("--{name}: expected true/false, got '{other}'")),
        },
        // a bare `--flag` lands here, and means the same as `=true`
        Err(e) if e.contains("needs a value") => Ok(Some(true)),
        Err(e) => Err(e),
    }
}

/// The settings document, refusing to start from one the services would reject.
fn load_settings(ctx: &Ctx) -> Result<SettingsFile, String> {
    let (doc, _) = open_settings_file(&ctx.settings_path).map_err(|e| {
        format!(
            "{e}\n[bb-auth-adm] create one with: bb-auth-adm -s {} settings init",
            ctx.settings_path
        )
    })?;
    Ok(doc)
}

/// Check the edit with the parser both services use, then write it.
///
/// The reload line says `reload`, not `restart`, and that is the whole point of this file: a
/// value here is live on the next request. On a host with `bb-auth-reload.path` installed the
/// operator does not even have to run it.
fn save_settings(ctx: &Ctx, doc: &SettingsFile) -> Result<(), String> {
    let pending = SettingsWrite::prepare(doc)?;
    if ctx.dry_run {
        print!("{}", pending.json());
        eprintln!("[bb-auth-adm] --dry-run: {} NOT written", ctx.settings_path);
        return Ok(());
    }
    let written = pending.commit(&ctx.settings_path)?;
    eprintln!(
        "[bb-auth-adm] previous file kept at {}",
        written.backup.display()
    );
    let s = pending.settings();
    eprintln!(
        "[bb-auth-adm] wrote {}: identity={}, {} profile claim(s), session_ttl={}s, {} admin(s)",
        ctx.settings_path,
        s.identity_attrs
            .iter()
            .map(|a| a.attr.as_str())
            .collect::<Vec<_>>()
            .join(","),
        s.profile_claims.len(),
        s.session_ttl,
        s.admins.len()
    );
    eprintln!("[bb-auth-adm] the gate re-reads it on: systemctl reload bb-auth");
    Ok(())
}

/// `settings init` creates a new settings file: a version and nothing else, which compiles to
/// the default of every setting it can hold.
///
/// Refuses to overwrite, for the reason `init` refuses to overwrite an access file: every
/// other command starts by reading, so this is the only way to lose one.
fn cmd_settings_init(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let doc = SettingsFile {
        version: SETTINGS_VERSION,
        ..Default::default()
    };
    // The access file's `init`, on the other file: see `cmd_init`.
    let write = SettingsWrite::prepare(&doc)?;
    if ctx.dry_run {
        print!("{}", write.json());
        eprintln!("[bb-auth-adm] --dry-run: {} NOT created", ctx.settings_path);
        return Ok(ExitCode::SUCCESS);
    }
    write.create(&ctx.settings_path)?;
    eprintln!(
        "[bb-auth-adm] created {}: the defaults, and no bb-auth-web administrator yet",
        ctx.settings_path
    );
    Ok(ExitCode::SUCCESS)
}

/// `settings show`: the file as the two services resolve it, defaults filled in.
///
/// Every line names the derived header where there is one, because that is the half an
/// operator cannot compute: they configure a claim and nginx configures a header.
fn cmd_settings_show(ctx: Ctx) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let (_, s) = open_settings_file(&ctx.settings_path)?;
    println!("file: {}", ctx.settings_path);
    println!();
    println!("gate");
    println!(
        "  identity_attrs          {}",
        s.identity_attrs
            .iter()
            .map(|a| format!("{} -> {}", a.attr, a.header))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  profile_claims          {}",
        match s.profile_claims.len() {
            0 => "(none)".to_string(),
            _ => s
                .profile_claims
                .iter()
                .map(|c| format!("{} -> {}", c.claim, c.header))
                .collect::<Vec<_>>()
                .join(", "),
        }
    );
    println!(
        "  allow_unverified_social {}{}",
        s.allow_unverified_social,
        match (&s.social_providers, s.allow_unverified_social) {
            (Some(p), true) => format!("  (providers: {})", p.join(", ")),
            (None, true) => "  (any federated provider)".to_string(),
            _ => String::new(),
        }
    );
    println!(
        "  login_url               {}",
        match s.login_url.as_str() {
            "" => "(none: the gate's own /auth/login)",
            url => url,
        }
    );
    println!(
        "  client_id               {}",
        match s.client_id.as_str() {
            "" => "(none: no login can complete)",
            id => id,
        }
    );
    println!(
        "  oauth_domain            {}",
        s.oauth_domain
            .as_deref()
            .unwrap_or("(none: no social sign-in)")
    );
    println!(
        "  social_callback_url     {}",
        s.social_callback_url.as_deref().unwrap_or("(none)")
    );
    println!(
        "  social_buttons          {}",
        match s.social_buttons.len() {
            0 => "(none: the sign-in page offers no social button)".to_string(),
            _ => s
                .social_buttons
                .iter()
                .map(|b| format!("{}={}", b.idp, b.audience))
                .collect::<Vec<_>>()
                .join(", "),
        }
    );
    // Derived, and printed as such: there is no list to keep in step, which is the whole
    // reason the app clients moved into this file.
    println!(
        "  (audiences)             {}",
        match s.audiences.len() {
            0 => "(none)".to_string(),
            _ => s.audiences.join(", "),
        }
    );
    println!(
        "  session_ttl_secs        {} ({} days)",
        s.session_ttl,
        s.session_ttl / 86_400
    );
    println!();
    println!("web");
    println!(
        "  admins                  {}",
        match s.admins.len() {
            0 => "(none: bb-auth-web will refuse to serve)".to_string(),
            _ => s.admins.join(", "),
        }
    );
    println!();
    println!("ui");
    // "(built-in)" rather than "(none)" for the two URLs: an unset stylesheet is not a page
    // with no styling, it is a page wearing the one compiled into the binary, and the
    // difference is the whole design.
    println!(
        "  brand_name              {}",
        s.brand_name.as_deref().unwrap_or("(each page's own name)")
    );
    println!(
        "  stylesheet_url          {}",
        s.stylesheet_url.as_deref().unwrap_or("(built-in only)")
    );
    println!(
        "  logo_url                {}",
        s.logo_url.as_deref().unwrap_or("(none)")
    );
    println!(
        "  theme                   {}{}",
        s.theme.code(),
        match s.theme {
            UiTheme::System => "  (follow the browser and the OS)",
            _ => "",
        }
    );
    Ok(ExitCode::SUCCESS)
}

/// `settings set`: change one or more of them. Absent flags leave their setting alone;
/// `--no-claims` and `--no-providers` are how a list is emptied, the spelling `scope set` and
/// `key set` already use. The four `ui` settings are emptied by passing an empty string, since
/// each holds one value and "" is what unset means for all of them.
fn cmd_settings_set(mut ctx: Ctx) -> Result<ExitCode, String> {
    let claims = ctx.flags.take_many("claims")?;
    let no_claims = ctx.flags.take_flag("no-claims")?;
    let identity = ctx.flags.take_many("identity")?;
    let ttl = ctx.flags.take_one("session-ttl")?;
    let social = take_tristate(&mut ctx.flags, "unverified-social")?;
    let providers = ctx.flags.take_many("providers")?;
    let login_url = ctx.flags.take_one("login-url")?;
    let client_id = ctx.flags.take_one("client-id")?;
    let domain = ctx.flags.take_one("oauth-domain")?;
    let callback = ctx.flags.take_one("social-callback-url")?;
    let buttons = ctx.flags.take_many("social-buttons")?;
    let no_buttons = ctx.flags.take_flag("no-social-buttons")?;
    let no_providers = ctx.flags.take_flag("no-providers")?;
    let stylesheet = ctx.flags.take_one("stylesheet")?;
    let logo = ctx.flags.take_one("logo")?;
    let brand = ctx.flags.take_one("brand")?;
    let theme = ctx.flags.take_one("theme")?;
    ctx.flags.finish()?;

    if !claims.is_empty() && no_claims {
        return Err("--claims and --no-claims contradict each other".into());
    }
    if !providers.is_empty() && no_providers {
        return Err("--providers and --no-providers contradict each other".into());
    }
    if !buttons.is_empty() && no_buttons {
        return Err("--social-buttons and --no-social-buttons contradict each other".into());
    }
    let nothing = claims.is_empty()
        && !no_claims
        && identity.is_empty()
        && ttl.is_none()
        && social.is_none()
        && providers.is_empty()
        && !no_providers
        && login_url.is_none()
        && client_id.is_none()
        && domain.is_none()
        && callback.is_none()
        && buttons.is_empty()
        && !no_buttons
        && stylesheet.is_none()
        && logo.is_none()
        && brand.is_none()
        && theme.is_none();
    if nothing {
        return Err("nothing to set (see --help)".into());
    }

    let mut doc = load_settings(&ctx)?;
    if no_claims {
        doc.gate.profile_claims.clear();
    } else if !claims.is_empty() {
        doc.gate.profile_claims = claims;
    }
    if !identity.is_empty() {
        doc.gate.identity_attrs = identity;
    }
    if let Some(t) = ttl {
        doc.gate.session_ttl_secs = t
            .trim()
            .parse()
            .map_err(|_| format!("--session-ttl: '{t}' is not a number of seconds"))?;
    }
    if let Some(v) = social {
        doc.gate.allow_unverified_social = v;
    }
    if no_providers {
        doc.gate.social_providers.clear();
    } else if !providers.is_empty() {
        doc.gate.social_providers = providers;
    }
    // The Cognito wiring. Each value is validated here as well as at the write, for the
    // reason the `ui` values are: the message then names the flag that was typed rather than
    // the field it lands in. Empty is how each of them is unset, so none needs a `--no-`
    // spelling of its own.
    if let Some(u) = login_url {
        if !u.trim().is_empty() {
            compile_login_url(&u).map_err(|e| format!("--login-url: {e}"))?;
        }
        doc.gate.login_url = u.trim().to_string();
    }
    if let Some(id) = client_id {
        doc.gate.client_id = compile_app_client_id("--client-id", &id)?;
    }
    if let Some(d) = domain {
        doc.gate.oauth_domain =
            compile_oauth_domain(&d).map_err(|e| e.replace("oauth_domain", "--oauth-domain"))?;
    }
    if let Some(u) = callback {
        compile_asset_url("--social-callback-url", &u)?;
        doc.gate.social_callback_url = u.trim().to_string();
    }
    // Which social buttons the sign-in page offers, and the app client each runs through.
    // Emptying the list takes the whole section off the page, which is the same page a
    // deployment with no oauth_domain at all serves.
    if no_buttons {
        doc.gate.social_buttons.clear();
    } else if !buttons.is_empty() {
        doc.gate.social_buttons = buttons
            .iter()
            .map(|entry| match entry.split_once('=') {
                Some((idp, aud)) => Ok(SocialButtonSpec::Wired(WiredButton {
                    idp: idp.trim().to_string(),
                    audience: aud.trim().to_string(),
                })),
                // Refused rather than guessed: there is no app client to fall back on any
                // more, and a button without one could not be drawn.
                None => Err(format!(
                    "--social-buttons: '{entry}' has no app client; write it as \
                     provider=<app client id>"
                )),
            })
            .collect::<Result<Vec<_>, String>>()?;
    }
    // The `ui` four. Each is validated here rather than left to the write, so the error names
    // the flag the operator typed instead of the field name in the file; the write validates
    // them again anyway, which is the guarantee, and this is only the better sentence.
    if let Some(u) = stylesheet {
        compile_asset_url("--stylesheet", &u)?;
        doc.ui.stylesheet_url = u.trim().to_string();
    }
    if let Some(u) = logo {
        compile_asset_url("--logo", &u)?;
        doc.ui.logo_url = u.trim().to_string();
    }
    if let Some(n) = brand {
        compile_brand_name(&n).map_err(|e| e.replace("brand_name", "--brand"))?;
        doc.ui.brand_name = n.trim().to_string();
    }
    if let Some(t) = theme {
        let parsed = UiTheme::parse(&t)
            .ok_or_else(|| format!("--theme: '{t}' is not one of system, light, dark"))?;
        doc.ui.theme = parsed.code().to_string();
    }
    save_settings(&ctx, &doc)?;
    Ok(ExitCode::SUCCESS)
}

/// `settings admin add|rm`: who may use `bb-auth-web`.
///
/// Removing the last one is refused, and that refusal is the same rule the binary enforces at
/// startup: an empty list must never come to mean "everyone". What this tool will happily do,
/// and the GUI will not, is remove *the person running it*, because this is the escape hatch
/// for exactly that case, reached over SSH by somebody who already has root.
fn cmd_settings_admin(ctx: Ctx, who: &[&str], add: bool) -> Result<ExitCode, String> {
    ctx.flags.finish()?;
    let mut doc = load_settings(&ctx)?;
    let mut changed = 0;
    for raw in who {
        let email = norm_email(raw);
        if email.is_empty() {
            continue;
        }
        let at = doc.web.admins.iter().position(|a| norm_email(a) == email);
        match (add, at) {
            (true, None) => {
                doc.web.admins.push(email.clone());
                changed += 1;
            }
            (true, Some(_)) => eprintln!("[bb-auth-adm] {email} is already an administrator"),
            (false, Some(i)) => {
                doc.web.admins.remove(i);
                changed += 1;
            }
            (false, None) => eprintln!("[bb-auth-adm] {email} is not an administrator"),
        }
    }
    if changed == 0 {
        eprintln!("[bb-auth-adm] nothing changed");
        return Ok(ExitCode::SUCCESS);
    }
    if doc.web.admins.is_empty() {
        return Err(
            "that would leave no bb-auth-web administrator, and an empty list must never come \
             to mean 'everyone': bb-auth-web refuses to serve without one"
                .into(),
        );
    }
    save_settings(&ctx, &doc)?;
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

/// Resolve a list of `--exclude` values with the library's [`parse_exclusion`], which is
/// where the rule lives: an enrolled person becomes their **uuid**, a group stays `@name`,
/// and an email the roster has never heard of stays itself.
///
/// The wrapper is the flag's name in the message and nothing else. It is not [`to_uuids`]
/// because an unknown email is *accepted* here: excluding a stranger is the only exclusion
/// that exists on an `authenticated` scope, which is precisely the scope that admits people
/// in no roster row.
fn to_exclusions(doc: &AccessFile, who: &[String]) -> Result<Vec<String>, String> {
    who.iter()
        .map(|w| parse_exclusion(doc, w).map_err(|e| format!("--exclude {e}")))
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

/// One roster row, plus what it reaches, which is the one question the file cannot be read
/// off by eye: a grant is written on the side of the place, so the tool computes it.
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
///
/// `--strict` makes a lint an exit code, which is what lets this sit in a deploy beside
/// `bb-auth --check-access`. The default stays 0: a lint is a remark about a file that works,
/// and a tool an operator runs by hand should not report failure for one. A pipeline that
/// wants them to count says so.
fn cmd_check(mut ctx: Ctx) -> Result<ExitCode, String> {
    let strict = ctx.flags.take_flag("strict")?;
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
            if let Some(j) = shadowing_scope(&a.scopes[..i], &s.urls) {
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
    if strict {
        eprintln!(
            "[bb-auth-adm] --strict: {} lint(s), exiting non-zero",
            lints.len()
        );
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// `can WHO URL [--as CLASS] [--key ID]` — put the question to the gate's own decision
/// function, and exit 0 only if it says yes. What `--check-access` is to the file, this is
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
        return Ok(verdict(
            &access,
            &doc,
            &Subject::Key(rec),
            at,
            &url,
            &ctx.settings_path,
        ));
    }

    let subject = Subject::Identifier(who);
    Ok(verdict(
        &access,
        &doc,
        &subject,
        at,
        &url,
        &ctx.settings_path,
    ))
}

/// The identity headers this deployment's settings file asks for, or the default when it
/// cannot be read.
///
/// Never an error: this is decoration on a verdict about the *access* file, and a settings
/// file that is missing (or belongs to a host this workstation is not) must not stop `can`
/// from answering. The default is what an unconfigured settings file compiles to, so the
/// fallback says what a default deployment does rather than guessing.
fn identity_headers(settings_path: &str) -> Vec<String> {
    match open_settings_file(settings_path) {
        Ok((_, s)) => s.identity_attrs.iter().map(|a| a.header.clone()).collect(),
        Err(_) => vec![bb_auth_core::IDENTITY_HEADER.to_string()],
    }
}

/// Print the gate's decision in the gate's own words, and turn it into an exit code.
fn verdict(
    access: &Access,
    doc: &AccessFile,
    subject: &Subject,
    at: Option<&str>,
    url: &str,
    settings_path: &str,
) -> ExitCode {
    let d = decide(access, subject, at);
    // What the gate will actually put on the wire, which is `gate.identity_attrs` and not a
    // header name spelled out here: on a `["uuid"]` deployment `X-Auth-Email` never arrives,
    // and this line is where somebody goes to find out what does. Best effort on purpose:
    // `can` answers a question about the ACCESS file, and an unreadable settings file must
    // not take that answer away, so the default the settings compile to is the fallback.
    let names = identity_headers(settings_path);
    let sees = |uuid: Option<&str>| {
        let who = match uuid.and_then(|u| user_pos(doc, u)) {
            Some(i) => Some(user_label(&doc.users[i])),
            None => match subject {
                Subject::Identifier(id) => Some(id.to_string()),
                _ => None,
            },
        };
        match who {
            Some(w) => format!(
                "  the application sees {}",
                names
                    .iter()
                    .map(|h| format!("{h}: {w}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            None => "  the application sees no identity".to_string(),
        }
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- the argument grammar -----------------------------------------------
    //
    // This tool writes the production access file, as root, over SSH, and until now its
    // parser had no test at all: the grammar was whatever `parse_args` happened to do, and
    // one of its behaviours (a bare flag) was detected by matching on the *text* of an error
    // message raised somewhere else. What follows pins the grammar itself, so that the next
    // person to touch it finds out from `cargo test` rather than from a host.

    /// `parse_args` over a command line written the way a person would type it.
    fn args(line: &str) -> (Vec<String>, Flags) {
        let argv: Vec<String> = line.split_whitespace().map(str::to_string).collect();
        parse_args(&argv).expect("this line parses")
    }

    #[test]
    fn the_two_spellings_of_a_flag_value_are_the_same_thing() {
        for line in [
            "scope add mpa admin --access restricted",
            "scope add mpa admin --access=restricted",
        ] {
            let (words, mut flags) = args(line);
            assert_eq!(words, ["scope", "add", "mpa", "admin"]);
            assert_eq!(
                flags.take_one("access").unwrap().as_deref(),
                Some("restricted")
            );
            flags.finish().expect("nothing left over");
        }
    }

    #[test]
    fn a_bare_flag_is_a_boolean_and_a_valued_one_is_still_read() {
        let (_, mut flags) = args("scope set mpa admin --no-scopes");
        assert_eq!(flags.take("no-scopes").unwrap(), Taken::Bare);

        // The whole point of the type: `take_flag` must not be reading this off an error
        // string. Bare is true, an explicit false is false, and a value that is neither is a
        // refusal rather than a silent true.
        let (_, mut flags) = args("key set bob laptop --force");
        assert!(flags.take_flag("force").unwrap());
        let (_, mut flags) = args("key set bob laptop --force=no");
        assert!(!flags.take_flag("force").unwrap());
        let (_, mut flags) = args("key set bob laptop --force=perhaps");
        assert!(flags.take_flag("force").is_err());
        let (_, mut flags) = args("key set bob laptop");
        assert!(!flags.take_flag("force").unwrap());
    }

    #[test]
    fn a_flag_that_wants_a_value_refuses_a_bare_one() {
        let (_, mut flags) = args("app add mpa --base");
        let e = flags.take_one("base").unwrap_err();
        assert!(e.contains("needs a value"), "{e}");
    }

    #[test]
    fn a_repeated_single_value_is_an_error_rather_than_a_silent_choice() {
        let (_, mut flags) = args("app add mpa --login-url a --login-url b");
        let e = flags.take_one("login-url").unwrap_err();
        assert!(e.contains("more than once"), "{e}");
    }

    #[test]
    fn take_many_accumulates_across_repeats_and_commas() {
        let (_, mut flags) = args("scope add mpa admin --url a,b --url c");
        assert_eq!(flags.take_many("url").unwrap(), ["a", "b", "c"]);
        // Empty items are dropped, so a trailing comma is not a pattern.
        let (_, mut flags) = args("scope add mpa admin --url a,,b,");
        assert_eq!(flags.take_many("url").unwrap(), ["a", "b"]);
        // And a bare one is still a missing value, not an empty list.
        let (_, mut flags) = args("scope add mpa admin --url");
        assert!(flags.take_many("url").is_err());
    }

    #[test]
    fn an_unclaimed_flag_is_refused_by_finish() {
        // The reflex the whole tool is built on: a typo must never be shrugged off by the
        // one program whose job is keeping typos out of the access file.
        let (_, flags) = args("user add bob@x.com --emial x");
        let e = flags.finish().unwrap_err();
        assert!(e.contains("--emial"), "{e}");
    }

    #[test]
    fn a_single_dash_option_is_refused_outright() {
        let argv: Vec<String> = ["user", "add", "-x"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let e = parse_args(&argv).unwrap_err();
        assert!(e.contains("unknown option"), "{e}");
    }

    #[test]
    fn a_value_that_looks_like_a_flag_is_treated_as_a_flag() {
        // A documented limit rather than a bug, and worth pinning so a change to it is a
        // decision: `--note --base` is read as two bare flags, so the note is reported
        // missing instead of being given the text "--base". A value that must start with two
        // dashes is written `--note=--base`.
        let (_, mut flags) = args("app add mpa --note --base");
        assert_eq!(flags.take("note").unwrap(), Taken::Bare);
        assert_eq!(flags.take("base").unwrap(), Taken::Bare);
        let (_, mut flags) = args("app add mpa --note=--base");
        assert_eq!(
            flags.take("note").unwrap(),
            Taken::Valued("--base".to_string())
        );
    }

    #[test]
    fn to_exclusions_keeps_a_stranger_and_resolves_a_user() {
        let doc: AccessFile = serde_json::from_str(
            r#"{ "version": 1, "user_groups": { "admins": [] },
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
    fn shadowing_scope_finds_the_broad_scope_listed_first() {
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
        let scopes = [broad, narrow];
        assert_eq!(shadowing_scope(&scopes[..1], &scopes[1].urls), Some(0));
        assert_eq!(shadowing_scope(&scopes[..0], &scopes[0].urls), None);
    }
}
