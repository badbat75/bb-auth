use crate::*;

// ---------------------------------------------------------------------------
// Editing an access file
// ---------------------------------------------------------------------------
//
// The membership rule, one step further than the sections above. Those are what an access
// file *means*; this is how one is edited and written — and it is here for the same reason
// the parser is: two programs must agree on it byte for byte. `bb-auth-adm` today, a web
// admin next. The write order (render → re-parse → compile → replace, atomically, with the
// mode and owner of the file being replaced) is not something either of them may re-invent,
// and neither is what a mutation refuses to do.
//
// Nothing here prints, and nothing here reads a flag or an env var: an operator-facing
// string belongs to whichever program has an operator. What comes back is a
// `Result<_, String>` naming the refusal — its wording is the refusal itself, so every
// caller reports the same reason, and the caller decides where to put it.

/// Open an access file for editing: the document to mutate, and the table the gate would
/// build from it as it stands.
///
/// A file the gate would reject is refused here too — an edit must start from a file that
/// works, or a tool would cheerfully fix one problem while carrying a fatal one to the
/// disk. Both halves come back because compiling is also what *emits* the parser's warnings
/// ("this user reaches nothing"), and an operator should hear each of those once, not once
/// per look.
pub fn open_access_file(path: &str) -> Result<(AccessFile, Access), String> {
    let doc = read_access_file(path)?;
    let access = compile_access(&doc)
        .map_err(|e| format!("{path}: the gate would reject this file as it stands: {e}"))?;
    Ok((doc, access))
}

/// Serialize a document to the exact bytes an access file is written as: pretty JSON plus
/// one trailing newline. The error is serde's own, unadorned.
pub fn render_access_file(doc: &AccessFile) -> Result<String, String> {
    let mut json = serde_json::to_string_pretty(doc).map_err(|e| e.to_string())?;
    json.push('\n');
    Ok(json)
}

/// An edited document, rendered to the exact bytes it would be written as, and already
/// compiled with the gate's own parser.
///
/// This type *is* the write order, made unskippable. The only way to obtain one is
/// [`AccessWrite::prepare`], which compiles; the only thing [`AccessWrite::commit`] puts on
/// disk is the byte string that was compiled; and `write_atomically` is private to this
/// crate so there is no other door. Nothing can slip in between the check and the write,
/// and no tool can write an access file that was not checked — a file the gate refuses at
/// startup is a boot loop under `Restart=on-failure`, and an editor is one of the only two
/// places (with `bb-auth --check-access`) that can catch it in time.
pub struct AccessWrite {
    json: String,
    access: Access,
}

impl AccessWrite {
    /// Render `doc`, then re-parse and compile the rendered text. `Err` means these bytes
    /// must not reach the disk, and says why.
    ///
    /// The round-trip through serde is not paranoia: what is checked has to be the byte
    /// string that lands on disk, not the document it came from.
    pub fn prepare(doc: &AccessFile) -> Result<AccessWrite, String> {
        let json = render_access_file(doc).map_err(|e| format!("cannot serialize: {e}"))?;
        let reparsed: AccessFile =
            serde_json::from_str(&json).map_err(|e| format!("serialized to invalid JSON: {e}"))?;
        let access = compile_access(&reparsed).map_err(|e| format!("refusing to write: {e}"))?;
        Ok(AccessWrite { json, access })
    }

    /// The bytes: what a dry run prints, and exactly what [`AccessWrite::commit`] writes.
    pub fn json(&self) -> &str {
        &self.json
    }

    /// The table the gate will build from those bytes — where a caller reads the counts it
    /// reports back ("N users, N api keys, …").
    pub fn access(&self) -> &Access {
        &self.access
    }

    /// Replace `path` with these bytes. The file must already exist: its mode and owner are
    /// what the replacement inherits.
    pub fn commit(&self, path: &str) -> Result<Written, String> {
        write_atomically(path, &self.json)
    }

    /// Create `path` with these bytes, and only if it does not exist yet.
    ///
    /// The other half of "there is one door". The two `init` commands used to write their
    /// first file with `std::fs::write` and a `chmod` of their own, which is a second way to
    /// put bytes in a place the gate will read: not compiled through the parser, not atomic,
    /// and preceded by an `exists()` check that is a race against itself. Today's payload is
    /// a default document and nothing is wrong with it; the invariant is stated absolutely
    /// so that nobody has to re-derive whether a *particular* instance is safe, and the next
    /// "create from a template" command would copy the shape it found.
    ///
    /// `create_new` is what makes the refusal-to-overwrite an operation of the filesystem
    /// rather than a check the caller does first. The mode is `0640` from the start: the gate
    /// reads this file as a group member and must not be the only one that can, and nobody
    /// else has any business reading it. The owner is left to whoever runs the tool, which is
    /// how the packages arrange it.
    pub fn create(&self, path: &str) -> Result<(), String> {
        create_new_file(path, &self.json)
    }
}

/// What a completed write hands back — and the proof that there *was* one, which is what
/// [`SealedKey::reveal`] asks for.
pub struct Written {
    /// The copy of the file that was replaced, kept one step back. The gate is stateless,
    /// but a roster is not reconstructible.
    pub backup: std::path::PathBuf,
}

/// Write `content` over `path`: a temp file in the same directory, then a rename.
///
/// Private on purpose: [`AccessWrite::commit`] is the only way in, so nothing can write an
/// access file the gate has not already accepted.
///
/// Mode and owner are copied from the file being replaced, and that is not cosmetic. The
/// live access file is `root:bb-auth 0640`; a rewrite by root that left it `root:root`
/// would be unreadable to the service, and the gate would die on its next start — a lockout
/// dressed up as a successful edit. So a failed `chown` aborts the write rather than warning
/// about it: nothing is renamed, and the old file stays intact.
///
/// The temp file is **unique per write**, and the durability is explicit:
///
/// * A shared temp name was the previous shape, on the argument that racing editors should
///   contend for one file rather than each rename its own over the other's work. That
///   argument describes a lost update, which is what the GUI's `rev` check catches; what a
///   shared name buys instead is two writers interleaving their bytes into a file *neither*
///   wrote, which both then rename. A file that does not parse is a fatal startup, i.e. a
///   boot loop, so the cheap answer is a name nobody else can be using.
/// * `sync_all` on the temp file and then on the directory, because "atomic" here means a
///   reader sees the old file or the new one, and says nothing about a machine that loses
///   power between the rename and the writeback. This file is the only current copy of the
///   access list; two `fsync`s per edit is nothing next to reconstructing it.
pub(crate) fn write_atomically(path: &str, content: &str) -> Result<Written, String> {
    let p = std::path::Path::new(path);
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty());
    // Unique per write: pid and a counter, which no other process and no other thread of
    // this one can be holding.
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let unique = format!(
        "{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let tmp = match dir {
        Some(d) => d.join(format!(
            ".{}.bb-auth.{unique}.tmp",
            p.file_name().unwrap_or_default().to_string_lossy()
        )),
        None => std::path::PathBuf::from(format!(".{path}.bb-auth.{unique}.tmp")),
    };

    let meta = std::fs::metadata(p).map_err(|e| format!("stat {path}: {e}"))?;
    // Keep one step back. The gate is stateless, but a roster is not reconstructible.
    let bak = format!("{path}.bak");
    std::fs::copy(p, &bak).map_err(|e| format!("backup {bak}: {e}"))?;

    let restore = |e: String| {
        let _ = std::fs::remove_file(&tmp);
        e
    };
    {
        use std::io::Write;
        let mut f =
            std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        f.write_all(content.as_bytes())
            .map_err(|e| restore(format!("write {}: {e}", tmp.display())))?;
        // Before the rename, not after: a rename that lands ahead of the data is how an
        // atomic replace ends up publishing an empty file.
        f.sync_all()
            .map_err(|e| restore(format!("fsync {}: {e}", tmp.display())))?;
    }
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
    // The rename itself is a directory operation, so the directory is what has to be durable
    // for it to survive a power cut. Best effort: on a filesystem that will not open a
    // directory for reading, an unsynced rename is still an improvement on no rename, and
    // failing an edit that has already landed would be the worse answer.
    if let Some(d) = dir {
        if let Ok(h) = std::fs::File::open(d) {
            let _ = h.sync_all();
        }
    }
    Ok(Written {
        backup: std::path::PathBuf::from(bak),
    })
}

/// Create `path` with `content`, refusing to touch a file that is already there.
///
/// Private, beside [`write_atomically`], for the same reason: [`AccessWrite::create`] and
/// [`SettingsWrite::create`] are the only callers, so a first file goes through the same
/// compile-then-write order every later edit does.
///
/// `create_new` makes "only if absent" the filesystem's answer rather than a caller's
/// `exists()` a moment earlier, which is a check whose result can already be stale when it
/// is read.
pub(crate) fn create_new_file(path: &str, content: &str) -> Result<(), String> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // From the first byte, not after a `chmod`: between the two there is a window where
        // the file is world-readable, and what goes in it is an access list.
        opts.mode(0o640);
    }
    let mut f = opts.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => {
            format!("{path} already exists: refusing to overwrite it")
        }
        _ => format!("create {path}: {e}"),
    })?;
    f.write_all(content.as_bytes())
        .map_err(|e| format!("write {path}: {e}"))?;
    f.sync_all().map_err(|e| format!("fsync {path}: {e}"))?;
    Ok(())
}

// --- lookups over the document ---------------------------------------------

/// Emails are matched the way the gate matches them: trimmed and lowercased.
pub fn norm_email(e: &str) -> String {
    e.trim().to_ascii_lowercase()
}

/// The URL as the gate will see it on `/auth/validate`: query and fragment stripped (nginx
/// sends `$uri`), authority lowercased. Comparing anything else would be answering a
/// different question from the one the gate answers.
///
/// Here rather than in a tool for that reason: it is a statement about *which* URL an
/// access file's patterns are matched against, so every program that asks "would this get
/// in?" — `bb-auth-adm can`, the web admin's tester — has to normalise it identically, the
/// same way they all share one matcher and one [`decide`].
pub fn request_url(url: &str) -> String {
    lower_authority(url.split(['?', '#']).next().unwrap_or(""))
}

/// The roster position of a user named by **either** key: their uuid, or any of their
/// emails.
///
/// Both, on purpose. The file references a user by uuid and only by uuid, but an operator
/// types an email, and a tool that made them paste a uuid to remove a person would be a
/// tool nobody uses. The uuid is tried first: it is the identity, and an email is only a
/// way to find it.
pub fn user_pos(doc: &AccessFile, key: &str) -> Option<usize> {
    let want = norm_email(key);
    doc.users
        .iter()
        .position(|u| u.uuid.trim().to_ascii_lowercase() == want)
        .or_else(|| {
            doc.users
                .iter()
                .position(|u| u.emails.iter().any(|e| norm_email(e) == want))
        })
}

/// The roster row named by uuid or email, to edit in place.
pub fn user_mut<'a>(doc: &'a mut AccessFile, key: &str) -> Result<&'a mut UserSpec, String> {
    match user_pos(doc, key) {
        Some(i) => Ok(&mut doc.users[i]),
        None => Err(format!(
            "no user '{}' (add them with: user add {})",
            key.trim(),
            key.trim()
        )),
    }
}

/// How a user is named back to an operator: their primary email if they have one, else
/// their uuid. Every message about a user goes through here, so a row with no email is
/// still nameable instead of being reported as an empty string.
pub fn user_label(u: &UserSpec) -> String {
    match u
        .emails
        .iter()
        .map(|e| norm_email(e))
        .find(|e| !e.is_empty())
    {
        Some(e) => e,
        None => u.uuid.trim().to_ascii_lowercase(),
    }
}

/// One user's API keys, by `id` (trimmed, case-sensitive: an id is a label, not an
/// address).
pub fn key_mut<'a>(
    doc: &'a mut AccessFile,
    key: &str,
    id: &str,
) -> Result<&'a mut ApiKeySpec, String> {
    let u = user_mut(doc, key)?;
    let owner = user_label(u);
    match u.api_keys.iter().position(|k| k.id.trim() == id.trim()) {
        Some(i) => Ok(&mut u.api_keys[i]),
        None => Err(format!("{owner}: no api key '{id}'")),
    }
}

/// The position of the application named `name`.
pub fn app_pos(doc: &AccessFile, name: &str) -> Option<usize> {
    doc.applications
        .iter()
        .position(|a| a.name.trim() == name.trim())
}

/// The application named `name`, to edit in place.
pub fn app_mut<'a>(doc: &'a mut AccessFile, name: &str) -> Result<&'a mut AppSpec, String> {
    match app_pos(doc, name) {
        Some(i) => Ok(&mut doc.applications[i]),
        None => Err(format!("no application '{}'", name.trim())),
    }
}

/// The position of `scope` inside `app`. A position, not a reference, because scope order
/// is meaning ([`AppRecord::scopes`]) and every caller ends up needing the index.
pub fn scope_pos(app: &AppSpec, scope: &str) -> Option<usize> {
    app.scopes
        .iter()
        .position(|s| s.name.trim() == scope.trim())
}

/// One scope of one application, to edit in place.
pub fn scope_mut<'a>(
    doc: &'a mut AccessFile,
    app: &str,
    scope: &str,
) -> Result<&'a mut ScopeSpec, String> {
    let a = app_mut(doc, app)?;
    match scope_pos(a, scope) {
        Some(i) => Ok(&mut a.scopes[i]),
        None => Err(format!("{}/{}: no such scope", app.trim(), scope.trim())),
    }
}

/// A user group's member list, to edit in place.
pub fn user_group_mut<'a>(
    doc: &'a mut AccessFile,
    name: &str,
) -> Result<&'a mut Vec<String>, String> {
    let name = name.trim();
    doc.user_groups
        .get_mut(name)
        .ok_or_else(|| format!("no user group '@{name}'"))
}

/// Every scope that names `@name`, as `application/scope`.
///
/// [`group_ref`] is what decides whether an entry is a reference, so this cannot drift
/// from what [`compile_access`] expands. The gate would refuse a file with a dangling
/// reference anyway ([`AccessWrite::prepare`] compiles before anything is written), and
/// this is what turns that refusal into a list of places to go and fix.
pub fn user_group_refs(doc: &AccessFile, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let names = |list: &Option<Vec<String>>| {
        list.iter()
            .flatten()
            .any(|g| group_ref(g) == Some(name.trim()))
    };
    for a in &doc.applications {
        for s in &a.scopes {
            let at = format!("{}/{}", a.name.trim(), s.name.trim());
            if names(&s.groups) {
                out.push(at.clone());
            }
            // An `excluded` reference counts every bit as much: `compile_access` refuses an
            // unknown group there too, so removing a group a scope excludes would produce a
            // file the gate rejects, which is exactly what this list exists to prevent.
            if names(&s.excluded) {
                out.push(format!("{at} ({EXCLUDED_REF})"));
            }
        }
    }
    out
}

/// How [`user_refs`] and [`user_group_refs`] mark a reference that keeps someone *out*
/// rather than letting them in. Display only, and one constant so the two agree.
pub const EXCLUDED_REF: &str = "excluded";

/// Resolve one entry an operator typed into a scope's `excluded`, the way the file spells it:
/// an enrolled person becomes their **uuid**, a group stays `@name`, and an email the roster
/// has never heard of stays itself.
///
/// Here, and not in each editor, because it is a statement about what an entry in that field
/// *means*, which is the library's membership test exactly as `decide` and `glob_match` are.
/// The two editors had one each and they had already drifted: the CLI accepted any `@token`
/// as a group, the GUI checked the grammar and that the group existed, so the same file was
/// refused at one form and written by the other.
///
/// A stranger's email is kept rather than refused, and that is the whole point of the field
/// on an `authenticated` scope: that scope admits exactly the people who are in no roster
/// row, so an exclusion that could only name enrolled people would be useless where it is
/// needed most. Anyone the roster *does* know is written as their uuid, so one exclusion
/// covers every identifier they have.
pub fn parse_exclusion(doc: &AccessFile, entry: &str) -> Result<String, String> {
    let raw = entry.trim();
    if raw.starts_with('@') {
        let g = group_ref(raw)
            .filter(|g| !g.is_empty())
            .ok_or_else(|| format!("'{raw}': a group reference is written '@name'"))?;
        if !doc.user_groups.contains_key(g) {
            return Err(format!("'{raw}': no user group '@{g}'"));
        }
        return Ok(raw.to_string());
    }
    if let Some(i) = user_pos(doc, raw) {
        return Ok(doc.users[i].uuid.trim().to_ascii_lowercase());
    }
    if raw.contains('@') {
        return Ok(norm_email(raw));
    }
    Err(format!(
        "'{raw}': not a user, not '@group' and not an email. An exclusion names somebody \
         enrolled, a group, or a stranger by their email"
    ))
}

/// The earlier scope of the same application that makes scope `urls` dead, if there is one:
/// its index, for a message that can name it.
///
/// Scopes are **first match wins in file order**, so a scope whose every pattern is already
/// answered by something above it never speaks, whatever it grants. That is a lint and never
/// an error: it is also how a carve-out is written the wrong way round, and telling an
/// operator which line to move is the whole value of it.
///
/// A heuristic, deliberately. Matching one glob against another has no exact answer
/// (`https://x.com/*` and `*://x.com/app1` cover each other partially), so this asks each of
/// the later scope's own pattern *strings* of the earlier scopes' compiled matchers, which
/// catches the case that actually happens: something broad listed first. Coverage may be
/// **joint**, i.e. each pattern answered by a different earlier scope, because that is what
/// first-match does; the index returned is the scope that answers the first pattern, which is
/// where an operator will look. The CLI used to require one earlier scope to cover the whole
/// list and the GUI did not, so a file was reported dead in one tool and clean in the other.
pub fn shadowing_scope(earlier: &[ScopeSpec], urls: &[String]) -> Option<usize> {
    let mine: Vec<&str> = urls
        .iter()
        .map(|u| u.trim())
        .filter(|u| !u.is_empty())
        .collect();
    if mine.is_empty() || earlier.is_empty() {
        return None;
    }
    // A scope whose patterns do not compile is skipped rather than assumed to cover
    // everything: the parser refuses that file anyway, and a lint must not accuse a scope on
    // the strength of a broken one above it.
    let compiled: Vec<Option<UrlScope>> = earlier
        .iter()
        .map(|s| UrlScope::compile(&s.urls).ok())
        .collect();
    let covering = |u: &str| {
        compiled
            .iter()
            .position(|c| c.as_ref().is_some_and(|c| c.allows(Some(u))))
    };
    let first = covering(mine[0])?;
    mine[1..]
        .iter()
        .all(|u| covering(u).is_some())
        .then_some(first)
}

/// Every place that names `uuid`: scopes as `application/scope`, groups as `@name`.
///
/// What [`remove_user`] sweeps, and what an editor shows before it does. A dangling
/// reference only warns at load, so nothing breaks if one survives; leaving one behind
/// would still be an editor quietly writing a file it knows is wrong.
pub fn user_refs(doc: &AccessFile, uuid: &str) -> Vec<String> {
    let want = norm_email(uuid);
    let mut out = Vec::new();
    let names = |list: &Option<Vec<String>>| list.iter().flatten().any(|u| norm_email(u) == want);
    for a in &doc.applications {
        for s in &a.scopes {
            let at = format!("{}/{}", a.name.trim(), s.name.trim());
            if names(&s.users) {
                out.push(at.clone());
            }
            // Marked, because the two say opposite things about the same row and a sweep
            // that reported them alike would read as if the user had been let in there.
            if names(&s.excluded) {
                out.push(format!("{at} ({EXCLUDED_REF})"));
            }
        }
    }
    for (name, members) in &doc.user_groups {
        if members.iter().any(|m| norm_email(m) == want) {
            out.push(format!("@{name}"));
        }
    }
    // The veto, marked like an exclusion and for the same reason: it is a reference that
    // keeps this person *out*, and a sweep that listed it beside a scope's members would
    // read as if they had been let in there. [`remove_user`] rewrites rather than drops it.
    if doc.denied.iter().any(|d| norm_email(d) == want) {
        out.push(format!("denied ({EXCLUDED_REF})"));
    }
    out
}

/// Apply the standard list edits to an optional list field: a full replacement (`set`),
/// then `add` (deduplicated) and `rm`. Returns `true` if anything changed.
///
/// `None` means "absent", which does not mean the same thing in every field it is used on:
/// on a key's `scopes` it is "every scope the owner reaches", on a scope's own lists it is
/// nobody. So `clear` says which one the caller wants an emptied list to collapse to.
pub fn edit_urls(
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

/// [`edit_urls`] over a plain list: an application's `base`, a scope's `urls`, a group's
/// members. There is no "inherit" to fall back to in any of them, so a cleared list is
/// empty, never absent.
pub fn edit_url_list(
    urls: &mut Vec<String>,
    set: Vec<String>,
    add: Vec<String>,
    rm: Vec<String>,
    clear: bool,
) -> bool {
    let mut opt = Some(std::mem::take(urls));
    let changed = edit_urls(&mut opt, set, add, rm, clear);
    *urls = opt.unwrap_or_default();
    changed
}

// --- document mutations ----------------------------------------------------

/// The refusal every mutation that lets a **new** email into the file makes, in one
/// sentence. Only new values: an address already in the file is never re-checked, so a row
/// this check would refuse does not block the edits around it.
fn check_new_email(email: &str) -> Result<(), String> {
    if well_formed_email(email) {
        return Ok(());
    }
    Err(format!(
        "'{email}' does not look like an email address (LOCAL@DOMAIN with a dotted domain, \
         like bob@example.com) — it could never match a Cognito identity"
    ))
}

/// A fresh identity: 122 random bits from the OS CSPRNG, in the canonical lowercase
/// 8-4-4-4-12 form (a version 4 UUID).
///
/// Minted here rather than typed by an operator, because the value has no meaning to
/// read: it exists to be stable, unique and never reused. The same entropy source that
/// mints an API key, and no new dependency for a value that is sixteen bytes and a
/// format string.
pub fn mint_uuid() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| format!("no entropy from the OS: {e}"))?;
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

/// Enrol `user`. A uuid is minted when the row carries none, every email is normalised on
/// the way in and must look like one ([`well_formed_email`]): a typo here is a dead
/// identifier that fails closed and is found only by the human it locks out.
///
/// Refuses a row whose uuid or any of whose emails is already in the file. The gate is
/// fatal on both, so this is the same refusal made earlier and with a better sentence.
pub fn add_user(doc: &mut AccessFile, mut user: UserSpec) -> Result<(), String> {
    user.uuid = match user.uuid.trim() {
        "" => mint_uuid()?,
        u => {
            let u = u.to_ascii_lowercase();
            if !well_formed_uuid(&u) {
                return Err(format!(
                    "'{u}' is not a uuid (canonical lowercase 8-4-4-4-12); leave it out and one \
                     is minted"
                ));
            }
            u
        }
    };
    if user_pos(doc, &user.uuid).is_some() {
        return Err(format!("{} is already in users", user.uuid));
    }
    let mut emails = Vec::with_capacity(user.emails.len());
    for raw in &user.emails {
        let e = norm_email(raw);
        check_new_email(&e)?;
        if user_pos(doc, &e).is_some() {
            return Err(format!("{e} already belongs to another user"));
        }
        if emails.contains(&e) {
            return Err(format!("{e} is listed twice"));
        }
        emails.push(e);
    }
    user.emails = emails;
    doc.users.push(user);
    Ok(())
}

/// Give a user another identifier, which must look like an email ([`well_formed_email`])
/// and must belong to nobody yet. `Ok(false)` means they already had it.
///
/// This is what a "rename" became. An identity is the uuid and never changes, so changing
/// how someone signs in is adding an identifier and dropping the old one: two edits the
/// gate validates one by one, and nothing in the file has to be re-pointed either time.
pub fn add_user_email(doc: &mut AccessFile, key: &str, email: &str) -> Result<bool, String> {
    let e = norm_email(email);
    match user_pos(doc, &e) {
        Some(i) if Some(i) == user_pos(doc, key) => return Ok(false),
        Some(_) => return Err(format!("{e} already belongs to another user")),
        None => {}
    }
    check_new_email(&e)?;
    user_mut(doc, key)?.emails.push(e);
    Ok(true)
}

/// Drop one identifier from a user. Refuses the last one: a row nobody can sign in as is
/// a row that only looks like a grant, and the way to retire a user is to remove or veto
/// them.
pub fn remove_user_email(doc: &mut AccessFile, key: &str, email: &str) -> Result<bool, String> {
    let want = norm_email(email);
    let u = user_mut(doc, key)?;
    if !u.emails.iter().any(|e| norm_email(e) == want) {
        return Ok(false);
    }
    if u.emails.len() == 1 {
        return Err(format!(
            "{want} is this user's only email; removing it would leave a row no credential can \
             ever resolve to"
        ));
    }
    u.emails.retain(|e| norm_email(e) != want);
    Ok(true)
}

/// Drop a user's row, every key it owned, and every reference to it. The removed row comes
/// back so a caller can say what went with it.
///
/// The sweep is the point, and it is new: with grants written on the side of the place, a
/// row can be named by any number of scopes and groups. A leftover reference grants
/// nothing (the gate warns and moves on), but an editor that knowingly left one would be
/// writing a file it knows is wrong, and the next person to read that scope would see a
/// member who does not exist.
pub fn remove_user(doc: &mut AccessFile, key: &str) -> Result<(UserSpec, Vec<String>), String> {
    let i = user_pos(doc, key).ok_or_else(|| format!("no user '{}'", key.trim()))?;
    let uuid = doc.users[i].uuid.trim().to_ascii_lowercase();
    let swept = user_refs(doc, &uuid);
    // The primary email, taken before anything is swept, because both rewrites below need it:
    // it is the spelling this file uses for an identity the roster does not know, and the
    // identity being removed is about to become exactly that.
    let primary = doc.users[i]
        .emails
        .iter()
        .map(|e| norm_email(e))
        .find(|e| !e.is_empty());
    for a in &mut doc.applications {
        for s in &mut a.scopes {
            if let Some(list) = s.users.as_mut() {
                list.retain(|u| norm_email(u) != uuid);
            }
            // An exclusion is REWRITTEN to that email, not swept, for the reason `denied`
            // below gives: it is a veto, and dropping it lifts it. The sequence is ordinary
            // housekeeping (keep somebody out of one area, tidy the roster afterwards), and
            // with an `authenticated` scope anywhere in the file that person re-registers on
            // Cognito under the same email and walks straight back into the scope they were
            // just shut out of. A row with no email has no stranger spelling to leave behind,
            // so its entry is dropped as it always was.
            if let Some(list) = s.excluded.as_mut() {
                match &primary {
                    Some(email) => {
                        // In place, so the entry keeps its position, and only once: a list
                        // that already names this email, or a second uuid entry, keeps one
                        // line, since two strings naming one identity is the look a stale
                        // reference must not have.
                        let mut written = list.iter().any(|u| norm_email(u) == *email);
                        list.retain_mut(|u| {
                            if norm_email(u) != uuid {
                                return true;
                            }
                            if written {
                                return false;
                            }
                            written = true;
                            *u = email.clone();
                            true
                        });
                    }
                    None => list.retain(|u| norm_email(u) != uuid),
                }
            }
        }
    }
    for members in doc.user_groups.values_mut() {
        members.retain(|m| norm_email(m) != uuid);
    }
    // The veto is REWRITTEN, not swept, and it is the one reference that must not simply go.
    //
    // Every other reference to a removed row is a grant, and a grant naming nobody is a line
    // to delete. `denied` is the opposite: dropping it *lifts* a suspension. The sequence is
    // ordinary housekeeping (suspend somebody, tidy the roster afterwards), and with an
    // `authenticated` scope anywhere in the file the same person then re-registers with
    // Cognito and walks straight back in, which is precisely the walk-back-in the sweep of
    // the other references exists to prevent.
    //
    // So a user veto becomes a stranger veto for the same person: their primary email, which
    // is the spelling `denied` uses for an identity the file has never heard of, and which is
    // exactly what this identity is about to become.
    if let Some(email) = primary {
        for d in doc.denied.iter_mut() {
            if norm_email(d) == uuid {
                *d = email.clone();
            }
        }
    }
    Ok((doc.users.remove(i), swept))
}

/// A freshly minted `bbk_` bearer, sealed until the file that carries its hash is on disk.
///
/// The order is the whole point, and this type is what keeps it: the bearer comes out of
/// [`SealedKey::reveal`] and nowhere else, and `reveal` asks for the [`Written`] receipt of
/// a completed write. Handing it over any earlier would hand out a credential that
/// authorizes nothing if the write then failed — and the raw key exists nowhere to retry
/// from, since the file keeps only `sha256(bearer)` and that lookup *is* the verification.
///
/// No `Debug`, no `Clone`, no `Display`: a bearer leaves through `reveal` or not at all.
#[must_use = "a minted key nobody reveals is a key its owner never gets"]
pub struct SealedKey {
    bearer: String,
}

impl SealedKey {
    /// The raw bearer — to be shown to its owner **once**, and stored nowhere.
    ///
    /// The receipt is not read; being able to produce one is the point. A caller that has
    /// no [`Written`] — a dry run, or a write that failed — has no bearer to hand out, and
    /// that is exactly right: nothing on disk has ever heard of this key.
    pub fn reveal(self, _receipt: &Written) -> String {
        self.bearer
    }
}

/// Mint a `bbk_` bearer and file its hash on `email`'s row as `key`.
///
/// `key.key_hash` is overwritten with [`mint_api_key`]'s — the caller supplies the label,
/// the window and the scope, never the secret. The bearer comes back sealed; see
/// [`SealedKey`] for why it cannot be had before the write.
///
/// Refuses a second key with the same id: an id is what names a key in a log and in
/// `key rotate`, so two of them make a revocation ambiguous.
pub fn add_api_key(
    doc: &mut AccessFile,
    key_owner: &str,
    mut key: ApiKeySpec,
) -> Result<SealedKey, String> {
    let id = key.id.trim().to_string();
    let u = user_mut(doc, key_owner)?;
    let owner = user_label(u);
    if u.api_keys.iter().any(|k| k.id.trim() == id) {
        return Err(format!(
            "{owner} already has a key '{id}' (replace its secret: key rotate {owner} {id})"
        ));
    }
    let (bearer, hash) = mint_api_key()?;
    key.id = id;
    key.key_hash = hash;
    u.api_keys.push(key);
    Ok(SealedKey { bearer })
}

/// Same row, same scope, new secret, re-dated to today — the answer to a leaked key. The
/// old bearer stops working the moment the gate reloads.
pub fn rotate_api_key(doc: &mut AccessFile, email: &str, id: &str) -> Result<SealedKey, String> {
    let k = key_mut(doc, email, id)?;
    let (bearer, hash) = mint_api_key()?;
    k.key_hash = hash;
    k.released = format_date(now());
    Ok(SealedKey { bearer })
}

/// Revoke one key by id, handing back the row that went.
pub fn remove_api_key(
    doc: &mut AccessFile,
    key_owner: &str,
    id: &str,
) -> Result<ApiKeySpec, String> {
    let u = user_mut(doc, key_owner)?;
    let owner = user_label(u);
    let i = u
        .api_keys
        .iter()
        .position(|k| k.id.trim() == id.trim())
        .ok_or_else(|| format!("{owner}: no api key '{id}'"))?;
    Ok(u.api_keys.remove(i))
}

/// Add an application. A name is required and must be free: it is how every other command
/// addresses the record, and it is the left half of every `application/scope`.
///
/// Application order carries no meaning (areas do not overlap, so at most one can ever
/// answer), which is why this appends and there is no move.
pub fn add_application(doc: &mut AccessFile, mut app: AppSpec) -> Result<(), String> {
    app.name = app.name.trim().to_string();
    if !valid_name(&app.name) {
        return Err("an application needs a name of [A-Za-z0-9_-]".into());
    }
    if app_pos(doc, &app.name).is_some() {
        return Err(format!(
            "application '{}' already exists (edit it: app set {})",
            app.name, app.name
        ));
    }
    doc.applications.push(app);
    Ok(())
}

/// Rename an application, refusing a name another one already answers to.
///
/// Every key restriction that named `application/scope` is re-pointed with it: a
/// restriction is written as a string, and leaving one behind would silently narrow a key
/// to a scope that no longer exists.
pub fn rename_application(doc: &mut AccessFile, name: &str, new_name: &str) -> Result<(), String> {
    let i = app_pos(doc, name).ok_or_else(|| format!("no application '{}'", name.trim()))?;
    let new = new_name.trim().to_string();
    if !valid_name(&new) {
        return Err("an application name must be [A-Za-z0-9_-]".into());
    }
    if app_pos(doc, &new).is_some_and(|j| j != i) {
        return Err(format!("application '{new}' already exists"));
    }
    let old = doc.applications[i].name.trim().to_string();
    doc.applications[i].name = new.clone();
    for u in &mut doc.users {
        for k in &mut u.api_keys {
            for r in k.scopes.iter_mut().flatten() {
                if let Some(rest) = r.trim().strip_prefix(&format!("{old}/")) {
                    *r = format!("{new}/{rest}");
                }
            }
        }
    }
    Ok(())
}

/// Drop an application, handing back the record that went. Everything inside it goes with
/// it, so this can take away every way into a URL area at once.
pub fn remove_application(doc: &mut AccessFile, name: &str) -> Result<AppSpec, String> {
    let i = app_pos(doc, name).ok_or_else(|| format!("no application '{}'", name.trim()))?;
    Ok(doc.applications.remove(i))
}

/// Insert a scope into an application at `at` (`None` = last, out of range = last), and
/// hand back where it landed.
///
/// Position is not decoration: scopes are first match wins, so where a scope lands decides
/// which requests it ever sees.
pub fn add_scope(
    doc: &mut AccessFile,
    app: &str,
    mut scope: ScopeSpec,
    at: Option<usize>,
) -> Result<usize, String> {
    scope.name = scope.name.trim().to_string();
    if !valid_name(&scope.name) {
        return Err("a scope needs a name of [A-Za-z0-9_-]".into());
    }
    let a = app_mut(doc, app)?;
    if scope_pos(a, &scope.name).is_some() {
        return Err(format!(
            "{}/{} already exists (edit it: scope set {} {})",
            a.name.trim(),
            scope.name,
            a.name.trim(),
            scope.name
        ));
    }
    let at = at.unwrap_or(a.scopes.len()).min(a.scopes.len());
    a.scopes.insert(at, scope);
    Ok(at)
}

/// Rename a scope, refusing a name its application already answers to, and re-pointing
/// every key restriction that named it.
pub fn rename_scope(
    doc: &mut AccessFile,
    app: &str,
    name: &str,
    new_name: &str,
) -> Result<(), String> {
    let new = new_name.trim().to_string();
    if !valid_name(&new) {
        return Err("a scope name must be [A-Za-z0-9_-]".into());
    }
    let a = app_mut(doc, app)?;
    let app_name = a.name.trim().to_string();
    let i =
        scope_pos(a, name).ok_or_else(|| format!("{app_name}/{}: no such scope", name.trim()))?;
    if scope_pos(a, &new).is_some_and(|j| j != i) {
        return Err(format!("{app_name}/{new} already exists"));
    }
    let old = a.scopes[i].name.trim().to_string();
    a.scopes[i].name = new.clone();
    let (was, now) = (format!("{app_name}/{old}"), format!("{app_name}/{new}"));
    for u in &mut doc.users {
        for k in &mut u.api_keys {
            for r in k.scopes.iter_mut().flatten() {
                if r.trim() == was {
                    *r = now.clone();
                }
            }
        }
    }
    Ok(())
}

/// Move a scope inside its application, from `from` to `to`; a position that does not
/// exist is a no-op.
///
/// Order is meaning: scopes are first match wins, so this changes which scope answers for
/// a URL, and therefore who gets in. It is the one edit that changes behaviour without
/// changing a single field.
pub fn move_scope(doc: &mut AccessFile, app: &str, from: usize, to: usize) -> Result<(), String> {
    let a = app_mut(doc, app)?;
    if from >= a.scopes.len() || to >= a.scopes.len() {
        return Ok(());
    }
    let s = a.scopes.remove(from);
    a.scopes.insert(to, s);
    Ok(())
}

/// Drop one scope, handing back the record that went.
pub fn remove_scope(doc: &mut AccessFile, app: &str, name: &str) -> Result<ScopeSpec, String> {
    let a = app_mut(doc, app)?;
    let app_name = a.name.trim().to_string();
    let i =
        scope_pos(a, name).ok_or_else(|| format!("{app_name}/{}: no such scope", name.trim()))?;
    Ok(a.scopes.remove(i))
}

/// Define a user group. A group is abbreviation, not a grant: defining one authorizes
/// nobody until a scope names it `@name`.
///
/// There is deliberately no rename: a reference names a group by its exact spelling, so
/// renaming one would silently re-point every scope that used it. Add the new name, move
/// the references, drop the old one: three edits the gate re-validates one by one.
pub fn add_user_group(
    doc: &mut AccessFile,
    name: &str,
    members: Vec<String>,
) -> Result<(), String> {
    let name = name.trim().to_string();
    if !valid_name(&name) {
        return Err("a user group needs a name of [A-Za-z0-9_-]".into());
    }
    if doc.user_groups.contains_key(&name) {
        return Err(format!(
            "user group '@{name}' already exists (edit it: group set {name})"
        ));
    }
    doc.user_groups.insert(name, members);
    Ok(())
}

/// Drop a user group, refusing while a scope still references it: the gate would reject
/// the resulting file, and the refusal here says which scopes to fix instead of leaving a
/// write to fail.
pub fn remove_user_group(doc: &mut AccessFile, name: &str) -> Result<Vec<String>, String> {
    let name = name.trim().to_string();
    if !doc.user_groups.contains_key(&name) {
        return Err(format!("no user group '@{name}'"));
    }
    let refs = user_group_refs(doc, &name);
    if !refs.is_empty() {
        return Err(format!(
            "user group '@{name}' is still referenced by {}: the gate would reject the file. \
             Change those scopes first, then remove the group.",
            refs.join(", ")
        ));
    }
    Ok(doc.user_groups.remove(&name).unwrap_or_default())
}

/// Veto whoever `who` names: a uuid, an enrolled user's email, or the email of an identity
/// the roster has never heard of. `Ok(false)` means it was already vetoed.
///
/// An enrolled user is always written down as their **uuid**, whichever way they were
/// named. That is what makes the veto cover every identifier they have, now and later: an
/// email written here would go on vetoing one way in while the person kept another.
///
/// A stranger is written down as the email itself, and that is the whole reason `denied`
/// still accepts one. An `authenticated` scope admits identities in no table, so for them
/// this is the only denial that exists.
///
/// `Err` if the value is neither, because a veto that vetoes nobody while reading as if it
/// did is the one failure this section cannot afford.
pub fn add_denied(doc: &mut AccessFile, who: &str) -> Result<bool, String> {
    let want = norm_email(who);
    let entry = match user_pos(doc, &want) {
        Some(i) => doc.users[i].uuid.trim().to_ascii_lowercase(),
        None if well_formed_uuid(&want) => want,
        None => {
            check_new_email(&want)?;
            want
        }
    };
    if doc.denied.iter().any(|d| norm_email(d) == entry) {
        return Ok(false);
    }
    doc.denied.push(entry);
    Ok(true)
}

/// Lift the veto on everyone listed, by uuid or by email, returning how many rows went.
///
/// An email is resolved the same way [`add_denied`] resolves one, so a veto added as
/// `bob@x.com` and written down as his uuid is lifted by naming either.
pub fn remove_denied(doc: &mut AccessFile, who: &[String]) -> usize {
    let want: Vec<String> = who
        .iter()
        .map(|w| {
            let w = norm_email(w);
            match user_pos(doc, &w) {
                Some(i) => doc.users[i].uuid.trim().to_ascii_lowercase(),
                None => w,
            }
        })
        .collect();
    let before = doc.denied.len();
    doc.denied.retain(|d| !want.contains(&norm_email(d)));
    before - doc.denied.len()
}
