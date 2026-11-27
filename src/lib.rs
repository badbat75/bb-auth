//! bb-auth-core, **the files bb-auth's programs share**: the access file above all, plus
//! the settings file beside it. Their schemas, their parsers, the URL matcher every check
//! goes through, and the authorization decision itself.
//!
//! This library exists for exactly one reason: there are programs that must agree, byte for
//! byte, on what a shared file *means*.
//!
//! * `bb-auth`, the gate, reads both ([`read_access`], [`decide`], [`read_settings`]).
//! * `bb-auth-adm`, the admin CLI, edits both, and must never write a file the gate would
//!   reject, nor believe it granted something the gate will not.
//! * `bb-auth-web`, the admin GUI, edits both through the same door.
//!
//! A second parser, or a second matcher, would be a second answer to "who may reach
//! what". So there is one of each, and it lives here. The gate keeps everything neither file
//! has an opinion about — HTTP, the session cookie, id_token validation, the nginx
//! contract — in its own single file, and neither admin tool links any of it.
//!
//! The same argument reaches one step further than the meaning of a file: **how one is
//! edited and written** ([`AccessWrite`], [`SettingsWrite`], [`open_access_file`], and the
//! document mutations beside them) is also something more than one program has to get right
//! byte for byte. Validate-before-write, atomic replace, mode and owner preserved: one
//! implementation, here.
//!
//! The crate root is a list of **private modules**, one per shared file (`access`,
//! `access_edit`, `settings`, `settings_refusal`, `audit`) beside the presentation contract
//! (`presentation`) and the shared response rules (`response`). Each opens `use crate::*;`,
//! and their items are re-exported flat, so every path is still `bb_auth_core::X` and
//! `grep -rn "fn name" src/` still finds any item. The gate's code is not here: it is one
//! file, `src/bin/bb-auth/main.rs`, read top to bottom.
//!
//! # Two files, and the line between them
//!
//! The access file answers **who reaches what**. The settings file holds the handful of
//! values that change *how the gate answers* and that must take effect **without a restart**,
//! and it is a file, rather than more env vars, for one mechanical reason: a process cannot
//! re-read its own environment. See the settings-file section for the three-part rule that
//! decides which of the two a setting belongs in, and why the rest of bb-auth's configuration
//! is in neither.
//!
//! # What is in an access file
//!
//! Four sibling sections answering four different questions ([`AccessFile`]):
//! `applications` describe places and who may reach them ([`AppRecord`], [`ScopeRecord`]),
//! `user_groups` names a reusable set of people, `denied` vetoes people, `users` is the
//! roster of identities.
//!
//! The model is **application-centric**, and that is the whole shape of it: a grant is
//! written once, on the side of the place. An application owns a literal URL area and a
//! list of named scopes; a scope owns URL patterns and one access policy; a user owns a
//! UUID, identifiers and keys, and no URL at all. Asking "who reaches this application?"
//! and "what does this application expose?" are both one lookup, which is what the
//! previous user-centric shape made a scan of the whole roster.
//!
//! Access is **enumerated, never assumed**: a URL no application covers is reachable by
//! nobody, a scope that lists nobody grants to nobody, and the veto in `denied` outranks
//! every grant on every credential. [`decide`] is that rule, and it is the only one.

use std::collections::{BTreeMap, HashMap, HashSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Namespace prefix marking a static API-key bearer credential (vs a Cognito
/// id_token JWT): `Authorization: Bearer bbk_<secret>`.
pub const API_KEY_PREFIX: &str = "bbk_";

/// Current Unix time in seconds, saturating to 0 if the clock predates the epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

mod access;
mod access_edit;
mod audit;
mod presentation;
mod response;
mod settings;
mod settings_refusal;

pub use access::*;
pub use access_edit::*;
pub use audit::*;
pub use presentation::*;
pub use response::*;
pub use settings::*;
pub use settings_refusal::*;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
