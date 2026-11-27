use super::*;

mod access;
mod access_edit;
mod audit;
mod presentation;
mod settings;
mod settings_refusal;

/// Write `json` to a uniquely-named temp file so tests can run in parallel.
pub(crate) fn users_tmp(name: &str, json: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("bb-auth-core-{name}.json"));
    std::fs::write(&p, json).unwrap();
    p
}

/// Parse `json` as an access file, through the real parser and a real temp file.
fn access_of(name: &str, json: &str) -> Access {
    let tmp = users_tmp(name, json);
    let a = read_access(tmp.to_str().unwrap()).unwrap();
    let _ = std::fs::remove_file(&tmp);
    a
}

fn doc_of(json: &str) -> AccessFile {
    serde_json::from_str(json).expect("fixture parses")
}

fn err_of<T>(r: Result<T, String>) -> String {
    match r {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e,
    }
}

const BOB: &str = "11111111-1111-4111-8111-111111111111";
const CAROL: &str = "22222222-2222-4222-8222-222222222222";
const BEARER: &str = "bbk_testkeytestkeytestkey";
/// Two applications, every access kind, a carve-out that only works because scopes
/// are first match wins, and a key narrower than its owner.
fn fixture() -> String {
    r#"{
          "version": 1,
          "applications": [
            { "name": "mpa",
              "base": ["https://app.x.com/mpa"],
              "login_url": "https://signup.x.com/",
              "denied_url": "https://app.x.com/mpa-denied",
              "scopes": [
                { "name": "healthz", "urls": ["https://app.x.com/mpa/healthz"],
                  "access": "anonymous" },
                { "name": "admin", "urls": ["https://app.x.com/mpa/admin/*"],
                  "access": "restricted", "groups": ["@admins"], "credentials": ["login"] },
                { "name": "onboarding", "urls": ["https://app.x.com/mpa/*"],
                  "access": "authenticated" } ] },
            { "name": "mcp",
              "base": ["https://ai.x.com/mcp"],
              "scopes": [
                { "name": "logs", "urls": ["https://ai.x.com/mcp/logs/*"],
                  "access": "restricted", "users": ["BOBUUID"] },
                { "name": "api", "urls": ["https://ai.x.com/mcp/*"],
                  "access": "restricted", "users": ["BOBUUID"],
                  "credentials": ["api_key"] } ] } ],
          "user_groups": { "admins": ["BOBUUID"] },
          "denied": ["spammer@x.com"],
          "users": [
            { "uuid": "BOBUUID", "emails": ["bob@x.com", "bob@old.com"],
              "api_keys": [ { "id": "laptop", "key_hash": "KEYHASH",
                              "released": "2026-01-01", "duration": "never",
                              "scopes": ["mcp/api"] } ] },
            { "uuid": "CAROLUUID", "emails": ["carol@x.com"] } ] }"#
        .replace("BOBUUID", BOB)
        .replace("CAROLUUID", CAROL)
        .replace("KEYHASH", &sha256_hex(BEARER))
}

fn fixture_key(a: &Access) -> &ApiKeyRecord {
    match decide_api_key(a, &sha256_hex(BEARER), 1_000) {
        KeyDecision::Granted(r) => r,
        _ => panic!("the fixture key must resolve"),
    }
}

/// The fixture with `excluded` on the scopes named, so each test below says only what
/// it is about.
fn with_exclusion(scope_urls: &str, excluded: &str) -> String {
    fixture().replace(
        &format!(r#""urls": ["{scope_urls}"],"#),
        &format!(r#""urls": ["{scope_urls}"], "excluded": [{excluded}],"#),
    )
}

/// A claim list from the comma-separated spelling, which is how these cases read best.
fn claims(spec: &str) -> Vec<String> {
    spec.split(',').map(str::to_string).collect()
}

/// The refusal, without asking the `Ok` side for a `Debug` it need not have. Generic over
/// the error because §13.31 changes it in mid-flight: the `String` leaf wrappers stay
/// `String`, while `compile_settings` answers `SettingsRefusal` and `prepare` answers
/// `PrepareError`. All three print the same sentence, so reading the sentence through
/// `Display` keeps every caller in this file compiling across every slice.
fn refusal<T, E: std::fmt::Display>(r: Result<T, E>) -> String {
    match r {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e.to_string(),
    }
}

/// A settings document through the real parser. The error stays the printed sentence:
/// §13.31 turns `compile_settings`' error type into `SettingsRefusal`, whose `Display` is
/// today's sentence byte for byte, so every caller here keeps reading the same text.
fn settings(json: &str) -> Result<Settings, String> {
    let f: SettingsFile = serde_json::from_str(json).map_err(|e| e.to_string())?;
    compile_settings(&f).map_err(|e| e.to_string())
}
