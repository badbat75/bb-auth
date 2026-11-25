---
name: architect-playbook
description: How the architect designs software and infrastructure in this project, and the pitfalls met so far. Use when designing or reviewing architecture.
---

Rules are in `AGENTS.md`. Format of this file: `AGENTS.md`, under "Skills".

## How to

- Before giving `access.json` a second writer, read `write_atomically`: an unprivileged writer
  must already own the file and belong to its group, so two writers mean one shared uid.
- A self-service Cognito action needs the user's own access token. A server-side `USER_AUTH` /
  `EMAIL_OTP` sign-in gets one with no JavaScript and no IAM credential.
- Check every AWS fact against the Cognito API reference
  (docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/) and mark what is unverified.

- To hide a secret from a unit, `InaccessiblePaths=` its whole directory, even the one holding the
  unit's own env file: `EnvironmentFile=` is read by the manager before any bind mount
  (systemd.exec(5)).

- rpi-01's applications own whole hosts (base `https://<host>`), so a new path on a host is a
  scope in that host's application, listed before its catch-all, never a new application.
  Read the live file with `sudo bb-auth-adm -f /opt/bb-auth/var/lib/access.json show`.

- A worker count here (`BB_AUTH_WORKERS`, `BB_AUTH_WEB_WORKERS`) bounds concurrent handlers, not
  connections: `tiny_http` 0.12 queues every parsed request with no bound, so too few workers is
  latency, never a refusal (`tiny_http-0.12.0/src/lib.rs`, `util/task_pool.rs` in the cargo registry).

- A Cognito API call from Rust here copies `login.html`: `POST` the issuer's origin with
  `Content-Type: application/x-amz-json-1.1` and `X-Amz-Target:
  AWSCognitoIdentityProviderService.<Action>`; the error is `__type` after its last `#`. Build
  the `ureq` agent with `http_status_as_error(false)` or a `400`'s body is lost.
- A plain-HTTP fake cannot be named through the settings file (`compile_issuer` is https-only):
  give `bb-auth-web`'s `Config` a field `from_env` never sets, as §13.22 does.
- A switch only a test harness may flip is a cargo feature plus `compile_error!` under
  `not(debug_assertions)`, plus a `grep -aq` of the env var name over `dist/` in `package.sh`:
  env var names survive `strip` and LTO in the release binary (measured, §13.24).
- A new field for the session cookie goes in the claims JSON segment under a key whose derived
  header `compile_profile_claims` reserves: old cookies still verify and a rollback binary still
  accepts new ones, so it is no `COOKIE_VERSION` bump (§13.25). A new positional segment is one.
- The real pool's facts are in `PLAN.md` step 5 (read 2026-11-25); its changes go through the
  OpenTofu repository named there, never the AWS CLI.

## Pitfalls

- `ureq` 3 has no timeout by default (`Timeouts::default`, `config.rs`): every outbound call needs
  `timeout_global` on its agent, or a slow peer pins a worker for ever.

- rpi-01's `auth.badbat75.com` vhost gates at server level (`snippets/bb-auth.conf`), unlike the
  README's per-location recipe: read `sudo nginx -T` before writing a location for it.

- `X-Auth-Email` can hold several emails joined by a space: never treat the whole header as one email.
- systemd `IPAddressDeny` also filters outbound traffic, so a unit that calls Cognito cannot copy
  `bb-auth-web`'s loopback lock.
- A systemd per-file `ReadOnlyPaths=` does not survive another namespace's rename onto that file: it
  is lazily detached (Linux 3.18, commit 8ed936b5671b). Guard a directory instead.
- bb-auth-web believes `X-Auth-Email` from any process that can reach its loopback port, not only from
  nginx. A design that adds a local caller must say what that caller could ask for.
- Group `bb-auth` reads `bb-auth.env` (the HMAC key) and the audit: a new unit in that group needs
  `InaccessiblePaths=` for what it must not read.
- The operator's `ui.stylesheet_url` loads after ours and can override a `hidden` attribute with a
  `display` rule: anything hidden for scripting-off browsers needs a `[hidden]` rule in our CSS too.
- `parse_duration("")` is `Dur::Never`: a form whose duration field goes missing mints a key that
  never expires unless the handler refuses empty first.
- The console already confirms a key removal (`act_rm` links to a `GET` `page_confirm`): read the
  console's flow before designing a "new" confirmation.
- Every page here sends `Referrer-Policy: no-referrer` (`PAGE_SECURITY_HEADERS`), so the gate's
  `Referer` fallback (`rd_candidate`) never fires for a link on our own pages: design with `?rd=`.
- `GateSettings` (and every settings section) is `deny_unknown_fields`: a new key makes an older
  binary refuse the file, so a new setting needs `skip_serializing_if` when empty and a
  deploy-then-set order (§13.19).
- `/auth/session`'s caller is the sign-in page's host, so `safe_rd`'s "caller's root" default is
  the auth host's root, never the application the person came from.
- A slice that lands a function with no production caller fails clippy (`dead_code`): land a
  client together with its first use.
- `DescribeUserPoolClient` omits `ReadAttributes`/`WriteAttributes` when they are the default,
  which is every attribute writable: an absent list is not "none".
- The rpi-01 pool has unlinked native and federated users sharing one email: `USERNAME` = email
  reaches the native one. Act on a session's Cognito user by its `cognito:username`, never its email.
