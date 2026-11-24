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
