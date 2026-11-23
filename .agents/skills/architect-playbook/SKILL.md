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

## Pitfalls

- `X-Auth-Email` can hold several emails joined by a space: never treat the whole header as one email.
- systemd `IPAddressDeny` also filters outbound traffic, so a unit that calls Cognito cannot copy
  `bb-auth-web`'s loopback lock.
