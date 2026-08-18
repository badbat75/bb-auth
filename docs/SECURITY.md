# Security

bb-auth is an authentication gate: a defect in it is a lockout or an unauthorized request,
so a report about one is worth more than a patch for anything else in the repository.

## Reporting

Open a **private** security advisory on the repository (Security → Advisories → Report a
vulnerability), or write to the address on the maintainer's GitHub profile. Please do not
open a public issue for something that lets somebody in.

Include what you would want to receive: the version (`bb-auth --version` on the host prints
the commit as well as the release), the request or the access-file fragment that triggers
it, and what you expected instead. There is no bounty and no formal SLA; a single
maintainer reads these.

## What is in scope

The three binaries and the two files they read:

* the gate: `/auth/validate`, `/auth/session`, `/auth/logout`, the two pages, the session
  cookie, id_token validation, the identity and profile headers;
* the access file and the grant model: anything that lets a subject reach a URL it is not
  granted, or keeps one out that is;
* the admin CLI and GUI: anything that writes a file the gate would refuse, that bypasses
  the same-origin or `rev` guards, or that reveals an API key bearer to somebody who should
  not have it.

## What is not

* **nginx configuration**: the gate's identity headers are only trustworthy because nginx
  clears them on every gated location and the application is unreachable except through
  nginx. A deployment that does not do that is misconfigured, and README says so at
  length. A report that the README's own blocks are wrong *is* in scope.
* **Reaching the loopback ports directly.** Both services speak plain HTTP and trust their
  reverse proxy for the request URL; the GUI takes its identity from a header. That is the
  documented deployment, and it is why the GUI refuses a non-loopback bind.
* **Anything an administrator can already do.** `web.admins` is full write access to the
  access file by design.

## Known posture

Two settings widen the door on purpose, and both are off by default:

* an `authenticated` scope admits any identity Cognito vouches for, and Cognito self-signup
  is open, so it means "anyone who can register";
* `allow_unverified_social` accepts an unverified email for federated logins only.

Together they mean "any social account, unverified email, no enrolment". The gate prints a
warning naming both at startup.
