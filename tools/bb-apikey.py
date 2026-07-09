#!/usr/bin/env python3
"""bb-apikey - mint a static `bbk_` API key for the bb-auth gate.

A tiny, dependency-free CLI (Python 3 stdlib only) that generates a high-entropy
API key, prints the RAW bearer ONCE (give it to the client), and prints the JSON
`api_keys` entry to paste into a user's record in BB_AUTH_USERS_FILE. The users
file only ever stores the SHA-256 of the key (`key_hash`) — never the key itself,
so the file at rest is not a live-credential dump. Losing the raw key means
minting a new one; there is no way to recover it.

The key is used as:  Authorization: Bearer bbk_<secret>
and validated by bb-auth per request against the owning user's / key's expiry and
authorized-URL scope. It is NOT a Cognito token and needs no AWS anything.

Usage
  bb-apikey.py <email> [--id LABEL] [--duration 365d] [--urls URL,URL] [--released YYYY-MM-DD]

Examples
  # a key for bob, valid 1 year, confined to the /mcp subtree of one host
  python bb-apikey.py bob@badbat75.com --id laptop --duration 365d \
      --urls https://mcp.badbat75.com/mcp,https://mcp.badbat75.com/mcp/*

  # a never-expiring key that inherits the user's own scope
  python bb-apikey.py svc@badbat75.com --id ci --duration never

duration: `<n>d` days, `<n>h` hours, bare `<n>` days, or `0`/`never` = no expiry.
urls:     comma-separated <scheme>://<host>/<path> patterns; omit to inherit the
          user's authorized_urls. To grant every URL, say so: `*://*/*`.
          Wildcards work in every component: `*` matches any run of characters but
          never `/` — except as the pattern's final character, where it swallows the
          rest of the URL, slashes included; `&` matches exactly one non-`/` char.
          So `/mcp/*` covers the whole subtree, while `/mcp*` would also match
          `/mcp-admin`. Note `https://host/mcp/*` does NOT match a bare `/mcp` —
          list both if the client hits the parent too (as in the example above).

Validate the resulting users file with:  bb-auth --check-users <file>
"""

import argparse
import datetime
import hashlib
import json
import secrets
import sys

KEY_PREFIX = "bbk_"  # must match API_KEY_PREFIX in src/main.rs


def eprint(*a):
    print(*a, file=sys.stderr)


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="bb-apikey",
        description="Mint a static bbk_ API key for the bb-auth gate.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("email", help="owning user (must be a user in BB_AUTH_USERS_FILE)")
    p.add_argument("--id", default="key", help="human label for logs/revocation (default: key)")
    p.add_argument("--duration", default="365d", help="validity: 365d / 24h / 0 / never (default: 365d)")
    p.add_argument("--urls", default="",
                   help="comma-separated <scheme>://<host>/<path> patterns; omit to inherit the user scope")
    p.add_argument("--released", default=datetime.date.today().isoformat(),
                   help="issue date YYYY-MM-DD (default: today)")
    p.add_argument("--bytes", type=int, default=32, dest="nbytes",
                   help="secret entropy in bytes (default: 32 = 256 bits)")
    args = p.parse_args(argv)

    # High-entropy, URL-safe secret (no ':', no whitespace, no padding).
    key = KEY_PREFIX + secrets.token_urlsafe(args.nbytes)
    key_hash = hashlib.sha256(key.encode()).hexdigest()

    entry = {
        "id": args.id,
        "key_hash": key_hash,
        "released": args.released,
        "duration": args.duration,
    }
    urls = [s.strip() for s in args.urls.split(",") if s.strip()]
    if urls:
        entry["authorized_urls"] = urls

    # bb-auth rejects a malformed pattern outright (a fatal parse error), so flag the
    # obvious mistakes here rather than at deploy time.
    for u in urls:
        if "://" not in u:
            eprint(f"WARNING: '{u}' has no scheme; bb-auth needs <scheme>://<host>/<path>"
                   + (" -- for every URL, use '*://*/*'" if u == "*" else ""))
        elif "/" not in u.split("://", 1)[1]:
            eprint(f"WARNING: '{u}' has no path; use '{u}/*' to cover the whole host")
        elif u.endswith("*") and not u.endswith("/*"):
            eprint(f"WARNING: '{u}' ends in '*' without a '/'; it also matches sibling names")

    eprint("=== give this to the client ONCE (not stored anywhere, cannot be recovered) ===")
    eprint(f"Authorization: Bearer {key}")
    eprint("")
    eprint(f"=== paste into the \"api_keys\" array of {args.email} in BB_AUTH_USERS_FILE ===")
    # The JSON entry goes to stdout so it can be captured/piped.
    print(json.dumps(entry, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        eprint("\naborted")
        sys.exit(130)
