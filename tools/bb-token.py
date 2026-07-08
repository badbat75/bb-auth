#!/usr/bin/env python3
"""bb-token - obtain/refresh a Cognito id_token for the bb-auth gate.

A tiny, dependency-free CLI (Python 3 stdlib only) that runs the same passwordless
Cognito flow the browser login page uses, and hands you an `id_token` to send as
`Authorization: Bearer <id_token>` to any bb-auth-gated service (e.g.
https://mcp.badbat75.com) from off-LAN.

It talks to the PUBLIC Cognito API directly (unsigned, like a browser) - it needs
NO AWS credentials, SDK, or CLI. The only inputs are your email and the one-time
code Cognito emails you.

Token lifetimes (badbat75 defaults): id_token ~1 h, refresh_token ~30 days. This
tool caches both and transparently refreshes the id_token (no new OTP) until the
refresh token expires; then you `login` again.

Commands
  login            interactive email + OTP login; caches the tokens
  token            print a valid id_token (refreshes if needed)   [default]
  header           print `Authorization: Bearer <id_token>`
  status           show cached email + id_token / refresh expiry
  logout           delete the cached tokens

Examples
  python bb-token.py login --email you@example.com
  curl -H "$(python bb-token.py header)" https://mcp.badbat75.com/mcp/foo/
  TOK=$(python bb-token.py token)

Config (flags override env override defaults)
  --region     BB_TOKEN_REGION     default: eu-central-1
  --client-id  BB_TOKEN_CLIENT_ID  default: 39c7grfrau8i7tvqqkej86sh98  (badbat75-public-register)
  --cache      BB_TOKEN_CACHE      default: ~/.bb-token/<client_id>.json  (0600; holds the refresh token)
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

DEFAULT_REGION = os.environ.get("BB_TOKEN_REGION", "eu-central-1")
DEFAULT_CLIENT_ID = os.environ.get("BB_TOKEN_CLIENT_ID", "39c7grfrau8i7tvqqkej86sh98")
EXP_SKEW = 60  # refresh this many seconds before the id_token actually expires


def eprint(*a):
    print(*a, file=sys.stderr)


# --- Cognito public API (unsigned JSON-1.1) -------------------------------------

def cognito(region, target, payload):
    """POST one AWSCognitoIdentityProviderService call. Returns the parsed JSON.
    Raises RuntimeError(message) on a Cognito error response."""
    url = f"https://cognito-idp.{region}.amazonaws.com/"
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": f"AWSCognitoIdentityProviderService.{target}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        msg = detail
        try:
            j = json.loads(detail)
            msg = j.get("message") or j.get("__type") or detail
        except ValueError:
            pass
        raise RuntimeError(f"Cognito {target} failed: {msg}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"network error calling Cognito: {e.reason}") from None


# --- token helpers --------------------------------------------------------------

def jwt_claims(token):
    """Decode (WITHOUT verifying) a JWT's payload. bb-auth does the real
    verification server-side; here we only need `exp`/`email` for cache bookkeeping."""
    try:
        seg = token.split(".")[1]
        pad = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad).decode())
    except Exception:
        return {}


def cache_path(args):
    if args.cache:
        return os.path.expanduser(args.cache)
    if os.environ.get("BB_TOKEN_CACHE"):
        return os.path.expanduser(os.environ["BB_TOKEN_CACHE"])
    return os.path.join(os.path.expanduser("~"), ".bb-token", f"{args.client_id}.json")


def load_cache(args):
    try:
        with open(cache_path(args), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_cache(args, data):
    path = cache_path(args)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        os.chmod(os.path.dirname(path), 0o700)
    except OSError:
        pass
    # Write 0600 from the start (the refresh token is a 30-day credential).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def store_result(args, auth_result, email, refresh_token, refresh_obtained_at):
    """Persist an AuthenticationResult (from login or refresh) into the cache."""
    id_token = auth_result["IdToken"]
    data = {
        "client_id": args.client_id,
        "region": args.region,
        "email": email,
        "id_token": id_token,
        "access_token": auth_result.get("AccessToken"),
        # refresh flows usually omit a new RefreshToken - keep the existing one.
        "refresh_token": auth_result.get("RefreshToken") or refresh_token,
        "id_token_exp": jwt_claims(id_token).get("exp"),
        "refresh_obtained_at": refresh_obtained_at,
    }
    save_cache(args, data)
    return data


# --- flows ----------------------------------------------------------------------

def do_login(args):
    email = args.email or input("Email: ").strip()
    if not email:
        eprint("no email given")
        return 2

    eprint(f"Requesting an email code for {email} ...")
    init = cognito(args.region, "InitiateAuth", {
        "AuthFlow": "USER_AUTH",
        "ClientId": args.client_id,
        "AuthParameters": {"USERNAME": email, "PREFERRED_CHALLENGE": "EMAIL_OTP"},
    })

    challenge = init.get("ChallengeName")
    session = init.get("Session")
    params = init.get("ChallengeParameters", {}) or {}

    # If Cognito insists on the choice step, pick EMAIL_OTP explicitly.
    if challenge == "SELECT_CHALLENGE":
        sel = cognito(args.region, "RespondToAuthChallenge", {
            "ClientId": args.client_id,
            "ChallengeName": "SELECT_CHALLENGE",
            "Session": session,
            "ChallengeResponses": {"USERNAME": email, "ANSWER": "EMAIL_OTP"},
        })
        challenge = sel.get("ChallengeName")
        session = sel.get("Session")
        params = sel.get("ChallengeParameters", {}) or params

    if challenge != "EMAIL_OTP":
        eprint(f"unexpected challenge from Cognito: {challenge!r}")
        return 1

    username = params.get("USERNAME", email)
    code = input("Email code: ").strip()

    resp = cognito(args.region, "RespondToAuthChallenge", {
        "ClientId": args.client_id,
        "ChallengeName": "EMAIL_OTP",
        "Session": session,
        "ChallengeResponses": {"USERNAME": username, "EMAIL_OTP_CODE": code},
    })
    result = resp.get("AuthenticationResult")
    if not result or "IdToken" not in result:
        eprint("login did not return tokens (wrong/expired code?)")
        return 1

    data = store_result(args, result, email, None, int(time.time()))
    left = int((data.get("id_token_exp") or 0) - time.time())
    eprint(f"OK - logged in as {email}. id_token valid ~{max(left, 0)//60} min; "
           f"cached at {cache_path(args)}")
    if not args.quiet:
        print(data["id_token"])
    return 0


def valid_id_token(args, allow_refresh=True):
    """Return a currently-valid id_token from cache, refreshing if needed, or None."""
    cache = load_cache(args)
    if not cache:
        return None, "no cached login - run: bb-token login"
    exp = cache.get("id_token_exp") or 0
    if time.time() < exp - EXP_SKEW and cache.get("id_token"):
        return cache["id_token"], None
    if not allow_refresh:
        return None, "id_token expired"
    rt = cache.get("refresh_token")
    if not rt:
        return None, "id_token expired and no refresh token - run: bb-token login"
    eprint("id_token expired - refreshing ...")
    try:
        resp = cognito(args.region, "InitiateAuth", {
            "AuthFlow": "REFRESH_TOKEN_AUTH",
            "ClientId": args.client_id,
            "AuthParameters": {"REFRESH_TOKEN": rt},
        })
    except RuntimeError as e:
        return None, f"{e}\nrefresh token likely expired - run: bb-token login"
    result = resp.get("AuthenticationResult")
    if not result or "IdToken" not in result:
        return None, "refresh returned no id_token - run: bb-token login"
    data = store_result(args, result, cache.get("email"), rt,
                        cache.get("refresh_obtained_at") or int(time.time()))
    return data["id_token"], None


def do_token(args):
    tok, err = valid_id_token(args)
    if err:
        eprint(err)
        return 1
    print(tok)
    return 0


def do_header(args):
    tok, err = valid_id_token(args)
    if err:
        eprint(err)
        return 1
    print(f"Authorization: Bearer {tok}")
    return 0


def do_status(args):
    cache = load_cache(args)
    if not cache:
        eprint(f"no cached login at {cache_path(args)} - run: bb-token login")
        return 1
    now = time.time()
    exp = cache.get("id_token_exp") or 0
    id_left = int(exp - now)
    rt_at = cache.get("refresh_obtained_at") or 0
    rt_exp = rt_at + 30 * 86400 if rt_at else 0  # 30-day default; informational
    print(f"cache     : {cache_path(args)}")
    print(f"email     : {cache.get('email')}")
    print(f"client_id : {cache.get('client_id')}  region: {cache.get('region')}")
    print(f"id_token  : {'valid' if id_left > EXP_SKEW else 'EXPIRED'} "
          f"({id_left//60} min left)")
    if rt_exp:
        rt_days = int((rt_exp - now) // 86400)
        print(f"refresh   : ~{rt_days} day(s) left (30-day default; auto-renews the id_token)")
    return 0


def do_logout(args):
    path = cache_path(args)
    try:
        os.remove(path)
        eprint(f"removed {path}")
    except FileNotFoundError:
        eprint("nothing cached")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="bb-token",
        description="Obtain/refresh a Cognito id_token for the bb-auth gate.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("command", nargs="?", default="token",
                   choices=["login", "token", "header", "status", "logout"])
    p.add_argument("--email", help="email for `login` (prompted if omitted)")
    p.add_argument("--region", default=DEFAULT_REGION)
    p.add_argument("--client-id", default=DEFAULT_CLIENT_ID, dest="client_id")
    p.add_argument("--cache", help="cache file path (default ~/.bb-token/<client_id>.json)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="`login`: don't also print the id_token")
    args = p.parse_args(argv)

    try:
        return {
            "login": do_login,
            "token": do_token,
            "header": do_header,
            "status": do_status,
            "logout": do_logout,
        }[args.command](args)
    except RuntimeError as e:
        eprint(str(e))
        return 1
    except KeyboardInterrupt:
        eprint("\naborted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
