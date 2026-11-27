// =====================================================================
// The self-service page at `/account/` (plan step 3c, docs/ARCHITECTURE.md §13.2).
//
// These are the tests `bb-auth-me` answers today, ported to this binary, because the page
// is moving here: one program then serves the console and the self-service page out of one
// pair of files, and the routing tests at the end are the boundary the move has to create.
// Every request here carries the proxy secret, because the secret check sits **above** the
// identity check: a request without it is a `403` whatever else it carries, so a test about
// the page has to be a request the proxy would have made.
//
// Two prefixes, not one: the console is mounted at `/admin` and the page lives at its own
// prefix `/account` (`BB_AUTH_WEB_ACCOUNT_PATH`, the field `cfg_for` fills in). The admin
// base is never empty in these fixtures, because an empty base covers every path and so
// cannot coexist with a self-service prefix: `compile_account_path` refuses it at startup.
//
// The fixtures' `web.admins` names `admin@x.com` and nobody else, on purpose. Bob, carol
// and the stranger all reach `/account/` and none of them is an administrator, which is the
// proof that this page never reads the allowlist; `admin@x.com` is the administrator with
// no roster row, and `/account/` answers them exactly as it answers a stranger.
// =====================================================================
