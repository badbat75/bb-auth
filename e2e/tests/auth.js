'use strict';
// Identity and request shape — the rules that hold before any page logic runs.
//
// The GUI trusts exactly one thing: the `X-Auth-Email` header nginx injects. No header
// is a 401 (a broken deployment must be an error page, not an anonymous session), a
// header that is not on BB_AUTH_WEB_ADMINS is a 403, and every mutation must arrive as
// a same-origin POST. These are raw-HTTP contracts, so this area speaks fetch, not the
// browser: what matters is the status line and that the file did not move.

const { doc, bytes, api } = require('../lib/harness');

async function run(ctx, t) {
  // --- who are you -----------------------------------------------------------------
  const r401 = await api(ctx, '/admin/', { email: null });
  t.eq('no identity header is a 401', r401.status, 401);
  const b401 = await r401.text();
  t.check('the 401 names the missing header contract', b401.includes('No identity header'), b401.slice(0, 300));
  t.check('the 401 points at the nginx wiring', b401.includes('auth_request'), b401.slice(0, 300));

  // friend@example.com is enrolled in the access file — the 403 is exactly the point:
  // being on the roster the gate enforces buys nothing here, only BB_AUTH_WEB_ADMINS does.
  const r403 = await api(ctx, '/admin/', { email: 'friend@example.com' });
  t.eq('authenticated non-admin is a 403', r403.status, 403);
  const b403 = await r403.text();
  t.check('the 403 names the allowlist', b403.includes('BB_AUTH_WEB_ADMINS'), b403.slice(0, 300));
  t.check('the 403 echoes who was refused', b403.includes('friend@example.com'), b403.slice(0, 300));

  const r200 = await api(ctx, '/admin/');
  t.eq('admin is let in', r200.status, 200);

  // --- where are you ---------------------------------------------------------------
  t.eq('unknown page under the base path is a 404', (await api(ctx, '/admin/nosuchpage')).status, 404);
  // Outside the base path nothing answers — a misconfigured nginx `location` must not
  // fall through to the dashboard.
  t.eq('outside the base path is a 404', (await api(ctx, '/')).status, 404);
  t.eq('no asset routes: /favicon.ico is a 404', (await api(ctx, '/favicon.ico')).status, 404);

  // --- a GET never mutates ----------------------------------------------------------
  const before = bytes(ctx);
  const rGet = await api(ctx, '/admin/sites/app1-onboarding/move');
  t.eq('GET on a POST-only route is a 405', rGet.status, 405);
  t.check('and writes nothing', bytes(ctx) === before, 'file changed under a GET');

  // --- strict same-origin on every POST ---------------------------------------------
  const post = (headers) =>
    api(ctx, '/admin/denied/+add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams({ rev: 'whatever', email: 'x@example.com' }).toString(),
    });

  const rForeign = await post({ Origin: 'https://evil.example.com' });
  t.eq('POST with a foreign Origin is a 403', rForeign.status, 403);
  t.check('the refusal explains the same-origin rule', (await rForeign.text()).includes('same-origin'));

  // No Sec-Fetch-Site and no Origin: whatever this is, it is not a browser posting a form.
  t.eq('POST with neither Sec-Fetch-Site nor Origin is a 403', (await post({})).status, 403);

  // Where the browser speaks, Sec-Fetch-Site is the whole answer — a matching Origin
  // does not rescue a cross-site submission.
  const rCross = await post({
    'Sec-Fetch-Site': 'cross-site',
    Origin: ctx.origin,
  });
  t.eq('cross-site Sec-Fetch-Site is a 403 even with a matching Origin', rCross.status, 403);

  // Identity is checked before anything else — an anonymous POST is a 401, not a 403.
  const rAnon = await api(ctx, '/admin/denied/+add', {
    method: 'POST',
    email: null,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'same-origin' },
    body: 'rev=whatever&email=x%40example.com',
  });
  t.eq('anonymous POST is a 401', rAnon.status, 401);

  t.check('none of the refused POSTs wrote anything', bytes(ctx) === before, 'file changed');
  t.check('and the denied list is untouched', !doc(ctx).denied.includes('x@example.com'));
}

module.exports = { run };
