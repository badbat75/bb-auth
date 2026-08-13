'use strict';
// The language switch. `?lang=` answers with a 302 that sets a display cookie and
// changes nothing else — it is the single redirect a GET performs, and the cookie
// carries no identity and no capability. From then on every page, including the
// refusals, renders in the chosen language; `html lang=` is the machine-readable proof,
// the copied strings pin the human-readable half.

const { newPage, pageLang, api } = require('../lib/harness');

async function run(ctx, t) {
  // The redirect + cookie contract, at the HTTP level.
  const r = await api(ctx, '/admin/?lang=it', { redirect: 'manual' });
  t.eq('?lang= answers with a 302', r.status, 302);
  const setCookie = r.headers.get('set-cookie') || '';
  t.check('setting the display cookie', setCookie.includes('lang=it'), setCookie);
  t.check('HttpOnly + SameSite=Lax — a display preference, hardened anyway',
    setCookie.includes('HttpOnly') && setCookie.includes('SameSite=Lax'), setCookie);
  t.check('and redirecting back under the base path', (r.headers.get('location') || '').startsWith('/admin'),
    r.headers.get('location'));

  const { context, page } = await newPage(ctx);
  try {
    await page.goto(ctx.base + '/?lang=it');
    t.eq('the page renders in Italian', await pageLang(page), 'it');
    await t.shot(page, 'home-it');

    // Persistence: a plain navigation, no query — the cookie answers.
    await page.goto(ctx.base + '/users');
    t.eq('the choice sticks across plain navigations', await pageLang(page), 'it');

    // The refusals speak it too: same browser (cookie kept), non-admin identity.
    await context.setExtraHTTPHeaders({ 'X-Auth-Email': 'friend@example.com' });
    const r403 = await page.goto(ctx.base + '/');
    t.eq('the 403 is still a 403 under lang=it', r403.status(), 403);
    t.check('and speaks Italian', (await page.locator('body').innerText())
      .includes('è autenticato, ma non è in BB_AUTH_WEB_ADMINS'), await page.locator('body').innerText());
    await t.shot(page, '403-it');
    await context.setExtraHTTPHeaders({ 'X-Auth-Email': 'admin@example.com' });

    // The `can` verdict — the operator-facing word — is translated.
    await page.goto(ctx.base + '/can?email=spammer%40example.com&url=https%3A%2F%2Fapp.example.com%2Fapp1');
    t.check('the denied verdict reads NEGATO', (await page.locator('main').innerText()).includes('NEGATO'));

    // And back: ?lang=en rewrites the cookie.
    await page.goto(ctx.base + '/?lang=en');
    t.eq('switching back to English works', await pageLang(page), 'en');
    await page.goto(ctx.base + '/users');
    t.eq('and persists the same way', await pageLang(page), 'en');
  } finally {
    await context.close();
  }
}

module.exports = { run };
