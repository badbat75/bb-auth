'use strict';
// The display preferences. `?lang=` answers with a 302 that sets a display cookie and
// changes nothing else: it is (with `?theme=`) one of the two redirects a GET performs,
// and the cookie carries no identity and no capability. From then on every page, including
// the refusals, renders in the chosen language; `html lang=` is the machine-readable proof,
// the copied strings pin the human-readable half.
//
// The Settings menu is the other half of this area: it is how a browser reaches those two
// parameters, and picking an option has to apply it on the spot while keeping the rest of
// the URL intact.

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
      .includes('è autenticato, ma non è amministratore'), await page.locator('body').innerText());
    await t.shot(page, '403-it');
    await context.setExtraHTTPHeaders({ 'X-Auth-Email': 'admin@example.com' });

    // The `can` verdict — the operator-facing word — is translated.
    await page.goto(ctx.base + '/apps/app1?email=spammer%40example.com&url=https%3A%2F%2Fapp.example.com%2Fapp1');
    t.check('the denied verdict reads NEGATO', (await page.locator('main').innerText()).includes('NEGATO'));

    // And back: ?lang=en rewrites the cookie.
    await page.goto(ctx.base + '/?lang=en');
    t.eq('switching back to English works', await pageLang(page), 'en');
    await page.goto(ctx.base + '/users');
    t.eq('and persists the same way', await pageLang(page), 'en');

    // --- the Settings menu ------------------------------------------------
    // Picking an option IS the interaction: the handler submits the form, so every `pick`
    // below is one navigation. The `<noscript>` submit button that does the same job for a
    // browser with scripting off is exercised in the nojs area, not here.
    const pick = (sel, value) =>
      Promise.all([page.waitForNavigation(), page.selectOption(`.menu select[name=${sel}]`, value)]);

    const canUrl = '/apps/app1?email=spammer%40example.com&url=https%3A%2F%2Fapp.example.com%2Fapp1';
    await page.goto(ctx.base + canUrl);
    t.check('the menu is closed until it is opened',
      !(await page.locator('details.settings').evaluate((d) => d.open)));
    await page.click('details.settings > summary');
    t.check('the language list box offers auto and the two languages',
      (await page.locator('.menu select[name=lang] option').evaluateAll(
        (os) => os.map((o) => o.value))).join(',') === 'auto,en,it');
    t.eq('and there is no button to press', await page.locator('.menu button').count(), 0);

    await pick('lang', 'it');
    t.eq('picking a language applies it on the spot', await pageLang(page), 'it');
    t.check('the parameter is redirected back out of the URL',
      !page.url().includes('lang='), page.url());
    t.check('and the rest of the query survived the round trip',
      page.url().includes('email=spammer%40example.com'), page.url());
    t.check('so the verdict is still on screen, now in Italian',
      (await page.locator('main').innerText()).includes('NEGATO'));

    // The theme is a second, independent pick, and it does not disturb the first.
    await page.click('details.settings > summary');
    await pick('theme', 'dark');
    t.eq('picking a theme applies it the same way',
      await page.locator('html').getAttribute('data-theme'), 'dark');
    t.eq('and leaves the language alone', await pageLang(page), 'it');
    t.check('with no parameter left in the URL',
      !page.url().includes('theme='), page.url());

    // Both choices stick, and the menu comes back showing them as the chosen options.
    await page.goto(ctx.base + '/users');
    t.eq('the language persists', await pageLang(page), 'it');
    t.eq('the theme persists', await page.locator('html').getAttribute('data-theme'), 'dark');
    await page.click('details.settings > summary');
    t.eq('the language list box reopens on the choice',
      await page.locator('.menu select[name=lang]').inputValue(), 'it');
    t.eq('and so does the theme list box',
      await page.locator('.menu select[name=theme]').inputValue(), 'dark');

    // Auto is a real choice and not just the absence of one: picking it undoes the fixed
    // language and hands the question back to the browser (Accept-Language is en here).
    await pick('lang', 'auto');
    t.eq('choosing auto goes back to following the browser', await pageLang(page), 'en');
    const cookies = await context.cookies();
    t.eq('and is stored as a choice of its own',
      (cookies.find((c) => c.name === 'lang') || {}).value, 'auto');
    await page.goto(ctx.base + '/users');
    await page.click('details.settings > summary');
    t.eq('so the menu reopens on auto, not on the language it resolved to',
      await page.locator('.menu select[name=lang]').inputValue(), 'auto');
    t.eq('and the theme is untouched by a language submit',
      await page.locator('html').getAttribute('data-theme'), 'dark');
    await t.shot(page, 'settings-menu');
  } finally {
    await context.close();
  }
}

module.exports = { run };
