'use strict';
// The no-JavaScript and PRG half of the design. Zero <script> tags is not an
// implementation detail: it is what makes the bfcache Back-button recovery on the 409
// reliable, and it means everything the suite tests is plain HTML semantics. PRG is the
// other half — a successful mutation answers 303 to `?msg=<key>`, so a reload of what
// the browser shows repeats nothing. And `can` answers with the gate's own decision
// function, read-only by construction.
//
// The rule is "no page may need it" rather than "no JavaScript": the Settings list boxes
// carry one inline handler that saves a click, and the last block here runs the whole GUI
// with scripting switched off to prove nothing else does.

const { doc, bytes, newPage, submit, mainText } = require('../lib/harness');

async function run(ctx, t) {
  const { context, page } = await newPage(ctx);
  try {
    // Zero scripts, sampled across page shapes: dashboard, list, form.
    for (const p of ['/', '/users', '/apps', '/apps/app1', '/users/b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d/keys/+add']) {
      await page.goto(ctx.base + p);
      t.eq(`no <script> on ${p}`, await page.locator('script').count(), 0);
      // And exactly one kind of handler, on exactly the two controls entitled to it.
      const handlers = await page.evaluate(() => [...document.querySelectorAll('*')]
        .flatMap((el) => [...el.attributes]
          .filter((a) => a.name.startsWith('on'))
          .map((a) => `${el.tagName.toLowerCase()}[${el.getAttribute('name')}] ${a.name}=${a.value}`)));
      t.eq(`the only JavaScript on ${p} is the settings list boxes`, handlers.join(' | '),
        'select[lang] onchange=this.form.submit() | select[theme] onchange=this.form.submit()');
    }

    // PRG: save, land on the msg page, reload it — a GET, so nothing can repeat.
    await page.goto(ctx.base + '/groups/admins/edit');
    const members = await page.locator('textarea[name=members]').inputValue();
    await page.fill('textarea[name=members]', members + '\nbot@example.com');
    await submit(page);
    t.check('a save lands on a GET with ?msg=', page.url().includes('?msg=group-saved'), page.url());
    t.check('and renders the flash', (await page.locator('.flash').count()) >= 1);
    const afterSave = bytes(ctx);
    await page.reload();
    t.check('reloading the landing page re-posts nothing', bytes(ctx) === afterSave, 'reload wrote bytes');
    t.check('and stays on the same URL', page.url().includes('?msg=group-saved'), page.url());

    // `can` — would this credential get in? The form is a GET: asking is not an action.
    await page.goto(ctx.base + '/can');
    const method = await page.locator('main form').first().evaluate((f) => (f.getAttribute('method') || 'get'));
    t.eq('the can form is a GET', method.toLowerCase(), 'get');

    const before = bytes(ctx);
    const verdict = async (email, url) => {
      await page.goto(`${ctx.base}/can?email=${encodeURIComponent(email)}&url=${encodeURIComponent(url)}`);
      return mainText(page);
    };
    // The corners of the grant model, answered by the library's own `decide`:
    t.check('a member of a restricted scope is AUTHORIZED',
      (await verdict('you@example.com', 'https://app.example.com/app1/admin/panel')).includes('AUTHORIZED'));
    t.check('the credential class is the place\'s to decide — a login on an api_key-only scope is DENIED',
      (await verdict('bot@example.com', 'https://mcp.example.com/mcp/context7/x')).includes('DENIED'));
    t.check('denied outranks everything — spammer@ on an authenticated scope is DENIED',
      (await verdict('spammer@example.com', 'https://app.example.com/app1')).includes('DENIED'));
    t.check('authenticated grants on identity alone — a stranger is AUTHORIZED there',
      (await verdict('stranger@example.com', 'https://app.example.com/app1')).includes('AUTHORIZED'));
    t.check('an anonymous scope needs no credential at all',
      (await verdict('', 'https://app.example.com/app1/healthz')).includes('AUTHORIZED'));
    t.check('a URL no application covers is reachable by nobody',
      (await verdict('you@example.com', 'https://nowhere.example.com/')).includes('DENIED'));
    await t.shot(page, 'can-denied');

    t.check('asking `can` wrote nothing', bytes(ctx) === before, 'can mutated the file');
  } finally {
    await context.close();
  }

  // --- the same GUI with scripting off ------------------------------------
  // The one handler is an enhancement, so everything has to still work without it: the
  // Settings menu grows its submit button back, and that button is the only path that
  // sets both preferences in a single trip.
  const noJs = await ctx.browser.newContext({
    viewport: { width: 1280, height: 900 },
    extraHTTPHeaders: { 'X-Auth-Email': 'admin@example.com' },
    javaScriptEnabled: false,
  });
  try {
    const page = await noJs.newPage();
    await page.goto(ctx.base + '/users');
    // `details` is HTML, not script: the menu still opens.
    await page.click('details.settings > summary');
    t.eq('with scripting off the Settings menu still opens',
      await page.locator('.menu select[name=lang]').count(), 1);
    t.eq('and grows its submit button back', await page.locator('.menu button').count(), 1);

    await page.selectOption('.menu select[name=lang]', 'it');
    await page.selectOption('.menu select[name=theme]', 'dark');
    t.eq('picking an option alone changes nothing without the click',
      await page.locator('html').getAttribute('lang'), 'en');
    await submit(page, '.menu button');
    t.eq('the button applies the language', await page.locator('html').getAttribute('lang'), 'it');
    t.eq('and the theme, both in one trip',
      await page.locator('html').getAttribute('data-theme'), 'dark');

    // Every other page shape is unchanged by scripting: a mutation still goes through.
    const beforeSave = bytes(ctx);
    await page.goto(ctx.base + '/denied/+add');
    await page.fill('input[name=email]', 'noscript@example.com');
    await submit(page);
    t.check('and a save still writes with no script anywhere', bytes(ctx) !== beforeSave);
    t.check('the file has the new row',
      doc(ctx).denied.includes('noscript@example.com'), JSON.stringify(doc(ctx).denied));

    // A list's filter is a GET form, so it navigates with no script at all. This is the
    // whole reason filtering and paging live in the query string.
    await page.goto(ctx.base + '/users');
    // Scoped to the roster's own control row: three lists share this page, and each one
    // has to submit only its own two parameters.
    const roster = '.listctl:has(input[name=uq])';
    await page.fill(`${roster} input[name=uq]`, 'bot@');
    await submit(page, `${roster} button`);
    t.check('the filter navigates with scripting off', page.url().includes('uq=bot'), page.url());
    const filtered = await mainText(page);
    t.check('and it narrows the roster', filtered.includes('bot@example.com'), filtered);
    t.check('dropping the rows it does not match',
      !filtered.includes('/users/8f14e45f'), filtered);
    t.check('while the groups section beside it is untouched',
      (await page.locator('h2:has-text("user_groups")').count()) === 1);
  } finally {
    await noJs.close();
  }
}

module.exports = { run };
