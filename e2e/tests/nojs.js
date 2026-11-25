'use strict';
// The no-JavaScript and PRG half of the design. Zero <script> tags is not an
// implementation detail: it is what makes the bfcache Back-button recovery on the 409
// reliable, and it means everything the suite tests is plain HTML semantics. PRG is the
// other half — a successful mutation answers 303 to `?msg=<key>`, so a reload of what
// the browser shows repeats nothing. And the access check answers with the gate's own
// decision function, read-only by construction.
//
// The rule is "no page may need it" rather than "no JavaScript": the Settings list boxes
// carry one inline handler that saves a click, the bearer reveal carries one script for its
// copy button (§13.14), and the last block here runs the whole GUI with scripting switched
// off to prove nothing else does.

const crypto = require('crypto');
const { doc, bytes, newPage, submit, mainText } = require('../lib/harness');

/** The CSP source expression that names a script whose bytes are `s`. */
const cspHashOf = (s) => 'sha256-' + crypto.createHash('sha256').update(s, 'utf8').digest('base64');

/** The mint's reveal page, reached by filling the key form of `user` and submitting it. The
 *  duration is chosen from the five, which is the one component both surfaces render (§13.15
 *  as amended by §13.16), so this walk picks a choice rather than typing a window. */
async function revealKey(page, base, user, id) {
  await page.goto(`${base}/users/${encodeURIComponent(user)}/keys/+add`);
  await page.fill('input[name=id]', id);
  await page.selectOption('select[name=duration]', '365d');
  return submit(page, 'main form button[type=submit]');
}

/** Every `.pill.ico` on the page, as the browser laid it out, with the name it carries.
 *  A control the person has to hit is a box, and the only honest measurement of a box is
 *  the one the layout engine made. */
async function iconBoxes(page) {
  return page.$$eval('.pill.ico', (els) => els.map((el) => {
    const r = el.getBoundingClientRect();
    return { w: Math.round(r.width), h: Math.round(r.height), name: (el.textContent || '').trim() };
  }));
}

/** The Preferences menu closes on a click outside it (docs/ARCHITECTURE.md section 13.20).
 *  `apply` submits the chosen theme the way that surface does (a change on the console with
 *  scripting on, the Apply button otherwise) and resolves once the navigation it causes ends. */
async function menuClosesOutside(t, page, who, apply) {
  const isOpen = () => page.$eval('details.settings', (d) => d.open);
  const open = () => page.click('details.settings > summary');
  await open();
  t.eq(`${who}: the trigger opens the menu`, await isOpen(), true);
  await page.mouse.click(4, 896);
  t.eq(`${who}: a click at the bottom-left of the viewport closes it`, await isOpen(), false);

  await open();
  await page.click('.menu select[name=theme]');
  t.eq(`${who}: a click on a list box inside leaves it open`, await isOpen(), true);
  await page.keyboard.press('Escape');

  const before = await page.locator('html').getAttribute('data-theme');
  const pick = before === 'dark' ? 'light' : 'dark';
  await apply(pick);
  t.eq(`${who}: submitting a theme still applies it`,
    await page.locator('html').getAttribute('data-theme'), pick);
}

async function run(ctx, t) {
  const { context, page } = await newPage(ctx);
  try {
    // Zero scripts, sampled across page shapes: dashboard, list, form.
    for (const p of ['/', '/users', '/apps', '/apps/app1', '/audit', '/users/b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d/keys/+add']) {
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

    // --- the one page that is allowed a script: the bearer reveal (§13.14) ------------
    // The copy button needs the clipboard, so this page is the estate's single exception to
    // "no page carries a script". Everything the rule promised about it is checked here: the
    // key alone in `#bearer`, one script, that response's own policy naming its hash, the
    // handler allowlist untouched, and a click that says it copied.
    const rMint = await revealKey(page, ctx.base, 'b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d', 'nojs-copy');
    t.eq('the mint is answered 200 by the reveal', rMint.status(), 200);
    t.eq('the reveal carries exactly one <script>', await page.locator('script').count(), 1);
    const key = (await page.locator('#bearer').innerText()).trim();
    t.check('the reveal shows the key in #bearer', key.startsWith('bbk_') && key.length >= 40, key);
    t.check('and shows the key alone, with no Authorization line',
      !(await mainText(page)).includes('Authorization'), (await mainText(page)).slice(0, 400));
    const script = await page.evaluate(() => [...document.querySelectorAll('script')].map((s) => s.textContent).join(''));
    const csp = rMint.headers()['content-security-policy'] || '';
    t.check("the response's own policy names the script it carries",
      csp.includes(cspHashOf(script)), csp);
    t.check('and the policy names no script by anything looser than a hash',
      !/script-src[^;]*'unsafe-inline'/.test(csp), csp);
    const revealHandlers = await page.evaluate(() => [...document.querySelectorAll('*')]
      .flatMap((el) => [...el.attributes].filter((a) => a.name.startsWith('on')).map((a) => a.name)));
    t.eq('the reveal carries the shell\'s two handlers and no third: the copy button is wired '
      + 'with addEventListener', revealHandlers.sort().join(' '), 'onchange onchange');
    const copy = page.locator('#bearer-copy');
    t.eq('the copy control is visible with scripting on', await copy.isVisible(), true);
    t.eq('and it is a button that cannot submit a form', await copy.getAttribute('type'), 'button');
    t.eq('it is the shared icon component, not a box of its own',
      await copy.getAttribute('class'), 'pill ico');
    // §13.17: the name is text inside the control, hidden visually, and the `title` says
    // the same words. One mechanism for every icon, because a `summary` carries no
    // reliable `aria-label`, and a tooltip that reads differently from the name a reader
    // speaks is two names for one control.
    t.check('the name is hidden text, and the tooltip repeats it',
      (await copy.locator('span.vh').innerText()) === 'Copy the key'
        && (await copy.getAttribute('title')) === 'Copy the key',
      await copy.evaluate((el) => el.outerHTML.slice(0, 220)));
    t.eq('and there is no second naming mechanism for it to drift from',
      await copy.getAttribute('aria-label'), null);
    // §13.17: the control carries **two** glyphs that swap on `data-state`, so "the glyph" is
    // not one element and a check aimed at it is a check aimed at both. The markup names each
    // by class, which is also what the stylesheet swaps on.
    t.eq('both glyphs are out of the reader\'s way, and the name is the only text',
      [await copy.locator('svg.i-copy').getAttribute('aria-hidden'),
        await copy.locator('svg.i-done').getAttribute('aria-hidden'),
        (await copy.evaluate((el) => el.textContent.trim()))],
      ['true', 'true', 'Copy the key']);
    t.eq('the copy glyph is painted, and the check is waiting for a click',
      [await page.locator('#bearer-copy .i-copy').isVisible(),
        await page.locator('#bearer-copy .i-done').isVisible()], [true, false]);
    t.eq('the status span is empty as served, because no click has happened',
      (await page.locator('#bearer-copy-status').innerText()).trim(), '');
    const done = await copy.getAttribute('data-done');
    t.check('it carries the text a successful copy shows', done === 'Copied', String(done));
    const failed = await copy.getAttribute('data-failed');
    t.check('and the text a refusal shows', !!failed && failed.startsWith('Copy refused'), String(failed));
    // The clipboard is a permission, and headless gives it to a loopback origin on request.
    // Where the browser will not grant it, the click still has to answer with the failure
    // text, so the checks below are about the page's word, not the clipboard's bytes.
    let granted = true;
    try {
      await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: ctx.origin });
    } catch (e) {
      granted = false;
    }
    await copy.click();
    t.eq('a click marks the button done, which is what swaps the glyph',
      await copy.getAttribute('data-state'), 'done');
    t.eq('the check glyph replaces the copy glyph',
      [await page.locator('#bearer-copy .i-copy').isVisible(),
        await page.locator('#bearer-copy .i-done').isVisible()], [false, true]);
    t.check('a click shows the copied word beside the icon',
      (await page.locator('#bearer-copy-status').innerText()).trim() === done,
      `${await page.locator('#bearer-copy-status').innerText()} vs ${done}`);
    t.eq('and the icon is still an icon: the word went to the status span, not the button',
      (await copy.evaluate((el) => el.textContent.trim())), 'Copy the key');
    if (granted) {
      const onClipboard = await page.evaluate(() => navigator.clipboard.readText());
      t.eq('and the clipboard holds exactly the key', onClipboard, key);
    } else {
      t.check('clipboard contents not verifiable: this browser granted no permission', true,
        'grantPermissions failed');
    }

    // §13.17's target size, measured by the browser rather than read out of a stylesheet.
    // The reveal's copy icon is this slice's, so not finding one is a failure. The console's
    // own icons arrive with the shared header (step 8b), so those pages are measured only
    // when they carry one: a size rule cannot be asserted of a control that does not exist.
    for (const width of [1280, 390]) {
      const at = width === 1280 ? 'desktop' : 'phone';
      await page.setViewportSize({ width, height: 900 });
      for (const p of ['/', '/users/b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d']) {
        await page.goto(ctx.base + p);
        for (const b of await iconBoxes(page)) {
          t.check(`the ${at} icon "${b.name}" on ${p} is at least 24 by 24 CSS pixels`,
            b.w >= 24 && b.h >= 24, JSON.stringify(b));
        }
      }
      // The keys row of the self-service page is the table row this slice builds, so its
      // icon is measured here too: a person who is not an administrator, one key minted
      // through the page's own form, and the row read at the same width as everything else.
      const person = await ctx.browser.newContext({
        viewport: { width, height: 900 },
        extraHTTPHeaders: { 'X-Auth-Email': 'you@example.com' },
      });
      const pPage = await person.newPage();
      await pPage.goto(`${ctx.origin}/account/keys/new`);
      await pPage.fill('input[name=id]', `nojs-size-${width}`);
      await pPage.selectOption('select[name=duration]', '365d');
      await submit(pPage, 'main form button[type=submit]');
      await pPage.goto(`${ctx.origin}/account/`);
      const rowBoxes = await iconBoxes(pPage);
      t.check(`the account keys row carries its revoke icon at ${at} width`,
        rowBoxes.length >= 1, JSON.stringify(rowBoxes));
      for (const b of rowBoxes) {
        t.check(`the ${at} account row icon "${b.name}" is at least 24 by 24 CSS pixels`,
          b.w >= 24 && b.h >= 24, JSON.stringify(b));
      }
      await person.close();
      await revealKey(page, ctx.base, 'b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d', `nojs-size-${width}`);
      const boxes = await iconBoxes(page);
      t.check(`the reveal carries its copy icon at ${at} width`, boxes.length >= 1, JSON.stringify(boxes));
      for (const b of boxes) {
        t.check(`the ${at} reveal icon "${b.name}" is at least 24 by 24 CSS pixels`,
          b.w >= 24 && b.h >= 24, JSON.stringify(b));
      }
    }
    await page.setViewportSize({ width: 1280, height: 900 });

    // §13.18 (8d-2), the arrangement as the layout engine made it. The header's brand starts
    // where the page's h1 starts (the console's `main` and the account's 620px column), at
    // both widths; a pill beside a button is as tall as the button; the six dashboard tiles
    // share one row at desktop width.
    const left = (p, sel) => p.locator(sel).first().evaluate((el) => el.getBoundingClientRect().left);
    const person8d = await ctx.browser.newContext({
      viewport: { width: 1280, height: 900 },
      extraHTTPHeaders: { 'X-Auth-Email': 'you@example.com' },
    });
    const acct8d = await person8d.newPage();
    for (const width of [1280, 360]) {
      await page.setViewportSize({ width, height: 900 });
      await acct8d.setViewportSize({ width, height: 900 });
      await page.goto(ctx.base + '/');
      t.check(`the console's brand shares the h1's left edge at ${width}`,
        Math.abs((await left(page, 'header .brand')) - (await left(page, 'main h1'))) <= 1,
        `${await left(page, 'header .brand')} vs ${await left(page, 'main h1')}`);
      await acct8d.goto(`${ctx.origin}/account/`);
      t.check(`the account's brand shares the h1's left edge at ${width}`,
        Math.abs((await left(acct8d, 'header .brand')) - (await left(acct8d, 'main h1'))) <= 1,
        `${await left(acct8d, 'header .brand')} vs ${await left(acct8d, 'main h1')}`);
    }
    // §13.18 (8d-3): the account id is one token. At 320px the page does not scroll sideways
    // and the id sits on one line (a hyphen break would make it two lines tall).
    await acct8d.setViewportSize({ width: 320, height: 800 });
    await acct8d.goto(`${ctx.origin}/account/`);
    const uid = await acct8d.evaluate(() => {
      const el = document.querySelector('code.uid');
      if (!el) return null;
      const lh = parseFloat(getComputedStyle(el).lineHeight) || el.getBoundingClientRect().height;
      return {
        text: el.textContent,
        lines: Math.round(el.getBoundingClientRect().height / lh),
        scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      };
    });
    t.check('the account id is a code.uid', uid !== null, 'no code.uid on /account/');
    t.check('the account id is one line tall at 320px', uid !== null && uid.lines === 1,
      JSON.stringify(uid));
    t.check('the account page has no horizontal scroll at 320px', uid !== null && uid.scroll <= 0,
      JSON.stringify(uid));
    await person8d.close();
    for (const width of [1280, 360]) {
      await page.setViewportSize({ width, height: 900 });
      await page.goto(ctx.base + '/groups/admins/edit');
      const heights = await page.evaluate(() => ({
        pill: document.querySelector('.actions .pill').getBoundingClientRect().height,
        button: document.querySelector('.actions button').getBoundingClientRect().height,
      }));
      t.check(`a pill beside a button is as tall as the button (within 1px) at ${width}`,
        Math.abs(heights.pill - heights.button) <= 1, JSON.stringify(heights));
    }
    // §13.21: the row's cells, the row pills, the filter fields and the ticks, as laid out.
    // The measurement of one table: for each keyed row (one with an actions cell), the cells'
    // bottoms and the actions cell's right edge against the table's, and the row pills' heights.
    const rowGeometry = (p) => p.$$eval('table', (tables) => tables.flatMap((tb) => {
      const tr = tb.getBoundingClientRect();
      return [...tb.querySelectorAll('tbody tr')].filter((r) => r.querySelector('td.pills')).map((r) => {
        const cells = [...r.children].map((c) => c.getBoundingClientRect());
        const act = r.querySelector('td.pills');
        const rr = r.getBoundingClientRect();
        return {
          bottoms: cells.map((c) => Math.round(c.bottom)),
          actRight: act.getBoundingClientRect().right,
          tableRight: tr.right,
          rowRight: rr.right,
          display: getComputedStyle(act).display,
          pills: [...r.querySelectorAll('.pill')].map((a) => Math.round(a.getBoundingClientRect().height * 10) / 10),
        };
      });
    }));
    const person21 = await ctx.browser.newContext({
      viewport: { width: 1280, height: 900 },
      extraHTTPHeaders: { 'X-Auth-Email': 'you@example.com' },
    });
    const acct21 = await person21.newPage();
    for (const width of [1280, 390]) {
      await page.setViewportSize({ width, height: 900 });
      await acct21.setViewportSize({ width, height: 900 });
      await acct21.goto(`${ctx.origin}/account/`);
      const surfaces = [['/account/', acct21, await rowGeometry(acct21)]];
      for (const path of ['/users', '/users/b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d']) {
        await page.goto(ctx.base + path);
        surfaces.push([path, page, await rowGeometry(page)]);
      }
      for (const [path, , rows] of surfaces) {
        t.check(`${path} has rows with an actions cell at ${width}`, rows.length >= 1, JSON.stringify(rows));
        for (const r of rows) {
          if (width === 1280) {
            t.check(`${path}: every cell of a row shares one bottom at ${width}`,
              new Set(r.bottoms).size === 1, JSON.stringify(r));
            t.check(`${path}: the actions cell reaches the table's right edge at ${width}`,
              Math.abs(r.actRight - r.tableRight) <= 1, JSON.stringify(r));
          } else {
            t.check(`${path}: the actions cell is a block, as wide as its row, at ${width}`,
              r.display === 'block' && Math.abs(r.actRight - r.rowRight) <= 1, JSON.stringify(r));
          }
          t.check(`${path}: row pills share one height at ${width}`,
            r.pills.length >= 1 && Math.max(...r.pills) - Math.min(...r.pills) <= 0.5, JSON.stringify(r));
        }
      }
      for (const path of ['/users', '/audit']) {
        await page.goto(ctx.base + path);
        const hs = await page.evaluate(() => {
          const f = document.querySelector('.listctl form');
          const h = (el) => el.getBoundingClientRect().height;
          return {
            apply: h(f.querySelector('button[type=submit]')),
            fields: [...f.querySelectorAll('input[type=search], select')]
              .filter((e) => e.getBoundingClientRect().height > 0).map(h),
          };
        });
        t.check(`${path}: a filter field equals its Apply's height at ${width}`,
          hs.fields.length >= 1 && hs.fields.every((x) => Math.abs(x - hs.apply) <= 0.5), JSON.stringify(hs));
      }
    }
    await person21.close();
    await page.goto(ctx.base + '/apps/app1/scopes/admin/edit');
    const accents = await page.$$eval('input[type=radio], input[type=checkbox]',
      (els) => els.map((e) => getComputedStyle(e).accentColor));
    t.check('the scope form has radios and ticks', accents.length >= 1, JSON.stringify(accents));
    t.check("a radio's or tick's accent-color is not auto",
      accents.length >= 1 && accents.every((a) => a !== 'auto'), JSON.stringify(accents));

    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto(ctx.base + '/');
    const tops = await page.$$eval('.cards .card', (els) => els.map((el) => Math.round(el.getBoundingClientRect().top)));
    t.check('the dashboard has six tiles', tops.length === 6, JSON.stringify(tops));
    t.check('and they share one top at 1280', new Set(tops).size === 1, JSON.stringify(tops));

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

    // The access check: would this credential get in? It is a section of the two pages that
    // hold half of its question, not a page of its own, and its form is a GET on both, because
    // asking is not an action. The old `/can` is gone, and asking for it says so.
    const gone = await page.goto(ctx.base + '/can');
    t.eq('the access check has no page of its own any more', gone.status(), 404);

    await page.goto(ctx.base + '/apps/app1');
    t.eq('an application page carries exactly one check form',
      await page.locator('main form.can').count(), 1);
    const method = await page.locator('main form.can').evaluate((f) => (f.getAttribute('method') || 'get'));
    t.eq('and it is a GET', method.toLowerCase(), 'get');
    t.eq("with the url field already on this area's base",
      await page.locator('main form.can input[name=url]').inputValue(), 'https://app.example.com/app1');

    const before = bytes(ctx);
    // Asked on the page of whichever application owns the URL, which is where an operator is
    // standing when the question comes up. The application is the area to ask FROM, not a
    // filter on the answer: `decide` resolves the URL against the whole file either way.
    const verdict = async (app, email, url) => {
      await page.goto(`${ctx.base}/apps/${app}?email=${encodeURIComponent(email)}&url=${encodeURIComponent(url)}`);
      return mainText(page);
    };
    // The corners of the grant model, answered by the library's own `decide`:
    t.check('a member of a restricted scope is AUTHORIZED',
      (await verdict('app1', 'you@example.com', 'https://app.example.com/app1/admin/panel')).includes('AUTHORIZED'));
    t.check('the credential class is the place\'s to decide — a login on an api_key-only scope is DENIED',
      (await verdict('mcp', 'bot@example.com', 'https://mcp.example.com/mcp/context7/x')).includes('DENIED'));
    t.check('denied outranks everything — spammer@ on an authenticated scope is DENIED',
      (await verdict('app1', 'spammer@example.com', 'https://app.example.com/app1')).includes('DENIED'));
    t.check('authenticated grants on identity alone — a stranger is AUTHORIZED there',
      (await verdict('app1', 'stranger@example.com', 'https://app.example.com/app1')).includes('AUTHORIZED'));
    t.check('an anonymous scope needs no credential at all',
      (await verdict('app1', '', 'https://app.example.com/app1/healthz')).includes('AUTHORIZED'));
    t.check('a URL no application covers is reachable by nobody',
      (await verdict('app1', 'you@example.com', 'https://nowhere.example.com/')).includes('DENIED'));
    await t.shot(page, 'can-denied');

    // And the same question from the other side. On a person's page the identity IS the page,
    // so there is one field and no way to ask about somebody else.
    await page.goto(`${ctx.base}/users/you%40example.com?url=${encodeURIComponent('https://app.example.com/app1/admin/panel')}`);
    t.eq("a person's check asks for the url and nothing else",
      await page.locator('main form.can input').count(), 1);
    t.check('and answers with the same verdict', (await mainText(page)).includes('AUTHORIZED'));
    t.check('about the person whose page it is', (await mainText(page)).includes('you@example.com'));
    await t.shot(page, 'can-on-a-person');

    // The answer arrives where the question was asked. A GET form lands on a fresh document
    // at the top of the page, which on an application is several screens above the form: the
    // fragment on the action is what stops the verdict appearing out of sight, and it has to
    // survive form submission for that to work, which is a browser behaviour rather than
    // something the server can check.
    await page.goto(ctx.base + '/apps/app1');
    await page.fill('main form.can input[name=url]', 'https://app.example.com/app1/admin/panel');
    await page.fill('main form.can input[name=email]', 'you@example.com');
    await Promise.all([
      page.waitForNavigation(),
      page.click('main form.can button[type=submit]'),
    ]);
    t.check('the check submits back to its own anchor', page.url().endsWith('#check'), page.url());
    t.eq('which the heading carries', await page.locator('h2#check').count(), 1);
    t.check('and the verdict is there', (await mainText(page)).includes('AUTHORIZED'));

    // Same on a person, where the form has one field and the same problem.
    await page.goto(ctx.base + '/users/you%40example.com');
    await page.fill('main form.can input[name=url]', 'https://app.example.com/app1/admin/panel');
    await Promise.all([
      page.waitForNavigation(),
      page.click('main form.can button[type=submit]'),
    ]);
    t.check("a person's check does too", page.url().endsWith('#check'), page.url());

    t.check('asking wrote nothing', bytes(ctx) === before, 'the access check mutated the file');
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

    // The cover is CSS, so light dismiss works with scripting off too (section 13.20).
    await page.goto(ctx.base + '/users');
    await menuClosesOutside(t, page, 'console, scripting off', async (pick) => {
      await page.selectOption('.menu select[name=theme]', pick);
      await Promise.all([page.waitForNavigation(), page.click('.menu button')]);
    });

    // Every other page shape is unchanged by scripting: a mutation still goes through.
    const beforeSave = bytes(ctx);
    await page.goto(ctx.base + '/denied/+add');
    await page.fill('input[name=email]', 'noscript@example.com');
    await submit(page);
    t.check('and a save still writes with no script anywhere', bytes(ctx) !== beforeSave);
    t.check('the file has the new row',
      doc(ctx).denied.includes('noscript@example.com'), JSON.stringify(doc(ctx).denied));

    // The reveal with scripting off (§13.14, §13.15). The rule is that no page *needs* a
    // script, and this is the one page that carries one, so the scripting-off walk has to
    // reach it: the key is shown in `#bearer`, the copy icon is not shown at all (a server
    // that showed it would be showing a dead control), and the script the server emitted
    // runs nothing.
    const rOff = await revealKey(page, ctx.base, 'b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d', 'nojs-off');
    t.eq('the mint is answered 200 with scripting off', rOff.status(), 200);
    const offKey = (await page.locator('#bearer').innerText()).trim();
    t.check('the key is shown, in #bearer', offKey.startsWith('bbk_'), offKey);
    t.check('and the page shows the key alone, with no Authorization line',
      !(await mainText(page)).includes('Authorization'), (await mainText(page)).slice(0, 400));
    t.eq('the copy icon is not shown', await page.locator('#bearer-copy').isVisible(), false);
    t.eq('and neither glyph is',
      [await page.locator('#bearer-copy .i-copy').isVisible(),
        await page.locator('#bearer-copy .i-done').isVisible()], [false, false]);
    t.eq('the status span says nothing, because nothing happened',
      (await page.locator('#bearer-copy-status').innerText()).trim(), '');
    t.eq('the response carries the one script this browser ignores',
      await page.locator('script').count(), 1);

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
