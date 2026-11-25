'use strict';
// The Settings tab — the OTHER file. The values the gate reads per request, the list
// of people this GUI opens for, and the look BOTH programs wear, all in one form guarded by
// the same hidden `rev`.
//
// What this area is really about is the boundary. The page must write settings.json and
// leave access.json alone; its `rev` must fingerprint the file it edits, or an out-of-band
// `bb-auth-adm settings set` would go unnoticed while every unrelated roster edit would
//409 it; and the two refusals that make it safe to hand an administrator — you may not
// empty the list, and you may not remove yourself — must fire before anything is written.

const {
  bytes, doc, writeDoc, settings, settingsBytes, writeSettings,
  newPage, submit, mainText, formBytes, openPreferences, barStaysOneRow, attr, text, count,
} = require('../lib/harness');

/** The Preferences menu closes on a click outside it (docs/ARCHITECTURE.md section 13.20).
 *  `apply` submits the chosen theme the way that surface does (a change on the console with
 *  scripting on, the Apply button otherwise) and resolves once the navigation it causes ends.
 *  §13.28 §2 moved the list boxes into a box nested in the panel, closed by default, so the
 *  walk opens both before it touches one. */
async function menuClosesOutside(t, page, who, apply) {
  const isOpen = () => page.$eval('details.settings', (d) => d.open);
  const open = () => page.click('details.settings > summary');
  await open();
  t.eq(`${who}: the trigger opens the menu`, await isOpen(), true);
  await page.mouse.click(4, 896);
  t.eq(`${who}: a click at the bottom-left of the viewport closes it`, await isOpen(), false);

  await openPreferences(page);
  await page.click('.menu select[name=theme]');
  t.eq(`${who}: a click on a list box inside leaves it open`, await isOpen(), true);
  await page.keyboard.press('Escape');

  const before = await page.locator('html').getAttribute('data-theme');
  const pick = before === 'dark' ? 'light' : 'dark';
  await apply(pick);
  t.eq(`${who}: submitting a theme still applies it`,
    await page.locator('html').getAttribute('data-theme'), pick);
}

/**
 * The panel's rows, top to bottom, as a person reads them (§13.28 §2). Each entry is a shape
 * the design names; the Sign out row is found by the word it shows, because the design names
 * the word and not a class, and a test that invented a class would pass a markup that shows
 * no word at all. The account row rides with the places (the user's decision of 2026-11-25,
 * which answers §13.28's open question 2), so it is listed between them and Preferences.
 */
const PANEL_ROWS = [
  { sel: 'p.who-full' },
  { sel: '.menu-places' },
  { sel: '.menu-places a.pill[href="/account/"]' },
  { sel: 'details.prefs' },
  { sel: '.menu a.pill', text: 'Sign out' },
];

/** The panel's rows in document order, as the index of each entry above (-1: not there). */
const panelOrder = (page) =>
  page.evaluate((rows) => {
    const panel = document.querySelector('details.settings .menu');
    if (!panel) return rows.map(() => -2);
    const all = Array.from(panel.querySelectorAll('*'));
    const at = (row) => {
      const hit = Array.from(panel.querySelectorAll(row.sel)).find(
        (el) => !row.text || el.textContent.includes(row.text)
      );
      return hit ? all.indexOf(hit) : -1;
    };
    return rows.map(at);
  }, PANEL_ROWS);

/**
 * The console's account panel, and the bar it hangs off (§13.28 §2, §4, §6).
 *
 * Every read goes through `attr` / `text` / `count`, and every click is asked for first,
 * because this area is here for the settings file: a walk that aborted on the first absent
 * row would stop testing the form, the two-step and the refusals, and a red suite would say
 * nothing about them. A missing control is recorded as a missing control.
 */
async function panelWalk(t, page, ctx) {
  const bar = 'header .bar > nav:not(.acct)';
  const sys = 'details.settings .menu-places a[href$="/config"]';

  await page.goto(ctx.base + '/config?lang=en');
  // The Settings page is not one of the bar's tabs, so the bar marks nothing here, and the
  // panel's System settings row is the one thing that says which page this is.
  t.eq('the bar marks no tab on this page', await count(page, `${bar} a.on`), 0);
  await page.click('details.settings > summary');
  t.eq('the panel row is the current page', await attr(page, sys, 'aria-current'), 'page');
  t.check('and wears the current mark', (await attr(page, sys, 'class') || '').includes('on'),
    await attr(page, sys, 'class'));
  t.eq('the row reads the page name', (await text(page, sys)).trim(), 'System settings');

  const who = await text(page, 'details.settings .menu p.who-full');
  t.check('the panel heads with every address of this identity', who.includes('admin@example.com'), who);
  t.check('and names no uuid, which is the account page to say',
    !/[0-9a-f]{8}-[0-9a-f]{4}-/i.test(who), who);
  const order = await panelOrder(page);
  t.check('who you are, then the places, then my preferences, then the way out',
    order.every((n, i) => n >= 0 && (i === 0 || n > order[i - 1])), JSON.stringify(order));
  t.eq('and the panel adds no lede to the page',
    await count(page, 'details.settings .menu p.lede'), 0);

  // The console's panel carries the way to the caller's own page (the user's decision of
  // 2026-11-25, §13.28 §2): one `a.pill` to the account prefix, among the places, worded in
  // the reader's language. Pinned in both languages, because the pair that breaks is the row
  // that ships the English word on an Italian page, and English alone passes on that.
  const acct = 'details.settings .menu a.pill[href="/account/"]';
  t.eq('the panel carries one Go to your account row', await count(page, acct), 1);
  t.eq('the row says Go to your account', (await text(page, acct)).trim(), 'Go to your account');
  await page.goto(ctx.base + '/config?lang=it');
  await page.click('details.settings > summary');
  t.eq('the row goes to the account prefix', await attr(page, acct, 'href'), '/account/');
  t.eq('and says the same words in Italian',
    (await text(page, acct)).trim(), 'Vai al tuo account');

  // The bar's tabs are hidden at and below 800px, so at phone width the panel's rows are the
  // only navigation the console has. A walk that only checked the desktop bar would not
  // notice a console that becomes unusable on a phone.
  for (const width of [360, 800]) {
    await page.setViewportSize({ width, height: 760 });
    await page.goto(ctx.base + '/users?lang=en');
    t.eq(`at ${width}: the bar shows no tabs`,
      await page.locator(bar).evaluate((el) => getComputedStyle(el).display).catch(() => 'absent'), 'none');
    await page.click('details.settings > summary');
    t.eq(`at ${width}: the panel carries the four tabs`, await count(page, '.menu-tabs a'), 4);
    t.eq(`at ${width}: the current one is marked`, await text(page, '.menu-tabs a[aria-current=page]'), 'Users');
    if ((await count(page, '.menu-tabs a[href$="/apps"]')) === 1) {
      await Promise.all([page.waitForNavigation(), page.click('.menu-tabs a[href$="/apps"]')]);
      t.check(`at ${width}: a panel tab navigates`, page.url().endsWith('/apps'), page.url());
      await page.click('details.settings > summary');
      t.eq(`at ${width}: and the panel marks the page it landed on`,
        await text(page, '.menu-tabs a[aria-current=page]'), 'Applications');
    } else {
      t.check(`at ${width}: a panel tab navigates`, false, 'no Applications row in the panel to click');
    }
  }
  await page.setViewportSize({ width: 1280, height: 900 });

  // The System settings row is the way to the settings page once the tab is gone from the
  // bar, so it has to work from a page that is not the one it names.
  await page.goto(ctx.base + '/users?lang=en');
  await page.click('details.settings > summary');
  t.eq('the row is not marked while on another page', await attr(page, sys, 'aria-current'), null);
  if ((await count(page, sys)) === 1) {
    await Promise.all([page.waitForNavigation(), page.click(sys)]);
    t.check('the System settings row reaches the settings page', page.url().endsWith('/config'), page.url());
  } else {
    t.check('the System settings row reaches the settings page', false, 'no row in the panel to click');
  }
  t.check('whose heading reads the same words as the row',
    (await text(page, 'main h1')).includes('System settings'), await text(page, 'main h1'));

  // The bar is one row at every width, with the widest brand an operator can type and a logo
  // present. The name pill is the piece that gives. The logo is root-relative because
  // `compile_asset_url` accepts no `data:` URL and this suite never reaches the network; a
  // broken image is sized by its CSS box, which is the box the bar lays out.
  const barLook = settings(ctx);
  const wideLook = settings(ctx);
  // The fixture carries no `ui` section at all (every page falls back to the built-in brand),
  // so this creates it rather than reaching into one.
  wideLook.ui = {
    ...(wideLook.ui || {}),
    brand_name: 'BadBat75 Operations Console',
    logo_url: '/img/logo.png',
  };
  writeSettings(ctx, wideLook);
  await barStaysOneRow(t, page, ctx.base, '/users', 'console bar');
  const g = await page.evaluate(() => {
    const img = document.querySelector('header a.brand img');
    const name = document.querySelector('header a.brand .t');
    const cs = (el) => (el ? getComputedStyle(el) : null);
    return {
      img: !!img,
      imgH: img ? cs(img).height : '',
      text: name ? name.textContent.trim() : '',
      clipped: name ? name.scrollWidth > name.clientWidth : false,
    };
  });
  t.check('the logo is in the brand and has a height', g.img && parseFloat(g.imgH) > 0, JSON.stringify(g));
  t.eq('the brand text is the configured one', g.text, 'BadBat75 Operations Console');
  t.check('and it is the piece that is cut, not the bar', g.clipped, JSON.stringify(g));
  await t.shot(page, 'settings-bar-wide');
  writeSettings(ctx, barLook);
}

async function run(ctx, t) {
  const { context, page } = await newPage(ctx);
  // `$$eval` is Playwright's, not JavaScript's eval: it runs this fixed function inside the
  // page over the matched elements, and nothing of it comes from the page under test.
  const openCount = () => page.$$eval('details.group', (ds) => ds.filter((d) => d.open).length);
  try {
    // --- the page opens folded, to its five headings -------------------------------
    // Everything below edits fields, and a field inside a folded group is one a person cannot
    // type into, so the first thing is the command that opens them all, which is remembered.
    await page.goto(ctx.base + '/config?lang=en');
    t.eq('a browser that never chose sees the headings only', await openCount(), 0);
    await Promise.all([page.waitForNavigation(), page.click('text=Expand all')]);
    t.eq('expand all opens every group', await openCount(), 5);

    // --- what the page shows is what the file says -------------------------------
    await page.goto(ctx.base + '/config?lang=en');
    t.eq('and the choice outlives the page it was made on', await openCount(), 5);
    t.eq('identity_attrs comes from the file',
      await page.locator('textarea[name=identity]').inputValue(), 'email');
    t.eq('and so does the default lifetime',
      await page.locator('input[name=ttl]').inputValue(), '2592000');
    t.eq('the administrator list is the one that let us in',
      await page.locator('textarea[name=admins]').inputValue(), 'admin@example.com');
    await t.shot(page, 'settings');

    // The form fingerprints the settings file, not the access file. Both are on disk and
    // they differ, so this is a real distinction rather than a coincidence.
    const fields = await formBytes(page);
    const crypto = require('crypto');
    const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
    t.eq('the rev is the settings file own', fields.rev, sha(settingsBytes(ctx)));
    t.check('and not the access file one', fields.rev !== sha(bytes(ctx)));

    // --- a save writes the one file and not the other ----------------------------
    const accessBefore = bytes(ctx);
    await page.fill('textarea[name=identity]', 'email\nuuid');
    await page.fill('textarea[name=claims]', ' given_name \n\n family_name ');
    await page.fill('input[name=ttl]', '604800');
    await page.check('input[name=social]');
    await page.fill('textarea[name=providers]', 'Google');
    await page.fill('textarea[name=admins]', 'admin@example.com\nsecond@example.com');
    t.eq('the save redirects', (await submit(page)).status(), 200);
    t.check('and says so', (await mainText(page)).includes('settings saved'));

    const s = settings(ctx);
    t.eq('identity_attrs written in order', s.gate.identity_attrs, ['email', 'uuid']);
    t.eq('claims trimmed, blanks dropped', s.gate.profile_claims, ['given_name', 'family_name']);
    t.eq('the lifetime is seconds', s.gate.session_ttl_secs, 604800);
    t.eq('the social relaxation is on', s.gate.allow_unverified_social, true);
    t.eq('narrowed to one provider', s.gate.social_providers, ['Google']);
    t.eq('and a second administrator was added', s.web.admins.length, 2);
    t.check('the access file was not touched', bytes(ctx) === accessBefore);

    // The reload shows the file, so the derived headers are the file's own doing.
    await page.goto(ctx.base + '/config?lang=en');
    t.eq('the saved claims come back', await page.locator('textarea[name=claims]').inputValue(),
      'given_name\nfamily_name');
    t.check('the checkbox is ticked', await page.locator('input[name=social]').isChecked());

    // --- the look, which is the one section BOTH programs read --------------------
    // It is on this page because it passes the same three-part rule the rest of the file
    // does, and the proof that it is live is the page you are looking at: save a stylesheet
    // and the very next render links it.
    await page.goto(ctx.base + '/config?lang=en');
    t.eq('no override is configured to start with',
      await page.locator('input[name=stylesheet]').inputValue(), '');
    t.check('and the page links nothing at all',
      (await page.locator('link[rel=stylesheet]').count()) === 0);
    t.check('while carrying the whole palette itself',
      (await page.locator('style').innerText()).includes('--accent:'));

    await page.fill('input[name=brand]', 'BadBat75');
    await page.fill('input[name=stylesheet]', 'https://assets.example.com/css/theme.css');
    await page.fill('input[name=logo]', '/img/logo.png');
    await page.selectOption('select[name=ui_theme]', 'dark');
    t.eq('the look saves', (await submit(page)).status(), 200);

    const look = settings(ctx).ui;
    t.eq('the stylesheet is written', look.stylesheet_url, 'https://assets.example.com/css/theme.css');
    t.eq('a root-relative logo is a shape it takes', look.logo_url, '/img/logo.png');
    t.eq('the brand is trimmed prose', look.brand_name, 'BadBat75');
    t.eq('and the theme is one of three words', look.theme, 'dark');

    await page.goto(ctx.base + '/config?lang=en');
    t.eq('the page now links it, once',
      await page.locator('link[rel=stylesheet]').getAttribute('href'),
      'https://assets.example.com/css/theme.css');
    t.eq('the deployment default reaches the html element',
      await page.locator('html').getAttribute('data-theme'), 'dark');
    // The visitor's own choice still wins over the deployment's default: the Settings menu
    // in the header is a preference, not a second copy of this field.
    await page.goto(ctx.base + '/config?lang=en&theme=light');
    t.eq('and a visitor override outranks it',
      await page.locator('html').getAttribute('data-theme'), 'light');

    // A URL the library refuses is refused here, attributed to its own field.
    await page.goto(ctx.base + '/config?lang=en');
    const lookBefore = settingsBytes(ctx);
    await page.fill('input[name=stylesheet]', 'javascript:alert(1)');
    t.eq('a stylesheet that is not a stylesheet is a 400', (await submit(page)).status(), 400);
    t.check('with the library own words', (await mainText(page)).includes('stylesheet_url'));
    t.check('and nothing written', settingsBytes(ctx) === lookBefore);

    // Put it back, so the refusal tests below start from a file that works.
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('input[name=stylesheet]', '');
    t.eq('and it can be unset again', (await submit(page)).status(), 200);
    t.eq('empty means unset', settings(ctx).ui.stylesheet_url, '');

    // --- the two-step, on the five that can shut the door -----------------------
    // A save that takes away one of the things people get in through is SHOWN before it is
    // written. It matters here rather than only in a unit test because it is a second form
    // round trip with no script behind it: the panel, the hidden token and the button are
    // the whole mechanism, and nojs.js runs this same page with scripting off.
    await page.goto(ctx.base + '/config?lang=en');
    const poolBefore = settings(ctx).gate.issuer;
    const otherPool = 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_OTHER';
    await page.fill('input[name=issuer]', otherPool);
    t.eq('moving the pool is held, not refused', (await submit(page)).status(), 200);
    const held = await mainText(page);
    t.check('the page says what it costs', held.includes('stop people getting in'), held.slice(0, 300));
    t.check('and shows both values', held.includes(otherPool) && held.includes(poolBefore));
    t.eq('nothing was written', settings(ctx).gate.issuer, poolBefore);

    // The confirmation is the same form, so the pending value is still in the field and the
    // token is in the page. Submitting it again is what a person does with the button.
    t.eq('the pending value is still in the form',
      await page.locator('input[name=issuer]').inputValue(), otherPool);
    t.check('and the token is with it',
      (await page.locator('input[name=confirm]').count()) === 1);
    t.eq('confirming writes it', (await submit(page)).status(), 200);
    t.eq('the pool moved', settings(ctx).gate.issuer, otherPool);

    // Put it back, confirming again, so what follows starts from the fixture's own pool.
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('input[name=issuer]', poolBefore);
    await submit(page);
    await submit(page);
    t.eq('and back', settings(ctx).gate.issuer, poolBefore);

    // A host the cookie can never reach is a refusal rather than a question: there is
    // nothing to confirm about a file the gate would not accept.
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('input[name=cookie_domain]', '.example.com');
    await page.fill('textarea[name=hosts]', 'example.com\n*.example.com\napp.elsewhere.com');
    t.eq('an unreachable host is a 400', (await submit(page)).status(), 400);
    t.check('naming the host', (await mainText(page)).includes('app.elsewhere.com'));

    // --- the two refusals that keep an administrator in the room -----------------
    const before = settingsBytes(ctx);
    await page.fill('textarea[name=admins]', 'second@example.com');
    t.eq('removing yourself is a 400', (await submit(page)).status(), 400);
    const self = await mainText(page);
    t.check('and says where it can be done', self.includes('bb-auth-adm'), self.slice(0, 400));

    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('textarea[name=admins]', '   ');
    t.eq('emptying the list is a 400', (await submit(page)).status(), 400);
    t.check('and says why', (await mainText(page)).includes('at least one administrator'));

    // A value the gate would refuse never reaches the disk either: the library is the one
    // that says so, in the sentence bb-auth-adm would print.
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('textarea[name=identity]', 'phone');
    t.eq('an unknown identity attribute is a 400', (await submit(page)).status(), 400);
    t.check('with the parser own words', (await mainText(page)).includes('unknown identity attribute'));

    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('input[name=ttl]', 'soon');
    t.eq('a lifetime that is not a number is a 400', (await submit(page)).status(), 400);

    t.check('none of the four refusals wrote anything', settingsBytes(ctx) === before);

    // --- the concurrency check, on the right file --------------------------------
    // An out-of-band `settings set` while the form was open: a 409, not a clobber.
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('input[name=ttl]', '999999');
    const oob = settings(ctx);
    oob.gate.session_ttl_secs = 86400;
    writeSettings(ctx, oob);
    t.eq('a stale rev is a 409', (await submit(page)).status(), 409);
    t.eq('the other writer edit survived', settings(ctx).gate.session_ttl_secs, 86400);

    // And the opposite: an edit to the ACCESS file must not 409 this form, because this
    // form is not about that file.
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('input[name=ttl]', '3600');
    const d = doc(ctx);
    d.users[0].notes = `oob ${d.users.length}`;
    writeDoc(ctx, d);
    t.eq('an unrelated roster edit does not 409 it', (await submit(page)).status(), 200);
    t.eq('and the save landed', settings(ctx).gate.session_ttl_secs, 3600);

    // --- the audit's rotation and retention: an amount and a unit each -------------
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('input[name=audit_rotation]', '1');
    await page.selectOption('select[name=audit_rotation_unit]', 'GiB');
    await page.fill('input[name=audit_retention]', '6');
    await page.selectOption('select[name=audit_retention_unit]', 'months');
    t.eq('rotation and retention save', (await submit(page)).status(), 200);
    t.eq('in the file\'s one spelling', [settings(ctx).audit.rotation, settings(ctx).audit.retention],
      ['1 GiB', '6 months']);
    // Nothing in space: refused, with the retention's box the one marked, and nothing written.
    await page.goto(ctx.base + '/config?lang=en');
    await page.selectOption('select[name=audit_rotation_unit]', 'months');
    await page.selectOption('select[name=audit_retention_unit]', 'years');
    await page.fill('input[name=audit_retention]', '1');
    t.eq('a policy with no size is refused', (await submit(page)).status(), 400);
    t.eq('on the retention box', await page.locator('input[name=audit_retention].invalid').count(), 1);
    t.eq('and the file keeps what it had', settings(ctx).audit.rotation, '1 GiB');

    // --- groups that fold -----------------------------------------------------------
    // Each is a `details`, so folding and unfolding is the browser's and needs no script,
    // and the two commands at the top are remembered across a save, which ends in a
    // redirect that carries no query. Only a browser can check any of that.
    await page.goto(ctx.base + '/config?lang=en');
    t.eq('every group is open, as chosen above', await openCount(), 5);
    await Promise.all([page.waitForNavigation(), page.click('text=Collapse all')]);
    t.eq('collapse all folds every group', await openCount(), 0);
    t.check('and leaves no parameter in the address', !page.url().includes('groups='), page.url());
    await page.click('#g-access > summary');
    t.eq('a heading opens its own group', await openCount(), 1);
    await page.fill('input[name=ttl]', '7200');
    t.eq('a save from a folded page still saves', (await submit(page)).status(), 200);
    t.eq('what the folded groups hold went with it', settings(ctx).gate.session_ttl_secs, 7200);
    t.eq('and the page comes back folded', await openCount(), 0);
    await Promise.all([page.waitForNavigation(), page.click('text=Expand all')]);
    t.eq('expand all opens them again', await openCount(), 5);

    // --- the Preferences menu closes on a click outside it (section 13.20) --------
    await page.goto(ctx.base + '/config?lang=en');
    await menuClosesOutside(t, page, 'console', (pick) => Promise.all([
      page.waitForNavigation(),
      page.selectOption('.menu select[name=theme]', pick),
    ]));

    // --- the account panel, and the bar, at every width (section 13.28) -------
    await panelWalk(t, page, ctx);

    // --- Italian ------------------------------------------------------------------
    await page.goto(ctx.base + '/config?lang=it');
    const it = await mainText(page);
    t.check('the page is translated', it.includes('Impostazioni'), it.slice(0, 200));
    t.check('including the help text', it.includes('senza riavvio'), it.slice(0, 400));
    await t.shot(page, 'settings-it');
  } finally {
    await context.close();
  }
}

module.exports = { run };
