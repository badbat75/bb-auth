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
  newPage, submit, mainText, formBytes, openPreferences, barStaysOneRow, headerLayout,
  openBarMenu, menuIsOpen, menuShape, menuIsOneSize, ACCT_MENU, NAV_MENU,
  attr, text, count,
} = require('../lib/harness');

/** The Preferences menu closes on a click outside it (docs/ARCHITECTURE.md section 13.20).
 *  `apply` submits the chosen theme the way that surface does (a change on the console with
 *  scripting on, the Apply button otherwise) and resolves once the navigation it causes ends.
 *  §13.28 §2 moved the list boxes into a box nested in the panel, closed by default, so the
 *  walk opens both before it touches one. §13.34 added a second `details.settings` to the bar
 *  (the ☰), so every read here goes through `ACCT_MENU`, which is the account one. */
async function menuClosesOutside(t, page, who, apply) {
  const isOpen = () => page.$eval(ACCT_MENU, (d) => d.open);
  const open = () => page.click(`${ACCT_MENU} > summary`);
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
 * The panel's rows, top to bottom, as a person reads them (§13.28 §2 as §13.34 §3 narrows
 * it). Each entry is a shape the design names; the Sign out row is found by the word it shows,
 * because the design names the word and not a class, and a test that invented a class would
 * pass a markup that shows no word at all. §13.34 took the tab rows and the System settings
 * row out of this list, so what is left is the caller, the caller's own page, Preferences and
 * the way out: the same list the account page has, minus the delete row.
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
  page.evaluate((args) => {
    const panel = document.querySelector(args.sel);
    if (!panel) return args.rows.map(() => -2);
    const all = Array.from(panel.querySelectorAll('*'));
    const at = (row) => {
      const hit = Array.from(panel.querySelectorAll(row.sel)).find(
        (el) => !row.text || el.textContent.includes(row.text)
      );
      return hit ? all.indexOf(hit) : -1;
    };
    return args.rows.map(at);
  }, { sel: `${ACCT_MENU} .menu`, rows: PANEL_ROWS });

/**
 * The console's account panel, the bar's tab strip and the ☰ that replaces it on a phone
 * (§13.28 §2, §4, §6, §13.34 §1 to §3).
 *
 * Every read goes through `attr` / `text` / `count`, and every click is asked for first,
 * because this area is here for the settings file: a walk that aborted on the first absent
 * row would stop testing the form, the two-step and the refusals, and a red suite would say
 * nothing about them. A missing control is recorded as a missing control.
 */
async function panelWalk(t, page, ctx) {
  const strip = 'header .bar > nav.tabs';
  const stripCurrent = `${strip} a[aria-current=page]`;
  const navTab = `${NAV_MENU} .menu-tabs a`;
  const navCurrent = `${navTab}[aria-current=page]`;
  const panel = `${ACCT_MENU} .menu`;
  const acct = `${panel} a.pill[href="/account/"]`;
  await page.setViewportSize({ width: 1280, height: 900 });

  // The settings page is a tab now (§13.34 §1), so the strip names the page a person is
  // standing on, in the reader's words, and the ☰'s copy marks the same page. The page's own
  // heading is a **different** word, deliberately: the tab has to fit the bar, and the heading
  // can say what the page is.
  for (const [lang, tab, heading] of [
    ['en', 'Settings', 'System settings'],
    ['it', 'Impostazioni', 'Impostazioni di sistema'],
  ]) {
    await page.goto(`${ctx.base}/config?lang=${lang}`);
    t.eq(`the strip marks one tab on the settings page (${lang})`, await count(page, stripCurrent), 1);
    t.eq(`and it is the settings tab (${lang})`, (await text(page, stripCurrent)).trim(), tab);
    t.check(`while the page's heading reads its own words (${lang})`,
      (await text(page, 'main h1')).includes(heading), await text(page, 'main h1'));

    // The ☰ is `display:none` at desktop width (§13.34 §2: the strip is the navigation there), so
    // its rows are opened and read at 941, the widest width that takes the phone path. A click on
    // a box the bar hides is a click on nothing, and times out.
    await page.setViewportSize({ width: 941, height: 760 });
    t.eq(`the ☰ is closed, so its rows are not marked until it opens (${lang})`,
      await menuIsOpen(page, NAV_MENU), false);
    t.eq(`the ☰ opens at 941 (${lang})`, await openBarMenu(page, NAV_MENU), true);
    t.eq(`the ☰ marks the same page the strip does (${lang})`, (await text(page, navCurrent)).trim(), tab);
    t.eq(`and its row carries the tab's word, not the page's (${lang})`,
      (await text(page, `${navTab}[href$="/config"]`)).trim(), tab);
    await page.setViewportSize({ width: 1280, height: 900 });

    // §13.34 §3: the account menu is the person's own things. It holds no copy of the tabs
    // (they ride in the ☰), names the settings page nowhere (it is a tab), and marks no
    // current row, because nothing in it is a page.
    await openBarMenu(page, ACCT_MENU);
    t.eq(`the account menu carries no copy of the tabs (${lang})`,
      await count(page, `${panel} .menu-tabs`), 0);
    t.eq(`and names the settings page nowhere (${lang})`,
      await count(page, `${panel} a[href$="/config"]`), 0);
    t.eq(`and marks no row as the current page (${lang})`,
      await count(page, `${panel} a[aria-current=page]`), 0);
  }

  await page.goto(ctx.base + '/users?lang=en');
  await openBarMenu(page, ACCT_MENU);
  const who = await text(page, `${panel} p.who-full`);
  t.check('the panel heads with every address of this identity', who.includes('admin@example.com'), who);
  t.check('and names no uuid, which is the account page to say',
    !/[0-9a-f]{8}-[0-9a-f]{4}-/i.test(who), who);
  const order = await panelOrder(page);
  t.check('who you are, then your own page, then my preferences, then the way out',
    order.every((n, i) => n >= 0 && (i === 0 || n > order[i - 1])), JSON.stringify(order));
  t.eq('and the panel adds no lede to the page', await count(page, `${panel} p.lede`), 0);

  // The console's panel carries the way to the caller's own page (the user's decision of
  // 2026-11-25, §13.28 §2), and §13.34 leaves it as the panel's **only** place. Pinned in both
  // languages, because the pair that breaks is the row that ships the English word on an
  // Italian page, and English alone passes on that.
  t.eq('the panel carries one Go to your account row', await count(page, acct), 1);
  t.eq('the row says Go to your account', (await text(page, acct)).trim(), 'Go to your account');
  t.eq('and it is the only place the panel offers',
    await count(page, `${panel} .menu-places a.pill`), 1);
  await page.goto(ctx.base + '/users?lang=it');
  await openBarMenu(page, ACCT_MENU);
  t.eq('the row goes to the account prefix', await attr(page, acct, 'href'), '/account/');
  t.eq('and says the same words in Italian',
    (await text(page, acct)).trim(), 'Vai al tuo account');

  // At and below the breakpoint the strip is gone and the ☰ is the only navigation the console
  // has (§13.34 §2), so the rows that reach every page live there. A walk that only checked the
  // desktop bar would not notice a console that becomes unusable on a phone. 360 is a phone,
  // 941 is the widest width that takes this path, the number §0 measured.
  for (const width of [360, 941]) {
    await page.setViewportSize({ width, height: 760 });
    await page.goto(ctx.base + '/users?lang=en');
    const l = await headerLayout(page);
    t.eq(`at ${width}: the bar's strip is hidden`, l.tabs, 'none');
    t.check(`at ${width}: the ☰ is in the bar`, l.navMenu !== 'none', l.navMenu);
    await openBarMenu(page, NAV_MENU);
    t.eq(`at ${width}: the ☰ holds the five tabs`, await count(page, `${navTab}`), 5);
    t.eq(`at ${width}: the current one is marked`, (await text(page, navCurrent)).trim(), 'Users');
    if ((await count(page, `${navTab}[href$="/apps"]`)) === 1) {
      await Promise.all([page.waitForNavigation(), page.click(`${navTab}[href$="/apps"]`)]);
      t.check(`at ${width}: a ☰ tab navigates`, page.url().endsWith('/apps'), page.url());
      await openBarMenu(page, NAV_MENU);
      t.eq(`at ${width}: and the ☰ marks the page it landed on`,
        (await text(page, navCurrent)).trim(), 'Applications');
    } else {
      t.check(`at ${width}: a ☰ tab navigates`, false, 'no Applications row in the ☰ to click');
    }
    // Settings is reachable from the ☰, which is the whole point of making it a tab: the row
    // that used to sit in the account menu is gone, and a phone that cannot reach the strip
    // must still reach the settings page in one click.
    if ((await count(page, `${navTab}[href$="/config"]`)) === 1) {
      await Promise.all([page.waitForNavigation(), page.click(`${navTab}[href$="/config"]`)]);
      t.check(`at ${width}: the ☰ reaches the settings page`, page.url().endsWith('/config'), page.url());
      t.check('whose heading reads the page name',
        (await text(page, 'main h1')).includes('System settings'), await text(page, 'main h1'));
    } else {
      t.check(`at ${width}: the ☰ reaches the settings page`, false, 'no Settings row in the ☰');
    }
  }
  await page.setViewportSize({ width: 1280, height: 900 });

  // On a desktop the tab is the way to the settings page, and it is marked only on the page it
  // names: a strip that marks its settings tab from `/users` says the person is somewhere they
  // are not.
  await page.goto(ctx.base + '/users?lang=en');
  t.eq('the settings tab is not marked from another page',
    await attr(page, `${strip} a[href$="/config"]`, 'aria-current'), null);
  if ((await count(page, `${strip} a[href$="/config"]`)) === 1) {
    await Promise.all([page.waitForNavigation(), page.click(`${strip} a[href$="/config"]`)]);
    t.check('the strip reaches the settings page', page.url().endsWith('/config'), page.url());
  } else {
    t.check('the strip reaches the settings page', false, 'no Settings tab in the strip to click');
  }

  // The two bar menus are one exclusive group (§13.34 §2): at a width where both live in the
  // bar, the keyboard reaches the second trigger with the first open, and opening it has to
  // close the other, with no script. Measured in Edge: two `details` with one `name` keep only
  // the one just opened.
  await page.setViewportSize({ width: 941, height: 760 });
  await page.goto(ctx.base + '/users?lang=en');
  t.eq('at 941: the ☰ opens on a click', await openBarMenu(page, NAV_MENU), true);
  const trig = page.locator(`${ACCT_MENU} > summary`);
  if ((await trig.count()) === 1) {
    await trig.focus();
    await page.keyboard.press('Enter');
    const both = await Promise.all([menuShape(page, ACCT_MENU), menuShape(page, NAV_MENU)]);
    t.eq('at 941: Enter on the account trigger opens it', both[0] && both[0].open, true);
    t.eq('and the ☰ closes: the two bar menus are one group', both[1] && both[1].open, false);
  } else {
    t.check('at 941: Enter on the account trigger opens it', false, 'no account trigger to focus');
    t.check('and the ☰ closes: the two bar menus are one group', false, 'no account trigger');
  }
  // The ☰ is a touch target, not a glyph: at phone width it is the only way to the tabs.
  const target = await page.evaluate(() => {
    const s = document.querySelector('header .bar nav.navm summary');
    const r = s ? s.getBoundingClientRect() : null;
    return r ? [Math.round(r.width), Math.round(r.height)] : null;
  });
  t.check('at 941: the ☰ is at least 30px tall (WCAG 2.5.8)',
    Array.isArray(target) && target[1] >= 30, JSON.stringify(target));
  await page.setViewportSize({ width: 1280, height: 900 });

  // The bar at every width the design measured, with scripting on, in both languages (§13.28
  // §4, §13.34 §2): 320 is the narrowest phone, 941 and 942 are the breakpoint's pair, 1280 is
  // the desktop strip. The same walk with scripting off lives in `nojs.js`, because a `details`
  // is markup and the bar has to behave the same with no script.
  await barStaysOneRow(t, page, ctx.base, '/users', 'console bar');

  // The two menus are the same box on both surfaces (§13.34 §3), which is the measurement the
  // stylesheet cannot make on its own.
  await menuIsOneSize(t, page.context(), ctx.base, 'console');
}

/**
 * The bar at the widths §13.34 §0 measured: 942, where the five tabs are still in the bar, and
 * 941, where they have moved into the ☰. A long brand, a logo and a long given name together
 * are the widest case the measurements name, and the Italian tab words are longer than the
 * English ones, so the bar's worst case is Italian.
 *
 * `barStaysOneRow` counts the vertical centres of the bar's **children**, and a strip that wraps
 * inside its own `nav` leaves all of them centred on one line, so the wrap is invisible to
 * it. This reads the strip's own rows and the bar's height, which is what a person sees grow,
 * and the Sign out glyph, which is the panel's unsized one (an `svg` with no box is 300x150).
 *
 * The given name needs the claim configured, because the header is read only where the
 * deployment says the proxy fills it, and it is the piece that pushes the trigger to its cap.
 */
async function barAtTheWorstWidth(t, ctx, look) {
  const withName = JSON.parse(JSON.stringify(look));
  withName.gate = { ...(withName.gate || {}), profile_claims: ['given_name'] };
  // The fixture sets no `ui` section, so the widest case has to be written: the long brand and
  // a logo are what the measurements name. The logo is root-relative, because
  // `compile_asset_url` accepts no `data:` URL and a suite must not reach the network; a broken
  // image is sized by its CSS box, which is the box the bar lays out.
  withName.ui = { ...(withName.ui || {}), brand_name: 'BadBat75 Operations Console', logo_url: '/img/logo.png' };
  writeSettings(ctx, withName);
  const context = await ctx.browser.newContext({
    viewport: { width: 942, height: 720 },
    extraHTTPHeaders: {
      'X-Auth-Email': 'admin@example.com',
      // Percent-encoded, as the gate sends a profile claim, and long enough to sit the trigger
      // at its cap: a short name leaves the bar room and the wrap never happens.
      'X-Auth-Given-Name': 'Christopher%20Maximilian',
    },
  });
  const page = await context.newPage();
  try {
    for (const width of [942, 941]) {
      for (const lang of ['en', 'it']) {
        await page.setViewportSize({ width, height: 720 });
        await page.goto(`${ctx.base}/users?lang=${lang}`);
        // The glyph is measured where it is visible: a closed `details` renders no box, and a
        // 0x0 box passes any "at most 24px" check without measuring anything.
        await openBarMenu(page, ACCT_MENU);
        t.eq(`at ${width} ${lang}: the panel opens`,
          await page.$eval(ACCT_MENU, (d) => d.open).catch(() => false), true);
        const g = await page.evaluate((acct) => {
          const box = (el) => (el ? el.getBoundingClientRect() : null);
          const bar = document.querySelector('header .bar');
          // Whichever navigation box is showing is the one counted: at 942 that is the bar's
          // strip, at 941 the ☰ trigger. The ☰'s **panel** is deliberately not measured: it is
          // a column that hangs below the bar, so its rows are not the bar's, and counting them
          // would read a five-row panel as a five-row bar.
          const visible = (sel) => {
            const el = document.querySelector(sel);
            return el && getComputedStyle(el).display !== 'none' ? el : null;
          };
          const strip = visible('header .bar > nav.tabs') || visible('header .bar nav.navm');
          // Distinct vertical centres of a box's children: 1 means one row.
          const rows = (el) => new Set(
            [...el.children]
              .filter((c) => getComputedStyle(c).display !== 'none')
              .map((c) => {
                const r = c.getBoundingClientRect();
                return Math.round(r.top + r.height / 2);
              })
          ).size;
          const icon = box(document.querySelector(`${acct} .menu a.pill svg.i-out`));
          const name = document.querySelector(`${acct} > summary .who-name`);
          const de = document.documentElement;
          return {
            barH: Math.round(box(bar).height),
            stripRows: strip ? rows(strip) : -1,
            sideways: de.scrollWidth - de.clientWidth,
            icon: icon ? [Math.round(icon.width), Math.round(icon.height)] : null,
            name: name ? name.textContent.trim() : '',
            logo: !!document.querySelector('header a.brand img'),
          };
        }, ACCT_MENU);
        // The setup, so a bar that quietly dropped the name or the mark cannot pass by being narrow.
        t.check(`at ${width} ${lang}: the bar carries the given name and the logo`,
          g.name.startsWith('Christopher') && g.logo, JSON.stringify(g));
        t.check(`at ${width} ${lang}: the bar is one row tall`, g.barH <= 40, `bar height ${g.barH}px`);
        t.eq(`at ${width} ${lang}: the navigation is one row`, g.stripRows, 1);
        t.eq(`at ${width} ${lang}: the document does not scroll sideways`, g.sideways, 0);
        t.check(`at ${width} ${lang}: the Sign out glyph is at most 24px`,
          Array.isArray(g.icon) && Math.max(...g.icon) <= 24, JSON.stringify(g.icon));
      }
    }
    await page.setViewportSize({ width: 1280, height: 900 });
  } finally {
    // The settings file goes back as this walk found it: it is the file the area's other
    // checks read, and its bytes are what the form's `rev` fingerprints.
    writeSettings(ctx, look);
    await context.close();
  }
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
    // The refusal speaks this page's words now, so what stays true of it is the SHAPE it
    // names. The wire key `stylesheet_url` used to be asserted here, and that was the
    // library's English sentence, which §13.31 replaced. Read the refusal block itself: the
    // look group is folded on load, so a page-wide innerText search reads what the browser
    // exposes of the form, and `#form-error` is absent on a page that refused nothing.
    const refusal = await page.locator('#form-error').innerText();
    t.check('the refusal names the shape it wants', refusal.includes('https://'), refusal.slice(0, 300));
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
    // The refusal's own block, in the page's register: the label of the field, then what is
    // needed (§13.31 §10). The body is not searched, because the body carries the help text.
    t.eq('and says why, opening with the label of the field',
      (await page.locator('div.err').first().innerText()).trim(),
      "Administrators: at least one is needed; an empty list must never come to mean 'everyone'.");

    // A value the gate would refuse never reaches the disk either, and the page says so in
    // the reader's own words, naming the field by its visible label (§13.31 §4). The library's
    // English sentence, which is what this checked while the page showed it, is what
    // bb-auth-adm prints at a shell; the page's block is the one under test here.
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('textarea[name=identity]', 'phone');
    t.eq('an unknown identity attribute is a 400', (await submit(page)).status(), 400);
    t.eq('the refusal names the field by its label',
      (await page.locator('div.err').first().innerText()).trim(),
      "Identity attributes: 'phone' is not one of: uuid, email.");

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

    // --- the bar at its widest, last: it writes the settings file (a long brand, a logo, a
    // profile claim) to sit the bar at its cap, so it runs after every check that reads the
    // file as the fixture wrote it, and puts the file back on the way out.
    await barAtTheWorstWidth(t, ctx, settings(ctx));
  } finally {
    await context.close();
  }
}

module.exports = { run };
