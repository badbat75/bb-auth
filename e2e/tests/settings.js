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
  newPage, submit, mainText, formBytes, openPreferences, barStaysOneRow, barGeometry, headerLayout,
  openBarMenu, menuIsOpen, menuShape, menuIsOneSize, ACCT_MENU, NAV_MENU,
  brandGeometry, namePillGeometry, brandWordsWhole, brandWordsHidden, routeLogo,
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
    // its rows are opened and read at 883, the widest width that takes the phone path (§13.34 §10
    // measured it). A click on a box the bar hides is a click on nothing, and times out.
    await page.setViewportSize({ width: 883, height: 760 });
    t.eq(`the ☰ is closed, so its rows are not marked until it opens (${lang})`,
      await menuIsOpen(page, NAV_MENU), false);
    t.eq(`the ☰ opens at 883 (${lang})`, await openBarMenu(page, NAV_MENU), true);
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
  // 883 is the widest width that takes this path, the number §10 measured.
  for (const width of [360, 883]) {
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
  await page.setViewportSize({ width: 883, height: 760 });
  await page.goto(ctx.base + '/users?lang=en');
  t.eq('at 883: the ☰ opens on a click', await openBarMenu(page, NAV_MENU), true);
  const trig = page.locator(`${ACCT_MENU} > summary`);
  if ((await trig.count()) === 1) {
    await trig.focus();
    await page.keyboard.press('Enter');
    const both = await Promise.all([menuShape(page, ACCT_MENU), menuShape(page, NAV_MENU)]);
    t.eq('at 883: Enter on the account trigger opens it', both[0] && both[0].open, true);
    t.eq('and the ☰ closes: the two bar menus are one group', both[1] && both[1].open, false);
  } else {
    t.check('at 883: Enter on the account trigger opens it', false, 'no account trigger to focus');
    t.check('and the ☰ closes: the two bar menus are one group', false, 'no account trigger');
  }
  // The ☰ is a touch target, not a glyph: at phone width it is the only way to the tabs.
  const target = await page.evaluate(() => {
    const s = document.querySelector('header .bar nav.navm summary');
    const r = s ? s.getBoundingClientRect() : null;
    return r ? [Math.round(r.width), Math.round(r.height)] : null;
  });
  t.check('at 883: the ☰ is at least 30px tall (WCAG 2.5.8)',
    Array.isArray(target) && target[1] >= 30, JSON.stringify(target));
  await page.setViewportSize({ width: 1280, height: 900 });

  // The bar at every width the design measured, with scripting on, in both languages (§13.28
  // §4, §13.34 §2): 320 is the narrowest phone, 883 and 884 are the breakpoint's pair (§13.34
  // §10), 1280 is the desktop strip. The same walk with scripting off lives in `nojs.js`, because
  // a `details` is markup and the bar has to behave the same with no script.
  await barStaysOneRow(t, page, ctx.base, '/users', 'console bar');

  // The two menus are the same box on both surfaces (§13.34 §3), which is the measurement the
  // stylesheet cannot make on its own.
  await menuIsOneSize(t, page.context(), ctx.base, 'console');
}

/**
 * The brand's **name**, whole at the phone widths §13.34 §0 walked, in both languages, with the
 * bar on one row. `.brand .t` carries `min-width:0`, so a brand with no room left is the piece
 * that gets cut, "bb-au…", at 320, 360 and 390. The name is the piece with no second copy
 * anywhere on the page, so this is the measurement of it: `scrollWidth` past `clientWidth` is
 * the ellipsis, and equal numbers is the name being whole.
 *
 * §13.34 §10 removed the tag line that used to share the slot, so there is one line here to
 * measure and nothing beside it to write a sentence about. The bar's one row is asserted beside
 * every width, because a rule that bought the name's room by making the bar wrap is this fix
 * turned into the fault §13.28 §4 exists to catch.
 */
async function brandStaysWhole(t, page, base) {
  for (const width of [320, 360, 390]) {
    await page.setViewportSize({ width, height: 720 });
    for (const lang of ['en', 'it']) {
      await page.goto(`${base}/users?lang=${lang}`);
      const name = await page.evaluate(() => {
        const el = document.querySelector('header .brand .t');
        if (!el) return null;
        return {
          sw: Math.round(el.scrollWidth),
          cw: Math.round(el.clientWidth),
          word: el.textContent.trim(),
        };
      });
      if (!t.check(`at ${width} ${lang}: the bar carries the brand's name`, !!name,
        JSON.stringify(name))) continue;
      t.check(`at ${width} ${lang}: the name "${name.word}" is not cut`, name.sw <= name.cw,
        `scrollWidth ${name.sw} past clientWidth ${name.cw}`);
      const g = await barGeometry(page);
      t.eq(`at ${width} ${lang}: the bar is one row, ${g.height}px tall`,
        [g.rows, g.kids > 1, g.height <= 40], [1, true, true]);
      t.eq(`at ${width} ${lang}: the document does not scroll sideways`, g.sideways, 0);
    }
  }
  // Back to the width and the language the rest of the area walks at, so a walk that measures
  // the brand leaves nothing of its own behind (the language is a cookie, not a query).
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(`${base}/users?lang=en`);
}

/**
 * The bar's brand at the phone widths and above them (§13.34 §12g, the user's option (c) of
 * 2026-11-27): at 640px and below the mark stays on the row and the **words** go, and above the
 * phone the words are on the row. Three surfaces, in English: the console as an administrator,
 * the account page as its own person, and the console's `403` as a person who is not an
 * administrator (the console's URL with a roster row that is not on `web.admins`).
 *
 * The words go by the clip pattern `base.css`'s `.vh` uses, and the check reads the box and the
 * document's own string together for that reason. The image's `alt` is empty, so the words are
 * the bar's only name: a 1px box is the phone layout, and the same words read out to a reader is
 * the part that makes it a layout rather than a lost name. `display` and `visibility` are read
 * beside `position` because a rule that hides them from a reader is the failure §12g's option (b)
 * was built to avoid, and the box comparison alone cannot see the difference.
 *
 * `logo_url` naming a path nothing answers is the walk that pins the other half, the §13.34 §12c
 * bug: the mechanism once lived at the top level, so a mark that does not load (present, and 0
 * wide) left the bar with no name at 1280 as much as at 320. Above the phone the words are whole
 * here, and the empty brand a broken mark leaves **on a phone** is the cost option (c) accepts
 * with no script to catch it.
 */
async function thePhoneHidesTheWordsAndTheConsoleKeepsThem(t, ctx, look) {
  const brand = 'BadBat75';
  const broken = {
    ...look,
    ui: { ...(look.ui || {}), brand_name: brand, logo_url: '/img/logo.png' },
  };
  writeSettings(ctx, broken);
  const context = await ctx.browser.newContext({ viewport: { width: 360, height: 800 } });
  const page = await context.newPage();
  try {
    const surfaces = [
      { at: `${ctx.base}/users`, email: 'admin@example.com', label: 'the console' },
      { at: `${ctx.origin}/account/`, email: 'you@example.com', label: 'the account page' },
      { at: `${ctx.base}/users`, email: 'you@example.com', label: "the non-administrator's 403" },
    ];
    for (const s of surfaces) {
      await page.setExtraHTTPHeaders({ 'X-Auth-Email': s.email });
      for (const w of [1280, 884, 360, 320]) {
        await page.setViewportSize({ width: w, height: 800 });
        await page.goto(`${s.at}?lang=en`);
        const g = await brandGeometry(page);
        const label = `${s.label} with a mark that does not load`;
        if (w > 640) brandWordsWhole(t, brand, g, label, w);
        else brandWordsHidden(t, brand, g, label, w);
        const bar = await barGeometry(page);
        t.eq(`${label} at ${w}: the bar is one row, ${bar.height}px tall`,
          [bar.rows, bar.height <= 40, bar.sideways === 0], [1, true, true]);
      }
    }
  } finally {
    await context.close();
  }
  // The same bar on a phone with a mark that **answers** (`routeLogo`): the mark is the whole
  // brand, at the 96px the sheet caps it at, and the words are the hidden strip beside it.
  const good = {
    ...broken,
    ui: { ...broken.ui, logo_url: '/img/logo.svg' },
  };
  writeSettings(ctx, good);
  const marked = await ctx.browser.newContext({ viewport: { width: 360, height: 800 } });
  await routeLogo(marked);
  const page2 = await marked.newPage();
  try {
    await page2.setExtraHTTPHeaders({ 'X-Auth-Email': 'admin@example.com' });
    await page2.goto(`${ctx.base}/users?lang=en`);
    const g = await brandGeometry(page2);
    brandWordsHidden(t, brand, g, 'the console with a mark that loads', 360);
    t.check('at 360 with a mark that loads: the mark has the room it is capped at',
      !!g.mark && g.mark.cw >= 96, JSON.stringify(g.mark));
    const bar = await barGeometry(page2);
    t.eq('at 360 with a mark that loads: the bar is one row, the mark\'s 35px',
      [bar.rows, bar.height <= 40], [1, true]);
  } finally {
    await marked.close();
    writeSettings(ctx, look);
  }
}

/**
 * The phone's brand slot keeps the room its mark needs (§13.34 §12g's follow-up, found in the
 * designer's review of step 19, 2026-11-27). Below 640 the words give way, so the mark **is** the
 * brand, and the mark never shrinks (`.brand img` is `flex:none`). The slot does shrink: it is one
 * of the bar's give. So on the phone's first line, where the ☰ and a name pill at its cap leave
 * the row no slack, the slot is the piece the row spends and the mark is left standing outside the
 * box shrunk under it. Measured here on 2026-11-27 at 320 with a mark and the long given name: an
 * **87px** slot under a 96px mark (the designer's review measured 86px), the mark's right edge at
 * x=147 and the name pill's left edge at x=145, so the deployment's logo paints over the left
 * border of the one control the phone's whole panel is reached through.
 *
 * What is asserted is where the mark **ends** against where the pill **starts**: that is what a
 * person sees, and it is the number that was wrong. The slot's own right edge is read beside it,
 * because that is the mechanism (a slot narrower than the mark it holds), and the bar's row count
 * and the document's sideways scroll ride along, because a fix that bought the mark's room by
 * making the row overflow is the fault §13.28 §4 exists to catch.
 *
 * The mark has to be a real box. `routeLogo` answers it (§13.34 §12c): an image that never loaded
 * is 0x30, sits inside any slot and overlaps nothing, so every clearance assertion in this walk
 * would pass on a layout no deployment shows. The mark's box is therefore checked before the
 * clearance is read. The long given name is the piece that crowds the row (§13.34 §10a's
 * measurement string), and it needs `gate.profile_claims` configured to be read at all.
 *
 * 360 is walked beside 320 because it is the roomier phone width, where the row has slack today: a
 * rule that stops the slot shrinking must not cost this width its scroll.
 */
async function thePhoneMarkStaysClearOfThePill(t, ctx, look) {
  const wired = {
    ...look,
    gate: { ...(look.gate || {}), profile_claims: ['given_name'] },
    ui: { ...(look.ui || {}), brand_name: 'BadBat75 Estate Services', logo_url: '/img/logo.svg' },
  };
  writeSettings(ctx, wired);
  const context = await ctx.browser.newContext({
    viewport: { width: 320, height: 800 },
    extraHTTPHeaders: {
      'X-Auth-Email': 'admin@example.com',
      'X-Auth-Given-Name': 'Bartholomew-Alexander%20Montgomery',
    },
  });
  await routeLogo(context);
  const page = await context.newPage();
  try {
    for (const w of [320, 360]) {
      await page.setViewportSize({ width: w, height: 800 });
      await page.goto(`${ctx.base}/users?lang=en`);
      const g = await brandGeometry(page);
      const pill = await namePillGeometry(page);
      // The setup, so a bar that quietly dropped the mark cannot pass by overlapping nothing.
      t.check(`at ${w}: the bar carries the 96px mark`,
        !!g.mark && g.mark.cw >= 96, JSON.stringify(g.mark));
      if (!g.mark || !pill.pill) continue;
      t.check(`at ${w}: the mark stays inside the brand slot`, g.brand.right >= g.mark.right,
        `slot ${g.brand.w}px ending at ${g.brand.right}, mark ${g.mark.w}px ending at ${g.mark.right}`);
      t.check(`at ${w}: the mark stops before the name pill`, g.mark.right <= pill.pill.x,
        `mark ends at x=${g.mark.right}, the pill starts at x=${pill.pill.x}`);
      const bar = await barGeometry(page);
      t.eq(`at ${w}: the bar is one row, ${bar.height}px, no sideways scroll`,
        [bar.rows, bar.height <= 40, bar.sideways === 0], [1, true, true]);
    }
  } finally {
    // The settings file goes back as this walk found it: the area's other checks read it as the
    // fixture wrote it, and the form's `rev` fingerprints its bytes.
    await context.close();
    writeSettings(ctx, look);
  }
}

/**
 * The brand is whole where the bar has room (§13.34 §12e): "BadBat75 Operations Console" with a
 * mark that loads, on the console at 1280 and 1024 in both languages, with the short given name
 * and with the long one §10a measured. At each: the words are whole, the bar is one row of at
 * most 40px with no sideways scroll, and the name pill is at the 128px floor. The floor is a
 * measurement taken with the long name, so it is asserted with the long name; a short name makes
 * a small pill and says nothing about the give.
 *
 * Then `/account/` at 1280 and 700 with "BadBat75 Estate Services" and the mark: whole name, bar
 * at most 40px. The account page has no tabs, so it is the surface the long brand is whole on at
 * every width (§13.34 §12g 2).
 *
 * A mark that does not load is not enough here: its box is 0 wide, the words get the room the
 * mark was supposed to take, and every "is the name whole" assertion passes on a layout no
 * deployment shows. The suite's server answers nothing that is not the GUI, so the browser
 * answers the mark (`routeLogo`).
 */
async function brandHasRoom(t, ctx, look) {
  const brand = 'BadBat75 Operations Console';
  const wired = {
    ...look,
    gate: { ...(look.gate || {}), profile_claims: ['given_name'] },
    ui: { ...(look.ui || {}), brand_name: brand, logo_url: '/img/logo.svg' },
  };
  writeSettings(ctx, wired);
  for (const [given, who] of [
    ['Ada', 'a short given name'],
    ['Bartholomew-Alexander%20Montgomery', 'the long given name'],
  ]) {
    const context = await ctx.browser.newContext({
      viewport: { width: 1280, height: 800 },
      extraHTTPHeaders: { 'X-Auth-Email': 'admin@example.com', 'X-Auth-Given-Name': given },
    });
    await routeLogo(context);
    const page = await context.newPage();
    try {
      for (const w of [1280, 1024]) {
        for (const lang of ['en', 'it']) {
          await page.setViewportSize({ width: w, height: 800 });
          await page.goto(`${ctx.base}/users?lang=${lang}`);
          const g = await brandGeometry(page);
          brandWordsWhole(t, brand, g, `the console with ${who} in ${lang}`, w);
          const bar = await barGeometry(page);
          t.eq(`the console with ${who} in ${lang}: the bar is one row, ${bar.height}px, `
            + 'no sideways scroll',
            [bar.rows, bar.height <= 40, bar.sideways === 0], [1, true, true]);
          if (who === 'the long given name') {
            const pill = await namePillGeometry(page);
            t.check(`the console at ${w} in ${lang} with ${who}: the name pill is at least 128px`,
              !!pill && !!pill.pill && pill.pill.w >= 128, JSON.stringify(pill));
          }
        }
      }
    } finally {
      await context.close();
    }
  }
  // The account page, which has no tabs and so the widest cap of the three surfaces.
  const estate = { ...wired, ui: { ...wired.ui, brand_name: 'BadBat75 Estate Services' } };
  writeSettings(ctx, estate);
  const acct = await ctx.browser.newContext({
    viewport: { width: 1280, height: 800 },
    extraHTTPHeaders: { 'X-Auth-Email': 'you@example.com' },
  });
  await routeLogo(acct);
  const page = await acct.newPage();
  try {
    for (const w of [1280, 700]) {
      await page.setViewportSize({ width: w, height: 800 });
      await page.goto(`${ctx.origin}/account/?lang=en`);
      const g = await brandGeometry(page);
      brandWordsWhole(t, 'BadBat75 Estate Services', g, 'the account page', w);
      const bar = await barGeometry(page);
      t.eq(`the account page at ${w}: the bar is one row, ${bar.height}px tall`,
        [bar.rows, bar.height <= 40], [1, true]);
    }
  } finally {
    await acct.close();
    writeSettings(ctx, look);
  }
}

/**
 * The bar at the widths §13.34 §10 measured: 884, where the five tabs are still in the bar, and
 * 883, where they have moved into the ☰; plus 1280, the desktop reference the design's opening
 * measurement is written from ("the name is cut at 118px of 224", "from 1400 down to 884"). A
 * long brand, a logo and a long given name together are the widest case the measurements name,
 * and the Italian tab words are longer than the English ones, so the bar's worst case is Italian.
 * The three strings are the ones §10a wrote down ("BadBat75 Estate Services" with a logo, and
 * "Bartholomew-Alexander Montgomery"), because that is the case the breakpoint was picked on.
 *
 * §13.34 §12 replaces the measurement this walk used to make. The old one compared the brand's
 * box at 884 with its box at a desktop width, and a name the cap holds at both is equal at both
 * while being cut at 884: **the equality is the ellipsis**. What is measured here instead is one
 * box against its own text at one width (the words are whole: `scrollWidth` no greater than the
 * box), and the name pill at the other end. The pill is the half the design hangs on, because the
 * account end shrank **first** at 883 (`nav.acct{flex-shrink:100}`) and the brand was cut while
 * the pill still had room to give: its floor of 128px, and 133px with this brand and name in
 * Italian above the breakpoint (§13.34 §12b), is the number the breakpoint was picked on
 * (§13.34 §10a), a measurement taken with this given name, so it is asserted with this name.
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
  // a mark are what the measurements name, in the spelling §10a measured. The mark is a path the
  // **browser** answers (`routeLogo`), because the suite's server answers nothing that is not
  // the GUI, and a mark that fails to load is a 0-wide box: the words get the room the mark was
  // supposed to take, and every "is the name whole" assertion here would pass on a layout no
  // deployment shows (§13.34 §12c).
  withName.ui = { ...(withName.ui || {}), brand_name: 'BadBat75 Estate Services', logo_url: '/img/logo.svg' };
  writeSettings(ctx, withName);
  const context = await ctx.browser.newContext({
    viewport: { width: 884, height: 720 },
    extraHTTPHeaders: {
      'X-Auth-Email': 'admin@example.com',
      // Percent-encoded, as the gate sends a profile claim, and the long name §10a measured:
      // it is the one that sits the trigger at its cap, and a short name leaves the bar room and
      // the squeeze the rule exists to prevent never happens.
      'X-Auth-Given-Name': 'Bartholomew-Alexander%20Montgomery',
    },
  });
  await routeLogo(context);
  const page = await context.newPage();
  try {
    // The widths the bar is widest at, in the language the bar is widest in. 884 and 883 are the
    // breakpoint's own edge, where the five tabs are still in the bar (884) and where they are
    // not (883); 1280 is the desktop reference the measurement §13.34 §12a opens with ("the name
    // is cut at 118px of 224" at 1280, "from 1400 down to 884"). `brandHasRoom` is the walk that
    // asserts the room at the desktop widths in both languages; here 1280 is the same case in the
    // strings the breakpoint was picked on, so the cut the fix is about is measured in both.
    for (const width of [1280, 884, 883]) {
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
          // Whichever navigation box is showing is the one counted: at 884 that is the bar's
          // strip, at 883 the ☰ trigger. The ☰'s **panel** is deliberately not measured: it is
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
          // The name pill's box is the trigger, not the word inside it: the word is cut with an
          // ellipsis, and the number the breakpoint was picked on is the box's width.
          const trig = box(document.querySelector(`${acct} > summary`));
          const brandEl = document.querySelector('header .brand .t');
          const de = document.documentElement;
          return {
            barH: Math.round(box(bar).height),
            stripRows: strip ? rows(strip) : -1,
            sideways: de.scrollWidth - de.clientWidth,
            icon: icon ? [Math.round(icon.width), Math.round(icon.height)] : null,
            name: name ? name.textContent.trim() : '',
            logo: !!document.querySelector('header .brand img'),
            pill: trig ? Math.round(trig.width) : 0,
            brand: brandEl
              ? [Math.round(brandEl.scrollWidth), Math.round(brandEl.getBoundingClientRect().width)]
              : null,
          };
        }, ACCT_MENU);
        // The setup, so a bar that quietly dropped the name or the mark cannot pass by being narrow.
        t.check(`at ${width} ${lang}: the bar carries the given name and the logo`,
          g.name.startsWith('Bartholomew') && g.logo, JSON.stringify(g));
        t.check(`at ${width} ${lang}: the bar is one row tall`, g.barH <= 40, `bar height ${g.barH}px`);
        t.eq(`at ${width} ${lang}: the navigation is one row`, g.stripRows, 1);
        t.eq(`at ${width} ${lang}: the document does not scroll sideways`, g.sideways, 0);
        t.check(`at ${width} ${lang}: the Sign out glyph is at most 24px`,
          Array.isArray(g.icon) && Math.max(...g.icon) <= 24, JSON.stringify(g.icon));
        // The widths the breakpoint is measured at, plus its desktop reference, in the language
        // the bar is widest in. They promise different things, and the difference is §13.34 §12's
        // arithmetic:
        //
        //  - 1280 is §12a's opening measurement: the 14rem cap leaves the words 118px beside the
        //    mark with the bar's room standing empty, which is the fault the step is about. With
        //    the bar's own budget as the cap, the words are whole here.
        //  - 884, with the five tabs in the bar, is the tight case, and the design does **not**
        //    promise the brand's words are whole there: the budget is the bar's content box at
        //    884 less the 14rem the breakpoint was measured with, so "this brand is cut at 884"
        //    is the design, not the fault. What the breakpoint rests on is the other end: the
        //    name pill, whose smallest width above the breakpoint is 133px in Italian with this
        //    given name (§13.34 §12b). That is the number to pin here, because the fix moves the
        //    give onto the pill and a give that goes past the floor moves the breakpoint.
        //  - 883, with the tabs in the ☰, is the loose case: the cap is `max(14rem,100% - 12.5rem)`,
        //    which at 883 is roomier than this brand needs, so the words are whole and a cut is
        //    the cap being a length of a brand again. Today it is cut at 118px of 191 **while the
        //    pill stands over its floor**: the brand giving while the pill has room is the fault
        //    §12 is about, and it is what these checks are red for.
        if (lang === 'it') {
          if (width === 884) {
            t.check('at 884 it: the name pill stands at the 133px the breakpoint was measured on',
              g.pill >= 133, `${g.pill}px`);
          } else {
            t.check(`at ${width} it: the brand's words are whole`,
              Array.isArray(g.brand) && g.brand[1] > 0 && g.brand[0] <= g.brand[1],
              `slot ${g.brand && g.brand[1]}px, words ${g.brand && g.brand[0]}px`);
            if (width === 883) {
              t.check('at 883 it: the name pill stands at its 128px floor',
                g.pill >= 128, `${g.pill}px`);
            }
          }
        }
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
  // The brand's name at the phone widths, measured **before** this area writes a `ui` section:
  // with no brand configured, the bar wears the built-in one, which is the brand the design's
  // measurement was taken on (§13.34 §0). Later in this file the settings form writes a long
  // brand, and that state is walked by `barAtTheWorstWidth` at the widths the design named.
  await brandStaysWhole(t, page, ctx.base);
  // The bar's room, at the widths the design says a long brand is whole at, with a mark the
  // browser answers and the two given names the measurement names (§13.34 §12e). This writes a
  // `ui` section and puts the file back, so it runs beside the built-in-look walk above and
  // before the form walk, whose `rev` fingerprints the file's bytes.
  await brandHasRoom(t, ctx, settings(ctx));
  // The phone arm and the desktop arm of the brand, on a mark the server does not answer: the
  // words are whole above 640 (§13.34 §12c's bug was that a 0-wide mark left the bar nameless at
  // every width) and a hidden strip at 360 and 320 (§13.34 §12g, the user's option (c)).
  await thePhoneHidesTheWordsAndTheConsoleKeepsThem(t, ctx, settings(ctx));
  // The phone's first line with a mark that **loads**: the slot must not be shrunk out from under
  // the mark, which is the piece that overflows onto the name pill at 320 (§13.34 §12g's
  // follow-up). This writes a `ui` section and a profile claim, so it runs beside the walks above,
  // before the form walk fingerprints the fixture's bytes.
  await thePhoneMarkStaysClearOfThePill(t, ctx, settings(ctx));
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
