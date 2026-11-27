'use strict';
// Shared plumbing for the test areas. Two rules keep the suite deterministic:
//
// * Every assertion goes through `Checker` — a test never throws to signal failure, it
//   records, so one broken expectation does not hide the next twenty. A *thrown* error
//   (element not found, navigation timeout) is still caught per-area by the runner and
//   recorded as that area's failure.
// * The JSON file is the source of truth. A page can say anything; what the suite trusts
//   is `doc()` / `bytes()` — the exact state of the access file after each mutation,
//   which is also what the gate would load.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/** Collects named pass/fail results for one test area. */
class Checker {
  constructor(area, shotsDir) {
    this.area = area;
    this.shotsDir = shotsDir;
    this.results = [];
  }

  /** Record one expectation. Returns the verdict so callers can chain on it. */
  check(name, ok, detail) {
    this.results.push({ name, ok: !!ok, detail: ok ? undefined : String(detail ?? '') });
    return !!ok;
  }

  /** `check` with the got/want spelled out on failure. */
  eq(name, got, want) {
    const same = JSON.stringify(got) === JSON.stringify(want);
    return this.check(name, same, `got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
  }

  /** Screenshot, only when E2E_SHOTS=1 — evidence, never an assertion. */
  async shot(page, name) {
    if (!this.shotsDir) return;
    await page.screenshot({ path: path.join(this.shotsDir, `${this.area}-${name}.png`), fullPage: true });
  }
}

/** The working access file, parsed. Read fresh every time — the server rewrites it. */
const doc = (ctx) => JSON.parse(fs.readFileSync(ctx.accessFile, 'utf8'));

/** The working access file, exact bytes — what `rev` and "wrote nothing" are about. */
const bytes = (ctx) => fs.readFileSync(ctx.accessFile, 'utf8');

/** The working settings file, parsed and raw: the other file the GUI edits. */
const settings = (ctx) => JSON.parse(fs.readFileSync(ctx.settingsFile, 'utf8'));
const settingsBytes = (ctx) => fs.readFileSync(ctx.settingsFile, 'utf8');

/** An out-of-band write to the settings file, as a `bb-auth-adm settings set` would do. */
const writeSettings = (ctx, d) => fs.writeFileSync(ctx.settingsFile, JSON.stringify(d, null, 2) + '\n');

/** An out-of-band write, as a `bb-auth-adm` over SSH would do it: valid file, new bytes. */
const writeDoc = (ctx, d) => fs.writeFileSync(ctx.accessFile, JSON.stringify(d, null, 2) + '\n');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

/**
 * A fresh browser context + page carrying the identity nginx would inject.
 * `email: null` sends no header at all (the broken-deployment case).
 * Caller closes it: `await context.close()`.
 */
async function newPage(ctx, email = 'admin@example.com') {
  const context = await ctx.browser.newContext({
    viewport: { width: 1280, height: 900 },
    extraHTTPHeaders: email === null ? {} : { 'X-Auth-Email': email },
  });
  const page = await context.newPage();
  return { context, page };
}

/** Submit the one form in `main` and hand back the navigation's response. */
async function submit(page, selector = 'main form button[type=submit]') {
  const [resp] = await Promise.all([page.waitForNavigation(), page.click(selector)]);
  return resp;
}

const mainText = (page) => page.locator('main').innerText();
const pageLang = (page) => page.locator('html').getAttribute('lang');

/** Raw HTTP against the server, identity header included unless `email: null`. */
function api(ctx, urlPath, opts = {}) {
  const headers = Object.assign({}, opts.headers);
  if (opts.email !== null) headers['X-Auth-Email'] = opts.email || 'admin@example.com';
  const url = urlPath.startsWith('http') ? urlPath : ctx.origin + urlPath;
  return fetch(url, { ...opts, headers, redirect: opts.redirect || 'follow' });
}

/**
 * Re-submit `fields` to `action` from the current page — byte-wise what a browser does
 * when the direct POST response (the reveal page) is reloaded and the resubmission
 * confirmed. Built as a same-origin form so `Sec-Fetch-Site` says what a real reload
 * would say; a plain `page.reload()` is not guaranteed to re-POST under automation.
 */
async function resubmit(page, action, fields) {
  const [resp] = await Promise.all([
    page.waitForNavigation(),
    page.evaluate(({ action, fields }) => {
      const f = document.createElement('form');
      f.method = 'POST';
      f.action = action;
      for (const [k, v] of Object.entries(fields)) {
        const i = document.createElement('input');
        i.type = 'hidden';
        i.name = k;
        i.value = v;
        f.appendChild(i);
      }
      document.body.appendChild(f);
      f.submit();
    }, { action, fields }),
  ]);
  return resp;
}

/**
 * Choose a duration in a key form (§13.15 as amended by §13.16): the three presets
 * are options of `select[name=duration]`, and every other window is `custom` plus
 * the `days` box beside it. A test that types a window into the text field the form
 * no longer has fails as a locator timeout, which says nothing about the form.
 * `value` is the string the file is expected to end up holding, so `'30d'` means
 * custom, 30 days.
 */
async function setDuration(page, value, scope = 'main form') {
  const sel = `${scope} select[name=duration]`;
  if (['365d', '182d', '91d', 'never'].includes(value)) {
    await page.selectOption(sel, value);
    return;
  }
  await page.selectOption(sel, 'custom');
  await page.fill(`${scope} input[name=days]`, value.replace(/d$/, ''));
}

/** The exact fields the first form in `main` would post, hidden `rev` included. */
const formBytes = (page) =>
  page.locator('main form').first().evaluate((f) => Object.fromEntries(new FormData(f).entries()));

/**
 * Reading a control without throwing when it is not there.
 *
 * A walk that asserts a control exists must record that it is missing, not abort the area:
 * Playwright's `locator.innerText()` and `getAttribute()` reject on an empty locator, and an
 * unhandled rejection ends every check that came after. These three answer `null` / `''` /
 * `0` instead, so a red suite says which control is absent and keeps testing the rest.
 */
const attr = (page, sel, name) => page.locator(sel).first().getAttribute(name).catch(() => null);
const text = (page, sel) => page.locator(sel).first().innerText().catch(() => '');
const count = (page, sel) => page.locator(sel).count();
/** One property of a control, read by a function run in the page: `d.open`, a computed style. */
const prop = (page, sel, fn) => page.locator(sel).first().evaluate(fn).catch(() => null);

/**
 * Open the header's account panel, and the Preferences box nested inside it
 * (docs/ARCHITECTURE.md §13.28 §2), so a `.menu select` is reachable for a click.
 *
 * Both are `details`, and the box is closed by default, so a test that reaches a list box has
 * to open two things. Doing it here is the point: a test that opens one and not the other
 * fails as a click timeout on a hidden element, which says nothing about the panel.
 * Idempotent, so a walk can call it at every step.
 */
async function openPreferences(page) {
  const openIt = async (sel) => {
    const box = page.locator(sel);
    if ((await box.count()) === 0) return false;
    if (!(await box.evaluate((d) => d.open))) await page.click(`${sel} > summary`);
    return true;
  };
  const outer = await openIt(ACCT_MENU);
  const inner = await openIt(`${ACCT_MENU} details.prefs`);
  return outer && inner;
}

/**
 * The bar's geometry, as a person sees it (§13.28 §4): does every displayed child of `.bar`
 * share one vertical centre, and does the document scroll sideways?
 *
 * Both numbers come from layout, so only a browser can answer them, which is why this lives
 * here and not in the Rust suite. `rows` counts distinct vertical centres: one means one row.
 */
/** The tab links the bar **renders**: how many rows they stack into, and how many there are.
 *  `rows` counts distinct vertical centres, so a strip that is showing is **one** row, and the
 *  count is what says the row carries all five. A strip hidden by the 883 block generates no
 *  box, so both are 0. */
const barTabRows = (page) =>
  page.evaluate(() => {
    const ys = new Set();
    let links = 0;
    for (const el of document.querySelectorAll('header .bar > nav.tabs a')) {
      const r = el.getBoundingClientRect();
      if (r.height > 0) {
        links += 1;
        ys.add(Math.round(r.top + r.height / 2));
      }
    }
    return { rows: ys.size, links };
  });

const barGeometry = (page) =>
  page.evaluate(() => {
    const bar = document.querySelector('header .bar');
    const kids = [...bar.children].filter((el) => {
      const s = getComputedStyle(el);
      return s.display !== 'none' && s.visibility !== 'hidden';
    });
    const centres = new Set(
      kids.map((el) => Math.round(el.getBoundingClientRect().top + el.getBoundingClientRect().height / 2))
    );
    const de = document.documentElement;
    return {
      rows: centres.size,
      kids: kids.length,
      height: Math.round(bar.getBoundingClientRect().height),
      sideways: de.scrollWidth - de.clientWidth,
      barScroll: bar.scrollWidth - bar.clientWidth,
    };
  });

/**
 * The brand slot as the browser lays it out: the slot's box, the words' box, the mark's box,
 * and the computed style of each. A word is hidden by **some** property, and which one is not
 * the point, so §13.34 §12e asks for the words to be visible (a box laid out, no text spilling
 * out of it, the text read back) and not for one named property to have one value.
 */
const brandGeometry = (page) =>
  page.evaluate(() => {
    const box = (sel) => {
      const el = document.querySelector(sel);
      if (!el) return null;
      const r = el.getBoundingClientRect();
      const s = getComputedStyle(el);
      return {
        w: Math.round(r.width),
        // `scrollWidth` past `clientWidth` is the ellipsis; `clientWidth` of 0 is a box with no
        // room at all, which a `position:absolute` strip out of the row reports.
        cw: el.clientWidth,
        sw: Math.round(el.scrollWidth),
        x: Math.round(r.left),
        right: Math.round(r.right),
        display: s.display,
        visibility: s.visibility,
        position: s.position,
      };
    };
    const words = document.querySelector('header .brand .t');
    return {
      brand: box('header .brand'),
      words: box('header .brand .t'),
      mark: box('header .brand img'),
      text: words ? words.textContent.trim() : '',
    };
  });

/**
 * The name pill as the browser lays it out: the trigger's box and its label's box. The trigger
 * is `.bar .who` (§13.28 §4: the bar's first give), and its floor of 128px is the number the
 * 883/884 breakpoint was picked on (§13.34 §10a), so "the brand got its room" only means
 * something when the pill is still standing at that floor.
 */
const namePillGeometry = (page) =>
  page.evaluate(() => {
    const box = (sel) => {
      const el = document.querySelector(sel);
      if (!el) return null;
      const r = el.getBoundingClientRect();
      return {
        w: Math.round(r.width),
        cw: el.clientWidth,
        sw: Math.round(el.scrollWidth),
        // The edges beside the width: a brand that overflows its own slot is measured by what it
        // overlaps, and that is a position, not a length.
        x: Math.round(r.left),
        right: Math.round(r.right),
      };
    };
    return { pill: box('.bar .who'), label: box('.bar .who .who-name') };
  });

/**
 * Serve the deployment's mark on every page of this context (docs/ARCHITECTURE.md §13.34 §12c).
 *
 * A check of the brand slot with a mark configured is worthless if the mark does not load: a
 * broken image box is 0x30 in Chromium, so the brand's words get the room the mark was
 * supposed to take, and every "is the name whole" assertion passes on a layout the deployment
 * never shows. The suite's server cannot answer for `/img/logo.svg`: the origin is a TCP proxy
 * that forwards to the GUI over a unix socket, and a root-relative path that is not a route the
 * GUI serves comes back as the GUI's own `403`/`404`, never as bytes. `context.route` is the
 * browser answering, so the server, its access file and its fixtures are untouched.
 *
 * The mark is 120x36 and `.brand img` is `height:30px; max-width:96px`, so the box on the page
 * is 96x30 at the SVG's aspect, and the bar's height is the mark's height plus its 5px of
 * vertical padding, which is the height `barGeometry` reports.
 */
async function routeLogo(context) {
  await context.route('**/img/logo.svg', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'image/svg+xml',
      body:
        '<svg xmlns="http://www.w3.org/2000/svg" width="120" height="36" viewBox="0 0 120 36">' +
        '<rect width="120" height="36" rx="8" fill="#7f1d1d"/>' +
        '<path d="M22 9l22 18H22z" fill="#fff"/></svg>',
    }),
  );
}

/**
 * The brand's words are **whole**, not merely clipped: the box has room (`clientWidth` above 0),
 * no text overflows it (`scrollWidth` no greater than `clientWidth`), the words are the bar's
 * own row (not pulled out of it), the text reads the brand, and the words sit inside the
 * viewport (§13.34 §12e).
 *
 * This replaces the desktop-width comparison the suite used to make. A name that fits the
 * brand's cap at both widths is equal at both while being cut at the narrow one, so "as wide as
 * at 1280" passes on the ellipsis: that equality **is** the ellipsis. `scrollWidth` past
 * `clientWidth` is the ellipsis, and it is measurable at a single width. The `position` check is
 * the shape the hidden-words mechanism shipped in: a `position:absolute` strip taken out of the
 * row reports a 1px box and an ellipsis, which no box-to-box comparison sees (§13.34 §12c).
 */
function brandWordsWhole(t, brand, g, label, w) {
  t.check(`${label} at ${w}: the brand's words are whole (${brand})`,
    !!g.words && g.words.cw > 0 && g.words.sw <= g.words.cw,
    JSON.stringify({ brand, w, words: g.words }));
  t.check(`${label} at ${w}: the words are in the bar's row, not pulled out of it`,
    !!g.words && g.words.position !== 'absolute' && g.words.position !== 'fixed',
    JSON.stringify({ brand, w, words: g.words }));
  t.check(`${label} at ${w}: the bar names the deployment (${brand})`,
    !!g.words && g.text === brand, JSON.stringify({ brand, w, text: g.text }));
  t.check(`${label} at ${w}: the words sit inside the viewport (${brand})`,
    !!g.words && g.words.right <= w + 1,
    JSON.stringify({ brand, w, words: g.words }));
}

/**
 * The brand as the bar shows it **on a phone** (docs/ARCHITECTURE.md §13.34 §12g, the user's
 * option (c) of 2026-11-27): the mark is on the row, and the words are out of it, hidden by the
 * clip pattern `base.css`'s `.vh` uses. The pair of claims is the point. The mark shows, because
 * a bar that hides its mark is the rule the reversal takes back. The words are a 1px box, and
 * `display` on them is not `none` and `visibility` is not `hidden`: the image's `alt` is empty,
 * so those words are the bar's only name, and a rule that hides them from a reader leaves an
 * estate-wide accessibility failure, not a phone layout.
 */
function brandWordsHidden(t, brand, g, label, w) {
  t.check(`${label} at ${w}: the mark is on the row`,
    !!g.mark && g.mark.display !== 'none', JSON.stringify({ brand, w, mark: g.mark }));
  t.check(`${label} at ${w}: the words are a strip out of the row, not a box with no room`,
    !!g.words && g.words.position === 'absolute' && g.words.cw <= 1,
    JSON.stringify({ brand, w, words: g.words }));
  t.check(`${label} at ${w}: the words are hidden from eyes only`,
    !!g.words && g.words.display !== 'none' && g.words.visibility !== 'hidden',
    JSON.stringify({ brand, w, words: g.words }));
  t.check(`${label} at ${w}: the bar names the deployment to a reader (${brand})`,
    !!g.words && g.text === brand, JSON.stringify({ brand, w, text: g.text }));
}


/**
 * Which of the two tab strips is showing (§13.28 §4, §13.34): the bar's own, above the
 * breakpoint, or the ☰'s copy of it, at and below. The strip is `nav.tabs` and the ☰ is
 * `nav.navm`; both are children of the bar, so "the bar's nav that is not the account end"
 * would now match the ☰ first and read the wrong box. The rows are `div.menu-tabs`, and they
 * live in the ☰ alone: the account menu gave them up in §13.34.
 */
const headerLayout = (page) =>
  page.evaluate(() => {
    const disp = (sel) => {
      const el = document.querySelector(sel);
      return el ? getComputedStyle(el).display : 'absent';
    };
    const links = (sel) => document.querySelectorAll(sel).length;
    return {
      tabs: disp('header .bar > nav.tabs'),
      navMenu: disp('header .bar > nav.navm'),
      // The links in each box, as the document holds them. A box hidden by `display:none` keeps
      // its children, so these count the rows that *exist*, which is the claim the surfaces with
      // no tabs are asked about; the rows that *show* are measured by opening the menu.
      tabLinks: links('header .bar > nav.tabs a'),
      menuLinks: links('header .bar > nav.navm .menu-tabs a'),
      acctLinks: links('header .bar > nav.acct .menu-tabs a'),
    };
  });

/**
 * The bar is on one row, and the document does not scroll sideways, at every width the design
 * measured (§13.28 §4, §13.34 §10): 320, 360, 640, 641, 883, 884, 1024, 1280. The breakpoint
 * on the inside, so 883 and 884 are the pair that says where it is. Each width is measured in
 * both languages: the Italian words are the longer ones ("Impostazioni" against "Settings", and
 * the account menu's "Menu di navigazione"), so the bar's worst case is Italian and a walk that
 * only speaks English measures the easy half.
 *
 * The caller sets the settings first: the widest case the measurements name is a long
 * `ui.brand_name` with a logo present, and the logo has to be a URL the browser answers, which
 * is what `routeLogo` is for (§13.34 §12c).
 *
 * The bar's **height** is asserted beside the row count, because the row count alone passes on
 * a bar that grew: every child of a flex row with `align-items:center` has the same centre, so
 * a brand that wraps its mark above its name is one row at 80px, and the page below loses 40px
 * of it. A bar carrying a mark is 40px (the 30px mark plus the 5px of padding top and bottom);
 * with no mark it is 25px (§13.34 §12a).
 */
async function barStaysOneRow(t, page, base, path, label, tabs = true) {
  for (const width of [320, 360, 640, 641, 883, 884, 1024, 1280]) {
    await page.setViewportSize({ width, height: 720 });
    for (const lang of ['en', 'it']) {
      const sep = path.includes('?') ? '&' : '?';
      await page.goto(`${base}${path}${sep}lang=${lang}`);
      const g = await barGeometry(page);
      t.eq(`${label} at ${width} ${lang}: one row, ${g.height}px tall`,
        [g.rows, g.kids > 1, g.height <= 40], [1, true, true]);
      t.eq(`${label} at ${width} ${lang}: the document does not scroll sideways`, g.sideways, 0);
      t.eq(`${label} at ${width} ${lang}: the bar does not scroll sideways`, g.barScroll, 0);
      const l = await headerLayout(page);
      if (tabs) {
        const inMenu = width <= 883;
        // The two boxes swap: above the breakpoint the strip shows and the ☰ takes no room, at
        // and below it the strip is out and the ☰ is in. Their **rows** are not measured here: a
        // closed `details` renders nothing, and a child of a `display:none` box keeps its own
        // computed `display`, so "are the rows showing" is not a question a stylesheet read
        // answers. They are measured where they are shown, by opening the menu
        // (`e2e/tests/settings.js`, `e2e/tests/nojs.js`), and that the top-level rule does not
        // hide the ☰'s rows is pinned in Rust by `the_bar_stays_one_row_at_every_width`.
        t.eq(`${label} at ${width} ${lang}: the tabs are ${inMenu ? 'in the ☰' : 'in the bar'}`,
          [l.tabs === 'none', l.navMenu === 'none'],
          [inMenu, !inMenu]);
        // The strip's links are the rows the geometry above counts: a strip that is showing is
        // **one** row carrying all five, so the breakpoint is a move and not a narrowing.
        const rows = await barTabRows(page);
        t.eq(`${label} at ${width} ${lang}: the strip is ${inMenu ? 'gone' : 'one row of five'}`,
          [rows.rows, rows.links], inMenu ? [0, 0] : [1, 5]);
      } else {
        // This surface has no tabs at any width, so it must not grow a second strip either, in
        // the ☰ it does not have or in the account menu it shares with the console.
        t.eq(`${label} at ${width} ${lang}: no tabs, in the bar, the ☰ or the account menu`,
          [l.tabLinks, l.menuLinks, l.acctLinks], [0, 0, 0]);
      }
    }
  }
  await page.setViewportSize({ width: 1280, height: 900 });
}

/**
 * The bar's two menus, by the selectors §13.34 names (§2). Both outer boxes carry the class
 * `settings` (it is what carries the open look and the §13.20 cover), so the account menu has
 * to be read as "the `details.settings` that is not the ☰": a bare `details.settings` matches
 * the ☰ first on the console, and a walk that opens one and measures the other is the trap
 * this constant exists to close.
 */
const ACCT_MENU = 'header .bar nav.acct details.settings';
const NAV_MENU = 'header .bar nav.navm details.navmenu';

/**
 * Open one of the bar's menus by its trigger, as a pointer does, and answer whether it is
 * open. Idempotent, so a walk can call it at every step, and honest about absence: a surface
 * with no ☰ (`/account/`) answers `false` rather than throwing, so a check that the page has
 * no navigation menu reads as that check, not as a locator timeout.
 */
async function openBarMenu(page, sel = ACCT_MENU) {
  const box = page.locator(sel);
  if ((await box.count()) === 0) return false;
  if (!(await box.evaluate((d) => d.open))) await page.click(`${sel} > summary`);
  return box.evaluate((d) => d.open);
}

/**
 * Whether one bar menu is open, and `null` when the page has no such box. A surface with no ☰
 * (`/account/`, the console's `403`) answers a check about it as an absence, which is a fact a
 * walk can record; a rejected `$eval` is an exception, and in an area that is written to keep
 * walking past a missing control it takes the rest of the area with it.
 */
const menuIsOpen = (page, sel = ACCT_MENU) =>
  page.locator(sel).evaluate((d) => d.open).catch(() => null);

/**
 * One bar menu, as a person sees it (§13.34 §3): the class of the three boxes that make it,
 * the width of its panel, and the hrefs of its rows.
 *
 * The width is the measurement §13.34 §0 says a unit test cannot take. The panel was
 * shrink-to-fit against its trigger, so one rule produced a 230px panel on the console and a
 * 286px panel on `/account/`, and both pages looked correct in their own stylesheet. Reading
 * `getBoundingClientRect()` on both surfaces, in one browser, is the only way to see that the
 * two menus are two sizes. The class names come back too, because "one object" is a claim
 * about the markup as well as about the box.
 */
const menuShape = (page, sel = ACCT_MENU) =>
  page.evaluate((s) => {
    const d = document.querySelector(s);
    if (!d) return null;
    const summary = d.querySelector(':scope > summary');
    const menu = d.querySelector(':scope > .menu');
    const box = menu ? menu.getBoundingClientRect() : null;
    return {
      open: d.open,
      name: d.getAttribute('name'),
      detailsClass: d.getAttribute('class'),
      summaryClass: summary ? summary.getAttribute('class') : null,
      menuClass: menu ? menu.getAttribute('class') : null,
      width: box ? Math.round(box.width * 10) / 10 : null,
      right: box ? Math.round(box.right) : null,
      // The panel's rows, as links, excluding anything nested in a box of its own (the
      // Preferences list boxes are not rows).
      rows: menu
        ? Array.from(menu.querySelectorAll('a.pill')).map((a) => a.getAttribute('href'))
        : [],
    };
  }, sel);

/**
 * The account menu is **one box on both surfaces** (§13.34 §3), measured in a browser.
 *
 * This is the check §13.34 §0 says a unit test cannot take. The panel was shrink-to-fit
 * against its trigger, so one shared rule produced a 230px panel on the console and a 286px
 * panel on `/account/`: every stylesheet read correctly on its own page, and the two surfaces
 * disagreed by 56px. A declared width fixes it, and only a layout engine can say the fix
 * landed. The caller is the same person on both pages, because the drift was a property of the
 * surface and not of who was looking at it.
 *
 * The width is the declared one, capped to the viewport that opens it:
 * `min(20rem, viewport - 32)`, so 320 on a desktop and on a 360 phone, and the cap is what
 * keeps the last row reachable on a 320 one.
 */
async function menuIsOneSize(t, context, base, label) {
  const origin = new URL(base).origin;
  const page = await context.newPage();
  const width = (viewport) => Math.min(320, viewport - 32);
  try {
    for (const viewport of [1280, 360]) {
      const seen = {};
      for (const [surface, url] of [
        ['console', `${base}/users?lang=en`],
        ['account', `${origin}/account/?lang=en`],
      ]) {
        await page.setViewportSize({ width: viewport, height: 900 });
        await page.goto(url);
        const opened = await openBarMenu(page, ACCT_MENU);
        t.eq(`${label} at ${viewport} on ${surface}: the account menu opens`, opened, true);
        seen[surface] = await menuShape(page, ACCT_MENU);
      }
      const c = seen.console;
      const a = seen.account;
      if (!c || !a) {
        t.check(`${label} at ${viewport}: both surfaces have an account menu`, false,
          JSON.stringify(seen));
        continue;
      }
      t.eq(`${label} at ${viewport}: the panel is the declared width on the console`,
        c.width, width(viewport));
      t.eq(`${label} at ${viewport}: and on the account page`, a.width, width(viewport));
      // Within half a pixel, because the number comes from a layout engine.
      t.check(`${label} at ${viewport}: the two panels are one width`,
        Math.abs(c.width - a.width) <= 0.5, `${c.width}px / ${a.width}px`);
      // One object, in the markup as well as in the box: the same class on the three boxes
      // that make the menu, so a surface cannot quietly put the panel in a box of its own.
      for (const part of ['detailsClass', 'summaryClass', 'menuClass']) {
        t.eq(`${label}: ${part} is the same on both surfaces`, c[part], a[part]);
      }
      t.eq(`${label}: the ☰ is in the bar's exclusive group, the account menu is the other half`,
        [c.name, a.name], ['bar-menu', 'bar-menu']);
    }
    await page.setViewportSize({ width: 1280, height: 900 });
  } finally {
    await page.close();
  }
}

module.exports = {
  Checker, doc, bytes, writeDoc, settings, settingsBytes, writeSettings, sha256, newPage, submit,
  mainText, pageLang, api, resubmit, formBytes, setDuration, openPreferences, barGeometry,
  barStaysOneRow, headerLayout, openBarMenu, menuIsOpen, menuShape, menuIsOneSize,
  brandGeometry, namePillGeometry, brandWordsWhole, brandWordsHidden, routeLogo,
  ACCT_MENU, NAV_MENU,
  attr, text, count, prop,
};
