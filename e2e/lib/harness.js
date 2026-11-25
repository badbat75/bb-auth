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
  const outer = await openIt('details.settings');
  const inner = await openIt('details.prefs');
  return outer && inner;
}

/**
 * The bar's geometry, as a person sees it (§13.28 §4): does every displayed child of `.bar`
 * share one vertical centre, and does the document scroll sideways?
 *
 * Both numbers come from layout, so only a browser can answer them, which is why this lives
 * here and not in the Rust suite. `rows` counts distinct vertical centres: one means one row.
 */
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
      sideways: de.scrollWidth - de.clientWidth,
      barScroll: bar.scrollWidth - bar.clientWidth,
    };
  });

/**
 * Which of the two tab strips is showing (§13.28 §4): the bar's, above the breakpoint, or the
 * panel's, at and below it. The selector is the bar's `nav` that is not the account end, which
 * is where the tabs live; the panel's rows are `.menu-tabs`.
 */
const headerLayout = (page) =>
  page.evaluate(() => {
    const disp = (sel) => {
      const el = document.querySelector(sel);
      return el ? getComputedStyle(el).display : 'absent';
    };
    const links = (sel) => document.querySelectorAll(sel).length;
    return {
      tabs: disp('header .bar > nav:not(.acct)'),
      menuTabs: disp('.menu-tabs'),
      // The rows themselves. A surface with no tabs may carry an empty `nav` (the shell emits
      // one), so "no tabs" is a count of links, not the display of a box.
      tabLinks: links('header .bar > nav:not(.acct) a'),
      menuLinks: links('.menu-tabs a'),
    };
  });

/**
 * The bar is on one row, and the document does not scroll sideways, at every width the design
 * measured (§13.28 §4): 320, 360, 640, 641, 800, 801, 1024, 1280. The breakpoint is on the
 * inside, so 800 and 801 are the pair that says where it is. Each width is measured in both
 * languages: the Italian words are the longer ones ("Impostazioni di sistema" against "System
 * settings"), so the bar's worst case is Italian and a walk that only speaks English measures
 * the easy half.
 *
 * The caller sets the settings first: the widest case the measurements name is a long
 * `ui.brand_name` with a logo present, and the logo is a root-relative path, because
 * `compile_asset_url` accepts no `data:` URL and a suite must not reach the network. A broken
 * image is sized by its CSS box, which is the box the bar lays out, so the geometry is real.
 */
async function barStaysOneRow(t, page, base, path, label, tabs = true) {
  for (const width of [320, 360, 640, 641, 800, 801, 1024, 1280]) {
    await page.setViewportSize({ width, height: 720 });
    for (const lang of ['en', 'it']) {
      const sep = path.includes('?') ? '&' : '?';
      await page.goto(`${base}${path}${sep}lang=${lang}`);
      const g = await barGeometry(page);
      t.eq(`${label} at ${width} ${lang}: one row`, [g.rows, g.kids > 1], [1, true]);
      t.eq(`${label} at ${width} ${lang}: the document does not scroll sideways`, g.sideways, 0);
      t.eq(`${label} at ${width} ${lang}: the bar does not scroll sideways`, g.barScroll, 0);
      const l = await headerLayout(page);
      if (tabs) {
        const inPanel = width <= 800;
        // Both flags read "is hidden", so the pair is (bar hidden, panel rows hidden): above the
        // breakpoint the bar shows and the panel's rows do not, at and below it the other way.
        t.eq(`${label} at ${width} ${lang}: the tabs are ${inPanel ? 'in the panel' : 'in the bar'}`,
          [l.tabs === 'none', l.menuTabs === 'none'], [inPanel, !inPanel]);
      } else {
        // This surface has no tabs at any width, so it must not grow a second strip either. The
        // shell emits an empty `nav` here, so the rule is about rows, not about boxes.
        t.eq(`${label} at ${width} ${lang}: no tabs, in the bar or anywhere`,
          [l.tabLinks, l.menuLinks], [0, 0]);
      }
    }
  }
  await page.setViewportSize({ width: 1280, height: 900 });
}

module.exports = {
  Checker, doc, bytes, writeDoc, settings, settingsBytes, writeSettings, sha256, newPage, submit,
  mainText, pageLang, api, resubmit, formBytes, setDuration, openPreferences, barGeometry,
  barStaysOneRow, headerLayout, attr, text, count, prop,
};
