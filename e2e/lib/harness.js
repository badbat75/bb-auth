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
const doc = (ctx) => JSON.parse(fs.readFileSync(ctx.usersFile, 'utf8'));

/** The working access file, exact bytes — what `rev` and "wrote nothing" are about. */
const bytes = (ctx) => fs.readFileSync(ctx.usersFile, 'utf8');

/** An out-of-band write, as a `bb-auth-adm` over SSH would do it: valid file, new bytes. */
const writeDoc = (ctx, d) => fs.writeFileSync(ctx.usersFile, JSON.stringify(d, null, 2) + '\n');

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

/** The exact fields the first form in `main` would post, hidden `rev` included. */
const formBytes = (page) =>
  page.locator('main form').first().evaluate((f) => Object.fromEntries(new FormData(f).entries()));

module.exports = {
  Checker, doc, bytes, writeDoc, sha256, newPage, submit, mainText, pageLang, api, resubmit, formBytes,
};
