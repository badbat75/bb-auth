#!/usr/bin/env node
'use strict';
// The visual walk-through: every page shape bb-auth-web can render, captured as a
// full-page screenshot in light, dark and phone. Same binary, same bootstrap and same
// throwaway fixture as the suite (lib/server.js) — this one asserts nothing, it produces
// evidence a human looks at when judging the design.
//
//   node e2e/shots.js                    # -> e2e/artifacts/visual/{light,dark,phone,it}/
//   node e2e/shots.js dashboard users    # only the scenes whose name contains one of these
//
// Two kinds of thing are captured. SCENES are page shapes. STATES are what the pointer
// and the keyboard do to a control: a hover colour, a focus ring. Both live here on
// purpose. A review that needs a hover state needs it EVERY time the chrome is touched,
// so writing a scratch Playwright script for it once per review is how a check ends up
// unrepeatable, undocumented, and quietly different each time.
//
// A scene is a name plus the steps that leave the browser looking at that state. The
// interesting half of the inventory cannot be reached with a GET — the flash after a
// save, the in-context 400, the 409, the reveal-once bearer are all POST responses — so a
// scene may drive forms; the fixture is restored before each one, which is what keeps the
// set order-independent exactly as the suite's areas are.

const fs = require('fs');
const path = require('path');

const { E2E_DIR, FIXTURE, boot } = require('./lib/server');
const { submit, formBytes, resubmit, writeDoc, doc } = require('./lib/harness');

/** Where a screenshot lands. Under artifacts/, which is gitignored. */
const OUT = path.join(E2E_DIR, 'artifacts', 'visual');

/**
 * The ways a page is looked at. `light` and `dark` are the two `prefers-color-scheme`
 * arms and are the only ones that run the interaction states, since a hover or a focus
 * ring is a colour. `phone` is narrow enough to force every wrap. `it` exists because the
 * GUI is bilingual and half of a design review is reading the copy: it sets the language
 * cookie once, then renders the scenes that carry prose.
 */
const VIEWS = [
  { tag: 'light', colorScheme: 'light', viewport: { width: 1280, height: 900 }, states: true },
  { tag: 'dark', colorScheme: 'dark', viewport: { width: 1280, height: 900 }, states: true },
  { tag: 'phone', colorScheme: 'light', viewport: { width: 390, height: 844 } },
  {
    tag: 'it',
    colorScheme: 'light',
    viewport: { width: 1280, height: 900 },
    lang: 'it',
    // Only where there is something to read: a form's field measures do not change.
    only: ['dashboard', 'users', 'denied', 'sites', 'can-authorized', 'can-denied',
      'user-rm', 'key-minted', 'error-refused', 'conflict', 'conflict-mint', 'forbidden',
      'settings-menu'],
  },
  // An explicit theme is only worth photographing against the OPPOSITE `colorScheme`:
  // that is the pair that proves the choice beat the operating system. Under a matching
  // OS these would be pixel-identical to the `light` and `dark` views above, and would
  // prove only that the cookie did no harm.
  {
    tag: 'theme-light',
    colorScheme: 'dark',
    theme: 'light',
    viewport: { width: 1280, height: 900 },
    only: ['dashboard', 'users'],
  },
  {
    tag: 'theme-dark',
    colorScheme: 'light',
    theme: 'dark',
    viewport: { width: 1280, height: 900 },
    only: ['dashboard', 'users'],
  },
  // Scripting off. Exactly one page shape differs: the Settings menu grows back the submit
  // button that the one inline handler makes unnecessary. It is a shape a reviewer would
  // otherwise never see, and the only proof by eye that the handler is an enhancement.
  {
    tag: 'noscript',
    colorScheme: 'light',
    viewport: { width: 1280, height: 900 },
    javaScriptEnabled: false,
    only: ['settings-menu'],
  },
];

/** `go` is a plain GET of a path below the base; most scenes are one of these. */
const go = (p) => async (page, ctx) => { await page.goto(ctx.base + p); };

/**
 * Press Tab until `selector` holds the focus, then stop. Keyboard focus, not
 * `element.focus()`: Chromium only matches `:focus-visible` when the last interaction was
 * a key, so a programmatic focus would photograph a ring that a real user never sees.
 */
async function tabTo(page, selector, max = 30) {
  for (let i = 0; i < max; i++) {
    await page.keyboard.press('Tab');
    const there = await page.evaluate(
      (sel) => document.activeElement?.matches(sel) ?? false,
      selector,
    );
    if (there) return true;
  }
  throw new Error(`tabTo: ${selector} never took focus in ${max} presses`);
}

const SCENES = [
  // ---- the read-only inventory -------------------------------------------
  ['dashboard', go('/')],
  ['groups', go('/groups')],
  ['sites', go('/sites')],
  ['denied', go('/denied')],
  ['users', go('/users')],
  ['user-detail', go('/users/bot%40example.com')],
  ['can-empty', go('/can')],
  ['can-authorized', go('/can?email=friend%40example.com&url=https%3A%2F%2Fapp.example.com%2Freports')],
  ['can-denied', go('/can?email=spammer%40example.com&url=https%3A%2F%2Fapp.example.com%2Fapp1')],

  // ---- the forms ---------------------------------------------------------
  ['user-add', go('/users/%2Badd')],
  ['user-edit', go('/users/friend%40example.com/edit')],
  ['key-add', go('/users/bot%40example.com/keys/%2Badd')],
  ['key-edit', go('/users/bot%40example.com/keys/laptop/edit')],
  ['site-add', go('/sites/%2Badd')],
  ['site-edit', go('/sites/app1-onboarding/edit')],
  ['group-edit', go('/groups/mcp/edit')],
  ['deny-add', go('/denied/%2Badd')],

  // The Settings menu, open. A scene and not a state: what is inside it is prose (so the
  // `it` view has to see it) and a 230px panel hanging off the right edge (so the phone
  // does). It is the one page shape a `goto` cannot reach, because `details` remembers
  // nothing across a navigation.
  ['settings-menu', async (page, ctx) => {
    await page.goto(ctx.base + '/users');
    await page.click('details.settings > summary');
  }],

  // ---- the confirmations: a GET that changes nothing ----------------------
  ['user-rm', go('/users/friend%40example.com/rm')],
  ['key-rm', go('/users/bot%40example.com/keys/laptop/rm')],
  ['site-rm', go('/sites/app1-onboarding/rm')],

  // ---- the states only a POST reaches ------------------------------------
  // The flash: a save, then the 303 lands on the page carrying ?msg=.
  ['flash-saved', async (page, ctx) => {
    await page.goto(ctx.base + '/groups/mcp/edit');
    await submit(page);
  }],
  // The in-context refusal: the library's own words, the typed input preserved, 400.
  ['error-refused', async (page, ctx) => {
    await page.goto(ctx.base + '/users/%2Badd');
    await page.fill('input[name=email]', 'not-an-email');
    await page.fill('textarea[name=urls]', 'https://app.example.com/*');
    await submit(page);
  }],
  // The reveal-once bearer: the only page that ever shows a secret.
  ['key-minted', async (page, ctx) => {
    await page.goto(ctx.base + '/users/bot%40example.com/keys/%2Badd');
    await page.fill('input[name=id]', 'demo');
    await page.fill('input[name=duration]', '90d');
    await submit(page);
  }],
  // The generic 409: a form rendered against bytes someone else has since replaced.
  ['conflict', async (page, ctx) => {
    await page.goto(ctx.base + '/groups/mcp/edit');
    const fields = await formBytes(page);
    const d = doc(ctx);
    d.denied.push('someone-else@example.com'); // an out-of-band `bb-auth-adm` write
    writeDoc(ctx, d);
    await resubmit(page, ctx.base + '/groups/mcp/edit', fields);
  }],
  // The mint-specific 409: a reloaded reveal page, which must not mint a second key.
  ['conflict-mint', async (page, ctx) => {
    await page.goto(ctx.base + '/users/bot%40example.com/keys/%2Badd');
    await page.fill('input[name=id]', 'demo');
    const fields = await formBytes(page);
    await submit(page);
    await resubmit(page, ctx.base + '/users/bot%40example.com/keys/%2Badd', fields);
  }],
  // The two refusals a browser can hit head-on, rendered as pages.
  ['not-found', go('/users/nobody%40example.com')],
  ['forbidden', async (page, ctx) => {
    // A Cognito identity that is not on BB_AUTH_WEB_ADMINS: authenticated, not an admin.
    await page.setExtraHTTPHeaders({ 'X-Auth-Email': 'friend@example.com' });
    await page.goto(ctx.base + '/');
    await page.setExtraHTTPHeaders({ 'X-Auth-Email': 'admin@example.com' });
  }],
];

/**
 * The states a plain `goto` cannot photograph: what the pointer and the keyboard do to a
 * control. They live here rather than in a scratch script per review because they are
 * needed every time the chrome is touched, and a hover rule nobody ever looked at is a
 * hover rule nobody can vouch for.
 *
 * Only the `light` and `dark` views run these (see `VIEWS[].states`): every one of them
 * is a colour, and a phone has no pointer to hover with.
 */
const STATES = [
  // A row action, hovered: `remove` must part company with `edit` before the click.
  // Reached structurally (last cell of the first row), not by the group's class name, so
  // renaming the CSS object these live in cannot silently turn this state into a SKIP.
  ['hover-row-remove', async (page, ctx) => {
    await page.goto(ctx.base + '/users');
    await page.hover('tbody tr:first-child td:last-child a:last-of-type');
  }],
  ['hover-row-edit', async (page, ctx) => {
    await page.goto(ctx.base + '/users');
    await page.hover('tbody tr:first-child td:last-child a:first-of-type');
  }],
  // The row itself, and the creating action above it.
  ['hover-table-row', async (page, ctx) => {
    await page.goto(ctx.base + '/users');
    await page.hover('tbody tr:nth-child(2) td:first-child');
  }],
  ['hover-add', async (page, ctx) => {
    await page.goto(ctx.base + '/users');
    await page.hover('p.primary a');
  }],
  // The other two members of the pill family: a form's way out, and the header's one
  // non-tab control. They share one object with the row actions above, so the three hovers
  // are only ever right or wrong together, which is the point of photographing all three.
  ['hover-cancel', async (page, ctx) => {
    await page.goto(ctx.base + '/users/%2Badd');
    await page.hover('main form .actions a');
  }],
  ['hover-settings', async (page, ctx) => {
    await page.goto(ctx.base + '/users');
    await page.hover('details.settings > summary');
  }],
  // The list box, which is the one control type the GUI gained with the Settings menu and
  // the only one that lives on no page a `goto` can reach. Its hovered sibling, the Apply
  // button, is deliberately not here: no `button` in this stylesheet has a hover rule, so
  // there would be nothing in the frame to look at.
  ['focus-select', async (page, ctx) => {
    await page.goto(ctx.base + '/users');
    await page.click('details.settings > summary');
    await tabTo(page, '.menu select[name=lang]');
  }],
  // A dashboard count: four of the five navigate, and must say so on hover.
  ['hover-card', async (page, ctx) => {
    await page.goto(ctx.base + '/');
    await page.hover('a.card');
  }],
  // The focus ring, reached the way a keyboard user reaches it.
  ['focus-nav', async (page, ctx) => {
    await page.goto(ctx.base + '/users');
    await tabTo(page, 'nav a');
  }],
  ['focus-input', async (page, ctx) => {
    await page.goto(ctx.base + '/users/%2Badd');
    await tabTo(page, 'input[name=email]');
  }],
  ['focus-submit', async (page, ctx) => {
    await page.goto(ctx.base + '/users/%2Badd');
    await tabTo(page, 'main form button[type=submit]');
  }],
];

/** The scenes a view runs: its own `only` list, minus anything the CLI filtered out. */
function scenesFor(view, filters) {
  const all = view.states === true ? [...SCENES, ...STATES] : SCENES;
  const mine = view.only ? all.filter(([n]) => view.only.includes(n)) : all;
  return filters.length ? mine.filter(([n]) => filters.some((f) => n.includes(f))) : mine;
}

async function main() {
  const filters = process.argv.slice(2);
  const known = [...SCENES, ...STATES].map(([n]) => n);
  if (filters.length && !known.some((n) => filters.some((f) => n.includes(f)))) {
    console.error(`no scene matches ${filters.join(' ')}. Known: ${known.join(', ')}`);
    process.exit(1);
  }

  fs.rmSync(OUT, { recursive: true, force: true });
  const { ctx, stop } = await boot();
  let shot = 0;
  const failed = [];
  try {
    for (const view of VIEWS) {
      const scenes = scenesFor(view, filters);
      if (!scenes.length) continue;
      const dir = path.join(OUT, view.tag);
      fs.mkdirSync(dir, { recursive: true });
      const context = await ctx.browser.newContext({
        viewport: view.viewport,
        colorScheme: view.colorScheme,
        deviceScaleFactor: 2, // legible when a human zooms in on a 1-pixel border
        extraHTTPHeaders: { 'X-Auth-Email': 'admin@example.com' },
        // Only the `noscript` view sets this; everywhere else it is Playwright's default.
        javaScriptEnabled: view.javaScriptEnabled !== false,
      });
      const page = await context.newPage();
      // Language and theme are cookies the server sets on a `?lang=` / `?theme=`
      // redirect, so one visit each arms every scene below: the same door a human uses,
      // not a fabricated cookie.
      if (view.lang) await page.goto(`${ctx.base}/?lang=${view.lang}`);
      if (view.theme) await page.goto(`${ctx.base}/?theme=${view.theme}`);
      for (const [name, steps] of scenes) {
        fs.copyFileSync(FIXTURE, ctx.usersFile); // every scene starts from the fixture
        // One scene that cannot reach its state (a selector the markup no longer has,
        // typically) must not cost the other hundred their screenshot: this is evidence
        // for a human, not an assertion, so it degrades instead of aborting. The exit
        // code still says something went wrong.
        try {
          await steps(page, ctx);
          await page.screenshot({ path: path.join(dir, `${name}.png`), fullPage: true });
          console.log(`  ${view.tag.padEnd(6)} ${name}`);
          shot++;
        } catch (e) {
          failed.push(`${view.tag}/${name}: ${e.message.split('\n')[0]}`);
          console.log(`  ${view.tag.padEnd(6)} ${name}  SKIPPED`);
        }
      }
      await context.close();
    }
  } finally {
    await stop();
  }
  console.log(`\n${shot} screenshots -> ${OUT}`);
  if (failed.length) {
    console.error(`\n${failed.length} scene(s) could not be reached:`);
    for (const f of failed) console.error(`  ${f}`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error('FATAL:', e.stack || e.message);
  process.exit(1);
});
