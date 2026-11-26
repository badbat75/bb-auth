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

const { E2E_DIR, FIXTURE, SETTINGS_FIXTURE, boot } = require('./lib/server');
const { submit, formBytes, resubmit, writeDoc, doc, setDuration, openPreferences } = require('./lib/harness');
const { profileSettingsBytes, PROFILE_HEADERS } = require('./lib/cognito');
const { DELETE } = require('./lib/intake');

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
    only: ['dashboard', 'users', 'denied', 'apps', 'app-detail', 'can-authorized',
      'can-denied', 'can-on-a-person', 'user-rm', 'key-minted', 'error-refused', 'conflict',
      'conflict-mint', 'forbidden', 'settings-menu', 'config-landing-refused',
      // The account panel is the copy of this slice: its rows are translated words, and the
      // Italian spellings are the long ones that stress the bar's one row (§13.28 §4).
      'settings-menu-prefs', 'config-menu', 'forbidden-menu', 'account-menu-prefs',
      // The self-service page is prose a person reads in their own language, so the copy of
      // the table's headings and the refusal is worth reading in Italian too.
      'account', 'account-new', 'account-new-scopes', 'account-error', 'account-rm', 'account-menu',
      // The profile edit is all prose (section 13.23, and §13.25 and §13.26 for what it acts
      // on): every shape of it is read in Italian too.
      'account-profile', 'account-profile-edit', 'account-profile-nothing',
      'account-profile-code', 'account-profile-code-wrong', 'account-profile-saved',
      'account-profile-expired', 'account-profile-gone', 'account-profile-provider',
      'account-profile-notyours', 'account-profile-noanswer', 'account-profile-unsure',
      // The deletion is the prose of this slice: the page that asks lists what goes, and the
      // outcome pages are the ones a person reads in the worst minute of their day, so every
      // one of them is read in Italian too (§13.30 §5).
      'account-menu-delete', 'account-delete', 'account-delete-stranger',
      'account-delete-typed-wrong', 'account-delete-protected', 'account-delete-queued',
      'account-delete-partial', 'account-delete-unsure', 'account-delete-some',
      'account-delete-changed'],
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

/** The self-service page is reached by a person who is **not** on `web.admins`, so a scene
 *  that walks it swaps the identity header for one of the roster's own and puts the
 *  administrator back afterwards: every scene of a view shares one browser context, and a
 *  scene that left `you@example.com` in place would render the next one's console as a 403. */
const asPerson = (page) => page.setExtraHTTPHeaders({ 'X-Auth-Email': 'you@example.com' });
const asAdmin = (page) => page.setExtraHTTPHeaders({ 'X-Auth-Email': 'admin@example.com' });
/** The fixture's delete row: two addresses, one API key, a place in `@staff`. The deletion
 *  scenes swap to it for the same reason `asPerson` exists, and for one more: the page that
 *  asks has to have a keys line and a groups line to photograph, and two addresses to say
 *  "any one of these" about. */
const asCaller = (page) => page.setExtraHTTPHeaders({
  'X-Auth-Email': 'person@example.com person@legacy.example.com',
});
/** A path under the self-service prefix, which is a sibling of the console's base (§13). */
const acct = (ctx, p) => `${ctx.origin}/account${p}`;

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

/**
 * A profile scene (docs/ARCHITECTURE.md section 13.23, and §13.25 for what the edit acts on).
 * The settings that offer the edit are written, the fake Cognito is emptied and the browser
 * carries the identity nginx would send plus the profile claims it would forward; `who` is the
 * identity header's value, and `headers` the whole set, so a scene can drop
 * `X-Auth-Native-Username` and be a federated session. The administrator is put back
 * afterwards, because a view's scenes share one browser context.
 */
const profileScene = (steps, who = 'you@example.com', headers = PROFILE_HEADERS) => async (page, ctx) => {
  fs.writeFileSync(ctx.settingsFile, profileSettingsBytes());
  ctx.cognito.reset();
  await page.setExtraHTTPHeaders({ ...headers, 'X-Auth-Email': who });
  try {
    await steps(page, ctx);
  } finally {
    await asAdmin(page);
  }
};
/** The claims of a session with no Cognito user to write to (§13.25 step 1): nginx forwarded
 *  the profile and no `X-Auth-Native-Username`, because the person signed in with a provider. */
const NO_NATIVE = Object.fromEntries(
  Object.entries(PROFILE_HEADERS).filter(([k]) => k !== 'X-Auth-Native-Username'),
);
/** The pool's answer to a start, naming a user who is **not** the session's (§13.25 (3)). */
const challengeForOther = (username) => ({
  status: 200,
  body: {
    ChallengeName: 'EMAIL_OTP',
    Session: 'fake-session-1',
    ChallengeParameters: { USERNAME: username, CODE_DELIVERY_DESTINATION: 'y***@e***.com' },
  },
});
/** Change the given name, empty the family name, and send the code: the code page follows. */
const sendChanges = async (page, ctx) => {
  await page.goto(acct(ctx, '/profile'));
  await page.fill('input[name=given_name]', 'Augusta');
  await page.fill('input[name=family_name]', '');
  await submit(page, 'form[action="/account/profile"] button[type=submit]');
};
/** The code page, then a code typed and saved. */
const sendCode = async (page) => {
  await page.fill('form[action="/account/profile/code"] input[name=code]', '123456');
  await submit(page, 'form[action="/account/profile/code"] button[type=submit]');
};

const SCENES = [
  // ---- the read-only inventory -------------------------------------------
  ['dashboard', go('/')],
  ['groups', go('/groups')],
  ['apps', go('/apps')],
  // The application detail page: the one place the scopes appear in file order, with the
  // reorder buttons that make that order editable.
  ['app-detail', go('/apps/app1')],
  ['denied', go('/denied')],
  ['users', go('/users')],
  ['user-detail', go('/users/bot%40example.com')],
  // The access check, which is a section of the two pages above rather than a page: on an
  // application it takes both halves of the question and its url field starts on the area's
  // own base; on a person the identity is the page and only the url is asked. Both verdicts
  // are photographed, because granted and refused are two different panels.
  ['can-authorized', go('/apps/app1?email=you%40example.com&url=https%3A%2F%2Fapp.example.com%2Fapp1%2Fadmin%2Fpanel')],
  ['can-denied', go('/apps/app1?email=spammer%40example.com&url=https%3A%2F%2Fapp.example.com%2Fapp1')],
  ['can-on-a-person', go('/users/you%40example.com?url=https%3A%2F%2Fapp.example.com%2Fapp1%2Fadmin%2Fpanel')],

  // The audit, which is the one page whose content this GUI cannot produce: the gate writes
  // that file. So the scene lays one down first, of four rows that differ in the ways the
  // table has to keep legible — a sign-in naming its provider, a refusal naming a scope and a
  // reason, a key acting as the row it belongs to, and a sign-out, which is neither. Three of
  // them carry where they came from, the way a gate with both audit headers configured writes
  // them, and one does not, which is what a row from before that looks like.
  ['audit', async (page, ctx) => {
    const ago = (s) => Math.floor(Date.now() / 1000) - s;
    const from = (ip, ua, rid) => ({ ip, ua, rid });
    const safari = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 ' +
      '(KHTML, like Gecko) Version/17.6 Safari/605.1.15';
    const rows = [
      { v: 1, ts: ago(4000), kind: 'access_refused', cred: { type: 'key', id: 'laptop' },
        uuid: 'b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d', app: 'app1', scope: 'admin',
        url: 'https://app.example.com/app1/admin/panel', reason: 'key_out_of_scope',
        ...from('198.51.100.23', 'claude-code/2.1.0', '0b6e3c2a9f8d4e1b7c5a3f2e1d0c9b8a') },
      { v: 1, ts: ago(2400), kind: 'login_refused', cred: { type: 'anonymous' },
        reason: 'token_invalid' },
      { v: 1, ts: ago(1200), kind: 'login_ended', cred: { type: 'session' },
        subject: 'you@example.com', url: 'https://app.example.com/app1',
        ...from('2001:db8:4f::1c', safari, '7d2a0e9c1b3f4a5e8d6c2b1a0f9e8d7c') },
      { v: 1, ts: ago(300), kind: 'login_granted', cred: { type: 'social', provider: 'Google' },
        subject: 'newcomer@example.com', url: 'https://app.example.com/app1',
        sub: '9d8e7f60-1a2b-4c3d-8e9f-0a1b2c3d4e5f',
        ...from('203.0.113.7', safari, '5f1c0a9e7b2d4c3a8e6f1b0d9c7a5e3f') },
    ];
    fs.writeFileSync(ctx.auditFile, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
    await page.goto(ctx.base + '/audit');
  }],

  // ---- the forms ---------------------------------------------------------
  ['user-add', go('/users/%2Badd')],
  ['user-edit', go('/users/you%40example.com/edit')],
  ['key-add', go('/users/bot%40example.com/keys/%2Badd')],
  ['key-edit', go('/users/bot%40example.com/keys/laptop/edit')],
  ['app-add', go('/apps/%2Badd')],
  ['app-edit', go('/apps/app1/edit')],
  // The scope form is the richest one in the GUI, so it is photographed on a scope that
  // fills every control: `admin` is restricted, names a group, excludes somebody and ticks
  // one credential class.
  ['scope-edit', go('/apps/app1/scopes/admin/edit')],
  ['group-edit', go('/groups/admins/edit')],
  ['deny-add', go('/denied/%2Badd')],

  // The other file. One page, one form, and the two shapes worth looking at: as it reads,
  // and refusing a save. It is last in the bar and last here.
  ['config', go('/config')],
  ['config-refused', async (page, ctx) => {
    // Opened first: the page starts folded, and a refusal is photographed next to its field.
    await page.goto(ctx.base + '/config?groups=open');
    await page.fill('textarea[name=admins]', 'somebody@else.example.com');
    await submit(page);
  }],
  ['config-landing-refused', async (page, ctx) => {
    await page.goto(ctx.base + '/config?groups=open');
    await page.fill('input[name=landing_url]', 'https://evil.example.org/account/');
    await submit(page);
  }],

  // The Settings menu, open. A scene and not a state: what is inside it is prose (so the
  // `it` view has to see it) and a 230px panel hanging off the right edge (so the phone
  // does). It is the one page shape a `goto` cannot reach, because `details` remembers
  // nothing across a navigation.
  ['settings-menu', async (page, ctx) => {
    await page.goto(ctx.base + '/users');
    await page.click('details.settings > summary');
  }],
  // The same panel with the nested Preferences box open (§13.28 §2): the box is closed by
  // default, so the two list boxes and the console's Apply are a state of their own.
  ['settings-menu-prefs', async (page, ctx) => {
    await page.goto(ctx.base + '/users');
    await openPreferences(page);
  }],
  // The panel on the Settings page, where its System settings row is the current page. The
  // tab is gone from the bar, so this row is the only thing that says where the person is.
  ['config-menu', async (page, ctx) => {
    await page.goto(ctx.base + '/config');
    await page.click('details.settings > summary');
  }],
  // The bar with the widest brand an operator can type and a logo present (§13.28 §4, §6):
  // the one page shape that shows what the bar cuts when it runs out of room.
  ['header-logo', async (page, ctx) => {
    // The runner puts the fixture back before every scene, so this writes and walks away.
    const s = JSON.parse(SETTINGS_FIXTURE);
    s.ui = { ...(s.ui || {}), brand_name: 'BadBat75 Operations Console', logo_url: '/img/logo.png' };
    fs.writeFileSync(ctx.settingsFile, JSON.stringify(s, null, 2) + '\n');
    await page.goto(ctx.base + '/users');
  }],

  // ---- the confirmations: a GET that changes nothing ----------------------
  ['user-rm', go('/users/bot%40example.com/rm')],
  ['key-rm', go('/users/bot%40example.com/keys/laptop/rm')],
  ['app-rm', go('/apps/app1/rm')],
  ['scope-rm', go('/apps/app1/scopes/admin/rm')],

  // ---- the self-service page (§13.16) ------------------------------------
  // The keys table, the row that opens below it, the refusal that keeps the row, and the
  // revoke card. Each mints its own key first: the fixture's caller has none, and an empty
  // section photographs as a sentence, which is the other shape and is worth one shot too.
  ['account', async (page, ctx) => {
    await asPerson(page);
    await page.goto(acct(ctx, '/keys/new'));
    await page.fill('input[name=id]', 'demo');
    await submit(page);
    await page.goto(acct(ctx, '/'));
    await asAdmin(page);
  }],
  // The account menu, open: the panel that carries the Preferences box on the surface a person
  // who is not an administrator reaches.
  ['account-menu', async (page, ctx) => {
    await asPerson(page);
    await page.goto(acct(ctx, '/'));
    await page.click('details.settings > summary');
    await asAdmin(page);
  }],
  // The same panel with its Preferences box open: this surface shows its Apply always, and
  // the box is the only thing that hides it from a review.
  ['account-menu-prefs', async (page, ctx) => {
    await asPerson(page);
    await page.goto(acct(ctx, '/'));
    await openPreferences(page);
    await asAdmin(page);
  }],
  ['account-new', async (page, ctx) => {
    await asPerson(page);
    await page.goto(acct(ctx, '/keys/new'));
    await asAdmin(page);
  }],
  // A caller who has a scope to narrow to (bot@example.com reaches `mcp/api` and more), so the
  // scope radios and the ticks beneath them get photographed. The fixture's `you@example.com`
  // has none, and its form carries a hidden `restrict=all` instead. The scene throws when
  // there is nothing to photograph, so a fixture that loses the scopes is SKIPPED, not green.
  ['account-new-scopes', async (page, ctx) => {
    await page.setExtraHTTPHeaders({ 'X-Auth-Email': 'bot@example.com' });
    try {
      await page.goto(acct(ctx, '/keys/new'));
      const radios = await page.locator('input[name=restrict][type=radio]').count();
      const ticks = await page.locator('input[name=scope]').count();
      if (radios !== 2 || ticks < 1) {
        throw new Error(`no scope radios to photograph (radios=${radios}, scopes=${ticks})`);
      }
    } finally {
      await asAdmin(page);
    }
  }],
  ['account-error', async (page, ctx) => {
    await asPerson(page);
    await page.goto(acct(ctx, '/keys/new'));
    await page.fill('input[name=id]', 'My Laptop');
    await submit(page);
    await asAdmin(page);
  }],
  ['account-rm', async (page, ctx) => {
    await asPerson(page);
    await page.goto(acct(ctx, '/keys/new'));
    await page.fill('input[name=id]', 'demo');
    await submit(page);
    await page.goto(acct(ctx, '/'));
    await page.click('a[href*="/account/keys/remove"]');
    await asAdmin(page);
  }],

  // ---- the self-service deletion (§13.30): ten shapes ---------------------------------
  // The row that opens the walk, the page that asks, and every outcome page the intake can
  // leave a person on. The caller is the fixture's delete row (`person@example.com`, two
  // addresses, one key, a place in `@staff`), because the page that asks has to have a keys
  // line, a groups line and the "any of these addresses" arm to photograph.
  ['account-menu-delete', async (page, ctx) => {
    await asCaller(page);
    await page.goto(acct(ctx, '/'));
    await page.click('details.settings > summary');
    await asAdmin(page);
  }],
  ['account-delete', async (page, ctx) => {
    await asCaller(page);
    await page.goto(acct(ctx, '/delete'));
    await asAdmin(page);
  }],
  // A caller the file has no row for: the page answers with one fact and no uuid, because
  // the sign-in accounts are theirs and the record is nobody's.
  ['account-delete-stranger', async (page, ctx) => {
    await page.setExtraHTTPHeaders({ 'X-Auth-Email': 'friend@example.com' });
    await page.goto(acct(ctx, '/delete'));
    await asAdmin(page);
  }],
  // The in-context refusal: the typed address is not one of this account, so the page that
  // asked comes back with the value kept and the field marked.
  ['account-delete-typed-wrong', async (page, ctx) => {
    await asCaller(page);
    await page.goto(acct(ctx, '/delete'));
    await page.fill('form[action="/account/delete"] input[name=confirm_email]', 'nobody@example.com');
    await submit(page);
    await asAdmin(page);
  }],
  // The intake says this account is locked, ahead of any write, so nothing has gone.
  ['account-delete-protected', async (page, ctx) => {
    await asCaller(page);
    ctx.intake.setProtected(['person@legacy.example.com']);
    await page.goto(acct(ctx, '/delete'));
    await page.fill('form[action="/account/delete"] input[name=confirm_email]', 'person@example.com');
    await submit(page);
    await asAdmin(page);
  }],
  // Everything accepted: the row is gone and the accounts are queued, which is all this page
  // can say. The sign out is its one action.
  ['account-delete-queued', async (page, ctx) => {
    await asCaller(page);
    await page.goto(acct(ctx, '/delete'));
    await page.fill('form[action="/account/delete"] input[name=confirm_email]', 'person@example.com');
    await submit(page);
    await asAdmin(page);
  }],
  // The first queue refused, after the row already went: the page has to say both.
  ['account-delete-partial', async (page, ctx) => {
    await asCaller(page);
    ctx.intake.inOrder('POST', DELETE, [{ status: 503 }, { status: 202, json: { ok: true, status: 'accepted' } }]);
    await page.goto(acct(ctx, '/delete'));
    await page.fill('form[action="/account/delete"] input[name=confirm_email]', 'person@example.com');
    await submit(page);
    await asAdmin(page);
  }],
  // The intake gave no answer, so the page cannot say whether anything is queued.
  ['account-delete-unsure', async (page, ctx) => {
    await asCaller(page);
    ctx.intake.script('POST', DELETE, { close: true });
    await page.goto(acct(ctx, '/delete'));
    await page.fill('form[action="/account/delete"] input[name=confirm_email]', 'person@example.com');
    await submit(page);
    await asAdmin(page);
  }],
  // One address queued and one refused: the page names the addresses it cannot confirm, which
  // is the fact the person has no way to check for themselves.
  ['account-delete-some', async (page, ctx) => {
    await asCaller(page);
    ctx.intake.inOrder('POST', DELETE, [{ status: 202, json: { ok: true, status: 'accepted' } }, { status: 503 }]);
    await page.goto(acct(ctx, '/delete'));
    await page.fill('form[action="/account/delete"] input[name=confirm_email]', 'person@example.com');
    await submit(page);
    await asAdmin(page);
  }],
  // The file moved under the page (a `bb-auth-adm` over SSH), so the press posts nothing.
  ['account-delete-changed', async (page, ctx) => {
    await asCaller(page);
    await page.goto(acct(ctx, '/delete'));
    const fields = await formBytes(page);
    const d = doc(ctx);
    d.users.find((u) => (u.emails || []).includes('bot@example.com')).notes = 'moved out of band';
    writeDoc(ctx, d);
    await resubmit(page, `${ctx.origin}/account/delete`, fields);
    await asAdmin(page);
  }],

  // ---- the profile edit (section 13.23, §13.25, §13.26): twelve shapes -------------------
  ['account-profile', profileScene(async (page, ctx) => { await page.goto(acct(ctx, '/')); })],
  // The form of a native session: one identity, and the address is not a field (§13.26 §4).
  ['account-profile-edit', profileScene(async (page, ctx) => {
    await page.goto(acct(ctx, '/profile'));
  })],
  ['account-profile-nothing', profileScene(async (page, ctx) => {
    await page.goto(acct(ctx, '/profile'));
    await submit(page, 'form[action="/account/profile"] button[type=submit]');
  })],
  ['account-profile-code', profileScene(sendChanges)],
  ['account-profile-code-wrong', profileScene(async (page, ctx) => {
    await sendChanges(page, ctx);
    ctx.cognito.script([['RespondToAuthChallenge', {
      status: 400, body: { __type: 'CodeMismatchException', Session: 'fake-session-2' },
    }]]);
    await sendCode(page);
  })],
  ['account-profile-saved', profileScene(async (page, ctx) => {
    await sendChanges(page, ctx);
    await sendCode(page);
  })],
  ['account-profile-expired', profileScene(async (page, ctx) => {
    await sendChanges(page, ctx);
    ctx.cognito.script([['RespondToAuthChallenge', { status: 400, body: { __type: 'ExpiredCodeException' } }]]);
    await sendCode(page);
  })],
  // The pool no longer has the user the session names (§13.25: the request names it by
  // username, so this is a lost account, not a person who signs in some other way).
  ['account-profile-gone', profileScene(async (page, ctx) => {
    ctx.cognito.script([['InitiateAuth', { status: 400, body: { __type: 'UserNotFoundException' } }]]);
    await sendChanges(page, ctx);
  })],
  // A session with no Cognito user to write to: the page says so, and there is no form. It is
  // the shape a federated sign-in sees, and the one a scene cannot reach by POST.
  ['account-profile-provider', profileScene(async (page, ctx) => {
    await page.goto(acct(ctx, '/'));
  }, 'you@example.com', NO_NATIVE)],
  // The pool answered for a different user: the refusal, not a code step (§13.25 (3)).
  ['account-profile-notyours', profileScene(async (page, ctx) => {
    ctx.cognito.script([['InitiateAuth', challengeForOther('9b2f6d1c-7a44-4c1e-8f52-6d0c1b9e4a77')]]);
    await sendChanges(page, ctx);
  })],
  // The two silences each cost the binary's whole five-second bound.
  ['account-profile-noanswer', profileScene(async (page, ctx) => {
    ctx.cognito.script([['InitiateAuth', 'silent']]);
    await sendChanges(page, ctx);
  })],
  ['account-profile-unsure', profileScene(async (page, ctx) => {
    await sendChanges(page, ctx);
    ctx.cognito.script([['UpdateUserAttributes', 'silent']]);
    await sendCode(page);
  })],

  // ---- the states only a POST reaches ------------------------------------
  // The flash: a save, then the 303 lands on the page carrying ?msg=.
  ['flash-saved', async (page, ctx) => {
    await page.goto(ctx.base + '/groups/admins/edit');
    await submit(page);
  }],
  // The in-context refusal: the library's own words, the typed input preserved, 400.
  ['error-refused', async (page, ctx) => {
    await page.goto(ctx.base + '/users/%2Badd');
    await page.fill('input[name=email]', 'not-an-email');
    await submit(page);
  }],
  // The reveal-once bearer: the only page that ever shows a secret.
  ['key-minted', async (page, ctx) => {
    await page.goto(ctx.base + '/users/bot%40example.com/keys/%2Badd');
    await page.fill('input[name=id]', 'demo');
    await setDuration(page, '90d');
    await submit(page);
  }],
  // The generic 409: a form rendered against bytes someone else has since replaced.
  ['conflict', async (page, ctx) => {
    await page.goto(ctx.base + '/groups/admins/edit');
    const fields = await formBytes(page);
    const d = doc(ctx);
    d.denied.push('someone-else@example.com'); // an out-of-band `bb-auth-adm` write
    writeDoc(ctx, d);
    await resubmit(page, ctx.base + '/groups/admins/edit', fields);
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
    // A Cognito identity that is not on web.admins: authenticated, not an admin.
    await page.setExtraHTTPHeaders({ 'X-Auth-Email': 'friend@example.com' });
    await page.goto(ctx.base + '/');
    await page.setExtraHTTPHeaders({ 'X-Auth-Email': 'admin@example.com' });
  }],
  // The same refusal with its panel open (§13.28 §2): this caller has no places of the
  // console to reach, so the panel is who they are, their preferences, and the way out.
  ['forbidden-menu', async (page, ctx) => {
    await page.setExtraHTTPHeaders({ 'X-Auth-Email': 'friend@example.com' });
    try {
      await page.goto(ctx.base + '/');
      await page.click('details.settings > summary');
    } finally {
      await page.setExtraHTTPHeaders({ 'X-Auth-Email': 'admin@example.com' });
    }
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
  // The two surfaces where the text colour flips between the arms, which is what makes them
  // worth a frame each: a filled accent surface carries --on-accent, white on light and dark
  // on dark since 2026-08-19, and both of these are one. The tab is also the only pill whose
  // hover fill is photographed anywhere.
  ['hover-tab', async (page, ctx) => {
    await page.goto(ctx.base + '/users');
    // The bar's strip only: the panel's rows are `nav a` too, and they are in the DOM while
    // the panel is closed, so an unscoped selector is a strict-mode violation.
    await page.hover('header .bar > nav:not(.acct) a:not(.on)');
  }],
  ['hover-submit', async (page, ctx) => {
    await page.goto(ctx.base + '/users/%2Badd');
    await page.hover('main form button[type=submit]');
  }],
  // The list box, which is the one control type the GUI gained with the Settings menu and
  // the only one that lives on no page a `goto` can reach.
  ['focus-select', async (page, ctx) => {
    await page.goto(ctx.base + '/users');
    // Both disclosures: a closed `details` does not render its fields, so a Tab walk never
    // reaches a list box that is folded away (§13.28 §2).
    await openPreferences(page);
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
        // Every scene starts from the fixture, both files: the settings scenes write to
        // the second one exactly as the others write to the first. The audit starts absent,
        // and the one scene that wants rows lays them down itself.
        fs.copyFileSync(FIXTURE, ctx.accessFile);
        fs.writeFileSync(ctx.settingsFile, SETTINGS_FIXTURE);
        fs.rmSync(ctx.auditFile, { force: true });
        ctx.cognito.reset();
        // The deletion fake forgets both what the last scene asked and what it was told to
        // answer: the scripted answers are per scene, and a `503` that outlived its scene
        // would paint the next page with the last scene's outcome.
        ctx.intake.reset();
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
