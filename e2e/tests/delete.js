'use strict';
// The self-service deletion (docs/ARCHITECTURE.md §13.30), walked in a real browser against
// the loopback intake fake (lib/intake.js). The Rust suite drives the same contract with
// `FakeIntake` over a socket; this area is the only place a whole delete walk happens in a
// browser, which is where the half-states live: the page a `503` answers after the roster
// row already went, the page that says *some* addresses are queued and lists the ones it
// cannot confirm, the page a protected address is refused on, the page an intake that
// stopped answering leaves the person with.
//
// What is asserted, in the order the walk meets it: the menu's last row (§13.28 §5, §13.30
// §1); the confirmation page's facts list, field and hidden uuid (§13.30 §2); the typed
// address as the confirmation, refused with the page kept and nothing sent (§13.30 §3); the
// success walk, where the row goes **before** the first `POST` and every address of the
// header is queued in the header's order (§13.29 W3), and which completes with the `303`
// through the gate's logout of §13.32 §1, asserted as the redirect itself: this harness has
// no gate behind `/auth/logout`, so following it lands on the console's 403, and the notice
// the redirect names is the gate's page, pinned in Rust; the stale page as a `409` that
// posts nothing; each outcome page of §13.30 §4 in its own words; and the keyboard walk,
// because the row that costs an account has to be reachable by Enter alone.
//
// The file is the source of truth as everywhere else: after every walk the assertions read
// `doc(ctx)`, so "nothing was deleted" is a fact about the file and not about a sentence.
// Each check restores the fixture and the fake, so the destructive ones do not reorder the
// rest of the area.

const fs = require('fs');

const {
  doc, bytes, writeDoc, api, submit, resubmit, formBytes, newPage, mainText,
  barStaysOneRow, barGeometry, attr, text, count, prop,
} = require('../lib/harness');
const { FIXTURE } = require('../lib/server');
const { WHOAMI, DELETE } = require('../lib/intake');

// The caller of the fixture's delete row: two addresses, one API key, a place in `@staff`,
// and in no scope. That is what gives the confirmation page a keys line, a groups line and
// the "any of these addresses" arm, and what makes deleting the row sweep something.
const WHO = 'person@example.com';
const LEGACY = 'person@legacy.example.com';
const TWO = `${WHO} ${LEGACY}`;
const UUID = 'a7c1e9d4-2b6f-4c81-9d3a-5e0b7f2c6a19';
// A caller the file has no row for: an `authenticated` scope admits them, and their deletion
// is the pool's alone, so their page names no record and their walk writes no file.
const STRANGER = 'friend@example.com';
// A roster caller with **one** address and no keys: the arm of every outcome page that
// speaks of "the address you signed in with" and says nothing about the others.
const SOLO = 'you@example.com';

const PAGE = '/account/';
const DEL = '/account/delete';
const FORM = 'form[action="/account/delete"]';
const FIELD = `${FORM} input[name=confirm_email]`;
const SUBMIT = `${FORM} button[type=submit]`;
const CANCEL = `${FORM} a.pill[href="/account/"]`;
const MENU = 'details.settings';
const ROW = '.menu a.pill.rm';
// The e2e server always names a logout URL, so every page that ends in Sign out has one.
const OUT = '/auth/logout';
// §13.32 §1: a completed deletion on a deployment with a logout URL answers a `303` to the
// gate's logout, with the gate's sign-in page (and its deletion notice) as the round trip,
// and renders no page. This harness has no gate behind `/auth/logout`, so these walks assert
// the redirect and stop: following it lands on the console's 403, and the notice is the
// gate's page, pinned in Rust (`the_sign_in_page_shows_the_deletion_notice_only_for_its_code`).
const DONE_REDIRECT = '/auth/logout?rd=%2Fauth%2Flogin%3Fnotice%3Daccount-deleted';

/** The English words of the `K` table, verbatim, so a rewording is a red test and not a
 *  green one that stopped matching what a person reads. */
const W = {
  menu: 'Delete account and all its data',
  title: 'Delete your account',
  lead: 'This cannot be undone. To confirm, type your email address below and press Delete my account.',
  goes: 'What is deleted',
  record: 'Your bb-auth record, and every access an administrator gave you by name.',
  keys: 'Your API keys, which stop working within seconds:',
  groups: 'Your place in these groups:',
  one: 'Every sign-in account with this email address, whether you sign in with an emailed code or with a provider such as Google:',
  many: 'Every sign-in account with any of these email addresses, whether you sign in with an emailed code or with a provider such as Google:',
  later: 'The sign-in accounts are not deleted at once: they are queued for a separate deletion service.',
  auditSize: 'The record of your sign-ins and refusals is kept until newer entries replace it; this deployment keeps at most',
  typeLabel: 'Type your email address to confirm',
  hint: 'Any one of the addresses above.',
  confirm: 'Delete my account',
  cancel: 'cancel',
  back: '← back',
  typedWrong: "The email address typed is not one of this account's, so nothing was deleted. Type it as it is shown above.",
  gone: 'Your API keys and every access an administrator gave you by name are gone.',
  // Retired by plan step 14b (2026-11-26, §13.32 §1, §13.33 §3): a completed deletion answers
  // a `303` through the gate's logout, and the done page's heading and sentences moved to
  // the sign-in page's notice, which the Rust suite pins in both languages. The walks below
  // assert the redirect, not the page that used to carry them.
  signOut: 'Sign out',
  partial: 'Your account is only partly deleted',
  notQueued: 'Your sign-in accounts could not be queued for deletion, so they still exist. Try again later; if it fails again, tell an administrator.',
  some: 'The sign-in accounts of some of your addresses are queued for deletion; the others may not be.',
  unconfirmed: 'Addresses not confirmed as queued:',
  retryOne: 'Trying again covers only the address you signed in with; for the others, tell an administrator.',
  unsure: 'Your account may not be fully deleted',
  maybe: 'The deletion service did not answer, so your sign-in accounts may or may not be queued for deletion. Trying again is safe, even if they were.',
  notDone: 'Your account was not deleted',
  protected: 'This account cannot be deleted from this page, and nothing was deleted. If you want it deleted, ask an administrator.',
  noCheck: 'The deletion service did not answer as expected, so nothing was deleted and you can still sign in. Try again in a minute; if it fails again, tell an administrator.',
  retry: 'Try again',
  startAgain: 'Start again',
  changedTitle: 'Your account changed',
  changed: 'Your account changed after you opened this page, so nothing was deleted. Start again to see what would be deleted now.',
  // Retired by plan step 13 (2026-11-26), which deleted `K::AccountNoRow` with this sentence.
  // It is kept here, as the string of the assert at the end of the success walk, to pin that
  // the sentence never comes back on the page of a person who has no row.
  noRow: 'bb-auth has no roster row for you.',
  csrf: 'this POST did not come from a page of this site.',
};

/** The row's own state in the file, read straight off the bytes the gate would load. */
const rowOf = (ctx, email) => doc(ctx).users.find((u) => (u.emails || []).includes(email));
const keyIds = (ctx, email) => (rowOf(ctx, email)?.api_keys || []).map((k) => k.id);

/** Back to the pristine fixture and a fake that remembers nothing, so every check in this
 *  area starts from the same file and the destructive ones cost the rest of it nothing. */
const restore = (ctx) => {
  fs.copyFileSync(FIXTURE, ctx.accessFile);
  ctx.intake.reset();
};

/** The words of every `li` of the facts list, in the order the page writes them. */
const factLines = (page) => page.locator('div.panel.bad ul.plain li').allInnerTexts();
/** The pills of an outcome page, as `{text, href}`, in the order the page writes them. A row of
 *  two rides in `div.actions` for its gap, a single pill stays in `p.primary`, so the reader asks
 *  both and takes whichever holds them. */
const pills = async (page) => {
  const box = page.locator('main div.actions, main p.primary');
  if ((await box.count()) === 0) return [];
  return box.locator('a').evaluateAll((as) => as.map((a) => ({
    text: a.innerText.trim(),
    href: a.getAttribute('href'),
  })));
};
/** What the intake was asked, oldest first, each as `METHOD path <address>`. */
const asked = (ctx) => ctx.intake.callsMade().map((c) => `${c.method} ${c.path} ${c.email}`);
/** One tick, for a check that reads what the intake recorded out of a request body: the
 *  record exists the moment the request is seen, its fields land with the bytes. */
const settle = () => new Promise((r) => setTimeout(r, 50));
/** The words of the page a response carried, for a check that names nobody. */
const bodyOf = async (resp) => (await resp.text()).replace(/<[^>]*>/g, ' ');

module.exports = {
  async run(ctx, t) {
    const { origin } = ctx;
    const acct = (p) => `${origin}${p}`;
    /** Submit the delete form and hand back the response the POST **itself** got, without
     *  following it: a completed deletion answers a `303` (§13.32 §1), and the harness's
     *  `submit` follows the redirect onto this server's own 403, where no check lives. The
     *  predicate matches only the form's own `POST`, on this origin, never an intake call. */
    const submitPost = async (page) => {
      const [resp] = await Promise.all([
        page.waitForResponse((r) => r.url() === acct(DEL) && r.request().method() === 'POST'),
        page.click(SUBMIT),
      ]);
      return resp;
    };

    // ---- the row that opens the walk -------------------------------------------------

    {
      const { context, page } = await newPage(ctx, WHO);
      try {
        await page.goto(acct(PAGE));
        t.check('the page is the account page, not a 404 wearing the same bar',
          (await count(page, 'main p.lede')) > 0, `${await count(page, 'main p.lede')} ledes`);
        await page.click(`${MENU} > summary`);
        const shape = await page.locator('.menu').evaluate((m) => {
          const kids = [...m.children];
          const last = kids[kids.length - 1];
          const prev = kids[kids.length - 2];
          const svgs = last ? [...last.querySelectorAll('svg')] : [];
          return {
            last: last && {
              tag: last.tagName,
              cls: last.className,
              href: last.getAttribute('href'),
              text: last.innerText.trim(),
              glyphs: svgs.length,
              hidden: svgs.every((s) => s.getAttribute('aria-hidden') === 'true'),
            },
            before: prev && prev.className,
          };
        });
        t.eq('the menu ends in the delete link', shape.last && [shape.last.tag, shape.last.cls, shape.last.href],
          ['A', 'pill rm', DEL]);
        t.eq('its words name what the press costs', shape.last && shape.last.text, W.menu);
        t.eq('its glyph is decoration behind the word', shape.last && [shape.last.glyphs, shape.last.hidden], [1, true]);
        t.eq('a rule separates it from Sign out', shape.before, 'sep');
        t.eq('Sign out is the row before it', await text(page, '.menu a.pill[href="/auth/logout"]'), W.signOut);
        // The row is a link to the page that asks, never a submission: a browser prefetches the
        // last row of an open menu, and that must not cost a person their account. The panel
        // does carry a form (the Preferences box applies with a button), so what must be absent
        // is a form that reaches the delete.
        t.eq('the panel carries no form that posts the delete',
          await count(page, `.menu form[action="${DEL}"]`), 0);
        t.eq('and the row is one link', await count(page, ROW), 1);
      } finally {
        await context.close();
      }
    }
    {
      // The console's panel has no such row: this is what a person does to their own account,
      // and an administrator takes a roster row through the users page.
      const { context, page } = await newPage(ctx, 'admin@example.com');
      try {
        await page.goto(`${origin}/`);
        await page.click(`${MENU} > summary`);
        t.eq('the console menu has no delete row', await count(page, ROW), 0);
        t.eq('and the console serves no delete page', (await api(ctx, '/delete')).status, 404);
      } finally {
        await context.close();
      }
    }

    // ---- the confirmation page -------------------------------------------------------

    {
      const { context, page } = await newPage(ctx, TWO);
      try {
        await page.goto(acct(DEL));
        t.eq('the page is the delete page', await text(page, 'h1'), W.title);
        t.eq('and says up front that it cannot be undone', await text(page, 'main p.lede'), W.lead);
        t.eq('the page keeps its one lede', await count(page, 'main p.lede'), 1);
        t.eq('the facts are headed', await text(page, 'div.panel.bad p.lbl'), W.goes);
        const lines = await factLines(page);
        t.eq('the record, the keys, the groups, then the sign-in accounts', lines, [
          W.record,
          `${W.keys} phone`,
          `${W.groups} staff`,
          `${W.many} ${WHO}, ${LEGACY}`,
        ]);
        t.eq('the sign-in line is last, because it is the one that does not go at once',
          lines[lines.length - 1].startsWith(W.many), true);
        const muted = await page.locator('div.panel.bad p.muted').allInnerTexts();
        t.eq('the queue is said plainly', muted[0], W.later);
        // The settings fixture names no `audit` section, so this is the size arm: the default
        // policy keeps two files of `AUDIT_MAX_BYTES`, which is what `max_bytes` answers.
        t.eq('and so is how long the estate keeps what it recorded about this account',
          muted[1], `${W.auditSize} 8 MiB.`);
        t.eq('the form posts to the delete page', await attr(page, FORM, 'action'), DEL);
        t.eq('the row is carried as a hidden field, not in the path',
          await attr(page, `${FORM} input[name=uuid]`, 'value'), UUID);
        t.eq('the field asks for the address', await text(page, `${FORM} label span.lbl`), W.typeLabel);
        t.eq('it is a text field named for the wire', await attr(page, FIELD, 'type'), 'text');
        t.eq('it is required', await attr(page, FIELD, 'required'), '');
        t.eq('and asks for an address on a phone', await attr(page, FIELD, 'inputmode'), 'email');
        t.eq('the field is marked by its own class', await attr(page, FIELD, 'class'), 'f-email');
        t.eq('two addresses get the hint', await text(page, `${FORM} label span.hint`), W.hint);
        t.eq('the button names the press', await text(page, SUBMIT), W.confirm);
        t.eq('and is marked destructive', await attr(page, SUBMIT, 'class'), 'danger');
        t.eq('cancel is a link back to the page', await text(page, CANCEL), W.cancel);
        t.eq('nothing is focused on load',
          await page.evaluate(() => document.activeElement.tagName), 'BODY');
        t.eq('the page carries no script', await count(page, 'script'), 0);
        t.eq('no field is marked invalid before anything was typed',
          await attr(page, FIELD, 'aria-invalid'), null);
      } finally {
        await context.close();
      }
    }
    {
      // A caller the file has no row for: the page answers, because the sign-in accounts are
      // theirs, and it names no record, no keys and no groups.
      const { context, page } = await newPage(ctx, STRANGER);
      try {
        await page.goto(acct(DEL));
        t.eq('a stranger sees the page', await text(page, 'h1'), W.title);
        const lines = await factLines(page);
        t.eq('with one fact: the sign-in accounts', lines.length, 1);
        t.eq('naming the address they signed in with', lines[0], `${W.one} ${STRANGER}`);
        t.eq('one address, so no hint about picking one', await count(page, `${FORM} span.hint`), 0);
        t.eq('and no uuid to post, because the page says the file names nobody',
          await attr(page, `${FORM} input[name=uuid]`, 'value'), '');
      } finally {
        await context.close();
      }
    }

    // ---- the typed address is the confirmation ---------------------------------------

    {
      restore(ctx);
      const before = bytes(ctx);
      const { context, page } = await newPage(ctx, TWO);
      try {
        await page.goto(acct(DEL));
        await page.fill(FIELD, 'nobody@example.com');
        const resp = await submit(page);
        t.eq('an address that is not one of this account is refused', resp.status(), 400);
        const body = await mainText(page);
        t.check('the refusal says what is wrong with the address', body.includes(W.typedWrong),
          body.slice(0, 400));
        t.eq('the page that asked is kept', await text(page, 'h1'), W.title);
        t.eq('the typed value is kept in the field',
          await prop(page, FIELD, (i) => i.value), 'nobody@example.com');
        t.eq('the field is marked invalid', await attr(page, FIELD, 'aria-invalid'), 'true');
        t.eq('and points at the message', await attr(page, FIELD, 'aria-describedby'), 'form-error');
        t.eq('the message is the box above the fields', await text(page, 'div.err#form-error'), W.typedWrong);
        t.eq('the intake was asked nothing', asked(ctx), []);
        t.eq('and the file is the bytes it was', bytes(ctx), before);
      } finally {
        await context.close();
      }
    }
    {
      // The door ahead of every check: a `POST` that says it came from another site is
      // refused before the body is read, so a foreign form never reaches the intake.
      restore(ctx);
      const before = bytes(ctx);
      const resp = await api(ctx, DEL, {
        method: 'POST',
        email: TWO,
        headers: {
          'sec-fetch-site': 'cross-site',
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: `confirm_email=${WHO}&uuid=${UUID}&rev=deadbeef`,
      });
      t.eq('a cross-site POST is refused', resp.status, 403);
      const body = await bodyOf(resp);
      t.check('and says where a POST may come from', body.includes(W.csrf), body.slice(0, 400));
      t.eq('the intake was asked nothing', asked(ctx), []);
      t.eq('the row stands', rowOf(ctx, WHO) !== undefined, true);
      t.eq('and the file is the bytes it was', bytes(ctx), before);
    }

    // ---- cancel ----------------------------------------------------------------------

    {
      restore(ctx);
      const before = bytes(ctx);
      const { context, page } = await newPage(ctx, TWO);
      try {
        await page.goto(acct(DEL));
        await page.fill(FIELD, WHO);
        await page.click(CANCEL);
        await page.waitForLoadState('load');
        t.eq('cancel lands on the account page', new URL(page.url()).pathname, PAGE);
        t.eq('the intake was asked nothing', asked(ctx), []);
        t.eq('the row stands', rowOf(ctx, WHO) !== undefined, true);
        t.eq('the key stands', keyIds(ctx, WHO), ['phone']);
        t.eq('the group stands', doc(ctx).user_groups.staff, [UUID]);
        t.eq('and the file is the bytes it was', bytes(ctx), before);
      } finally {
        await context.close();
      }
    }

    // ---- the success walk ------------------------------------------------------------

    {
      restore(ctx);
      const { context, page } = await newPage(ctx, TWO);
      try {
        await page.goto(acct(DEL));
        await page.fill(FIELD, WHO);
        const resp = await submitPost(page);
        t.eq('the right address is accepted', resp.status(), 303);
        t.eq('through the gate logout, with the sign-in notice as the round trip: no page, so no words',
          await resp.headerValue('location'), DONE_REDIRECT);
        // The file: the row, its keys, and every reference to it.
        t.eq('the roster row is gone', rowOf(ctx, WHO), undefined);
        t.eq('its key went with it', keyIds(ctx, WHO), []);
        t.eq('the group it was in no longer names it', doc(ctx).user_groups.staff, []);
        t.eq('every other group is untouched', doc(ctx).user_groups.admins.length, 2);
        t.eq('and nobody else lost a key', keyIds(ctx, 'bot@example.com'), ['laptop', 'ci']);
        // The calls: every address asked before any is posted, then each posted, in the
        // header's order, each naming one address twice (the header and the form field).
        t.eq('the intake was asked about every address, then posted to each, in order',
          asked(ctx), [
            `GET ${WHOAMI} ${WHO}`,
            `GET ${WHOAMI} ${LEGACY}`,
            `POST ${DELETE} ${WHO}`,
            `POST ${DELETE} ${LEGACY}`,
          ]);
        // The record's form fields are filled as the body arrives, which is a tick after the
        // response lands, so a check that reads one waits for the bytes.
        await settle();
        t.eq('each POST names its address in the form as well as the header',
          ctx.intake.callsMade().filter((c) => c.method === 'POST').map((c) => c.form.confirm_email),
          [WHO, LEGACY]);
        const rawAfter = await (await api(ctx, PAGE, { email: TWO })).text();
        // Words the person reads, with the stylesheets stripped: the palette's own comments
        // spell `decide` and `opacity`, so a check on the raw bytes is a check on the CSS.
        const after = rawAfter.replace(/<style\b[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]*>/g, ' ');
        // Step 13: the page says nothing about a row it does not have. The deleted person reads
        // the same shape of page as everybody else: the addresses they sign in with, and no
        // sentence about the row, because the line under the addresses exists to name an account
        // id and there is none left to name.
        t.check('the account page afterwards says nothing about the row',
          !after.includes(W.noRow), after.slice(0, 400));
        t.check('and shows no account id', !after.includes('Account id'), after.slice(0, 400));
      } finally {
        await context.close();
      }
    }
    {
      // The stranger's walk: the same redirect, one effect short. The file is never opened
      // for writing, because there is no row to take.
      restore(ctx);
      const before = bytes(ctx);
      const { context, page } = await newPage(ctx, STRANGER);
      try {
        await page.goto(acct(DEL));
        await page.fill(FIELD, STRANGER);
        const resp = await submitPost(page);
        t.eq('a stranger is queued too', resp.status(), 303);
        t.eq('on the same redirect, because the sign-in accounts are theirs and the record is nobody\'s',
          await resp.headerValue('location'), DONE_REDIRECT);
        t.eq('the intake was asked once, then posted once', asked(ctx), [
          `GET ${WHOAMI} ${STRANGER}`,
          `POST ${DELETE} ${STRANGER}`,
        ]);
        t.eq('and the file is the bytes it was', bytes(ctx), before);
      } finally {
        await context.close();
      }
    }

    // ---- the page that says the file moved -------------------------------------------

    {
      restore(ctx);
      const { context, page } = await newPage(ctx, TWO);
      try {
        await page.goto(acct(DEL));
        const fields = await formBytes(page);
        // An out-of-band write, exactly as `bb-auth-adm` over SSH does it: a valid file, new
        // bytes, and a page that no longer describes it.
        const d = doc(ctx);
        d.users.find((u) => (u.emails || []).includes('bot@example.com')).notes = 'moved out of band';
        writeDoc(ctx, d);
        const resp = await resubmit(page, DEL, fields);
        t.eq('a page whose file moved is refused', resp.status(), 409);
        t.eq('with the page that says the account changed', await text(page, 'h1'), W.changedTitle);
        t.check('and the sentence that says nothing was deleted',
          (await mainText(page)).includes(W.changed), (await mainText(page)).slice(0, 400));
        t.eq('offering the way back in, and the way back', await pills(page), [
          { text: W.startAgain, href: DEL },
          { text: W.back, href: PAGE },
        ]);
        t.eq('the intake was asked nothing', asked(ctx), []);
        t.eq('the row stands', rowOf(ctx, WHO) !== undefined, true);
      } finally {
        await context.close();
      }
    }

    // ---- the intake says no ----------------------------------------------------------

    {
      // The protected list is the intake's, and `whoami` answers for it ahead of any write,
      // so nothing has gone when this page appears.
      restore(ctx);
      const before = bytes(ctx);
      ctx.intake.setProtected([LEGACY]);
      const { context, page } = await newPage(ctx, TWO);
      try {
        await page.goto(acct(DEL));
        await page.fill(FIELD, WHO);
        const resp = await submit(page);
        t.eq('a protected address is refused', resp.status(), 403);
        t.eq('on the page that says the account was not deleted', await text(page, 'h1'), W.notDone);
        const body = await mainText(page);
        t.check('in words that say nothing was deleted', body.includes(W.protected), body.slice(0, 400));
        t.check('and name no list, no address and no rule', !body.includes(LEGACY), body.slice(0, 400));
        t.eq('offering only the way back', await pills(page), [{ text: W.back, href: PAGE }]);
        t.eq('every address is asked before anything is written, so the walk stops at the first',
          asked(ctx), [`GET ${WHOAMI} ${WHO}`, `GET ${WHOAMI} ${LEGACY}`]);
        t.eq('the row stands', rowOf(ctx, WHO) !== undefined, true);
        t.eq('the key stands', keyIds(ctx, WHO), ['phone']);
        t.eq('and the file is the bytes it was', bytes(ctx), before);
      } finally {
        await context.close();
      }
    }
    {
      // `whoami` answered, in a way the contract does not read. Nothing was sent, so the
      // account stands, signing in still works, and the retry is the way forward.
      restore(ctx);
      const before = bytes(ctx);
      ctx.intake.script('GET', WHOAMI, { json: {} });
      const { context, page } = await newPage(ctx, TWO);
      try {
        await page.goto(acct(DEL));
        await page.fill(FIELD, WHO);
        const resp = await submit(page);
        t.eq('an unusable answer is refused', resp.status(), 502);
        t.eq('on the page that says the account was not deleted', await text(page, 'h1'), W.notDone);
        t.check('in the words that say nothing was deleted and signing in still works',
          (await mainText(page)).includes(W.noCheck), (await mainText(page)).slice(0, 400));
        t.eq('offering the retry and the way back', await pills(page), [
          { text: W.retry, href: DEL },
          { text: W.back, href: PAGE },
        ]);
        t.eq('the walk stops at the first address it cannot check', asked(ctx), [`GET ${WHOAMI} ${WHO}`]);
        t.eq('the row stands', rowOf(ctx, WHO) !== undefined, true);
        t.eq('and the file is the bytes it was', bytes(ctx), before);
      } finally {
        await context.close();
      }
    }

    // ---- the half-states, where the row has already gone ------------------------------

    {
      // The first `POST` refused: the row is already gone (it goes ahead of the first post),
      // so "your account was not deleted" would be false, and the page leads with what did go.
      restore(ctx);
      ctx.intake.inOrder('POST', DELETE, [{ status: 503 }, { status: 202, json: { ok: true, status: 'accepted' } }]);
      const { context, page } = await newPage(ctx, TWO);
      try {
        await page.goto(acct(DEL));
        await page.fill(FIELD, WHO);
        const resp = await submit(page);
        t.eq('a refused post is a 502', resp.status(), 502);
        t.eq('on the page that says the account is only partly deleted',
          await text(page, 'h1'), W.partial);
        const lede = await text(page, 'main p.lede');
        t.check('which leads with what did go, then says the accounts are not queued',
          lede.includes(W.gone) && lede.includes(W.notQueued), lede.slice(0, 400));
        t.check('and for two addresses says the retry reaches only one',
          lede.includes(W.retryOne), lede.slice(0, 400));
        t.eq('offering the retry and the sign out', await pills(page), [
          { text: W.retry, href: DEL },
          { text: W.signOut, href: OUT },
        ]);
        t.eq('the row went before the post', rowOf(ctx, WHO), undefined);
        t.eq('so the key went with it', keyIds(ctx, WHO), []);
        t.eq('and the intake was asked once, and stopped', asked(ctx), [
          `GET ${WHOAMI} ${WHO}`,
          `GET ${WHOAMI} ${LEGACY}`,
          `POST ${DELETE} ${WHO}`,
        ]);
        // The retry, from this page, over a row that is already gone: the confirmation page it
        // renders is the stranger's, and the walk over the header's addresses is the same walk.
        await page.click(`main div.actions a[href="${DEL}"], main p.primary a[href="${DEL}"]`);
        t.eq('the retry opens the page again', await text(page, 'h1'), W.title);
        // The facts list is the stranger's (no record, no keys, no group), and the sign-in line
        // is still the "any of these addresses" arm: the arm follows the addresses the header
        // named, not a roster row the file no longer has.
        t.eq('as a stranger, because the row is gone', await factLines(page),
          [`${W.many} ${WHO}, ${LEGACY}`]);
        await page.fill(FIELD, WHO);
        const again = await submitPost(page);
        t.eq('and the second attempt is accepted', again.status(), 303);
        t.eq('with the same redirect: the walk is complete, so there is no page left to claim anything',
          await again.headerValue('location'), DONE_REDIRECT);
        // Three posts in all: the one the first attempt lost, then both addresses queued by
        // the retry, which covers the whole header again.
        t.eq('the intake was posted to three times in all',
          asked(ctx).filter((c) => c.startsWith('POST')).length, 3);
      } finally {
        await context.close();
      }
    }
    {
      // The second address refused: some accounts are queued and this one is not, so the page
      // cannot speak of the accounts as a whole, and the addresses it cannot confirm are the
      // fact the person has no way to check.
      restore(ctx);
      ctx.intake.inOrder('POST', DELETE, [{ status: 202, json: { ok: true, status: 'accepted' } }, { status: 503 }]);
      const { context, page } = await newPage(ctx, TWO);
      try {
        await page.goto(acct(DEL));
        await page.fill(FIELD, WHO);
        const resp = await submit(page);
        t.eq('a second address refused is a 502', resp.status(), 502);
        t.eq('on the page that says the account is only partly deleted',
          await text(page, 'h1'), W.partial);
        const lede = await text(page, 'main p.lede');
        t.check('which says some are queued and the others may not be',
          lede.includes(W.gone) && lede.includes(W.some) && lede.includes(W.retryOne),
          lede.slice(0, 400));
        const muted = await text(page, 'main p.muted');
        t.check('and lists the addresses it cannot confirm', muted.startsWith(W.unconfirmed),
          muted.slice(0, 300));
        t.check('naming the refused one and every one after it', muted.includes(LEGACY), true);
        t.check('and not the one it queued', !muted.includes(WHO), muted.slice(0, 300));
        t.eq('offering the retry and the sign out', await pills(page), [
          { text: W.retry, href: DEL },
          { text: W.signOut, href: OUT },
        ]);
        t.eq('the walk stopped at the refusal', asked(ctx).filter((c) => c.startsWith('POST')).length, 2);
      } finally {
        await context.close();
      }
    }
    {
      // One address, so the page says nothing about the others: the retry covers the whole
      // account. The intake drops the connection, which is the client's "no answer".
      restore(ctx);
      ctx.intake.script('POST', DELETE, { close: true });
      const { context, page } = await newPage(ctx, SOLO);
      try {
        await page.goto(acct(DEL));
        await page.fill(FIELD, SOLO);
        const resp = await submit(page);
        t.eq('an intake that gives no answer is a 504', resp.status(), 504);
        t.eq('on the page that says the account may not be fully deleted',
          await text(page, 'h1'), W.unsure);
        const lede = await text(page, 'main p.lede');
        t.check('which says the record went and the accounts may or may not be queued',
          lede.includes(W.gone) && lede.includes(W.maybe), lede.slice(0, 400));
        t.check('and says nothing about other addresses, because there are none',
          !lede.includes(W.retryOne), lede.slice(0, 400));
        t.eq('offering the retry and the sign out', await pills(page), [
          { text: W.retry, href: DEL },
          { text: W.signOut, href: OUT },
        ]);
        t.eq('the row went', rowOf(ctx, SOLO), undefined);
      } finally {
        await context.close();
      }
    }

    // ---- the keyboard, and the width --------------------------------------------------

    {
      restore(ctx);
      const { context, page } = await newPage(ctx, TWO);
      try {
        await page.goto(acct(PAGE));
        t.eq('the page takes no focus on load',
          await page.evaluate(() => document.activeElement.tagName), 'BODY');
        await page.focus(`${MENU} > summary`);
        await page.keyboard.press('Enter');
        t.eq('Enter opens the account panel', await prop(page, MENU, (d) => d.open), true);
        // The panel's rows in tab order: Preferences, Sign out, Delete. The row that costs an
        // account is the last thing in it, and nothing after it, so hop to it and stop there.
        const focusOf = () => page.evaluate(() => {
          const el = document.activeElement;
          return { tag: el.tagName, href: el.getAttribute('href'), inMenu: !!el.closest('.menu') };
        });
        const seen = [];
        for (let i = 0; i < 8; i++) {
          await page.keyboard.press('Tab');
          seen.push(await focusOf());
          if (seen[seen.length - 1].href === DEL) break;
        }
        const del = seen.findIndex((s) => s.href === DEL);
        const out = seen.findIndex((s) => s.href === OUT);
        t.check('the delete row is reached by Tab alone', del >= 0, JSON.stringify(seen));
        t.check('Sign out comes before it', out >= 0 && out < del, JSON.stringify(seen));
        t.eq('every row hopped to is a row of the panel', seen.every((s) => s.inMenu), true);
        await page.keyboard.press('Tab');
        t.eq('and one more Tab leaves the panel, so the row is its last',
          (await focusOf()).inMenu, false);
        await page.keyboard.press('Shift+Tab');
        t.eq('and back on the row', (await focusOf()).href, DEL);
        await Promise.all([page.waitForNavigation(), page.keyboard.press('Enter')]);
        t.eq('and Enter opens the page it names', new URL(page.url()).pathname, DEL);
        // The page's own order: the field, the press, the way out.
        const order = [];
        for (let i = 0; i < 8; i++) {
          await page.keyboard.press('Tab');
          order.push(await page.evaluate(() => {
            const el = document.activeElement;
            return el.name || el.getAttribute('href') || el.tagName;
          }));
        }
        const field = order.indexOf('confirm_email');
        const press = order.indexOf('BUTTON');
        const cancel = order.indexOf(PAGE);
        t.check('Tab goes field, then the press, then cancel',
          field >= 0 && press > field && cancel > press, JSON.stringify(order));
      } finally {
        await context.close();
      }
    }
    {
      restore(ctx);
      const { context, page } = await newPage(ctx, TWO);
      try {
        // The bar carries the account menu on every page of this prefix, and this is the page
        // with the longest words in it, so it is the one to measure (§13.28 §4).
        await barStaysOneRow(t, page, origin, '/account/delete', 'the delete page', false);
      } finally {
        await context.close();
      }
    }
    {
      // The outcome page is the one a person reads on a phone with their account half gone, and
      // it is a `POST` response, so the bar is measured where the page is, at the narrowest
      // width, in both languages: the language cookie is armed by a visit first, which is the
      // door a person uses, and the walk that follows lands on the page itself.
      for (const lang of ['en', 'it']) {
        restore(ctx);
        const { context, page } = await newPage(ctx, TWO);
        try {
          await page.goto(`${acct(PAGE)}?lang=${lang}`);
          ctx.intake.inOrder('POST', DELETE, [
            { status: 503 },
            { status: 202, json: { ok: true, status: 'accepted' } },
          ]);
          await page.goto(acct(DEL));
          await page.fill(FIELD, WHO);
          await submit(page);
          await page.setViewportSize({ width: 320, height: 720 });
          t.eq(`the partial page at 320 ${lang} is reached`, await text(page, 'h1'),
            lang === 'it' ? 'Il tuo account è stato eliminato solo in parte' : W.partial);
          const g = await barGeometry(page);
          t.eq(`the partial page at 320 ${lang}: one row`, g.rows, 1);
          t.eq(`the partial page at 320 ${lang}: the document does not scroll sideways`, g.sideways, 0);
          t.eq(`the partial page at 320 ${lang}: the bar does not scroll sideways`, g.barScroll, 0);
        } finally {
          await context.close();
        }
      }
    }
  },
};
