'use strict';
// The Audit tab: the one page here that reads a file nobody in this suite can write through
// the GUI, because the GUI never writes it. So the fixture is laid down as the gate would
// have laid it down — one JSON object per line, oldest first, which is what an append-only
// file looks like — and everything below is about what the page does with it.
//
// Three things are worth driving in a real browser rather than in a unit test. The filters
// are three list boxes and a text field in ONE form, so a period and a name have to apply
// together on one submit. The pager and the filters are query parameters, so Refresh can be a
// plain link and the whole view has to survive it. And the page has to say something honest
// when the file is not there at all, which is the state every deployment starts in.

const fs = require('fs');
const { newPage, mainText } = require('../lib/harness');

/** Seconds ago, as the gate would have stamped it. */
const ago = (secs) => Math.floor(Date.now() / 1000) - secs;

/** Write an audit file exactly as the gate appends one: oldest line first. */
function writeAudit(ctx, events) {
  fs.writeFileSync(ctx.auditFile, events.map((e) => JSON.stringify(e)).join('\n') + '\n');
}

async function run(ctx, t) {
  const rows = [
    // Older than every period the page offers, so only "Everything" reaches it.
    {
      v: 1,
      ts: ago(40 * 86400),
      kind: 'login_granted',
      cred: { type: 'local' },
      subject: 'ancient@example.com',
    },
    {
      v: 1,
      ts: ago(600),
      kind: 'access_refused',
      cred: { type: 'key', id: 'laptop' },
      uuid: 'b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d',
      app: 'app1',
      scope: 'admin',
      url: 'https://app.example.com/app1/admin/panel',
      reason: 'key_out_of_scope',
    },
    {
      v: 1,
      ts: ago(300),
      kind: 'login_refused',
      cred: { type: 'anonymous' },
      reason: 'token_invalid',
    },
    {
      v: 1,
      ts: ago(60),
      kind: 'login_granted',
      cred: { type: 'social', provider: 'Google' },
      subject: 'newcomer@example.com',
    },
  ];
  // Thirty more of one shape, to put the pager over its 25-row page. Older than the four
  // above, so those four are all on page one: what is under test here is the page, and a
  // check that silently depended on where the pager cut would be a check about the fixture.
  for (let i = 0; i < 30; i++) {
    rows.push({
      v: 1,
      ts: ago(1000 + i),
      kind: 'access_refused',
      cred: { type: 'session' },
      subject: `crowd${i}@example.com`,
      app: 'app1',
      scope: 'admin',
      reason: 'not_member',
    });
  }
  rows.sort((a, b) => a.ts - b.ts);
  writeAudit(ctx, rows);

  const { context, page } = await newPage(ctx);
  try {
    await page.goto(ctx.base + '/audit');
    const text = await mainText(page);
    t.check('the audit renders its rows', text.includes('newcomer@example.com'), text);
    // Newest first, which is the whole reading order of the page.
    t.check(
      'newest first',
      text.indexOf('newcomer@example.com') < text.indexOf('laptop'),
      text
    );
    // A key names its owner's row, and the row is a link to that person's page.
    t.eq(
      'a key event links to the row it acted as',
      await page.locator('main a[href$="/users/b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d"]').count() > 0,
      true
    );
    t.check('the provider is named beside the credential', text.includes('Google'), text);
    // The reason is a code in the file and a sentence on the page.
    t.check(
      'a refusal explains itself in words',
      text.includes('is not among the scopes this key restricted itself to'),
      text
    );
    t.check(
      'and the default period is a day, so nothing older is here',
      !text.includes('ancient@example.com'),
      text
    );
    await t.shot(page, 'audit');

    // --- the filters, all three list boxes and the text field in one form ---
    const apply = () =>
      Promise.all([page.waitForNavigation(), page.click('.listctl form button[type=submit]')]);

    // The period and the text field, applied together on one submit, which is the whole
    // reason they share a form: the oldest event there is, found by name.
    await page.selectOption('.listctl select[name=aw]', 'all');
    await page.fill('.listctl input[name=aq]', 'ancient@');
    await apply();
    t.check(
      'Everything reaches the oldest event there is',
      (await mainText(page)).includes('ancient@example.com'),
      page.url()
    );
    await page.fill('.listctl input[name=aq]', '');
    await apply();

    await page.selectOption('.listctl select[name=ac]', 'key');
    await apply();
    let after = await mainText(page);
    t.check('the credential filter keeps the keys', after.includes('laptop'), after);
    t.check('and drops everything else', !after.includes('newcomer@example.com'), after);
    t.check('while the period it was set with survives', page.url().includes('aw=all'), page.url());

    await page.selectOption('.listctl select[name=ac]', '');
    await page.selectOption('.listctl select[name=ao]', 'ok');
    await apply();
    after = await mainText(page);
    t.check('the outcome filter keeps the sign-ins', after.includes('newcomer@example.com'), after);
    t.check('and drops the refusals', !after.includes('laptop'), after);

    // The text field and a list box, submitted together: one form, one Apply.
    await page.selectOption('.listctl select[name=ao]', '');
    await page.fill('.listctl input[name=aq]', 'crowd7@');
    await apply();
    after = await mainText(page);
    t.check('the text filter matches on the identity', after.includes('crowd7@example.com'), after);
    t.check('and excludes the rest', !after.includes('crowd8@example.com'), after);

    // --- the pager, and Refresh keeping the whole view ---------------------
    await page.goto(ctx.base + '/audit?aw=all');
    t.check('a long period pages', (await page.locator('.listctl .pager').count()) > 0);
    await Promise.all([page.waitForNavigation(), page.click('.listctl .pager a')]);
    t.check('page two is reachable', page.url().includes('ap=2'), page.url());

    await page.goto(ctx.base + '/audit?aw=all&ac=session&aq=crowd1');
    const before = await mainText(page);
    await Promise.all([page.waitForNavigation(), page.click('main p.primary a')]);
    t.check('Refresh keeps the period', page.url().includes('aw=all'), page.url());
    t.check('the credential', page.url().includes('ac=session'), page.url());
    t.check('and the filter', page.url().includes('aq=crowd1'), page.url());
    t.eq('and shows the same page again', await mainText(page), before);

    // --- and what an audit nobody has written yet looks like ---------------
    fs.rmSync(ctx.auditFile, { force: true });
    await page.goto(ctx.base + '/audit');
    const empty = await mainText(page);
    t.check('a file that does not exist is an empty list, not an error', empty.includes('none'), empty);
    t.eq('and the tab is still there', await page.locator('nav a.pill.on').innerText(), 'Audit');
  } finally {
    await context.close();
  }
}

module.exports = { run };
