'use strict';
// Full CRUD through the forms, each mutation asserted against the JSON file itself —
// the page is presentation, the file is what the gate loads. Also pins the PRG
// contract's visible half (a 303 to `?msg=<key>` with a flash) and its one deliberate
// exception, the mint/rotate reveal page.

const { doc, bytes, sha256, newPage, submit, mainText } = require('../lib/harness');

async function run(ctx, t) {
  const { context, page } = await newPage(ctx);
  try {
    // ================= url_groups =================================================
    await page.goto(ctx.base + '/groups/+add');
    await page.fill('input[name=name]', 'testgrp');
    await page.fill('textarea[name=urls]', 'https://test.example.com/*');
    await submit(page);
    t.check('group add lands on the list via PRG', page.url().endsWith('/admin/groups?msg=group-added'), page.url());
    t.check('and shows the flash', (await page.locator('.flash').innerText()).includes('url group added'));
    t.eq('group add writes the group', doc(ctx).url_groups.testgrp, ['https://test.example.com/*']);
    await t.shot(page, 'group-added');

    await page.goto(ctx.base + '/groups/testgrp/edit');
    await page.fill('textarea[name=urls]', 'https://test.example.com/*\nhttps://test2.example.com/api/*');
    await submit(page);
    t.check('group edit redirects with msg=group-saved', page.url().endsWith('?msg=group-saved'), page.url());
    t.eq('group edit rewrites the patterns', doc(ctx).url_groups.testgrp,
      ['https://test.example.com/*', 'https://test2.example.com/api/*']);

    await page.goto(ctx.base + '/groups/testgrp/rm');
    t.check('group rm is a confirm page with a form', (await page.locator('main form').count()) >= 1);
    await submit(page);
    t.check('group rm redirects with msg=group-removed', page.url().endsWith('?msg=group-removed'), page.url());
    t.check('group rm deletes the group', !('testgrp' in doc(ctx).url_groups));

    // Removing @mcp must be refused: bot@example.com references it, and a dangling
    // '@mcp' would make the file fatal to the gate. The library says no; the GUI's job
    // is to relay that as a 400 that writes nothing.
    await page.goto(ctx.base + '/groups/mcp/rm');
    const rRef = await submit(page);
    t.eq('removing a referenced group is refused with a 400', rRef.status(), 400);
    t.check('and the group is still in the file', 'mcp' in doc(ctx).url_groups);
    await t.shot(page, 'group-rm-refused');

    // ================= sites ======================================================
    await page.goto(ctx.base + '/sites/+add');
    await page.fill('input[name=name]', 'test-site');
    await page.fill('textarea[name=urls]', 'https://test.example.com/area\nhttps://test.example.com/area/*');
    await page.check('input[name=public_auth]');
    await page.fill('input[name=login_url]', 'https://login.test.example.com/');
    await submit(page);
    t.check('site add redirects with msg=site-added', page.url().endsWith('/admin/sites?msg=site-added'), page.url());
    const added = doc(ctx).sites.find((s) => s.name === 'test-site');
    t.check('site add writes the record', !!added && added.public_auth === true
      && added.login_url === 'https://login.test.example.com/' && added.urls.length === 2,
      JSON.stringify(added));
    t.eq('a new site is appended last — order is first-match-wins, so position matters',
      doc(ctx).sites.map((s) => s.name), ['app1-onboarding', 'test-site']);

    await page.goto(ctx.base + '/sites/test-site/edit');
    await page.uncheck('input[name=public_auth]');
    await page.fill('input[name=login_url]', '');
    await submit(page);
    const edited = doc(ctx).sites.find((s) => s.name === 'test-site');
    t.check('site edit clears public_auth and login_url', !!edited && !edited.public_auth && !edited.login_url,
      JSON.stringify(edited));

    // Reorder — the ↑/↓ forms POST dir=up|down; the edge buttons are disabled, because
    // a move off either end is not an error, it is a button you cannot press.
    await page.goto(ctx.base + '/sites');
    const upOf = (n) => page.locator(`form[action="/admin/sites/${n}/move"]:has(input[name="dir"][value="up"]) button`);
    const downOf = (n) => page.locator(`form[action="/admin/sites/${n}/move"]:has(input[name="dir"][value="down"]) button`);
    t.check('the first site\'s ↑ is disabled', await upOf('app1-onboarding').isDisabled());
    t.check('the last site\'s ↓ is disabled', await downOf('test-site').isDisabled());
    await Promise.all([page.waitForNavigation(), upOf('test-site').click()]);
    t.check('move up redirects with msg=site-moved', page.url().endsWith('?msg=site-moved'), page.url());
    t.eq('and the file order flipped', doc(ctx).sites.map((s) => s.name), ['test-site', 'app1-onboarding']);
    await Promise.all([page.waitForNavigation(), downOf('test-site').click()]);
    t.eq('move down restores the order', doc(ctx).sites.map((s) => s.name), ['app1-onboarding', 'test-site']);
    await t.shot(page, 'sites-reordered');

    await page.goto(ctx.base + '/sites/test-site/rm');
    await submit(page);
    t.check('site rm redirects with msg=site-removed', page.url().endsWith('?msg=site-removed'), page.url());
    t.eq('and the file holds only the fixture site again', doc(ctx).sites.map((s) => s.name), ['app1-onboarding']);

    // ================= denied =====================================================
    await page.goto(ctx.base + '/denied/+add');
    await page.fill('input[name=email]', 'blocked@example.com');
    await submit(page);
    t.check('deny add redirects with msg=denied-added', page.url().endsWith('?msg=denied-added'), page.url());
    t.check('the veto is in the file', doc(ctx).denied.includes('blocked@example.com'));

    await page.goto(ctx.base + '/denied/blocked%40example.com/rm');
    await submit(page);
    t.check('deny rm redirects with msg=denied-removed', page.url().endsWith('?msg=denied-removed'), page.url());
    t.check('the veto is lifted', !doc(ctx).denied.includes('blocked@example.com'));
    t.check('the fixture veto is untouched', doc(ctx).denied.includes('spammer@example.com'));

    // ================= users ======================================================
    await page.goto(ctx.base + '/users/+add');
    await page.fill('input[name=email]', 'newguy@example.com');
    await page.fill('textarea[name=urls]', 'https://app.example.com/*\n@mcp');
    await submit(page);
    t.check('user add lands on the user page with msg=user-added',
      page.url().endsWith('/admin/users/newguy%40example.com?msg=user-added'), page.url());
    t.eq('the roster row is written, @group reference kept verbatim',
      doc(ctx).users.find((u) => u.email === 'newguy@example.com')?.authorized_urls,
      ['https://app.example.com/*', '@mcp']);

    await page.goto(ctx.base + '/users/newguy%40example.com/edit');
    await page.fill('textarea[name=urls]', '@mcp\nhttps://other.example.com/x/*');
    await submit(page);
    t.check('user edit redirects with msg=user-saved', page.url().endsWith('?msg=user-saved'), page.url());
    t.eq('user edit rewrites the scope',
      doc(ctx).users.find((u) => u.email === 'newguy@example.com')?.authorized_urls,
      ['@mcp', 'https://other.example.com/x/*']);

    // A GUI edit must be surgical: notes on the user, notes on their keys, and the
    // top-of-file _comment block are all content the form never showed — losing any of
    // them on a save would make the GUI a destructive editor.
    await page.goto(ctx.base + '/users/bot%40example.com/edit');
    await page.fill('textarea[name=urls]', '@mcp');
    await submit(page);
    const bot = doc(ctx).users.find((u) => u.email === 'bot@example.com');
    t.check('an edit preserves the user\'s notes', !!bot.notes, JSON.stringify(bot));
    t.check('and the notes on their keys', !!bot.api_keys.find((k) => k.id === 'laptop').notes);
    t.check('and the top _comment block', Array.isArray(doc(ctx)._comment) && doc(ctx)._comment.length > 0);

    await page.goto(ctx.base + '/users/newguy%40example.com/rm');
    await submit(page);
    t.check('user rm redirects with msg=user-removed', page.url().endsWith('/admin/users?msg=user-removed'), page.url());
    t.check('and the row is gone', !doc(ctx).users.find((u) => u.email === 'newguy@example.com'));

    // ================= api_keys ===================================================
    // Mint. The reveal is deliberately NOT PRG: the direct POST response is the only
    // place the bearer ever exists, so the URL stays the mint form's own.
    await page.goto(ctx.base + '/users/bot%40example.com/keys/+add');
    await page.fill('input[name=id]', 'e2e-key');
    await page.fill('input[name=duration]', '30d');
    await submit(page);
    t.check('the reveal is the direct POST response (no redirect)',
      page.url().endsWith('/users/bot%40example.com/keys/+add'), page.url());
    const reveal = await mainText(page);
    t.check('the reveal shows the bearer as a ready-to-paste header', reveal.includes('Authorization: Bearer bbk_'));
    const bearer = (reveal.match(/bbk_[A-Za-z0-9_-]+/) || [null])[0];
    const keyOf = (id) => doc(ctx).users.find((u) => u.email === 'bot@example.com').api_keys.find((k) => k.id === id);
    const minted = keyOf('e2e-key');
    t.check('the file stores sha256(bearer), never the bearer',
      !!bearer && !!minted && minted.key_hash === sha256(bearer) && !bytes(ctx).includes(bearer),
      JSON.stringify(minted));
    t.eq('the requested duration landed', minted?.duration, '30d');
    t.check('released is stamped as a date', /^\d{4}-\d{2}-\d{2}$/.test(minted?.released || ''), minted?.released);
    await t.shot(page, 'key-reveal');

    // Reveal-once: the bearer exists on that one response and nowhere else.
    await page.goto(ctx.base + '/users/bot%40example.com');
    t.check('the bearer appears on no later page', !(await mainText(page)).includes('bbk_'));

    await page.goto(ctx.base + '/users/bot%40example.com/keys/e2e-key/edit');
    await page.fill('input[name=duration]', '90d');
    await submit(page);
    t.check('key edit redirects with msg=key-saved', page.url().endsWith('?msg=key-saved'), page.url());
    t.eq('and the duration moved', keyOf('e2e-key')?.duration, '90d');

    // Rotate: same id, new secret — the answer to a leak (or a lost bearer).
    await page.goto(ctx.base + '/users/bot%40example.com/keys/e2e-key/rotate');
    t.check('rotate is a confirm page', (await page.locator('main form').count()) >= 1);
    await submit(page);
    const rotText = await mainText(page);
    const bearer2 = (rotText.match(/bbk_[A-Za-z0-9_-]+/) || [null])[0];
    t.check('rotate reveals a fresh bearer', !!bearer2 && bearer2 !== bearer);
    t.check('and the file now verifies only the new one',
      !!bearer2 && keyOf('e2e-key')?.key_hash === sha256(bearer2));
    t.eq('rotate replaces, never duplicates',
      doc(ctx).users.find((u) => u.email === 'bot@example.com').api_keys.filter((k) => k.id === 'e2e-key').length, 1);

    await page.goto(ctx.base + '/users/bot%40example.com/keys/e2e-key/rm');
    await submit(page);
    t.check('key rm redirects with msg=key-removed', page.url().endsWith('?msg=key-removed'), page.url());
    t.check('the key is gone', !keyOf('e2e-key'));
    t.eq('and the fixture keys are untouched',
      doc(ctx).users.find((u) => u.email === 'bot@example.com').api_keys.map((k) => k.id), ['laptop', 'ci']);
  } finally {
    await context.close();
  }
}

module.exports = { run };
