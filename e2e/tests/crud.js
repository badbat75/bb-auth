'use strict';
// Full CRUD through the forms, each mutation asserted against the JSON file itself —
// the page is presentation, the file is what the gate loads. Also pins the PRG
// contract's visible half (a 303 to `?msg=<key>` with a flash) and its one deliberate
// exception, the mint/rotate reveal page.

const { doc, bytes, sha256, newPage, submit, mainText } = require('../lib/harness');

// The fixture's identities. Every reference in the file is a uuid, and the forms take an
// email and resolve it, so both spellings appear below on purpose.
const YOU = '8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b';
const BOT = 'b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d';
const userBy = (ctx, email) => doc(ctx).users.find((u) => (u.emails || []).includes(email));
const appBy = (ctx, name) => doc(ctx).applications.find((a) => a.name === name);

async function run(ctx, t) {
  const { context, page } = await newPage(ctx);
  try {
    // ================= user_groups ================================================
    await page.goto(ctx.base + '/groups/+add');
    await page.fill('input[name=name]', 'testgrp');
    await page.fill('textarea[name=members]', 'you@example.com');
    await submit(page);
    t.check('group add lands on the users page via PRG', page.url().endsWith('/admin/users?msg=group-added'), page.url());
    t.check('and shows the flash', (await page.locator('.flash').innerText()).includes('group added'));
    t.eq('group add resolves the email to the uuid the file stores', doc(ctx).user_groups.testgrp, [YOU]);
    await t.shot(page, 'group-added');

    await page.goto(ctx.base + '/groups/testgrp/edit');
    await page.fill('textarea[name=members]', 'you@example.com\nbot@example.com');
    await submit(page);
    t.check('group edit redirects with msg=group-saved', page.url().endsWith('?msg=group-saved'), page.url());
    t.eq('group edit rewrites the membership', doc(ctx).user_groups.testgrp, [YOU, BOT]);

    await page.goto(ctx.base + '/groups/testgrp/rm');
    t.check('group rm is a confirm page with a form', (await page.locator('main form').count()) >= 1);
    await submit(page);
    t.check('group rm redirects with msg=group-removed', page.url().endsWith('?msg=group-removed'), page.url());
    t.check('group rm deletes the group', !('testgrp' in doc(ctx).user_groups));

    // Removing @admins must be refused: app1/admin references it, and a dangling
    // '@admins' would make the file fatal to the gate. The library says no; the GUI's
    // job is to relay that as a 400 that writes nothing.
    await page.goto(ctx.base + '/groups/admins/rm');
    const rRef = await submit(page);
    t.eq('removing a referenced group is refused with a 400', rRef.status(), 400);
    t.check('and the group is still in the file', 'admins' in doc(ctx).user_groups);
    await t.shot(page, 'group-rm-refused');

    // ================= a scope's own veto ==========================================
    // `excluded` is checked before the scope grants, so it can keep one member of a group
    // out of one place. Written through the same form, resolved the same way: an enrolled
    // person becomes a uuid, a stranger stays their email.
    await page.goto(ctx.base + '/apps/app1/scopes/admin/edit');
    await page.fill('textarea[name=excluded]', ['you@example.com', 'stranger@example.com'].join('\n'));
    await submit(page);
    const admin = () => appBy(ctx, 'app1').scopes.find((x) => x.name === 'admin');
    t.eq('a scope exclusion resolves a user to their uuid and keeps a stranger as typed',
      admin().excluded, [YOU, 'stranger@example.com']);
    t.check('and the gate agrees: the excluded member of @admins is now DENIED',
      (await (async () => {
        await page.goto(`${ctx.base}/apps/app1?email=you%40example.com&url=${encodeURIComponent('https://app.example.com/app1/admin/panel')}`);
        return mainText(page);
      })()).includes('DENIED'));
    await t.shot(page, 'scope-excluded');

    // And the one place it cannot mean anything is refused rather than dropped.
    await page.goto(ctx.base + '/apps/app1/scopes/healthz/edit');
    await page.fill('textarea[name=excluded]', 'you@example.com');
    const rExcl = await submit(page);
    t.eq('excluding on an anonymous scope is refused with a 400', rExcl.status(), 400);
    t.check('and says why', (await mainText(page)).includes('no credential at all'));

    // ================= applications ===============================================
    await page.goto(ctx.base + '/apps/+add');
    await page.fill('input[name=name]', 'test-app');
    await page.fill('textarea[name=base]', 'https://test.example.com/area');
    await page.fill('input[name=login_url]', 'https://login.test.example.com/');
    await submit(page);
    t.check('app add redirects with msg=app-added', page.url().includes('msg=app-added'), page.url());
    const added = appBy(ctx, 'test-app');
    t.check('app add writes the record', !!added
      && added.login_url === 'https://login.test.example.com/'
      && added.base.length === 1, JSON.stringify(added));
    t.eq('the fixture applications are untouched',
      doc(ctx).applications.map((a) => a.name), ['app1', 'mcp', 'test-app']);

    await page.goto(ctx.base + '/apps/test-app/edit');
    await page.fill('input[name=login_url]', '');
    await submit(page);
    t.check('app edit clears login_url', !appBy(ctx, 'test-app').login_url,
      JSON.stringify(appBy(ctx, 'test-app')));

    // ================= scopes =====================================================
    // Order is meaning here: first match wins, so where a scope lands decides which
    // requests it ever sees.
    await page.goto(ctx.base + '/apps/test-app/scopes/+add');
    await page.fill('input[name=name]', 'open');
    await page.fill('textarea[name=urls]', 'https://test.example.com/area/*');
    await page.check('input[name=access][value=authenticated]');
    await submit(page);
    t.check('scope add redirects with msg=scope-added', page.url().includes('msg=scope-added'), page.url());
    t.eq('scope add writes it', appBy(ctx, 'test-app').scopes.map((s) => s.name), ['open']);
    t.eq('with the access word it was given', appBy(ctx, 'test-app').scopes[0].access, 'authenticated');

    await page.goto(ctx.base + '/apps/test-app/scopes/+add');
    await page.fill('input[name=name]', 'health');
    await page.fill('textarea[name=urls]', 'https://test.example.com/area/healthz');
    await page.check('input[name=access][value=anonymous]');
    await submit(page);
    t.eq('a new scope is appended last', appBy(ctx, 'test-app').scopes.map((s) => s.name), ['open', 'health']);
    await t.shot(page, 'scopes-added');

    // Reorder — the ↑/↓ forms POST dir=up|down; the edge buttons are disabled, because
    // a move off either end is not an error, it is a button you cannot press.
    await page.goto(ctx.base + '/apps/test-app');
    const moveOf = (n, dir) => page.locator(
      `form[action="/admin/apps/test-app/scopes/${n}/move"]:has(input[name="dir"][value="${dir}"]) button`);
    t.check('the first scope\'s ↑ is disabled', await moveOf('open', 'up').isDisabled());
    t.check('the last scope\'s ↓ is disabled', await moveOf('health', 'down').isDisabled());
    await Promise.all([page.waitForNavigation(), moveOf('health', 'up').click()]);
    t.check('move up redirects with msg=scope-moved', page.url().includes('msg=scope-moved'), page.url());
    t.eq('and the file order flipped — the carve-out now answers first',
      appBy(ctx, 'test-app').scopes.map((s) => s.name), ['health', 'open']);
    await Promise.all([page.waitForNavigation(), moveOf('health', 'down').click()]);
    t.eq('move down restores the order', appBy(ctx, 'test-app').scopes.map((s) => s.name), ['open', 'health']);
    await t.shot(page, 'scopes-reordered');

    await page.goto(ctx.base + '/apps/test-app/scopes/health/rm');
    await submit(page);
    t.check('scope rm redirects with msg=scope-removed', page.url().includes('msg=scope-removed'), page.url());
    t.eq('and only the other scope is left', appBy(ctx, 'test-app').scopes.map((s) => s.name), ['open']);

    await page.goto(ctx.base + '/apps/test-app/rm');
    await submit(page);
    t.check('app rm redirects with msg=app-removed', page.url().includes('msg=app-removed'), page.url());
    t.eq('and the fixture applications are back to themselves',
      doc(ctx).applications.map((a) => a.name), ['app1', 'mcp']);

    // ================= denied =====================================================
    await page.goto(ctx.base + '/denied/+add');
    await page.fill('input[name=email]', 'blocked@example.com');
    await submit(page);
    t.check('deny add redirects with msg=denied-added', page.url().endsWith('?msg=denied-added'), page.url());
    t.check('a stranger is vetoed by the email itself', doc(ctx).denied.includes('blocked@example.com'));

    await page.goto(ctx.base + '/denied/blocked%40example.com/rm');
    await submit(page);
    t.check('deny rm redirects with msg=denied-removed', page.url().endsWith('?msg=denied-removed'), page.url());
    t.check('the veto is lifted', !doc(ctx).denied.includes('blocked@example.com'));
    t.check('the fixture veto is untouched', doc(ctx).denied.includes('spammer@example.com'));

    // An enrolled user is vetoed by UUID, whichever way they were named, so every email
    // they hold goes with it.
    await page.goto(ctx.base + '/denied/+add');
    await page.fill('input[name=email]', 'bot@old.example.com');
    await submit(page);
    t.check('denying one address of a user writes their uuid', doc(ctx).denied.includes(BOT),
      JSON.stringify(doc(ctx).denied));
    await page.goto(ctx.base + '/denied/' + BOT + '/rm');
    await submit(page);
    t.check('and lifting it takes the uuid back out', !doc(ctx).denied.includes(BOT));

    // ================= users ======================================================
    await page.goto(ctx.base + '/users/+add');
    await page.fill('input[name=email]', 'newguy@example.com');
    await submit(page);
    t.check('user add lands on the new row with msg=user-added',
      page.url().includes('msg=user-added') && page.url().includes('/admin/users/'), page.url());
    const fresh = userBy(ctx, 'newguy@example.com');
    t.check('the roster row is written with a minted uuid',
      !!fresh && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(fresh.uuid),
      JSON.stringify(fresh));
    t.check('and it carries no url of its own: a user reaches what a scope says',
      Object.keys(fresh).every((k) => ['uuid', 'emails', 'notes', 'api_keys'].includes(k)),
      JSON.stringify(fresh));

    // An identifier is added and dropped on its own: that is what replaced a rename,
    // because the identity never changes.
    await page.goto(ctx.base + '/users/' + fresh.uuid + '/emails/+add');
    await page.fill('input[name=email]', 'newguy@other.example.com');
    await submit(page);
    t.eq('an email is added to the same identity', userBy(ctx, 'newguy@example.com').emails,
      ['newguy@example.com', 'newguy@other.example.com']);
    await page.goto(ctx.base + '/users/' + fresh.uuid + '/emails/newguy%40other.example.com/rm');
    await submit(page);
    t.eq('and dropped again', userBy(ctx, 'newguy@example.com').emails, ['newguy@example.com']);

    // A GUI edit must be surgical: notes on the user, notes on their keys, and the
    // top-of-file _comment block are all content the form never showed — losing any of
    // them on a save would make the GUI a destructive editor.
    await page.goto(ctx.base + '/apps/app1/scopes/admin/edit');
    await page.fill('textarea[name=urls]', 'https://app.example.com/app1/admin/*');
    await submit(page);
    const bot = userBy(ctx, 'bot@example.com');
    t.check('an edit preserves a user\'s notes', !!bot.notes, JSON.stringify(bot));
    t.check('and the notes on their keys', !!bot.api_keys.find((k) => k.id === 'laptop').notes);
    t.check('and the top _comment block', Array.isArray(doc(ctx)._comment) && doc(ctx)._comment.length > 0);

    await page.goto(ctx.base + '/users/' + fresh.uuid + '/rm');
    await submit(page);
    t.check('user rm redirects with msg=user-removed', page.url().endsWith('/admin/users?msg=user-removed'), page.url());
    t.check('and the row is gone', !userBy(ctx, 'newguy@example.com'));

    // ================= api_keys ===================================================
    // Mint. The reveal is deliberately NOT PRG: the direct POST response is the only
    // place the bearer ever exists, so the URL stays the mint form's own.
    await page.goto(ctx.base + '/users/' + BOT + '/keys/+add');
    await page.fill('input[name=id]', 'e2e-key');
    await page.fill('input[name=duration]', '30d');
    await submit(page);
    t.check('the reveal is the direct POST response (no redirect)',
      page.url().endsWith('/users/' + BOT + '/keys/+add'), page.url());
    const reveal = await mainText(page);
    t.check('the reveal shows the bearer as a ready-to-paste header', reveal.includes('Authorization: Bearer bbk_'));
    const bearer = (reveal.match(/bbk_[A-Za-z0-9_-]+/) || [null])[0];
    const keyOf = (id) => userBy(ctx, 'bot@example.com').api_keys.find((k) => k.id === id);
    const minted = keyOf('e2e-key');
    t.check('the file stores sha256(bearer), never the bearer',
      !!bearer && !!minted && minted.key_hash === sha256(bearer) && !bytes(ctx).includes(bearer),
      JSON.stringify(minted));
    t.eq('the requested duration landed', minted?.duration, '30d');
    t.check('released is stamped as a date', /^\d{4}-\d{2}-\d{2}$/.test(minted?.released || ''), minted?.released);
    await t.shot(page, 'key-reveal');

    // Reveal-once: the bearer exists on that one response and nowhere else.
    await page.goto(ctx.base + '/users/' + BOT);
    t.check('the bearer appears on no later page', !(await mainText(page)).includes('bbk_'));

    await page.goto(ctx.base + '/users/' + BOT + '/keys/e2e-key/edit');
    await page.fill('input[name=duration]', '90d');
    await page.fill('textarea[name=scopes]', 'mcp/api');
    await submit(page);
    t.check('key edit redirects with msg=key-saved', page.url().endsWith('?msg=key-saved'), page.url());
    t.eq('and the duration moved', keyOf('e2e-key')?.duration, '90d');
    t.eq('the restriction is a scope name, never a url', keyOf('e2e-key')?.scopes, ['mcp/api']);

    // Rotate: same id, new secret — the answer to a leak (or a lost bearer).
    await page.goto(ctx.base + '/users/' + BOT + '/keys/e2e-key/rotate');
    t.check('rotate is a confirm page', (await page.locator('main form').count()) >= 1);
    await submit(page);
    const rotText = await mainText(page);
    const bearer2 = (rotText.match(/bbk_[A-Za-z0-9_-]+/) || [null])[0];
    t.check('rotate reveals a fresh bearer', !!bearer2 && bearer2 !== bearer);
    t.check('and the file now verifies only the new one',
      !!bearer2 && keyOf('e2e-key')?.key_hash === sha256(bearer2));
    t.eq('rotate replaces, never duplicates',
      userBy(ctx, 'bot@example.com').api_keys.filter((k) => k.id === 'e2e-key').length, 1);

    await page.goto(ctx.base + '/users/' + BOT + '/keys/e2e-key/rm');
    await submit(page);
    t.check('key rm redirects with msg=key-removed', page.url().endsWith('?msg=key-removed'), page.url());
    t.check('the key is gone', !keyOf('e2e-key'));
    t.eq('and the fixture keys are untouched',
      userBy(ctx, 'bot@example.com').api_keys.map((k) => k.id), ['laptop', 'ci']);
  } finally {
    await context.close();
  }
}

module.exports = { run };
