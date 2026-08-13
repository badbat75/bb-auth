'use strict';
// Refused submissions. The contract for every one of them is the same, and it is the
// library's validate-before-write made visible: status 400, the error rendered
// in-context on the same form with the typed input preserved, and **zero bytes
// written** — the server re-runs the gate's own parser on the exact bytes about to
// land, so a file the gate would reject can never leave this GUI either.
//
// Includes the two v3.0.1 refusals: a malformed email on `users · add` and on
// `denied · add` is caught up front with the library's message, instead of surviving
// until the whole-file compile refuses it with a message about someone else's row.

const { doc, bytes, newPage, submit, mainText } = require('../lib/harness');

async function run(ctx, t) {
  const { context, page } = await newPage(ctx);
  const pristine = bytes(ctx);
  try {
    // Each case: goto form, fill, submit; expect 400 + nothing written.
    const refused = async (name, marker) => {
      const before = bytes(ctx);
      const resp = await submit(page);
      t.eq(`${name}: refused with a 400`, resp.status(), 400);
      t.check(`${name}: nothing written`, bytes(ctx) === before, 'file changed');
      if (marker) {
        const text = await mainText(page);
        t.check(`${name}: the error is on the page`, text.includes(marker),
          `missing ${JSON.stringify(marker)} in: ${text.slice(0, 400)}`);
      }
    };

    // A malformed URL pattern in a group — fatal to the gate, so refused here.
    await page.goto(ctx.base + '/groups/+add');
    await page.fill('input[name=name]', 'badgrp');
    await page.fill('textarea[name=urls]', 'htp:/bad');
    await refused('bad pattern in group add');
    t.eq('bad pattern: the typed name is preserved on the re-rendered form',
      await page.locator('input[name=name]').inputValue(), 'badgrp');
    t.eq('bad pattern: and the typed urls', await page.locator('textarea[name=urls]').inputValue(), 'htp:/bad');
    await t.shot(page, 'bad-pattern');

    // An unknown @group reference — the trap --check-users exists for.
    await page.goto(ctx.base + '/users/+add');
    await page.fill('input[name=email]', 'valid@example.com');
    await page.fill('textarea[name=urls]', '@nosuchgroup');
    await refused('unknown @group in user add', 'nosuchgroup');
    t.check('unknown @group: no row written', !doc(ctx).users.find((u) => u.email === 'valid@example.com'));

    // v3.0.1 (a): a malformed email on users · add, refused in-context with the
    // library's own words.
    await page.goto(ctx.base + '/users/+add');
    await page.fill('input[name=email]', 'not an email');
    await page.fill('textarea[name=urls]', '*://*/*');
    await refused('malformed email in user add', 'does not look like an email address');
    t.eq('malformed email: the input is preserved for correction',
      await page.locator('input[name=email]').inputValue(), 'not an email');
    t.check('malformed email: no row written', !doc(ctx).users.find((u) => u.email === 'not an email'));
    await t.shot(page, 'bad-email');

    // v3.0.1 (a): the same door on denied · add — a veto that is a typo protects nobody.
    await page.goto(ctx.base + '/denied/+add');
    await page.fill('input[name=email]', 'bob@example,com');
    await refused('malformed email in denied add', 'does not look like an email address');
    t.check('malformed veto: not in the file', !doc(ctx).denied.includes('bob@example,com'));

    // login_url must be absolute https — it is emitted into headers and a Location:.
    await page.goto(ctx.base + '/sites/+add');
    await page.fill('input[name=name]', 'bad-site');
    await page.fill('textarea[name=urls]', 'https://ok.example.com/*');
    await page.fill('input[name=login_url]', 'http://insecure.example.com/');
    await refused('http login_url in site add');
    t.check('http login_url: no site written', !doc(ctx).sites.find((s) => s.name === 'bad-site'));

    // A group name outside [A-Za-z0-9_-] could never be referenced as @name.
    await page.goto(ctx.base + '/groups/+add');
    await page.fill('input[name=name]', 'bad name!');
    await page.fill('textarea[name=urls]', 'https://x.example.com/*');
    await refused('bad group name');

    // A duplicate roster row would make "which one answers?" ambiguous.
    await page.goto(ctx.base + '/users/+add');
    await page.fill('input[name=email]', 'bot@example.com');
    await page.fill('textarea[name=urls]', 'https://x.example.com/*');
    await refused('duplicate user add');
    t.eq('duplicate user: the roster kept exactly one row',
      doc(ctx).users.filter((u) => u.email === 'bot@example.com').length, 1);

    // A duration the library cannot parse mints nothing — and therefore reveals nothing.
    await page.goto(ctx.base + '/users/bot%40example.com/keys/+add');
    await page.fill('input[name=id]', 'badkey');
    await page.fill('input[name=duration]', 'tomorrow');
    await refused('bad duration on key mint');
    t.check('bad duration: no key written',
      !doc(ctx).users.find((u) => u.email === 'bot@example.com').api_keys.find((k) => k.id === 'badkey'));
    t.check('bad duration: no bearer on the page', !(await mainText(page)).includes('bbk_'));

    t.check('after every refusal the file is byte-identical to the fixture',
      bytes(ctx) === pristine, 'some refusal wrote bytes');
  } finally {
    await context.close();
  }
}

module.exports = { run };
