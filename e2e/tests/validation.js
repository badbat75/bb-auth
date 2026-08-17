'use strict';
// Refused submissions. The contract for every one of them is the same, and it is the
// library's validate-before-write made visible: status 400, the error rendered
// in-context on the same form with the typed input preserved, and **zero bytes
// written** — the server re-runs the gate's own parser on the exact bytes about to
// land, so a file the gate would reject can never leave this GUI either.
//
// Includes the refusals that are new in 4.0 and load-bearing: a base that is not
// literal, two applications claiming one URL, and a scope reaching outside its own area.

const { doc, bytes, newPage, submit, mainText } = require('../lib/harness');

const BOT = 'b3f1c8a2-4e77-4f1a-9c0d-1e2f3a4b5c6d';
const app1 = (ctx) => doc(ctx).applications.find((a) => a.name === 'app1');
const userBy = (ctx, email) => doc(ctx).users.find((u) => (u.emails || []).includes(email));

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

    // A malformed URL pattern in a scope — fatal to the gate, so refused here.
    await page.goto(ctx.base + '/apps/app1/scopes/+add');
    await page.fill('input[name=name]', 'badscope');
    await page.fill('textarea[name=urls]', 'htp:/bad');
    await page.check('input[name=access][value=authenticated]');
    await refused('bad pattern in scope add');
    t.eq('bad pattern: the typed name is preserved on the re-rendered form',
      await page.locator('input[name=name]').inputValue(), 'badscope');
    t.eq('bad pattern: and the typed urls', await page.locator('textarea[name=urls]').inputValue(), 'htp:/bad');
    await t.shot(page, 'bad-pattern');

    // A pattern outside the application's own area. The partition is what makes "one
    // application owns this URL" true, so a scope may not reach past its base.
    await page.goto(ctx.base + '/apps/app1/scopes/+add');
    await page.fill('input[name=name]', 'outside');
    await page.fill('textarea[name=urls]', 'https://elsewhere.example.com/x/*');
    await page.check('input[name=access][value=authenticated]');
    await refused('scope url outside the base', 'outside this application');
    t.check('outside the base: no scope written', !app1(ctx).scopes.find((s) => s.name === 'outside'));

    // An unknown @group reference — the trap --check-access exists for.
    await page.goto(ctx.base + '/apps/app1/scopes/+add');
    await page.fill('input[name=name]', 'ghost');
    await page.fill('textarea[name=urls]', 'https://app.example.com/app1/ghost/*');
    await page.check('input[name=access][value=restricted]');
    await page.fill('textarea[name=members]', '@nosuchgroup');
    await refused('unknown @group in scope add', 'nosuchgroup');
    t.check('unknown @group: no scope written', !app1(ctx).scopes.find((s) => s.name === 'ghost'));

    // A malformed email on users · add, refused in-context with the library's own words.
    await page.goto(ctx.base + '/users/+add');
    await page.fill('input[name=email]', 'not an email');
    await refused('malformed email in user add', 'does not look like an email address');
    t.eq('malformed email: the input is preserved for correction',
      await page.locator('input[name=email]').inputValue(), 'not an email');
    t.check('malformed email: no row written', !userBy(ctx, 'not an email'));
    await t.shot(page, 'bad-email');

    // The same door on denied · add — a veto that is a typo protects nobody.
    await page.goto(ctx.base + '/denied/+add');
    await page.fill('input[name=email]', 'bob@example,com');
    await refused('malformed email in denied add', 'does not look like an email address');
    t.check('malformed veto: not in the file', !doc(ctx).denied.includes('bob@example,com'));

    // login_url must be absolute https — it is emitted into headers and a Location:.
    await page.goto(ctx.base + '/apps/+add');
    await page.fill('input[name=name]', 'bad-app');
    await page.fill('textarea[name=base]', 'https://ok.example.com/area');
    await page.fill('input[name=login_url]', 'http://insecure.example.com/');
    await refused('http login_url in app add');
    t.check('http login_url: no application written',
      !doc(ctx).applications.find((a) => a.name === 'bad-app'));

    // A base carrying a wildcard is not an area: non-overlap is a string comparison, and
    // a glob has no place in one.
    await page.goto(ctx.base + '/apps/+add');
    await page.fill('input[name=name]', 'globby');
    await page.fill('textarea[name=base]', 'https://*.example.com/');
    await refused('wildcard in an application base', 'literal');

    // Two applications may not own the same URL: that is what makes at most one answer.
    await page.goto(ctx.base + '/apps/+add');
    await page.fill('input[name=name]', 'overlap');
    await page.fill('textarea[name=base]', 'https://app.example.com/app1/inner');
    await refused('overlapping application area', 'overlaps');

    // A group name outside [A-Za-z0-9_-] could never be referenced as @name.
    await page.goto(ctx.base + '/groups/+add');
    await page.fill('input[name=name]', 'bad name!');
    await page.fill('textarea[name=members]', 'you@example.com');
    await refused('bad group name');

    // A duplicate identifier would make "which row answers?" ambiguous.
    await page.goto(ctx.base + '/users/+add');
    await page.fill('input[name=email]', 'bot@example.com');
    await refused('duplicate user add');
    t.eq('duplicate user: the roster kept exactly one row',
      doc(ctx).users.filter((u) => (u.emails || []).includes('bot@example.com')).length, 1);

    // A duration the library cannot parse mints nothing — and therefore reveals nothing.
    await page.goto(ctx.base + '/users/' + BOT + '/keys/+add');
    await page.fill('input[name=id]', 'badkey');
    await page.fill('input[name=duration]', 'tomorrow');
    await refused('bad duration on key mint');
    t.check('bad duration: no key written',
      !userBy(ctx, 'bot@example.com').api_keys.find((k) => k.id === 'badkey'));
    t.check('bad duration: no bearer on the page', !(await mainText(page)).includes('bbk_'));

    t.check('after every refusal the file is byte-identical to the fixture',
      bytes(ctx) === pristine, 'some refusal wrote bytes');
  } finally {
    await context.close();
  }
}

module.exports = { run };
