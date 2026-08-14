'use strict';
// The `rev` check — every mutating form carries a hidden `rev` = sha256 of the file's
// exact bytes as the form was rendered, so a lost update against a `bb-auth-adm` over
// SSH (or another tab) is a visible 409 instead of a silent clobber.
//
// Two different 409s, and telling them apart is the point:
// * the **generic** one blames another writer, writes nothing, and points at the Back
//   button (no page here runs a script on load, so the bfcache still holds the form);
// * the **mint** route's own one fires when the stale `rev` comes with a key that now
//   exists — which is what a reloaded reveal page looks like. There the generic advice
//   ("make the change again") would mint a second key, so it offers a rotation instead.

const { doc, bytes, writeDoc, newPage, submit, mainText, resubmit, formBytes } = require('../lib/harness');

// The out-of-band writer: touch an unrelated note, keep the file valid — exactly what a
// bb-auth-adm session over SSH does to a form somebody left open.
function oobEdit(ctx, tag) {
  const d = doc(ctx);
  d.users.find((u) => u.email === 'you@example.com').notes = `oob ${tag} ${Date.now()}`;
  writeDoc(ctx, d);
}

async function run(ctx, t) {
  const { context, page } = await newPage(ctx);
  try {
    // --- the generic 409, English ------------------------------------------------
    await page.goto(ctx.base + '/users/friend%40example.com/edit?lang=en');
    await page.fill('textarea[name=urls]', 'https://app.example.com/typed-not-saved/*');
    oobEdit(ctx, 'en');
    const r409 = await submit(page);
    t.eq('a stale rev is a 409', r409.status(), 409);
    const en = await mainText(page);
    t.check('the generic 409 blames the file, not the admin', en.includes('The file changed'), en.slice(0, 300));
    t.check('it carries the Back-button recovery hint', en.includes('Back button'), en.slice(0, 400));
    t.check('and offers to reload the form',
      (await page.locator('main a[href*="friend%40example.com/edit"]').count()) >= 1);
    t.check('the conflicting edit was not applied', !bytes(ctx).includes('typed-not-saved'));
    await t.shot(page, 'generic-409-en');

    // The hint must be true: Back returns to the form as it was filled in.
    await page.goBack();
    t.eq('the Back button restores the typed input (bfcache)',
      await page.locator('textarea[name=urls]').inputValue(), 'https://app.example.com/typed-not-saved/*');

    // --- the generic 409, Italian ------------------------------------------------
    await page.goto(ctx.base + '/users/friend%40example.com/edit?lang=it');
    await page.fill('textarea[name=urls]', 'https://app.example.com/typed-it/*');
    oobEdit(ctx, 'it');
    t.eq('the Italian 409 is still a 409', (await submit(page)).status(), 409);
    const it = await mainText(page);
    t.check('the Italian copy is the same page', it.includes('Il file è cambiato'), it.slice(0, 300));
    t.check('Back-button hint, in Italian', it.includes('pulsante Indietro'), it.slice(0, 400));
    t.check('and again nothing was written', !bytes(ctx).includes('typed-it'));
    await t.shot(page, 'generic-409-it');

    // --- a stale form resubmitted after our own earlier save ----------------------
    // Two constraints make this a byte-replay rather than a Back-button dance. The
    // save must actually CHANGE bytes — a byte-identical rewrite leaves the file's rev
    // where it was, and the old form would still, correctly, be accepted. And a
    // history navigation is not reliably stale: on a re-fetch the browser restores the
    // *visible* fields but the hidden rev is re-rendered fresh by the server. What is
    // deterministically stale is the exact bytes the first submit posted.
    await page.goto(ctx.base + '/groups/mcp/edit?lang=en');
    const urls = await page.locator('textarea[name=urls]').inputValue();
    await page.fill('textarea[name=urls]', urls + '\nhttps://added.example.com/*');
    const staleFields = await formBytes(page); // rev as rendered + the typed content
    await submit(page);
    t.check('the save itself lands via PRG', page.url().endsWith('?msg=group-saved'), page.url());
    const rStale = await resubmit(page, '/admin/groups/mcp/edit', staleFields);
    t.eq('replaying the saved form\'s exact bytes is the generic 409', rStale.status(), 409);
    t.check('with the generic copy', (await mainText(page)).includes('The file changed'));

    // --- the mint-specific 409, English -----------------------------------------
    const mintUrl = '/admin/users/bot%40example.com/keys/+add';
    await page.goto(ctx.base + '/users/bot%40example.com/keys/+add?lang=en');
    await page.fill('input[name=id]', 'demo');
    await page.fill('input[name=duration]', '30d');
    const mintFields = await formBytes(page); // the exact bytes a reload would re-POST
    await submit(page);
    t.check('the mint reveals the bearer once', (await mainText(page)).includes('Authorization: Bearer bbk_'));
    const keyCount = (id) =>
      doc(ctx).users.find((u) => u.email === 'bot@example.com').api_keys.filter((k) => k.id === id).length;
    t.eq('one key named demo exists', keyCount('demo'), 1);

    const rMint = await resubmit(page, mintUrl, mintFields); // = reloading the reveal page
    t.eq('re-posting the mint form is a 409', rMint.status(), 409);
    const mc = await mainText(page);
    t.check('it is the mint-specific page', mc.includes('This key was already created'), mc.slice(0, 300));
    t.check('which says the bearer cannot be recovered', mc.includes('cannot be recovered'), mc.slice(0, 500));
    t.check('not the generic one', !mc.includes('The file changed'));
    t.check('and no Back-button hint — the typed input is not worth recovering', !mc.includes('Back button'));
    t.check('it offers the rotation instead',
      ((await page.locator('main a', { hasText: 'rotate this key' }).getAttribute('href')) || '')
        .includes('/keys/demo/rotate'));
    t.eq('still exactly one key — the resubmit minted nothing', keyCount('demo'), 1);
    t.check('and no bearer appears on the conflict page', !mc.includes('bbk_'));
    await t.shot(page, 'mint-409-en');

    // --- the mint-specific 409, Italian ------------------------------------------
    await page.goto(ctx.base + '/users/bot%40example.com/keys/+add?lang=it');
    await page.fill('input[name=id]', 'demo-it');
    await page.fill('input[name=duration]', '30d');
    const mintFieldsIt = await formBytes(page);
    await submit(page);
    t.check('the Italian reveal keeps the reveal-once contract',
      (await mainText(page)).includes('Authorization: Bearer bbk_'));
    const rMintIt = await resubmit(page, mintUrl, mintFieldsIt);
    t.eq('the Italian mint conflict is a 409', rMintIt.status(), 409);
    const mcIt = await mainText(page);
    t.check('Italian mint-conflict copy', mcIt.includes('Questa chiave è già stata creata'), mcIt.slice(0, 300));
    t.check('unrecoverable, in Italian', mcIt.includes('non può essere recuperato'), mcIt.slice(0, 500));
    t.check('rotation offered, in Italian', mcIt.includes('rigenera questa chiave'));
    t.eq('still exactly one demo-it key', keyCount('demo-it'), 1);
    await t.shot(page, 'mint-409-it');
  } finally {
    await context.close();
  }
}

module.exports = { run };
