'use strict';
// The self-service page at `/account`, driven as a roster person who is **not** on
// `web.admins` (`you@example.com`), with scripting off. Every other area drives `ctx.base`;
// this one drives the sibling prefix, which is the half of the binary a person who is not an
// administrator reaches (docs/ARCHITECTURE.md §13).
//
// Scripting off is the point of the area and not a garnish: this page emits no `<script>`
// tag and no handler at all, not even the console's two list boxes, so every mutation here
// is a plain form `POST` and the reveal-once bearer has to survive a Back button and a
// reload in a browser running no code.
//
// The contract checked, in order: the mint reveals a `bbk_` bearer exactly once and the file
// keeps only its hash; Back and a reload show the key in the list and no secret; a rotate
// shows a *different* secret once and replaces the hash in place; a revoke is a `303` back to
// the page; the same identity is a `403` on the console; and a form left open in a second tab
// is a `409` that mints nothing.

const { doc, bytes, sha256, settings, api, submit, mainText } = require('../lib/harness');

const WHO = 'you@example.com';
const UUID = '8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b';
const PAGE = '/account/';
// The three mutation paths, named by their `action` so a selector can never pick the wrong
// form: the keys section carries one mint, and a rotate and a revoke per key.
const MINT = 'form[action="/account/keys"]';
const ROTATE = 'form[action="/account/keys/rotate"]';
const REMOVE = 'form[action="/account/keys/remove"]';
// One key's own form, so an assertion about key A cannot be satisfied by key B's button.
const keyForm = (path, id) => `${path}:has(input[name="id"][value="${id}"])`;

/** The caller's own keys, straight off the file the gate would load. */
const myKeys = (ctx) =>
  (doc(ctx).users.find((u) => (u.emails || []).includes(WHO)).api_keys || []);
const idsOf = (ctx) => myKeys(ctx).map((k) => k.id);
const keyById = (ctx, id) => myKeys(ctx).find((k) => k.id === id);

/** The bearer a reveal page shows, out of the `Authorization: Bearer bbk_…` line. */
const bearerIn = (text) => (text.match(/Bearer (bbk_[A-Za-z0-9_-]+)/) || [])[1];
const occurrences = (hay, needle) => (needle ? hay.split(needle).length - 1 : 0);

// With scripting off, `page.evaluate` is unavailable, so the page-shape checks parse the
// document text the same way a reviewer would read it.
const tags = (html, re) => (html.match(re) || []);

async function run(ctx, t) {
  const url = ctx.origin + PAGE;
  const noJs = await ctx.browser.newContext({
    viewport: { width: 1280, height: 900 },
    extraHTTPHeaders: { 'X-Auth-Email': WHO },
    javaScriptEnabled: false,
  });
  const page = await noJs.newPage();
  const keys = page.locator('#keys');

  const mintKey = async (p, id) => {
    await p.fill(`${MINT} input[name=id]`, id);
    await p.fill(`${MINT} input[name=duration]`, '365d');
    return submit(p, `${MINT} button[type=submit]`);
  };

  // --- 1. the page renders, with scripting off -----------------------------------------
  const open = await page.goto(url);
  t.eq('the page answers 200 to a roster person who is not an administrator', open.status(), 200);
  const html = await page.content();
  t.eq('the page carries no <script> tag', tags(html, /<script/i).length, 0);
  t.eq('and no handler of any kind', tags(html, /<[^>]*\son[a-z]+\s*=/gi).length, 0);
  t.eq('the keys section is on the page', await keys.count(), 1);
  t.eq('its heading is the page\'s own words', (await keys.locator('h2').first().innerText()).trim(), 'API keys');
  t.eq('the mint form sits inside the keys section', await keys.locator(MINT).count(), 1);
  t.eq('it posts to the keys path',
    (await page.locator(MINT).getAttribute('method') || '').toLowerCase(), 'post');
  const rev = await page.locator(`${MINT} input[name=rev]`).inputValue();
  t.eq('its hidden rev is the sha256 of the file\'s exact bytes', rev, sha256(bytes(ctx)));
  const restrict = page.locator(`${MINT} input[name=restrict]`);
  const offered = [];
  for (let i = 0, n = await restrict.count(); i < n; i++) offered.push(await restrict.nth(i).getAttribute('value'));
  t.eq('restrict=all is on offer and checked',
    offered.length === 1 && offered[0] === 'all' && (await restrict.getAttribute('checked')) !== null, true);
  t.check('the caller is named with the address the header carried',
    (await mainText(page)).includes('signed in as') && (await mainText(page)).includes(WHO),
    (await mainText(page)).slice(0, 200));
  t.check('and the page names their uuid', (await mainText(page)).includes(UUID),
    (await mainText(page)).slice(0, 200));
  t.check('the keys list starts empty for this row', (await keys.innerText()).includes('None.'),
    await keys.innerText());
  const admins = (settings(ctx).web || {}).admins || [];
  t.check('this person is a roster row and not an administrator',
    !admins.includes(WHO) && admins.includes('admin@example.com'), JSON.stringify(admins));

  // --- 2. mint with restrict=all --------------------------------------------------------
  const rMint = await mintKey(page, 'self-serve');
  t.eq('the mint is answered 200', rMint.status(), 200);
  const mintedHtml = await page.content();
  const first = bearerIn(mintedHtml);
  t.check('the response shows a bbk_ bearer', !!first, mintedHtml.slice(0, 400));
  t.check('the bearer is the whole credential',
    !!first && first.startsWith('bbk_') && first.length >= 40, first);
  t.eq('the page shows that bearer exactly once', occurrences(mintedHtml, first), 1);
  t.check('the reveal page is headed by the key it made',
    (await page.locator('h1').innerText()).includes('self-serve'), await page.locator('h1').innerText());
  t.check('the file has the key', idsOf(ctx).includes('self-serve'), JSON.stringify(idsOf(ctx)));
  t.eq('restrict=all wrote no scopes field', (keyById(ctx, 'self-serve') || {}).scopes, undefined);
  t.eq('the key carries the window that was typed', (keyById(ctx, 'self-serve') || {}).duration, '365d');
  t.check('the file carries only the hash, never the bearer',
    !bytes(ctx).includes(first) && /^[0-9a-f]{64}$/.test((keyById(ctx, 'self-serve') || {}).key_hash || ''),
    JSON.stringify(keyById(ctx, 'self-serve')));

  // Back and a reload: the secret is gone, the key stays. A reload of the reveal page would
  // re-POST, so the walk is the one a person does: Back to the page, then reload *that*.
  await page.goBack();
  t.check('Back leaves the reveal page', page.url().endsWith(PAGE), page.url());
  t.check('the page from history shows no bearer', !(await mainText(page)).includes('bbk_'),
    (await mainText(page)).slice(0, 300));
  await page.reload();
  t.check('a reload of the page shows no bearer either', !(await mainText(page)).includes('bbk_'),
    (await mainText(page)).slice(0, 300));
  t.check('the reload lists the key', (await keys.innerText()).includes('self-serve'),
    await keys.innerText());
  t.eq('the file still has exactly one such key', idsOf(ctx).filter((i) => i === 'self-serve').length, 1);

  // --- 3. rotate -------------------------------------------------------------------------
  const hashBefore = (keyById(ctx, 'self-serve') || {}).key_hash;
  const rRot = await submit(page, `${keyForm(ROTATE, 'self-serve')} button`);
  t.eq('the rotate is answered 200', rRot.status(), 200);
  const rotHtml = await page.content();
  const second = bearerIn(rotHtml);
  t.check('the rotate shows a bbk_ bearer', !!second, rotHtml.slice(0, 400));
  t.check('the new bearer is not the mint\'s', !!second && second !== first,
    `${first} vs ${second}`);
  t.eq('the page shows the new bearer exactly once', occurrences(rotHtml, second), 1);
  t.eq('the rotate replaced the secret, not the key',
    idsOf(ctx).filter((i) => i === 'self-serve').length, 1);
  t.check('the file\'s key_hash changed in place',
    (keyById(ctx, 'self-serve') || {}).key_hash !== hashBefore, hashBefore);
  t.check('the new bearer is not in the file', !bytes(ctx).includes(second));

  // --- 4. revoke -------------------------------------------------------------------------
  // Freshen the page first: the rotate rewrote the file, so the form in history carries a rev
  // that is already stale, and a revoke submitted from it is a 409, not the flow under test.
  await page.goBack();
  await page.reload();
  const rRem = await submit(page, `${keyForm(REMOVE, 'self-serve')} button`);
  t.check('the revoke lands back on the page', page.url() === ctx.origin + PAGE, page.url());
  t.check('the key is gone from the file', !idsOf(ctx).includes('self-serve'), JSON.stringify(idsOf(ctx)));
  t.check('and gone from the list', !(await keys.innerText()).includes('self-serve'),
    await keys.innerText());

  // The status the browser followed is the thing under test, and a browser hides it: check it
  // at the HTTP level, on a key minted for the purpose.
  await mintKey(page, 'second');
  const r303 = await api(ctx, '/account/keys/remove', {
    method: 'POST',
    email: WHO,
    redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: ctx.origin },
    body: new URLSearchParams({ rev: sha256(bytes(ctx)), id: 'second' }).toString(),
  });
  t.eq('a revoke answers 303', r303.status, 303);
  t.eq('its Location is the page', r303.headers.get('location'), PAGE);
  t.check('the raw revoke removed the key', !idsOf(ctx).includes('second'), JSON.stringify(idsOf(ctx)));

  // --- 5. the same person at the console --------------------------------------------------
  const rAdmin = await page.goto(ctx.base + '/');
  t.eq('the same person is a 403 on the console', rAdmin.status(), 403);
  const refused = await mainText(page);
  t.check('the refusal names them', refused.includes(WHO), refused.slice(0, 300));
  t.check('and says they are not an administrator', refused.includes('Not an administrator'),
    refused.slice(0, 300));
  t.eq('the account page is still theirs', (await page.goto(url)).status(), 200);

  // --- 6. a stale rev across two tabs -----------------------------------------------------
  // Both tabs render from the same bytes; the first mint rewrites the file, so the second
  // tab's form carries a rev that is stale by exactly one write.
  const tabA = await noJs.newPage();
  const tabB = await noJs.newPage();
  await tabA.goto(url);
  await tabB.goto(url);
  const rA = await mintKey(tabA, 'first-tab');
  t.eq('the first tab\'s mint succeeds', rA.status(), 200);
  t.check('and reveals a bearer', !!bearerIn(await tabA.content()), (await tabA.content()).slice(0, 300));
  const rB = await mintKey(tabB, 'stale-tab');
  t.eq('the second tab\'s stale form is a 409', rB.status(), 409);
  const stale = await mainText(tabB);
  t.check('the 409 says the file changed', stale.includes('The file changed'), stale.slice(0, 300));
  t.check('it points back at the page',
    (await tabB.locator('a[href="/account/"]').count()) >= 1, page.url());
  t.check('the 409 shows no bearer', !stale.includes('bbk_'), stale.slice(0, 300));
  t.check('the stale tab minted nothing', !idsOf(ctx).includes('stale-tab'), JSON.stringify(idsOf(ctx)));
  t.eq('the file has exactly the first tab\'s key', idsOf(ctx), ['first-tab']);

  await page.close();
  await tabA.close();
  await tabB.close();
  await noJs.close();
}

module.exports = { run };
