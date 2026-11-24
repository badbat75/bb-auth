'use strict';
// The self-service page at `/account`, driven as a roster person who is **not** on
// `web.admins` (`you@example.com`), with scripting off. Every other area drives `ctx.base`;
// this one drives the sibling prefix, which is the half of the binary a person who is not an
// administrator reaches (docs/ARCHITECTURE.md §13).
//
// Scripting off is the point of the area and not a garnish: this page carries no handler at
// all, not even the console's two list boxes, so every mutation here is a plain link to a
// confirmation and a plain form `POST`, and the reveal-once bearer has to survive a Back
// button and a reload in a browser running no code. The one page under the prefix that emits
// a `<script>` is the bearer reveal (§13.14), and its script is the copy icon and nothing
// else: with scripting off the key is still shown, in `#bearer`, and the icon is not shown.
//
// The contract checked, in order: the keys table and its `+ New key` row (§13.16); the
// duration chosen from five, each choice landing on the file as the file spells it (six
// months, a custom number of days, and no expiry at all); a refusal that keeps the row open
// and writes nothing; a mint that reveals a `bbk_` bearer exactly once while the file keeps
// only its hash; rotate and revoke **through their confirmations**, cancelling each first, so
// a person who changes their mind keeps the credential and a person who means it replaces or
// removes exactly one secret; the same identity is a `403` on the console; and a form left
// open in a second tab is a `409` that mints nothing.

const { doc, bytes, sha256, settings, api, submit, mainText } = require('../lib/harness');

const WHO = 'you@example.com';
const UUID = '8f14e45f-ceea-467a-9f79-3b4e5c6d7a8b';
// Somebody else's row, and one of **their** key ids, for the case that must not become a way
// to read whose keys are whose: `deploy/access.example.json` files `laptop` under them.
const OTHER = 'bot@example.com';
const OTHER_KEY = 'laptop';
const PAGE = '/account/';
const NEW = '/account/keys/new';
// The mint form is a page of its own (§13.16): the keys table's `+` opens it, so the row it
// opens appears at the end of that table. It is named by its `action`, so a selector can
// never pick the confirmation forms, which live on other paths.
const MINT = 'form[action="/account/keys"]';
const DUR = `${MINT} select[name=duration]`;
// The two destructive paths, each reached by a link and answered by a confirmation card
// (§13.15), whose `POST` is the only thing that mutates.
const ROTATE = 'form[action="/account/keys/rotate"]';
const REMOVE = 'form[action="/account/keys/remove"]';
// One key's own row action, so an assertion about key A cannot be satisfied by key B's link.
const rotateLink = (id) => `a[href="/account/keys/rotate?id=${id}"]`;
const removeLink = (id) => `a[href="/account/keys/remove?id=${id}"]`;
/** A path the document names, as a URL `page.goto` accepts. Every `href` and `action` the
 *  pages emit is root-relative (`/account/keys/new`), which is what a browser resolves
 *  against the document and what `goto` refuses outright. The origin belongs to the page that
 *  carried the link, so it is read from there rather than rebuilt from the harness. */
const abs = (page, href) => new URL(href, page.url()).href;

/** The caller's own keys, straight off the file the gate would load. */
const myKeys = (ctx) =>
  (doc(ctx).users.find((u) => (u.emails || []).includes(WHO)).api_keys || []);
const idsOf = (ctx) => myKeys(ctx).map((k) => k.id);
const keyById = (ctx, id) => myKeys(ctx).find((k) => k.id === id);

/** The date a key stops working, out of the two fields the file carries. This is the gate's
 *  own arithmetic (`key_expiry`: `released` plus `duration`), so the assertion is about the
 *  window the gate honours, and not about a date a page printed. */
const expiryOf = (k) => {
  if (k.duration === 'never' || k.duration === '0' || k.duration === '-') return 'never';
  const m = /^(\d+)d$/.exec(k.duration);
  if (!m) return `?${k.duration}`;
  const at = new Date(`${k.released}T00:00:00Z`);
  at.setUTCDate(at.getUTCDate() + Number(m[1]));
  return at.toISOString().slice(0, 10);
};
/** Today, in the file's own spelling (UTC), so a mint's `released` is checked, not assumed. */
const today = () => new Date().toISOString().slice(0, 10);
const inDays = (n) => {
  const at = new Date();
  at.setUTCDate(at.getUTCDate() + n);
  return at.toISOString().slice(0, 10);
};

/** The bearer a reveal page shows: the text of `code#bearer` and nothing else (§13.14). The
 *  page shows the key alone, so this is the same string a click selects and the icon copies. */
const bearerIn = (html) => (html.match(/<code id="bearer"[^>]*>([^<]*)<\/code>/) || [])[1];
const occurrences = (hay, needle) => (needle ? hay.split(needle).length - 1 : 0);

// With scripting off, `page.evaluate` is unavailable, so the page-shape checks parse the
// document text the same way a reviewer would read it.
const tags = (html, re) => (html.match(re) || []);

/** The markup of one section, by id, as the server wrote it. */
const sectionOf = (html, id) => (new RegExp(`<section id="${id}"[\\s\\S]*?</section>`).exec(html) || [''])[0];
/** Every match of `re` in `s`, as strings. */
const all = (s, re) => [...s.matchAll(re)].map((m) => m[0]);
/** The words inside a tag, with the markup stripped. */
const words = (s) => s.replace(/<[^>]*>/g, '').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
/** Every `<a>` in `s`, read attribute by attribute, so no assertion depends on the order
 *  the attributes are written in. */
const anchors = (s) => [...s.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/g)].map((m) => ({
  html: m[0],
  text: words(m[2]),
  href: (/\bhref="([^"]*)"/.exec(m[1]) || [])[1] || '',
  cls: (/\bclass="([^"]*)"/.exec(m[1]) || [])[1] || '',
  label: (/\baria-label="([^"]*)"/.exec(m[1]) || [])[1] || '',
  title: (/\btitle="([^"]*)"/.exec(m[1]) || [])[1] || '',
}));
/** The class list of a tag, so a check is about the classes and not about the order the
 *  attributes are written in: the console's table cells carry `data-label` (the phone
 *  stacking label) beside `class`, and a regex demanding `class="mono">` is a regex about
 *  the order, which the phone rule breaks. */
const classesOf = (tag) => ((/\bclass="([^"]*)"/.exec(tag) || [])[1] || '').split(/\s+/).filter(Boolean);
/** What a person reads: the stylesheets and scripts every page inlines are stripped, then the
 *  markup. A "this refusal names nobody" check on the raw bytes is a check on the palette's
 *  comments, which say `decide`, `specificity` and `opacity`, so a key called `ci` is named by
 *  every page in the estate, including one that names nothing. */
const readable = (html) => words(html
  .replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
  .replace(/<script\b[\s\S]*?<\/script>/gi, ' '));

async function run(ctx, t) {
  const url = ctx.origin + PAGE;
  const noJs = await ctx.browser.newContext({
    viewport: { width: 1280, height: 900 },
    extraHTTPHeaders: { 'X-Auth-Email': WHO },
    javaScriptEnabled: false,
  });
  const page = await noJs.newPage();
  const keys = page.locator('#keys');

  /** The walk a person does, in the two halves a stale-form test needs to interrupt. */
  const openMint = async (p) => {
    await p.goto(url);
    await p.click(`a[href="${NEW}"]`);
  };
  const fillMint = async (p, id, duration, days) => {
    await p.fill(`${MINT} input[name=id]`, id);
    await p.selectOption(DUR, duration);
    if (days !== undefined) await p.fill(`${MINT} input[name=days]`, days);
  };
  const sendMint = (p) => submit(p, `${MINT} button[type=submit]`);
  const mintKey = async (p, id, duration, days) => {
    await openMint(p);
    await fillMint(p, id, duration, days);
    return sendMint(p);
  };

  // --- 1. the page renders, with scripting off -----------------------------------------
  const open = await page.goto(url);
  t.eq('the page answers 200 to a roster person who is not an administrator', open.status(), 200);
  const html = await page.content();
  t.eq('the page carries no <script> tag', tags(html, /<script/i).length, 0);
  t.eq('and no handler of any kind', tags(html, /<[^>]*\son[a-z]+\s*=/gi).length, 0);
  t.eq('the keys section is on the page', await keys.count(), 1);
  t.eq('its heading is the page\'s own words', (await keys.locator('h2').first().innerText()).trim(), 'API keys');
  t.check('the keys list starts empty for this row', (await keys.innerText()).includes('No API keys'),
    await keys.innerText());
  // §13.16: an empty section is a sentence, not a table with no rows. A table with a header
  // and nothing under it reads as a page that lost its data.
  const empty = sectionOf(html, 'keys');
  t.eq('an empty section carries no table', tags(empty, /<table\b/g).length, 0);
  t.eq('and the sentence is a muted paragraph of the section', tags(empty, /<p class="muted">/g).length, 1);
  t.eq('the page offers the way to add a key', await page.locator(`a[href="${NEW}"]`).count(), 1);
  t.check('the + says what it adds in words', (await page.locator(`a[href="${NEW}"]`).innerText()).includes('New key'),
    await page.locator(`a[href="${NEW}"]`).innerText());
  t.eq('and the mint form is not on this page, so the table is all a person reads first',
    await page.locator(MINT).count(), 0);
  const admins = (settings(ctx).web || {}).admins || [];
  t.check('this person is a roster row and not an administrator',
    !admins.includes(WHO) && admins.includes('admin@example.com'), JSON.stringify(admins));
  const text = await mainText(page);
  t.check('the caller is named with the address the header carried',
    text.includes('signed in as') && text.includes(WHO), text.slice(0, 200));
  t.check('and the page names their uuid', text.includes(UUID), text.slice(0, 200));

  // --- 2. the mint page: five choices, one picked --------------------------------------
  const openNew = await page.goto(abs(page, NEW));
  t.eq('the mint form is a page of its own', openNew.status(), 200);
  t.eq('it posts to the keys path',
    (await page.locator(MINT).getAttribute('method') || '').toLowerCase(), 'post');
  const rev = await page.locator(`${MINT} input[name=rev]`).inputValue();
  t.eq('its hidden rev is the sha256 of the file\'s exact bytes', rev, sha256(bytes(ctx)));
  const idField = page.locator(`${MINT} input[name=id]`);
  t.eq('the name field is required, so the first click cannot mint a keyless row',
    await idField.getAttribute('required') !== null, true);
  t.eq('and it states the grammar the server checks', await idField.getAttribute('pattern'), '[a-z0-9-]{1,32}');
  t.check('and it takes the focus, so the page is ready to type in',
    await idField.getAttribute('autofocus') !== null, true);
  // §13.16: the row is a row of the keys table, opened on a page of its own, so it spans the
  // table's four columns and is built out of the console's own form component.
  t.eq('the row is one cell across the table\'s four columns',
    await page.locator('td[colspan="4"]').count(), 1);
  t.eq('and it is a form.edit posting to the keys path',
    await page.locator('td[colspan="4"] form.edit').count(), 1);
  const dur = page.locator(DUR);
  const values = [];
  // `labels`, not `words`: the module's `words(s)` strips markup out of a tag, and this area
  // calls it further down. A local of that name here shadows it for the whole `run` body, and
  // the call site is 100 lines away, where it fails as "words is not a function".
  const labels = [];
  for (let i = 0, n = await dur.locator('option').count(); i < n; i++) {
    const opt = dur.locator('option').nth(i);
    values.push(await opt.getAttribute('value'));
    labels.push((await opt.innerText()).trim());
  }
  t.eq('five choices, longest to shortest, then no expiry, each spelled as the file spells it',
    values, ['365d', '182d', '91d', 'custom', 'never']);
  t.check('and each says its window in words',
    /year/.test(labels[0]) && /6.*month/.test(labels[1]) && /3.*month/.test(labels[2])
      && /day/.test(labels[3]) && /never/.test(labels[4]), JSON.stringify(labels));
  t.eq('a year is picked, so no click can mint with no duration named',
    await dur.inputValue(), '365d');
  t.check('the custom box is named for a screen reader, having no label of its own',
    (await page.locator(`${MINT} input[name=days]`).getAttribute('aria-label') || '').length > 0, true);
  const restrict = page.locator(`${MINT} input[name=restrict]`);
  const offered = [];
  for (let i = 0, n = await restrict.count(); i < n; i++) offered.push(await restrict.nth(i).getAttribute('value'));
  t.eq('restrict=all is on offer and checked',
    offered.length === 1 && offered[0] === 'all' && (await restrict.getAttribute('checked')) !== null, true);
  t.eq('the mint page carries no script', tags(await page.content(), /<script/i).length, 0);
  t.eq('and does not offer to open itself again', await page.locator(`a[href="${NEW}"]`).count(), 0);
  t.check('it carries the way back out', (await page.locator(`${MINT} a.pill`).innerText()).includes('cancel'),
    await page.locator(`${MINT} a.pill`).innerText());

  // --- 3. six months --------------------------------------------------------------------
  const r6 = await mintKey(page, 'half-year', '182d');
  t.eq('the mint is answered 200', r6.status(), 200);
  const mintedHtml = await page.content();
  const first = bearerIn(mintedHtml);
  t.check('the response shows a bbk_ bearer', !!first, mintedHtml.slice(0, 400));
  t.check('the bearer is the whole credential',
    !!first && first.startsWith('bbk_') && first.length >= 40, first);
  t.eq('the page shows that bearer exactly once', occurrences(mintedHtml, first), 1);
  t.check('the reveal shows the key alone, with no Authorization line',
    !mintedHtml.includes('Authorization'), mintedHtml.slice(0, 400));
  t.eq('the reveal response carries exactly one <script>', tags(mintedHtml, /<script/i).length, 1);
  const copy = page.locator('#bearer-copy');
  t.eq('the copy control is on the page', await copy.count(), 1);
  t.check('it is a button that can never submit a form',
    (await copy.getAttribute('type')) === 'button', await copy.getAttribute('type'));
  t.eq('it is the shared icon component, not a box of its own',
    await copy.getAttribute('class'), 'pill ico');
  // §13.17: an icon is named by text a reader speaks, not by an attribute a tooltip owns.
  // The name the person hears and the name the pointer shows are then one string, and
  // `textContent` is read from the element so the answer does not depend on the button
  // being unhidden by the reveal's script.
  t.check('the name is hidden text inside the control, and the tooltip says the same',
    (await copy.locator('span.vh').innerText()) === 'Copy the key'
      && (await copy.getAttribute('title')) === 'Copy the key',
    await copy.evaluate((el) => el.outerHTML.slice(0, 220)));
  t.eq('and there is no second naming mechanism for it to drift from',
    await copy.getAttribute('aria-label'), null);
  t.eq('the only words inside the button are that name',
    (await copy.evaluate((el) => el.textContent.trim())), 'Copy the key');
  t.eq('the word the click writes is served empty, because no click has happened',
    (await page.locator('#bearer-copy-status').innerText()).trim(), '');
  t.eq('it carries hidden, so the server never shows a dead control',
    (await copy.getAttribute('hidden')) !== null, true);
  t.eq('and a browser running no code shows it not', await copy.isVisible(), false);
  t.check('the reveal page is headed by the key it made',
    (await page.locator('h1').innerText()).includes('half-year'), await page.locator('h1').innerText());
  t.check('the file has the key', idsOf(ctx).includes('half-year'), JSON.stringify(idsOf(ctx)));
  t.eq('restrict=all wrote no scopes field', (keyById(ctx, 'half-year') || {}).scopes, undefined);
  const k6 = keyById(ctx, 'half-year') || {};
  t.eq('six months is stored as 182 days, the file\'s own spelling', k6.duration, '182d');
  t.eq('the key is stamped released today', k6.released, today());
  t.eq('and the gate reads its window as six months from today', expiryOf(k6), inDays(182));
  t.check('the file carries only the hash, never the bearer',
    !bytes(ctx).includes(first) && /^[0-9a-f]{64}$/.test(k6.key_hash || ''), JSON.stringify(k6));

  // Back and a reload: the secret is gone, the key stays. A reload of the reveal page would
  // re-POST, so the walk is the one a person does: Back to the mint page, then reload *that*.
  await page.goBack();
  t.check('Back leaves the reveal page', page.url().endsWith(NEW), page.url());
  t.check('the page from history shows no bearer', !(await mainText(page)).includes('bbk_'),
    (await mainText(page)).slice(0, 300));
  await page.reload();
  t.check('a reload of the mint page shows no bearer either', !(await mainText(page)).includes('bbk_'),
    (await mainText(page)).slice(0, 300));
  t.eq('and no script: the reveal is the only page in this area that carries one',
    tags(await page.content(), /<script/i).length, 0);
  t.check('the reload lists the key', (await keys.innerText()).includes('half-year'),
    await keys.innerText());
  t.eq('the file still has exactly one such key', idsOf(ctx).filter((i) => i === 'half-year').length, 1);

  // --- 4. a custom number of days, and no expiry at all ---------------------------------
  const r40 = await mintKey(page, 'forty', 'custom', '40');
  t.eq('a custom number is minted', r40.status(), 200);
  const k40 = keyById(ctx, 'forty') || {};
  t.eq('a bare number gets the unit the grammar needs', k40.duration, '40d');
  t.eq('and the window is forty days from today', expiryOf(k40), inDays(40));

  const rNever = await mintKey(page, 'no-end', 'never');
  t.eq('the self-service page mints a key that never expires', rNever.status(), 200);
  const kNever = keyById(ctx, 'no-end') || {};
  t.eq('the file carries the word, not a date invented for it', kNever.duration, 'never');
  t.eq('and the gate reads it as no expiry', expiryOf(kNever), 'never');
  await page.goto(url);
  t.check('the list says so in words, not by an empty cell',
    (await keys.innerText()).includes('never expires'), await keys.innerText());

  // --- the table the section is (§13.16) ------------------------------------------------
  // Three keys are on the row now, so this is the shape a person with keys sees; the empty
  // state above is the other half. Read out of the served bytes, because this area runs with
  // scripting off and the shape is the contract, not the layout.
  const sec = sectionOf(await page.content(), 'keys');
  t.eq('the section carries one table', tags(sec, /<table\b/g).length, 1);
  t.eq('with one tbody', tags(sec, /<tbody\b/g).length, 1);
  const th = all(sec, /<th\b[^>]*>[\s\S]*?<\/th>/g);
  t.eq('four columns, the last the actions, which needs no heading', th.length, 4);
  t.eq('the last heading is empty', words(th[3] || ''), '');
  t.check('the other three are the name, the scopes and the expiry',
    /name/i.test(words(th[0] || '')) && /scope/i.test(words(th[1] || ''))
      && /expir/i.test(words(th[2] || '')), JSON.stringify(th.map(words)));
  const rows = all(sec, /<tr\b[^>]*>[\s\S]*?<\/tr>/g).filter((r) => /<td\b/.test(r));
  t.eq('one row per key', rows.length, 3);
  const acts = anchors(sec);
  for (const id of ['half-year', 'forty', 'no-end']) {
    const row = rows.find((r) => new RegExp(`>\\s*${id}\\s*<`).test(r)) || '';
    t.check(`the ${id} row is there`, !!row, rows.join('\n').slice(0, 400));
    const firstTd = (/^<tr\b[^>]*>\s*(<td\b[^>]*>)/.exec(row) || [])[1] || '';
    t.check('its name is in a mono cell, the console\'s spelling for an identifier',
      classesOf(firstTd).includes('mono'), row.slice(0, 200));
    t.check('its actions are one pills cell holding a span.pills',
      /<td class="pills">[\s\S]*<span class="pills">/.test(row), row.slice(0, 300));
    const rot = acts.find((a) => a.href === `/account/keys/rotate?id=${id}`);
    const rm = acts.find((a) => a.href === `/account/keys/remove?id=${id}`);
    t.check(`rotate for ${id} is a link, not a form`, !!rot && rot.cls.split(' ').includes('pill'),
      JSON.stringify(rot));
    t.check(`rotate for ${id} says the verb, and names the key for a reader`,
      !!rot && /rotate/i.test(rot.text) && rot.label === `Rotate key ${id}`, JSON.stringify(rot));
    // §13.17: a destructive icon is the pill, squared, named by text a reader speaks. The
    // tooltip repeats that text, and there is no `aria-label` for the two to drift apart.
    t.check(`revoke for ${id} is the shared icon component`,
      !!rm && rm.cls === 'pill rm ico' && /<svg\b[^>]*aria-hidden="true"/.test(rm.html),
      JSON.stringify((rm && rm.html) || ''));
    t.check(`revoke for ${id} is named by hidden text and a tooltip, never by aria-label`,
      !!rm && rm.text === `Revoke key ${id}` && rm.title === `Revoke key ${id}` && rm.label === '',
      JSON.stringify(rm));
  }
  t.eq('the plain page carries no form that mutates a key',
    tags(sec, /<form\b[^>]*method=["']post["']/gi).length, 0);
  const plus = acts.find((a) => a.href === NEW);
  // §13.16: the console's add control is `p.primary` **holding** an `a.pill`, so `primary` is
  // the paragraph's class and not the link's, and the paragraph sits under the table because
  // the row the link opens lands at the table's end.
  const plusBlock = (/<p class="primary">[\s\S]*?<\/p>/.exec(sec) || [''])[0];
  t.check('the + is the console\'s add control: an a.pill inside p.primary, below the table '
    + 'where the row it opens lands',
    !!plus && plus.cls === 'pill' && plusBlock.includes(plus.html)
      && sec.indexOf('</table>') < sec.indexOf(plusBlock),
    JSON.stringify({ cls: (plus && plus.cls) || '', plusBlock: plusBlock.slice(0, 160) }));
  t.check('the section names no URL: a person reads places, not patterns',
    !/https?:\/\//.test(sec), sec.slice(0, 400));

  // The custom box's refusals, the half that protects a person from a key that outlives its
  // reason: an empty box is a refusal and not a default, and the row stays open with the
  // value kept, so the fix is a keystroke and not a re-mint.
  const before = bytes(ctx);
  const rBad = await mintKey(page, 'nope', 'custom', '');
  t.eq('an empty custom box is refused', rBad.status(), 400);
  t.check('the refusal says what to type', (await mainText(page)).includes('whole number of days'),
    (await mainText(page)).slice(0, 300));
  t.check('the row stays open with the name kept',
    (await page.locator(`${MINT} input[name=id]`).inputValue()) === 'nope',
    await page.locator(`${MINT} input[name=id]`).inputValue());
  t.eq('a refused mint writes nothing', bytes(ctx), before);
  t.check('and the key is not there', !idsOf(ctx).includes('nope'), JSON.stringify(idsOf(ctx)));

  // A name the grammar refuses, which is the other half of "the row stays open": the mark
  // sits on the field that caused it (§13.16), so the fix is a keystroke and not a re-mint.
  await page.goto(abs(page, NEW));
  const beforeId = bytes(ctx);
  await page.fill(`${MINT} input[name=id]`, 'My Laptop');
  const rBadId = await submit(page, `${MINT} button[type=submit]`);
  t.eq('a name the grammar refuses is a 400', rBadId.status(), 400);
  t.eq('the row stays open', await page.locator(MINT).count(), 1);
  t.eq('with the name kept exactly as it was typed',
    await page.locator(`${MINT} input[name=id]`).inputValue(), 'My Laptop');
  t.check('the mark is on the name field, not on the page',
    (await page.locator(`${MINT} input[name=id]`).getAttribute('class') || '').includes('invalid')
      && (await page.locator(`${MINT} input[name=id]`).getAttribute('aria-invalid')) === 'true',
    await page.locator(`${MINT} input[name=id]`).getAttribute('class'));
  t.check('the message names the grammar it failed',
    /lowercase/i.test(await page.locator('div.err').first().innerText()),
    await page.locator('div.err').first().innerText());
  t.eq('and a refused name writes nothing', bytes(ctx), beforeId);
  t.check('the key is not there', !idsOf(ctx).includes('My Laptop'), JSON.stringify(idsOf(ctx)));

  // --- 5. rotate, through its confirmation ----------------------------------------------
  // Freshen the page first: every mint rewrote the file, so a form left in history carries a
  // rev that is already stale, and a mutation submitted from it is a 409, not the flow here.
  await page.goto(url);
  const hashBefore = (keyById(ctx, 'no-end') || {}).key_hash;
  await page.click(rotateLink('no-end'));
  t.check('the rotate link opens a confirmation, and does not rotate',
    page.url().includes('/account/keys/rotate?id=no-end'), page.url());
  const cardText = await mainText(page);
  t.check('the card names the key it is about to replace', cardText.includes('no-end'),
    cardText.slice(0, 300));
  t.check('the card shows no secret, because a confirmation is not a reveal',
    !cardText.includes('bbk_'), cardText.slice(0, 300));
  t.eq('the card carries the fingerprint of the file as this page read it',
    await page.locator(`${ROTATE} input[name=rev]`).inputValue(), sha256(bytes(ctx)));
  t.eq('and this key\'s id', await page.locator(`${ROTATE} input[name=id]`).inputValue(), 'no-end');
  await page.click(`${ROTATE} a.pill`);
  t.check('cancelling lands back on the page', page.url().endsWith(PAGE), page.url());
  t.check('cancelling left the secret alone', (keyById(ctx, 'no-end') || {}).key_hash === hashBefore,
    JSON.stringify(keyById(ctx, 'no-end')));
  t.check('and the key is still listed', (await keys.innerText()).includes('no-end'),
    await keys.innerText());

  await page.click(rotateLink('no-end'));
  const rRot = await submit(page, `${ROTATE} button`);
  t.eq('confirming the rotate is answered 200', rRot.status(), 200);
  const rotHtml = await page.content();
  const second = bearerIn(rotHtml);
  t.check('the rotate shows a bbk_ bearer', !!second, rotHtml.slice(0, 400));
  t.check('the new bearer is not the mint\'s', !!second && second !== first, `${first} vs ${second}`);
  t.eq('the page shows the new bearer exactly once', occurrences(rotHtml, second), 1);
  t.eq('the rotate response carries exactly one <script>', tags(rotHtml, /<script/i).length, 1);
  t.check('the rotate replaced the secret, not the key',
    idsOf(ctx).filter((i) => i === 'no-end').length, 1);
  const kRot = keyById(ctx, 'no-end') || {};
  t.check('the file\'s key_hash changed in place', kRot.key_hash !== hashBefore, hashBefore);
  t.eq('a rotate of a key with no expiry keeps it that way', kRot.duration, 'never');
  t.check('the new bearer is not in the file', !bytes(ctx).includes(second));

  // --- 6. revoke, through its confirmation ----------------------------------------------
  await page.goto(url);
  await page.click(removeLink('no-end'));
  t.check('the revoke link opens a confirmation, and does not revoke',
    page.url().includes('/account/keys/remove?id=no-end'), page.url());
  const rmText = await mainText(page);
  t.check('the card names the key it is about to remove', rmText.includes('no-end'), rmText.slice(0, 300));
  t.check('the card says in words what the button does', /revok/i.test(rmText), rmText.slice(0, 300));
  t.eq('the card carries a fresh fingerprint',
    await page.locator(`${REMOVE} input[name=rev]`).inputValue(), sha256(bytes(ctx)));
  t.eq('and this key\'s id', await page.locator(`${REMOVE} input[name=id]`).inputValue(), 'no-end');
  await page.click(`${REMOVE} a.pill`);
  t.check('cancelling lands back on the page', page.url().endsWith(PAGE), page.url());
  t.check('cancelling left the key in the file', idsOf(ctx).includes('no-end'), JSON.stringify(idsOf(ctx)));
  t.check('and still listed', (await keys.innerText()).includes('no-end'), await keys.innerText());

  await page.click(removeLink('no-end'));
  await submit(page, `${REMOVE} button`);
  t.check('confirming the revoke lands back on the page', page.url() === ctx.origin + PAGE, page.url());
  t.check('the key is gone from the file', !idsOf(ctx).includes('no-end'), JSON.stringify(idsOf(ctx)));
  t.check('and gone from the list', !(await keys.innerText()).includes('no-end'), await keys.innerText());
  t.check('the other keys stand', idsOf(ctx).includes('half-year') && idsOf(ctx).includes('forty'),
    JSON.stringify(idsOf(ctx)));

  // The status the browser followed is the thing under test, and a browser hides it: check it
  // at the HTTP level, on a key minted for the purpose.
  await mintKey(page, 'second', '365d');
  const r303 = await api(ctx, '/account/keys/remove', {
    method: 'POST',
    email: WHO,
    redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: ctx.origin },
    body: new URLSearchParams({ rev: sha256(bytes(ctx)), id: 'second' }).toString(),
  });
  t.eq('a confirmed revoke answers 303', r303.status, 303);
  t.eq('its Location is the page', r303.headers.get('location'), PAGE);
  t.check('the raw revoke removed the key', !idsOf(ctx).includes('second'), JSON.stringify(idsOf(ctx)));

  // A confirmation asked for a key the caller does not have is a 404 that names nothing: the
  // step must not become a way to read whose keys are whose. `laptop` is on another row, so
  // the answer must not confirm that by naming its owner.
  const r404 = await api(ctx, `/account/keys/remove?id=${OTHER_KEY}`, { email: WHO });
  t.eq('a key on somebody else\'s row is a 404', r404.status, 404);
  const ghost = await r404.text();
  // Readable text, not bytes: every page inlines the stylesheets, whose comments say `decide`
  // and `specificity`, so a raw-bytes scan names `ci` on a page that names nothing.
  const ghostWords = readable(ghost);
  t.check('and it names no other person', !ghostWords.includes(OTHER), ghostWords.slice(0, 300));
  t.check('and no other key of theirs', !ghostWords.includes('ci'), ghostWords.slice(0, 300));

  // --- 7. the same person at the console --------------------------------------------------
  const rAdmin = await page.goto(ctx.base + '/');
  t.eq('the same person is a 403 on the console', rAdmin.status(), 403);
  const refused = await mainText(page);
  t.check('the refusal names them', refused.includes(WHO), refused.slice(0, 300));
  t.check('and says they are not an administrator', refused.includes('Not an administrator'),
    refused.slice(0, 300));
  t.eq('the account page is still theirs', (await page.goto(url)).status(), 200);

  // --- 8. a stale rev across two tabs -----------------------------------------------------
  // Tab B opens the mint page and fills it while the file is current; tab A's mint then
  // rewrites the file, so B's form carries a rev that is stale by exactly one write.
  const tabA = await noJs.newPage();
  const tabB = await noJs.newPage();
  const rA = await mintKey(tabA, 'first-tab', '365d');
  t.eq('the first tab\'s mint succeeds', rA.status(), 200);
  t.check('and reveals a bearer', !!bearerIn(await tabA.content()), (await tabA.content()).slice(0, 300));
  await openMint(tabB);
  await fillMint(tabB, 'stale-tab', '365d');
  const rWrite = await mintKey(tabA, 'third-tab', '365d');
  t.eq('a second mint from the first tab rewrites the file', rWrite.status(), 200);
  const rB = await sendMint(tabB);
  t.eq('the second tab\'s stale form is a 409', rB.status(), 409);
  const stale = await mainText(tabB);
  t.check('the 409 says the file changed', stale.includes('The file changed'), stale.slice(0, 300));
  t.check('it points back at the page',
    (await tabB.locator('a[href="/account/"]').count()) >= 1, tabB.url());
  t.check('the 409 shows no bearer', !stale.includes('bbk_'), stale.slice(0, 300));
  t.eq('the 409 carries no script: nothing was minted, so there is nothing to copy',
    tags(await tabB.content(), /<script/i).length, 0);
  t.check('the stale tab minted nothing', !idsOf(ctx).includes('stale-tab'), JSON.stringify(idsOf(ctx)));
  t.check('the two mints that were current both landed',
    idsOf(ctx).includes('first-tab') && idsOf(ctx).includes('third-tab'), JSON.stringify(idsOf(ctx)));

  await page.close();
  await tabA.close();
  await tabB.close();
  await noJs.close();
}

module.exports = { run };
