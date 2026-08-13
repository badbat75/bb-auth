'use strict';
// The no-JavaScript and PRG half of the design. Zero <script> tags is not an
// implementation detail: it is what makes the bfcache Back-button recovery on the 409
// reliable, and it means everything the suite tests is plain HTML semantics. PRG is the
// other half — a successful mutation answers 303 to `?msg=<key>`, so a reload of what
// the browser shows repeats nothing. And `can` answers with the gate's own decision
// function, read-only by construction.

const { doc, bytes, newPage, submit, mainText } = require('../lib/harness');

async function run(ctx, t) {
  const { context, page } = await newPage(ctx);
  try {
    // Zero scripts, sampled across page shapes: dashboard, list, form.
    for (const p of ['/', '/users', '/sites', '/users/bot%40example.com/keys/+add']) {
      await page.goto(ctx.base + p);
      t.eq(`no <script> on ${p}`, await page.locator('script').count(), 0);
    }

    // PRG: save, land on the msg page, reload it — a GET, so nothing can repeat.
    await page.goto(ctx.base + '/groups/mcp/edit');
    const urls = await page.locator('textarea[name=urls]').inputValue();
    await page.fill('textarea[name=urls]', urls);
    await submit(page);
    t.check('a save lands on a GET with ?msg=', page.url().includes('?msg=group-saved'), page.url());
    t.check('and renders the flash', (await page.locator('.flash').count()) >= 1);
    const afterSave = bytes(ctx);
    await page.reload();
    t.check('reloading the landing page re-posts nothing', bytes(ctx) === afterSave, 'reload wrote bytes');
    t.check('and stays on the same URL', page.url().includes('?msg=group-saved'), page.url());

    // `can` — would this credential get in? The form is a GET: asking is not an action.
    await page.goto(ctx.base + '/can');
    const method = await page.locator('main form').first().evaluate((f) => (f.getAttribute('method') || 'get'));
    t.eq('the can form is a GET', method.toLowerCase(), 'get');

    const before = bytes(ctx);
    const verdict = async (email, url) => {
      await page.goto(`${ctx.base}/can?email=${encodeURIComponent(email)}&url=${encodeURIComponent(url)}`);
      return mainText(page);
    };
    // The four corners of the grant model, answered by the library's own `decide`:
    t.check('a scoped user inside their scope is AUTHORIZED',
      (await verdict('bot@example.com', 'https://mcp.example.com/mcp/context7/x')).includes('AUTHORIZED'));
    t.check('denied outranks everything — spammer@ on a public_auth site is DENIED',
      (await verdict('spammer@example.com', 'https://app.example.com/app1')).includes('DENIED'));
    t.check('public_auth grants on identity alone — a stranger is AUTHORIZED there',
      (await verdict('stranger@example.com', 'https://app.example.com/app1')).includes('AUTHORIZED'));
    t.check('no grant source, no access — the same stranger elsewhere is DENIED',
      (await verdict('stranger@example.com', 'https://nowhere.example.com/')).includes('DENIED'));
    await t.shot(page, 'can-denied');

    t.check('asking `can` wrote nothing', bytes(ctx) === before, 'can mutated the file');
  } finally {
    await context.close();
  }
}

module.exports = { run };
