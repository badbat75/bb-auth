'use strict';
// The Settings tab — the OTHER file. Five values the gate reads per request, plus the list
// of people this GUI opens for, all in one form guarded by the same hidden `rev`.
//
// What this area is really about is the boundary. The page must write settings.json and
// leave access.json alone; its `rev` must fingerprint the file it edits, or an out-of-band
// `bb-auth-adm settings set` would go unnoticed while every unrelated roster edit would
//409 it; and the two refusals that make it safe to hand an administrator — you may not
// empty the list, and you may not remove yourself — must fire before anything is written.

const {
  bytes, doc, writeDoc, settings, settingsBytes, writeSettings,
  newPage, submit, mainText, formBytes,
} = require('../lib/harness');

async function run(ctx, t) {
  const { context, page } = await newPage(ctx);
  try {
    // --- what the page shows is what the file says -------------------------------
    await page.goto(ctx.base + '/config?lang=en');
    t.eq('the tab is in the bar', await page.locator('header nav a.pill.on').innerText(), 'Settings');
    t.eq('identity_attrs comes from the file',
      await page.locator('textarea[name=identity]').inputValue(), 'email');
    t.eq('and so does the default lifetime',
      await page.locator('input[name=ttl]').inputValue(), '2592000');
    t.eq('the administrator list is the one that let us in',
      await page.locator('textarea[name=admins]').inputValue(), 'admin@example.com');
    await t.shot(page, 'settings');

    // The form fingerprints the settings file, not the access file. Both are on disk and
    // they differ, so this is a real distinction rather than a coincidence.
    const fields = await formBytes(page);
    const crypto = require('crypto');
    const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
    t.eq('the rev is the settings file own', fields.rev, sha(settingsBytes(ctx)));
    t.check('and not the access file one', fields.rev !== sha(bytes(ctx)));

    // --- a save writes the one file and not the other ----------------------------
    const accessBefore = bytes(ctx);
    await page.fill('textarea[name=identity]', 'email\nuuid');
    await page.fill('textarea[name=claims]', ' given_name \n\n family_name ');
    await page.fill('input[name=ttl]', '604800');
    await page.check('input[name=social]');
    await page.fill('textarea[name=providers]', 'Google');
    await page.fill('textarea[name=admins]', 'admin@example.com\nsecond@example.com');
    t.eq('the save redirects', (await submit(page)).status(), 200);
    t.check('and says so', (await mainText(page)).includes('settings saved'));

    const s = settings(ctx);
    t.eq('identity_attrs written in order', s.gate.identity_attrs, ['email', 'uuid']);
    t.eq('claims trimmed, blanks dropped', s.gate.profile_claims, ['given_name', 'family_name']);
    t.eq('the lifetime is seconds', s.gate.session_ttl_secs, 604800);
    t.eq('the social relaxation is on', s.gate.allow_unverified_social, true);
    t.eq('narrowed to one provider', s.gate.social_providers, ['Google']);
    t.eq('and a second administrator was added', s.web.admins.length, 2);
    t.check('the access file was not touched', bytes(ctx) === accessBefore);

    // The reload shows the file, so the derived headers are the file's own doing.
    await page.goto(ctx.base + '/config?lang=en');
    t.eq('the saved claims come back', await page.locator('textarea[name=claims]').inputValue(),
      'given_name\nfamily_name');
    t.check('the checkbox is ticked', await page.locator('input[name=social]').isChecked());

    // --- the two refusals that keep an administrator in the room -----------------
    const before = settingsBytes(ctx);
    await page.fill('textarea[name=admins]', 'second@example.com');
    t.eq('removing yourself is a 400', (await submit(page)).status(), 400);
    const self = await mainText(page);
    t.check('and says where it can be done', self.includes('bb-auth-adm'), self.slice(0, 400));

    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('textarea[name=admins]', '   ');
    t.eq('emptying the list is a 400', (await submit(page)).status(), 400);
    t.check('and says why', (await mainText(page)).includes('at least one administrator'));

    // A value the gate would refuse never reaches the disk either: the library is the one
    // that says so, in the sentence bb-auth-adm would print.
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('textarea[name=identity]', 'phone');
    t.eq('an unknown identity attribute is a 400', (await submit(page)).status(), 400);
    t.check('with the parser own words', (await mainText(page)).includes('unknown identity attribute'));

    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('input[name=ttl]', 'soon');
    t.eq('a lifetime that is not a number is a 400', (await submit(page)).status(), 400);

    t.check('none of the four refusals wrote anything', settingsBytes(ctx) === before);

    // --- the concurrency check, on the right file --------------------------------
    // An out-of-band `settings set` while the form was open: a 409, not a clobber.
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('input[name=ttl]', '999999');
    const oob = settings(ctx);
    oob.gate.session_ttl_secs = 86400;
    writeSettings(ctx, oob);
    t.eq('a stale rev is a 409', (await submit(page)).status(), 409);
    t.eq('the other writer edit survived', settings(ctx).gate.session_ttl_secs, 86400);

    // And the opposite: an edit to the ACCESS file must not 409 this form, because this
    // form is not about that file.
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('input[name=ttl]', '3600');
    const d = doc(ctx);
    d.users[0].notes = `oob ${d.users.length}`;
    writeDoc(ctx, d);
    t.eq('an unrelated roster edit does not 409 it', (await submit(page)).status(), 200);
    t.eq('and the save landed', settings(ctx).gate.session_ttl_secs, 3600);

    // --- Italian ------------------------------------------------------------------
    await page.goto(ctx.base + '/config?lang=it');
    const it = await mainText(page);
    t.check('the page is translated', it.includes('Impostazioni'), it.slice(0, 200));
    t.check('including the help text', it.includes('senza riavvio'), it.slice(0, 400));
    await t.shot(page, 'settings-it');
  } finally {
    await context.close();
  }
}

module.exports = { run };
