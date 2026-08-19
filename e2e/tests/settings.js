'use strict';
// The Settings tab — the OTHER file. The values the gate reads per request, the list
// of people this GUI opens for, and the look BOTH programs wear, all in one form guarded by
// the same hidden `rev`.
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

    // --- the look, which is the one section BOTH programs read --------------------
    // It is on this page because it passes the same three-part rule the rest of the file
    // does, and the proof that it is live is the page you are looking at: save a stylesheet
    // and the very next render links it.
    await page.goto(ctx.base + '/config?lang=en');
    t.eq('no override is configured to start with',
      await page.locator('input[name=stylesheet]').inputValue(), '');
    t.check('and the page links nothing at all',
      (await page.locator('link[rel=stylesheet]').count()) === 0);
    t.check('while carrying the whole palette itself',
      (await page.locator('style').innerText()).includes('--accent:'));

    await page.fill('input[name=brand]', 'BadBat75');
    await page.fill('input[name=stylesheet]', 'https://assets.example.com/css/theme.css');
    await page.fill('input[name=logo]', '/img/logo.png');
    await page.selectOption('select[name=ui_theme]', 'dark');
    t.eq('the look saves', (await submit(page)).status(), 200);

    const look = settings(ctx).ui;
    t.eq('the stylesheet is written', look.stylesheet_url, 'https://assets.example.com/css/theme.css');
    t.eq('a root-relative logo is a shape it takes', look.logo_url, '/img/logo.png');
    t.eq('the brand is trimmed prose', look.brand_name, 'BadBat75');
    t.eq('and the theme is one of three words', look.theme, 'dark');

    await page.goto(ctx.base + '/config?lang=en');
    t.eq('the page now links it, once',
      await page.locator('link[rel=stylesheet]').getAttribute('href'),
      'https://assets.example.com/css/theme.css');
    t.eq('the deployment default reaches the html element',
      await page.locator('html').getAttribute('data-theme'), 'dark');
    // The visitor's own choice still wins over the deployment's default: the Settings menu
    // in the header is a preference, not a second copy of this field.
    await page.goto(ctx.base + '/config?lang=en&theme=light');
    t.eq('and a visitor override outranks it',
      await page.locator('html').getAttribute('data-theme'), 'light');

    // A URL the library refuses is refused here, attributed to its own field.
    await page.goto(ctx.base + '/config?lang=en');
    const lookBefore = settingsBytes(ctx);
    await page.fill('input[name=stylesheet]', 'javascript:alert(1)');
    t.eq('a stylesheet that is not a stylesheet is a 400', (await submit(page)).status(), 400);
    t.check('with the library own words', (await mainText(page)).includes('stylesheet_url'));
    t.check('and nothing written', settingsBytes(ctx) === lookBefore);

    // Put it back, so the refusal tests below start from a file that works.
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('input[name=stylesheet]', '');
    t.eq('and it can be unset again', (await submit(page)).status(), 200);
    t.eq('empty means unset', settings(ctx).ui.stylesheet_url, '');

    // --- the two-step, on the five that can shut the door -----------------------
    // A save that takes away one of the things people get in through is SHOWN before it is
    // written. It matters here rather than only in a unit test because it is a second form
    // round trip with no script behind it: the panel, the hidden token and the button are
    // the whole mechanism, and nojs.js runs this same page with scripting off.
    await page.goto(ctx.base + '/config?lang=en');
    const poolBefore = settings(ctx).gate.issuer;
    const otherPool = 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_OTHER';
    await page.fill('input[name=issuer]', otherPool);
    t.eq('moving the pool is held, not refused', (await submit(page)).status(), 200);
    const held = await mainText(page);
    t.check('the page says what it costs', held.includes('stop people getting in'), held.slice(0, 300));
    t.check('and shows both values', held.includes(otherPool) && held.includes(poolBefore));
    t.eq('nothing was written', settings(ctx).gate.issuer, poolBefore);

    // The confirmation is the same form, so the pending value is still in the field and the
    // token is in the page. Submitting it again is what a person does with the button.
    t.eq('the pending value is still in the form',
      await page.locator('input[name=issuer]').inputValue(), otherPool);
    t.check('and the token is with it',
      (await page.locator('input[name=confirm]').count()) === 1);
    t.eq('confirming writes it', (await submit(page)).status(), 200);
    t.eq('the pool moved', settings(ctx).gate.issuer, otherPool);

    // Put it back, confirming again, so what follows starts from the fixture's own pool.
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('input[name=issuer]', poolBefore);
    await submit(page);
    await submit(page);
    t.eq('and back', settings(ctx).gate.issuer, poolBefore);

    // A host the cookie can never reach is a refusal rather than a question: there is
    // nothing to confirm about a file the gate would not accept.
    await page.goto(ctx.base + '/config?lang=en');
    await page.fill('input[name=cookie_domain]', '.example.com');
    await page.fill('textarea[name=hosts]', 'example.com\n*.example.com\napp.elsewhere.com');
    t.eq('an unreachable host is a 400', (await submit(page)).status(), 400);
    t.check('naming the host', (await mainText(page)).includes('app.elsewhere.com'));

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
