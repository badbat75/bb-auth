'use strict';
// The profile edit on `/account` (docs/ARCHITECTURE.md §13.22, §13.23, §13.25 and §13.26), end
// to end against the fake Cognito of `lib/cognito.js`: the form, the emailed code, and every
// outcome page a person can land on. The Rust tests pin each handler; this area pins what a
// browser does with them (autofocus, Enter in a field, Back, the forms' order) and, above all,
// that the binary really sends the envelope the pool requires, since the fake refuses anything
// else.
//
// Driven as `you@example.com`, a roster row who is not an administrator, with the claims nginx
// would forward in the headers **and the native username it forwards** (§13.25): the edit acts
// on the user that header names, never on an address the form carries. One walk drops that
// header, which is a federated session, and sees a sentence and no form. `nojs.js` walks the
// happy path again with scripting off.

const fs = require('fs');
const { submit, api } = require('../lib/harness');
const { profileSettingsBytes, PROFILE_HEADERS, NATIVE_USERNAME } = require('../lib/cognito');

/** The headers of a session with nothing to edit: nginx forwarded the claims and no
 *  `X-Auth-Native-Username`, because the person signed in through a social provider. */
const NO_NATIVE = Object.fromEntries(
  Object.entries(PROFILE_HEADERS).filter(([k]) => k !== 'X-Auth-Native-Username'),
);
/** A `ChallengeParameters.USERNAME` that is **not** the session's user (§13.25 (3)). */
const OTHER_USERNAME = '9b2f6d1c-7a44-4c1e-8f52-6d0c1b9e4a77';

const WHO = 'you@example.com';
const PAGE = '/account/';
const EDIT = '/account/profile';
const CODE = '/account/profile/code';
// The form that starts an edit (and, on the code page, the one that starts it again).
const START = `form[action="${EDIT}"]`;
const START_BTN = `${START} button[type=submit]`;
const SAVE_FORM = `form[action="${CODE}"]`;
const SAVE_BTN = `${SAVE_FORM} button[type=submit]`;

const text = (page) => page.locator('main').innerText();
const h1 = async (page) => (await page.locator('h1').first().innerText()).trim();
const targets = (ctx) => ctx.cognito.calls.map((c) => c.target);

/** A context for the person, carrying what nginx would forward for them. `headers` is the
 *  whole set, so a walk can drop the native username and be a federated session. */
async function personPage(ctx, extra = {}, headers = PROFILE_HEADERS) {
  const context = await ctx.browser.newContext({
    viewport: { width: 1280, height: 900 },
    extraHTTPHeaders: { 'X-Auth-Email': WHO, ...headers },
    ...extra,
  });
  return { context, page: await context.newPage() };
}

/** Walks start from a path on the proxy's origin. */
const open = (ctx, page, p) => page.goto(ctx.origin + p);

async function run(ctx, t) {
  fs.writeFileSync(ctx.settingsFile, profileSettingsBytes());
  const { context, page } = await personPage(ctx);
  const start = async () => {
    await open(ctx, page, EDIT);
    await page.fill('input[name=given_name]', 'Augusta');
    await page.fill('input[name=family_name]', '');
    return submit(page, START_BTN);
  };
  try {
    // --- 1. the pill, the form, the code page --------------------------------------------
    ctx.cognito.reset();
    await open(ctx, page, PAGE);
    const pill = page.locator(`#profile a[href="${EDIT}"]`);
    t.eq('the Profile panel offers one Edit pill', await pill.count(), 1);
    t.eq('in words', (await pill.innerText()).trim(), 'Edit profile');
    t.eq('reading the page called nobody', ctx.cognito.calls.length, 0);

    await Promise.all([page.waitForNavigation(), pill.click()]);
    t.check('the pill opens the form', page.url().endsWith(EDIT), page.url());
    t.eq('the first editable field has the focus on arrival',
      await page.evaluate(() => document.activeElement && document.activeElement.name), 'given_name');
    t.eq('its value is what nginx forwarded', await page.inputValue('input[name=given_name]'), 'Ada');
    t.eq('the family name too', await page.inputValue('input[name=family_name]'), 'Lovelace');
    t.eq('the form names no address at all (§13.26)',
      await page.locator(`${START} [name=email]`).count(), 0);
    t.check('the reason the address is not a field is said under the fields',
      (await page.locator(`${START} p.muted`).innerText()).includes('only an administrator can change it'),
      await page.locator(START).innerText());
    t.check('no line names an address to send the code to',
      !(await page.locator(START).innerText()).includes('Send the code to'),
      await page.locator(START).innerText());
    t.eq('a configured claim that is not editable is not an input',
      await page.locator('input[name=phone_number]').count(), 0);
    t.eq('the form carries no script', await page.locator('script').count(), 0);

    const sent = await start();
    t.eq('Send code is answered 200 with the code page', sent.status(), 200);
    t.eq('the page is headed by its act', await h1(page), 'Enter the code');
    t.eq('exactly one call so far', targets(ctx), ['InitiateAuth']);
    const init = ctx.cognito.calls[0];
    t.eq('it is a USER_AUTH start asking for an email code',
      [init.body.AuthFlow, (init.body.AuthParameters || {}).PREFERRED_CHALLENGE], ['USER_AUTH', 'EMAIL_OTP']);
    t.eq('for the user the session names, on the native app client (§13.25)',
      [(init.body.AuthParameters || {}).USERNAME, init.body.ClientId], [NATIVE_USERNAME, 'email-client']);
    t.eq('in the envelope the pool requires', init.contentType, 'application/x-amz-json-1.1');
    const code = await text(page);
    t.check('the lede names the masked address the pool sent it to and says how long it lasts',
      code.includes('y***@e***.com') && code.includes('3 minutes'), code.slice(0, 300));
    t.check('and never the address itself (§13.26 §4)', !code.includes(WHO), code.slice(0, 300));
    const changes = page.locator('ul.changes li');
    t.eq('two changes are listed', await changes.count(), 2);
    const given = (await changes.nth(0).innerText()).replace(/\s+/g, ' ');
    t.check('the new given name is shown with the old one',
      given.includes('Given name') && given.includes('Augusta') && given.includes('was') && given.includes('Ada'), given);
    t.check('the emptied family name is a removal in words',
      (await changes.nth(1).locator('.tag.warn').innerText()).trim() === 'removed'
        && (await changes.nth(1).innerText()).includes('Lovelace'), await changes.nth(1).innerText());
    t.eq('the code field has the focus', await page.evaluate(() => document.activeElement && document.activeElement.name), 'code');
    t.eq('the code form names no address and no username (§13.26 §4: the code step reads the header)',
      await page.locator(`${SAVE_FORM} [name=email], ${SAVE_FORM} [name=username]`).count(), 0);
    t.eq('and the resend form beneath it names no address either',
      await page.locator(`${START} [name=email]`).count(), 0);

    // --- 2. a wrong code changes nothing -------------------------------------------------
    ctx.cognito.script([['RespondToAuthChallenge', {
      status: 400, body: { __type: 'CodeMismatchException', Session: 'fake-session-2' },
    }]]);
    await page.fill(`${SAVE_FORM} input[name=code]`, '000000');
    const wrong = await submit(page, SAVE_BTN);
    t.eq('a wrong code is a 400', wrong.status(), 400);
    t.check('the code page says so, inside the page',
      (await page.locator('#err').innerText()).includes('That code is not right'), await text(page));
    t.eq('the field is emptied', await page.inputValue(`${SAVE_FORM} input[name=code]`), '');
    t.eq('and marked invalid', await page.locator(`${SAVE_FORM} input[name=code]`).getAttribute('aria-invalid'), 'true');
    t.eq('the summary of changes is still there', await page.locator('ul.changes li').count(), 2);
    t.check('nothing was written', !targets(ctx).includes('UpdateUserAttributes'), JSON.stringify(targets(ctx)));

    // --- 3. the right code, typed the way it was pasted ----------------------------------
    const saved = await (async () => {
      await page.fill(`${SAVE_FORM} input[name=code]`, '123 456');
      return submit(page, SAVE_BTN);
    })();
    t.eq('the right code is answered 200', saved.status(), 200);
    const reply = ctx.cognito.calls.filter((c) => c.target === 'RespondToAuthChallenge');
    t.eq('the code reached the pool with its spaces gone',
      (reply[1].body.ChallengeResponses || {}).EMAIL_OTP_CODE, '123456');
    t.eq('answered with the Session the wrong code handed back', reply[1].body.Session, 'fake-session-2');
    t.eq('the code step names the user by the header it was sent, not by a form field (§13.25)',
      (reply[1].body.ChallengeResponses || {}).USERNAME, NATIVE_USERNAME);
    const update = ctx.cognito.calls.find((c) => c.target === 'UpdateUserAttributes');
    t.check('exactly one update was made', !!update && targets(ctx).filter((x) => x === 'UpdateUserAttributes').length === 1,
      JSON.stringify(targets(ctx)));
    t.eq('with the access token the pool gave', update && update.body.AccessToken, 'fake-access');
    const attrs = Object.fromEntries(((update && update.body.UserAttributes) || []).map((a) => [a.Name, a.Value]));
    t.eq('and only the changed attributes, the emptied one blank', attrs, { given_name: 'Augusta', family_name: '' });
    t.eq('the whole flow is four calls',
      targets(ctx), ['InitiateAuth', 'RespondToAuthChallenge', 'RespondToAuthChallenge', 'UpdateUserAttributes']);
    t.eq('the page says the profile is saved', await h1(page), 'Profile saved');
    const done = await text(page);
    t.check('it names what changed, in words', done.includes('Given name, Family name'), done);
    t.check('and when it shows', done.includes('from your next sign-in'), done);
    const html = await page.content();
    t.check('no token and no session reaches the page',
      !/fake-access|fake-refresh|fake-session|FAKE/.test(html), html.slice(0, 300));
    await Promise.all([page.waitForNavigation(), page.click('main a.pill')]);
    t.check('Back lands on the account page', page.url().endsWith(PAGE), page.url());
    t.check('which still shows the old value, as the page said it would',
      (await page.locator('#profile').innerText()).includes('Ada'), await page.locator('#profile').innerText());

    // --- 4. cancel leaves the read-only panel --------------------------------------------
    ctx.cognito.reset();
    await open(ctx, page, EDIT);
    await Promise.all([page.waitForNavigation(), page.click(`${START} a.pill`)]);
    t.check('Cancel returns to the account page', page.url().endsWith(PAGE), page.url());
    t.eq('with no form open', await page.locator('#profile form').count(), 0);
    t.eq('and the Edit pill back', await page.locator(`#profile a[href="${EDIT}"]`).count(), 1);
    t.eq('nobody was called', ctx.cognito.calls.length, 0);

    // --- 5. an expired code: start again, with the values kept ---------------------------
    ctx.cognito.reset();
    await start();
    ctx.cognito.script([['RespondToAuthChallenge', { status: 400, body: { __type: 'ExpiredCodeException' } }]]);
    await page.fill(`${SAVE_FORM} input[name=code]`, '123456');
    const exp = await submit(page, SAVE_BTN);
    t.eq('an expired code is a 400', exp.status(), 400);
    t.eq('headed by the result', await h1(page), 'Your profile was not changed');
    t.check('and says the code has expired', (await text(page)).includes('The code has expired'), await text(page));
    t.eq('it offers a new code', (await page.locator(`${START_BTN}`).innerText()).trim(), 'Send a new code');
    t.check('nothing was written', !targets(ctx).includes('UpdateUserAttributes'), JSON.stringify(targets(ctx)));
    await submit(page, START_BTN);
    t.eq('a new code is one more start', targets(ctx).filter((x) => x === 'InitiateAuth').length, 2);
    t.eq('on a fresh code page', await h1(page), 'Enter the code');
    t.eq('with the same two changes', await page.locator('ul.changes li').count(), 2);

    // --- 6. the user the session names is gone from the pool ------------------------------
    // §13.25: the request names that user by username, so `UserNotFoundException` no longer
    // means "this person signs in some other way" (that person is never offered a form at
    // all): it means the pool lost the very user the session names.
    ctx.cognito.reset();
    ctx.cognito.script([['InitiateAuth', { status: 400, body: { __type: 'UserNotFoundException' } }]]);
    const gone = await start();
    t.eq('a pool with no such user is a 400', gone.status(), 400);
    t.eq('headed by the result', await h1(page), 'Your profile was not changed');
    t.check('and told the sign-in service no longer has that account',
      (await text(page)).includes('no longer has the account you signed in with'), await text(page));
    t.check('and never that the profile belongs to a provider',
      !(await text(page)).includes('social provider'), await text(page));
    t.eq('no code was sent, so there is no form to ask for one', await page.locator('main form').count(), 0);
    t.eq('and the pool was asked once', targets(ctx), ['InitiateAuth']);

    // --- 7. a challenge that names a different user ---------------------------------------
    // §13.25 (3): the pool answers for the user it knows. A challenge naming another one is a
    // refusal, not a code step, and the only thing it may cost is the one call that asked.
    ctx.cognito.reset();
    ctx.cognito.script([['InitiateAuth', {
      status: 200,
      body: {
        ChallengeName: 'EMAIL_OTP',
        Session: 'fake-session-1',
        ChallengeParameters: { USERNAME: OTHER_USERNAME, CODE_DELIVERY_DESTINATION: 'y***@e***.com' },
      },
    }]]);
    const notYours = await start();
    t.eq('a challenge for another user is a 403', notYours.status(), 403);
    t.eq('headed by the result', await h1(page), 'Your profile was not changed');
    t.check('and says the sign-in service answered for a different account',
      (await text(page)).includes('answered for a different account'), await text(page));
    t.eq('the pool was asked once, and no code was ever sent for the other user',
      targets(ctx), ['InitiateAuth']);

    // --- 8. a federated session: nothing to edit ------------------------------------------
    // §13.25 step 1: with no `X-Auth-Native-Username` the session names no Cognito user this
    // gate may write to, so the page says so in one sentence and the pool is never called, on
    // a read or on a posted form.
    ctx.cognito.reset();
    const fed = await personPage(ctx, {}, NO_NATIVE);
    try {
      await open(ctx, fed.page, PAGE);
      const panel = fed.page.locator('#profile');
      t.eq('the profile panel offers no Edit pill',
        await panel.locator(`a[href="${EDIT}"]`).count(), 0);
      t.check('and says the profile comes from the provider',
        (await panel.innerText()).includes('your profile comes from that provider'), await panel.innerText());
      t.check('while the claims it does have are still read',
        (await panel.innerText()).includes('Ada'), await panel.innerText());
      const fedForm = await fed.page.goto(ctx.origin + EDIT);
      t.eq('the form path is the same page, not a refusal', fedForm.status(), 200);
      t.eq('with no form on it', await fed.page.locator(`${START} input[name=given_name]`).count(), 0);
      const fedPost = await api(ctx, EDIT, {
        method: 'POST',
        email: WHO,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Sec-Fetch-Site': 'same-origin',
          ...NO_NATIVE,
        },
        body: new URLSearchParams({ given_name: 'Augusta' }).toString(),
      });
      t.eq('a posted form is a 400 naming the same sentence', fedPost.status, 400);
      // A `Response` body is single-use: read it once, then assert on the string.
      const fedBody = await fedPost.text();
      t.check('and not an error: the person did nothing wrong',
        fedBody.includes('your profile comes from that provider')
        && !fedBody.includes('id="err"'), fedBody.slice(0, 300));
      t.eq('the pool was never called', ctx.cognito.calls.length, 0);
    } finally {
      await fed.context.close();
    }

    // --- 9. a pool that does not answer --------------------------------------------------
    ctx.cognito.reset();
    ctx.cognito.script([['InitiateAuth', 'silent']]);
    const t0 = Date.now();
    const mute = await start();
    const took = Date.now() - t0;
    t.eq('no answer is a 504', mute.status(), 504);
    t.check('and arrives at the bound, not before and not much after', took >= 4000 && took < 15000, `${took} ms`);
    t.eq('headed by the result', await h1(page), 'Your profile was not changed');
    t.check('saying how long it waited', (await text(page)).includes('did not answer within 5 seconds'), await text(page));
    t.eq('and offers a new code', (await page.locator(START_BTN).innerText()).trim(), 'Send a new code');
    const after = await page.goto(ctx.origin + PAGE);
    t.eq('the worker was freed: the account page still answers', after.status(), 200);

    // --- 10. a timeout at the update does not claim nothing changed ---------------------
    ctx.cognito.reset();
    await start();
    ctx.cognito.script([['UpdateUserAttributes', 'silent']]);
    await page.fill(`${SAVE_FORM} input[name=code]`, '123456');
    const unsure = await submit(page, SAVE_BTN);
    t.eq('a timeout at the update is a 504', unsure.status(), 504);
    t.eq('headed by the doubt', await h1(page), 'Your profile may not have been saved');
    t.check('which says it may or may not have been made',
      (await text(page)).includes('may or may not have been made'), await text(page));
    t.eq('and never says nothing changed', (await page.content()).includes('Your profile was not changed'), false);
    t.eq('with no way to ask for a new code', await page.locator(START_BTN).count(), 0);

    // --- 11. the keyboard alone ---------------------------------------------------------
    ctx.cognito.reset();
    await open(ctx, page, EDIT);
    t.eq('Tab from the top of the form stays in it: the first field has the focus already',
      await page.evaluate(() => document.activeElement.name), 'given_name');
    await page.keyboard.press('Control+A');
    await page.keyboard.type('Zed');
    await page.keyboard.press('Tab');
    t.eq('Tab goes to the next field', await page.evaluate(() => document.activeElement.name), 'family_name');
    await page.keyboard.press('Shift+Tab');
    const [enter] = await Promise.all([page.waitForNavigation(), page.keyboard.press('Enter')]);
    t.eq('Enter in a field sends the code', enter.status(), 200);
    t.eq('and lands on the code page', await h1(page), 'Enter the code');
    t.eq('with the focus in the code field', await page.evaluate(() => document.activeElement.name), 'code');
    await page.keyboard.type('123456');
    const [save] = await Promise.all([page.waitForNavigation(), page.keyboard.press('Enter')]);
    t.eq('Enter in the code field saves', save.status(), 200);
    t.eq('Save, not Send a new code',
      targets(ctx), ['InitiateAuth', 'RespondToAuthChallenge', 'UpdateUserAttributes']);
    t.eq('and the result is the saved page', await h1(page), 'Profile saved');
  } finally {
    await context.close();
  }
}

module.exports = { run };
