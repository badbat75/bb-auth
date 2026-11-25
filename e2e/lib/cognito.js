'use strict';
// A fake Cognito for the browser suites (docs/ARCHITECTURE.md §13.24).
//
// `bb-auth-web` calls the pool's JSON API for the profile edit, and the e2e build of it
// (cargo feature `e2e-fake-cognito`) is pointed at this server through
// `BB_AUTH_WEB_E2E_COGNITO_ENDPOINT`. It lives in the Node process that drives the browser so a
// scene scripts it directly, the way the Rust tests script their own `FakeCognito`.
//
// It answers `POST /` only, records every request as `{ target, body }`, and requires the
// envelope the real API requires (`Content-Type: application/x-amz-json-1.1`), so a regression
// in what the binary sends fails a walk instead of passing against a forgiving fake.

const http = require('http');

const TARGET_PREFIX = 'AWSCognitoIdentityProviderService.';
const CONTENT_TYPE = 'application/x-amz-json-1.1';

/** base64url of a string or a JSON value, without padding. */
const b64url = (v) =>
  Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

/**
 * An unsigned ID token: three base64url parts, the signature any bytes. The binary decodes the
 * payload and does not verify it (§13.22: the token arrived in the TLS answer of a call this
 * process made), so a signature would test nothing.
 */
function idToken(claims) {
  return `${b64url({ alg: 'RS256', typ: 'JWT', kid: 'fake' })}.${b64url(claims)}.${b64url('fake-signature')}`;
}

/** The pool and app client the e2e settings fixture names, read lazily (server.js requires this file). */
function fixtureWiring() {
  const { SETTINGS_FIXTURE } = require('./server');
  const gate = JSON.parse(SETTINGS_FIXTURE).gate;
  return { issuer: gate.issuer, clientId: gate.client_id };
}

/** The happy path: what the pool answers when nothing is scripted. */
function defaultReply(target, body, wiring) {
  switch (target) {
    case 'InitiateAuth':
      return {
        status: 200,
        body: {
          ChallengeName: 'EMAIL_OTP',
          Session: 'fake-session-1',
          ChallengeParameters: { USERNAME: (body.AuthParameters || {}).USERNAME },
        },
      };
    case 'RespondToAuthChallenge':
      return {
        status: 200,
        body: {
          AuthenticationResult: {
            IdToken: idToken({
              token_use: 'id',
              iss: wiring.issuer,
              aud: wiring.clientId,
              exp: Math.floor(Date.now() / 1000) + 3600,
              email_verified: true,
              email: (body.ChallengeResponses || {}).USERNAME,
            }),
            AccessToken: 'fake-access',
            RefreshToken: 'fake-refresh',
          },
        },
      };
    case 'UpdateUserAttributes':
      return { status: 200, body: {} };
    default:
      return { status: 400, body: { __type: 'UnknownOperationException' } };
  }
}

/**
 * Start the fake on `127.0.0.1:0`. Resolves to `{ url, script, calls, reset, close }`:
 *
 * - `url`: `http://127.0.0.1:<port>/`, what the binary is handed.
 * - `script([[target, reply], ...])`: queue replies. A request takes the first queued reply for
 *   its target, else the default. A reply is `{ status, body }` (sent as JSON) or `'silent'`,
 *   which reads the request and never answers until `close()`.
 * - `calls`: the recorded requests, in order, `{ target, body }` (a live array).
 * - `reset()`: forget the calls and any queued replies, and let go of held (silent) requests.
 * - `close()`: stop, dropping every held connection.
 */
function startFakeCognito(wiring = fixtureWiring()) {
  const calls = [];
  let queue = [];
  const sockets = new Set();

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const send = (status, body) => {
        res.writeHead(status, { 'Content-Type': CONTENT_TYPE });
        res.end(JSON.stringify(body));
      };
      const type = String(req.headers['content-type'] || '').toLowerCase();
      const header = String(req.headers['x-amz-target'] || '');
      const target = header.startsWith(TARGET_PREFIX) ? header.slice(TARGET_PREFIX.length) : header;
      let body = {};
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
      } catch {
        body = {};
      }
      if (req.method !== 'POST' || req.url !== '/') {
        return send(404, { __type: 'NotFound' });
      }
      calls.push({ target, body, contentType: type });
      if (type !== CONTENT_TYPE) {
        return send(400, { __type: 'InvalidContentTypeException' });
      }
      const at = queue.findIndex(([t]) => t === target);
      const reply = at >= 0 ? queue.splice(at, 1)[0][1] : defaultReply(target, body, wiring);
      if (reply === 'silent') return; // hold the socket: the caller's own bound is the test
      return send(reply.status, reply.body);
    });
  });
  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        url: `http://127.0.0.1:${port}/`,
        script: (list) => {
          queue = queue.concat(list);
        },
        calls,
        reset: () => {
          calls.length = 0;
          queue = [];
        },
        close: () =>
          new Promise((done) => {
            for (const s of sockets) s.destroy();
            server.close(() => done());
          }),
      });
    });
  });
}

// ---- what the profile walks and scenes share -------------------------------------------------

/** Settings that offer the edit: the e2e fixture plus four claims (two editable and used by the
 *  walks, a date for the hint, a phone number that is configured but not editable). */
function profileSettingsBytes() {
  const { SETTINGS_FIXTURE } = require('./server');
  const d = JSON.parse(SETTINGS_FIXTURE);
  d.gate.profile_claims = ['given_name', 'family_name', 'birthdate', 'phone_number'];
  return JSON.stringify(d, null, 2) + '\n';
}

/** What nginx forwards for the roster person of the walks, percent-encoded as the gate sends it. */
const PROFILE_HEADERS = {
  'X-Auth-Given-Name': 'Ada',
  'X-Auth-Family-Name': 'Lovelace',
  'X-Auth-Birthdate': '1815-12-10',
  'X-Auth-Phone-Number': '%2B390000',
};

module.exports = { startFakeCognito, idToken, profileSettingsBytes, PROFILE_HEADERS };
