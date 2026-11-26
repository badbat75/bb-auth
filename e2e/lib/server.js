'use strict';
// Bringing up the thing under test: build the binary, hand it a throwaway copy of the
// fixture, and start it on a port the OS picked. Shared by `run.js` (the suite) and
// `shots.js` (the visual walk-through) so both drive exactly the same server, started
// exactly the same way; a screenshot of a differently-configured binary would be
// evidence about nothing.
//
// The access file is ALWAYS a per-run temp copy: the callers write to it, and pointing a
// server at anything in the repo would make a test run a working-tree change.

const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');

const E2E_DIR = path.resolve(__dirname, '..');
const REPO = path.resolve(E2E_DIR, '..');
const FIXTURE = path.join(REPO, 'deploy', 'access.example.json');
const CHANNEL = process.env.E2E_BROWSER_CHANNEL || 'msedge';
const { startFakeCognito } = require('./cognito');
const { startIntake } = require('./intake');

/**
 * The proxy secret this suite starts the GUI with, and the value the harness puts on every
 * request. Any 32+ characters of `[A-Za-z0-9_-]` works (see `compile_proxy_secret`); this one
 * is fixed so a failing scene is reproducible.
 */
const PROXY_SECRET = 'e2e_test_web_proxy_secret_0123456789ABCDEF';
const PROXY_SECRET_HEADER = 'X-BB-Web-Secret';

/** Run a command, inheriting stdio; a non-zero exit is fatal to the whole run. */
function sh(cmd, cwd) {
  const r = spawnSync(cmd, { shell: true, cwd, stdio: 'inherit' });
  if (r.status !== 0) {
    console.error(`FATAL: \`${cmd}\` exited ${r.status}`);
    process.exit(1);
  }
}

/** Install the e2e dependencies on a fresh clone. No browser download: see README. */
function ensureDeps() {
  if (!fs.existsSync(path.join(E2E_DIR, 'node_modules', 'playwright'))) {
    console.log('== installing e2e dependencies (first run) ==');
    sh('npm install --no-audit --no-fund', E2E_DIR);
  }
  return require('playwright');
}

/**
 * Build the binary under test and return its path.
 *
 * It is built with the `e2e-fake-cognito` feature into its OWN target directory
 * (docs/ARCHITECTURE.md §13.24): the feature is what lets the process be pointed at the fake
 * Cognito, so the binary that carries it must never be `target/debug/bb-auth-web`, the one a
 * developer would copy by hand, and `cargo test` and this harness stop rebuilding over each other.
 */
function buildBin() {
  console.log('== cargo build --bin bb-auth-web --features e2e-fake-cognito ==');
  sh('cargo build --bin bb-auth-web --features e2e-fake-cognito --target-dir target/e2e', REPO);
  return path.join(REPO, 'target', 'e2e', 'debug', process.platform === 'win32' ? 'bb-auth-web.exe' : 'bb-auth-web');
}

/**
 * A fresh temp directory holding a copy of the fixture, plus the copy's path.
 *
 * The settings file is written beside it under the name the binary derives when nothing
 * names one, so the suite exercises that default rather than a path of its own invention.
 * Its one administrator is the identity every test signs in as.
 */
function tempAccessFile() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-auth-e2e-'));
  const file = path.join(dir, 'access.json');
  const settings = path.join(dir, 'settings.json');
  fs.copyFileSync(FIXTURE, file);
  fs.writeFileSync(settings, SETTINGS_FIXTURE);
  // The audit is named but not created: a deployment where the gate has recorded nothing yet
  // is the state every scene but one starts in, and the empty page is what it must look like.
  return { dir, file, settings, audit: path.join(dir, 'audit.jsonl') };
}

/** Ask the OS for a free loopback port. */
function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

/** Start bb-auth-web and resolve once it says it is listening. */
function startServer(bin, accessFile, auditFile, port, cognitoUrl, intakeUrl) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, [], {
      cwd: REPO,
      env: {
        ...process.env,
        BB_AUTH_ACCESS_FILE: accessFile,
        // Named explicitly rather than left to default, which on a developer's machine would
        // be a path under /var/log that this suite must never read or create.
        BB_AUTH_AUDIT_FILE: auditFile,
        BB_AUTH_WEB_LISTEN: `127.0.0.1:${port}`,
        // The secret the front proxy (startProxy) puts on every request. Set here rather than
        // left unset: the binary refuses to start without one, and a suite that started a
        // secret-less binary would be evidence about a deployment that cannot exist.
        BB_AUTH_WEB_PROXY_SECRET: PROXY_SECRET,
        BB_AUTH_WEB_BASE_PATH: '/admin',
        BB_AUTH_WEB_DEFAULT_LANG: 'en',
        // Root-relative, which is the shape a real deployment uses when the gate and the GUI
        // share a vhost. Set here so the header's Sign out control exists in every scene and
        // every screenshot: unset it and the control is absent by design, which is a state
        // its own unit test covers rather than this suite.
        BB_AUTH_WEB_LOGOUT_URL: '/auth/logout',
        // Where the profile edit's Cognito calls go: the fake of lib/cognito.js. Read only by a
        // build with the `e2e-fake-cognito` feature, which says so on stderr (checked below).
        BB_AUTH_WEB_E2E_COGNITO_ENDPOINT: cognitoUrl,
        // Where the delete walk's intake calls go: the fake of lib/intake.js. Set here, for every
        // area and every scene, because the account menu's delete row exists only where an intake
        // is wired (§13.30 §1), and a suite that left it unset would never reach the pages the
        // delete design is about. The secret is deliberately not set: it is optional (§13.29 W2)
        // and the fake records whatever arrives, so a run that set one would test a deployment
        // detail the intake does not check today.
        BB_AUTH_WEB_DELETE_INTAKE: intakeUrl,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let log = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`server did not report listening within 30s. stderr:\n${log}`));
    }, 30_000);
    // Both lines are required. "listening on" says the server is up; "E2E BUILD" says this
    // process really is the feature build that will reach the fake. Without the second, every
    // profile page would be a 502 "refused", which looks exactly like a scene, so the run is
    // aborted instead. The marker may print just after the listening line, so it gets a moment.
    let up = false;
    let grace;
    const watch = (chunk) => {
      log += chunk.toString();
      if (!up && log.includes('listening on')) {
        up = true;
        clearTimeout(timer);
        if (log.includes('E2E BUILD')) return resolve(child);
        grace = setTimeout(() => {
          child.kill();
          reject(new Error(`the server never printed its \`E2E BUILD\` line: this is not the e2e-fake-cognito build, so no Cognito call would reach the fake. stderr:\n${log}`));
        }, 2_000);
      }
      if (up && grace && log.includes('E2E BUILD')) {
        clearTimeout(grace);
        grace = undefined;
        resolve(child);
      }
    };
    child.stderr.on('data', watch);
    child.stdout.on('data', watch);
    child.once('exit', (code) => {
      clearTimeout(timer);
      clearTimeout(grace);
      reject(new Error(`server exited early (${code}). stderr:\n${log}`));
    });
  });
}

/**
 * A stand-in for nginx, in front of the GUI, that adds the proxy secret to every request.
 *
 * The suite has no nginx and drives a real browser straight at the binary, and the binary now
 * refuses any request that does not carry `X-BB-Web-Secret` (docs/ARCHITECTURE.md §13.3). A
 * proxy is the only way to put that header on *every* request a page makes: Playwright's
 * `extraHTTPHeaders` covers the contexts the harness builds, but the areas and the visual walk
 * open their own, and a header set per context is a header a scene can forget.
 *
 * It overwrites whatever the client sent under that name, which is what nginx's
 * `proxy_set_header` does, and it forwards `Host:` untouched: the GUI's same-origin fallback
 * compares `Origin`'s host with `Host`'s, and a proxy that rewrote it would refuse every write
 * on an otherwise healthy run.
 */
function startProxy(upstreamPort, port) {
  return new Promise((resolve, reject) => {
    const proxy = http.createServer((req, res) => {
      const headers = { ...req.headers, [PROXY_SECRET_HEADER.toLowerCase()]: PROXY_SECRET };
      const up = http.request(
        { host: '127.0.0.1', port: upstreamPort, path: req.url, method: req.method, headers },
        (upRes) => {
          res.writeHead(upRes.statusCode, upRes.headers);
          upRes.pipe(res);
        }
      );
      up.on('error', () => res.destroy());
      req.pipe(up);
    });
    proxy.once('error', reject);
    proxy.listen(port, '127.0.0.1', () => resolve(proxy));
  });
}

/**
 * The settings file every run starts from: the defaults, and the one administrator every
 * test signs in as. Written beside the access file under the name the binary derives when
 * nothing names one, so the suite exercises that default rather than a path of its own.
 */
const SETTINGS_FIXTURE =
  JSON.stringify(
    {
      version: 3,
      // The three the Settings page refuses to write empty, because each of them is a
      // deployment where nobody can get in: the app client the email flow uses, the pool
      // whose tokens are accepted, and the hosts a login may land on.
      gate: {
        client_id: 'email-client',
        issuer: 'https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_EXAMPLE',
        authorized_hosts: ['example.com', '*.example.com'],
      },
      web: { admins: ['admin@example.com'] },
    },
    null,
    2
  ) + '\n';

/**
 * Everything above, in the one order that works, and the teardown that undoes it.
 * Resolves to `{ ctx, stop }`: `ctx` is what a test area (or the visual walk) receives,
 * `stop()` closes the browser, kills the server and removes the temp directory.
 */
async function boot() {
  const { chromium } = ensureDeps();
  const bin = buildBin();
  const { dir, file: accessFile, settings: settingsFile, audit: auditFile } = tempAccessFile();
  // Two ports: the GUI's own, which nothing outside this process is allowed to talk to, and
  // the front proxy's, which is what the browser and every raw `api()` call address. The suite
  // has no nginx, so the proxy is what stands in for the one location that sets the secret.
  const port = await freePort();
  const proxyPort = await freePort();

  let server, proxy, browser, cognito, intake;
  const stop = async () => {
    if (browser) await browser.close().catch(() => {});
    if (proxy) proxy.close();
    if (server) server.kill();
    if (cognito) await cognito.close();
    if (intake) await intake.close();
    fs.rmSync(dir, { recursive: true, force: true });
  };
  try {
    cognito = await startFakeCognito();
    intake = await startIntake();
    server = await startServer(bin, accessFile, auditFile, port, cognito.url, intake.url);
    proxy = await startProxy(port, proxyPort);
    browser = await chromium.launch({ channel: CHANNEL, headless: true });
  } catch (e) {
    await stop();
    throw e;
  }
  const ctx = {
    browser,
    origin: `http://127.0.0.1:${proxyPort}`,
    base: `http://127.0.0.1:${proxyPort}/admin`,
    accessFile,
    settingsFile,
    auditFile,
    cognito,
    intake,
  };
  console.log(`== server on ${ctx.origin} via the proxy secret (file: ${accessFile}) | browser: ${CHANNEL} ==\n`);
  return { ctx, stop };
}

module.exports = { E2E_DIR, REPO, FIXTURE, SETTINGS_FIXTURE, CHANNEL, sh, boot };
