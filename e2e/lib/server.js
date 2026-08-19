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
const net = require('net');
const os = require('os');
const path = require('path');

const E2E_DIR = path.resolve(__dirname, '..');
const REPO = path.resolve(E2E_DIR, '..');
const FIXTURE = path.join(REPO, 'deploy', 'access.example.json');
const CHANNEL = process.env.E2E_BROWSER_CHANNEL || 'msedge';

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

/** Build the binary under test and return its path. Debug profile is fine here. */
function buildBin() {
  console.log('== cargo build --bin bb-auth-web ==');
  sh('cargo build --bin bb-auth-web', REPO);
  return path.join(REPO, 'target', 'debug', process.platform === 'win32' ? 'bb-auth-web.exe' : 'bb-auth-web');
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
  return { dir, file, settings };
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
function startServer(bin, accessFile, port) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, [], {
      cwd: REPO,
      env: {
        ...process.env,
        BB_AUTH_ACCESS_FILE: accessFile,
        BB_AUTH_WEB_LISTEN: `127.0.0.1:${port}`,
        BB_AUTH_WEB_BASE_PATH: '/admin',
        BB_AUTH_WEB_DEFAULT_LANG: 'en',
        // Root-relative, which is the shape a real deployment uses when the gate and the GUI
        // share a vhost. Set here so the header's Sign out control exists in every scene and
        // every screenshot: unset it and the control is absent by design, which is a state
        // its own unit test covers rather than this suite.
        BB_AUTH_WEB_LOGOUT_URL: '/auth/logout',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let log = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`server did not report listening within 30s. stderr:\n${log}`));
    }, 30_000);
    const watch = (chunk) => {
      log += chunk.toString();
      if (log.includes('listening on')) {
        clearTimeout(timer);
        resolve(child);
      }
    };
    child.stderr.on('data', watch);
    child.stdout.on('data', watch);
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`server exited early (${code}). stderr:\n${log}`));
    });
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
  const { dir, file: accessFile, settings: settingsFile } = tempAccessFile();
  const port = await freePort();

  let server, browser;
  const stop = async () => {
    if (browser) await browser.close().catch(() => {});
    if (server) server.kill();
    fs.rmSync(dir, { recursive: true, force: true });
  };
  try {
    server = await startServer(bin, accessFile, port);
    browser = await chromium.launch({ channel: CHANNEL, headless: true });
  } catch (e) {
    await stop();
    throw e;
  }
  const ctx = {
    browser,
    origin: `http://127.0.0.1:${port}`,
    base: `http://127.0.0.1:${port}/admin`,
    accessFile,
    settingsFile,
  };
  console.log(`== server on ${ctx.origin} (file: ${accessFile}) | browser: ${CHANNEL} ==\n`);
  return { ctx, stop };
}

module.exports = { E2E_DIR, REPO, FIXTURE, SETTINGS_FIXTURE, CHANNEL, sh, boot };
