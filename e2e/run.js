#!/usr/bin/env node
'use strict';
// Single-command E2E runner for bb-auth-web. Builds the binary, starts a real server on
// an ephemeral loopback port against a per-run temp copy of deploy/users.example.json —
// the tests mutate that file, so the server is NEVER pointed at anything in the repo —
// drives a real browser through every test area, prints a pass/fail summary, and exits
// non-zero on any failure. Each area starts from a fresh copy of the fixture, which is
// what makes the suite idempotent and the areas order-independent.
//
//   node e2e/run.js
//
// E2E_BROWSER_CHANNEL — Playwright channel, default `msedge` (this repo's dev machine
//                       has Edge, not Chrome; `chrome` works where it exists).
// E2E_SHOTS=1         — save screenshots into e2e/artifacts/ (gitignored). Off by
//                       default: evidence for a human, never part of an assertion.

const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const E2E_DIR = __dirname;
const REPO = path.resolve(E2E_DIR, '..');
const FIXTURE = path.join(REPO, 'deploy', 'users.example.json');
const CHANNEL = process.env.E2E_BROWSER_CHANNEL || 'msedge';
const AREAS = ['auth', 'crud', 'validation', 'conflict', 'i18n', 'nojs'];

function sh(cmd, cwd) {
  const r = spawnSync(cmd, { shell: true, cwd, stdio: 'inherit' });
  if (r.status !== 0) {
    console.error(`FATAL: \`${cmd}\` exited ${r.status}`);
    process.exit(1);
  }
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
function startServer(bin, usersFile, port) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, [], {
      cwd: REPO,
      env: {
        ...process.env,
        BB_AUTH_WEB_ADMINS: 'admin@example.com',
        BB_AUTH_USERS_FILE: usersFile,
        BB_AUTH_WEB_LISTEN: `127.0.0.1:${port}`,
        BB_AUTH_WEB_BASE_PATH: '/admin',
        BB_AUTH_WEB_DEFAULT_LANG: 'en',
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

async function main() {
  // 0. Dependencies — first run on a fresh clone installs playwright (no browser
  //    download: it drives the system Edge/Chrome through a channel).
  if (!fs.existsSync(path.join(E2E_DIR, 'node_modules', 'playwright'))) {
    console.log('== installing e2e dependencies (first run) ==');
    sh('npm install --no-audit --no-fund', E2E_DIR);
  }
  const { chromium } = require('playwright');

  // 1. The binary under test — the working tree's, debug profile is fine here.
  console.log('== cargo build --bin bb-auth-web ==');
  sh('cargo build --bin bb-auth-web', REPO);
  const bin = path.join(REPO, 'target', 'debug', process.platform === 'win32' ? 'bb-auth-web.exe' : 'bb-auth-web');

  // 2. Per-run working copy of the fixture. Never a repo file: the tests write to it.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-auth-e2e-'));
  const usersFile = path.join(tmp, 'users.json');
  fs.copyFileSync(FIXTURE, usersFile);

  const shotsDir = process.env.E2E_SHOTS === '1' ? path.join(E2E_DIR, 'artifacts') : null;
  if (shotsDir) fs.mkdirSync(shotsDir, { recursive: true });

  const port = await freePort();
  let server, browser;
  const areas = [];
  try {
    server = await startServer(bin, usersFile, port);
    browser = await chromium.launch({ channel: CHANNEL, headless: true });
    const ctx = {
      browser,
      origin: `http://127.0.0.1:${port}`,
      base: `http://127.0.0.1:${port}/admin`,
      usersFile,
    };
    console.log(`== server on ${ctx.origin} (file: ${usersFile}) | browser: ${CHANNEL} ==\n`);

    const { Checker } = require('./lib/harness');
    for (const area of AREAS) {
      fs.copyFileSync(FIXTURE, usersFile); // every area starts from the pristine fixture
      const t = new Checker(area, shotsDir);
      try {
        await require(`./tests/${area}`).run(ctx, t);
      } catch (e) {
        t.check('area completed without an unhandled error', false, e.stack || e.message);
      }
      areas.push(t);
    }
  } finally {
    if (browser) await browser.close().catch(() => {});
    if (server) server.kill();
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  // 3. Summary — one line per area, every failure spelled out, exit code = the verdict.
  console.log('\n== bb-auth-web e2e summary ==');
  let pass = 0, fail = 0;
  for (const t of areas) {
    const ok = t.results.filter((r) => r.ok).length;
    const total = t.results.length;
    pass += ok;
    fail += total - ok;
    console.log(`  ${t.area.padEnd(12)} ${ok}/${total}${ok === total ? '' : '  FAILURES'}`);
    for (const r of t.results.filter((r) => !r.ok)) {
      console.log(`    FAIL: ${r.name}${r.detail ? ` — ${r.detail}` : ''}`);
    }
  }
  console.log(`  ${'TOTAL'.padEnd(12)} ${pass}/${pass + fail}  ${fail === 0 ? 'PASS' : 'FAIL'}`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('FATAL:', e.stack || e.message);
  process.exit(1);
});
