#!/usr/bin/env node
'use strict';
// Single-command E2E runner for bb-auth-web. Builds the binary, starts a real server on
// an ephemeral loopback port against a per-run temp copy of deploy/access.example.json —
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
//
// The server bootstrap lives in lib/server.js, shared with shots.js.

const fs = require('fs');
const path = require('path');

const { E2E_DIR, FIXTURE, SETTINGS_FIXTURE, boot } = require('./lib/server');

const AREAS = ['auth', 'crud', 'settings', 'validation', 'conflict', 'i18n', 'nojs'];

async function main() {
  const shotsDir = process.env.E2E_SHOTS === '1' ? path.join(E2E_DIR, 'artifacts') : null;
  if (shotsDir) fs.mkdirSync(shotsDir, { recursive: true });

  const { ctx, stop } = await boot();
  const areas = [];
  try {
    const { Checker } = require('./lib/harness');
    for (const area of AREAS) {
      // Every area starts from the pristine fixture, both files: the settings area writes
      // to the second one exactly as the others write to the first.
      fs.copyFileSync(FIXTURE, ctx.accessFile);
      fs.writeFileSync(ctx.settingsFile, SETTINGS_FIXTURE);
      const t = new Checker(area, shotsDir);
      try {
        await require(`./tests/${area}`).run(ctx, t);
      } catch (e) {
        t.check('area completed without an unhandled error', false, e.stack || e.message);
      }
      areas.push(t);
    }
  } finally {
    await stop();
  }

  // Summary — one line per area, every failure spelled out, exit code = the verdict.
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
