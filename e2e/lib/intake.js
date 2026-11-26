'use strict';
/**
 * The deletion intake of docs/ARCHITECTURE.md §13.29 W1, as a loopback fake.
 *
 * This is the Node twin of the Rust `FakeIntake` the unit tests drive: the same two paths, the
 * same answers, the same recording. It exists because the e2e suite is the only place a whole
 * delete walk happens in a real browser, and a walk that ends at the intake's door is a walk
 * that never leaves it: the page a `503` answers, the page that says "some of it is queued",
 * the page a `403 protected` refuses, are all pages this suite has to look at.
 *
 * What it answers, per §13.29 W1:
 *
 *   GET  /account/whoami   200 {"ok":true,"email":<the address it was sent>,"protected":<bool>}
 *   POST /account/delete   202 {"ok":true,"status":"accepted"}
 *
 * The `email` of a `whoami` is the `X-Auth-Email` the request carried, lowercased and trimmed
 * exactly as the Rust fake takes it, and that echo is the whole point: the gate's client refuses
 * a `whoami` that answers for an address other than the one it asked about, so a fake that
 * answered a fixed address would hide the binding the check exists for.
 *
 * The `protected` set is configurable, and it is the only state the fake has by default: the
 * intake is the one that knows which addresses an administrator locked, and the gate asks it.
 *
 * Anything else can be scripted per path, in order, and the last entry repeats:
 *
 *   intake.script('GET', WHOAMI, { json: { ok: true, email: 'x@y.com', protected: true } })
 *   intake.inOrder('POST', DEL, [{ status: 503 }, { status: 202, json: { ok: true } }])
 *   intake.script('POST', DEL, { redirect: 'http://127.0.0.1:1/away' })       // not followed
 *   intake.script('POST', DEL, { none: true })    // no answer at all: the client's timeout
 *   intake.script('POST', DEL, { close: true })   // the connection dropped
 *
 * A scripted answer's status is 200 unless it says otherwise, and the contract's accept is
 * **202**, which the gate's client reads as the only accepted answer. So an accept written as
 * `{ json: { ok: true } }` is a 200, which the gate refuses: spell the 202 out.
 *
 * Every request is recorded, so a test can say what the intake was *asked*, which is the half of
 * §13.29 W3 ("the row goes before the first post") a page read cannot show.
 */
const http = require('http');
const { URL } = require('url');

/** The two paths of the contract, spelled once. */
const WHOAMI = '/account/whoami';
const DELETE = '/account/delete';
/** The header the gate offers the intake, which the fake records and never checks. */
const SECRET_HEADER = 'x-bb-delete-secret';
/** The header carrying the one address each request is about. */
const EMAIL_HEADER = 'x-auth-email';

/** Normalised the way the Rust fake normalises: the whole header, trimmed and lowercased. */
function addressOf(value) {
  return String(value == null ? '' : value).trim().toLowerCase();
}

class Intake {
  constructor() {
    this.port = 0;
    this.server = null;
    this.protectedSet = new Set();
    this.scriptMap = new Map();
    this.calls = [];
    this.silent = false;
  }

  /** The base URL to hand the binary as `BB_AUTH_WEB_DELETE_INTAKE`. */
  get url() {
    return `http://127.0.0.1:${this.port}`;
  }

  /**
   * The answer for one path, replacing whatever was scripted there. `res` is one of:
   * `{json}` (200, or `{status, json}`), `{status}` with no body, `{text, status}`,
   * `{redirect}` (a 302, which the client must not follow), `{none: true}` (no answer),
   * `{close: true}` (drop the connection).
   */
  script(method, path, res) {
    this.scriptMap.set(key(method, path), [res]);
    return this;
  }

  /** The answers for one path, in order. The last one repeats for every request after it. */
  inOrder(method, path, list) {
    if (!Array.isArray(list) || list.length === 0) throw new Error('inOrder needs a non-empty list');
    this.scriptMap.set(key(method, path), list.slice());
    return this;
  }

  /** The addresses the intake reports as protected. */
  setProtected(addresses) {
    this.protectedSet = new Set(addresses.map(addressOf));
    return this;
  }

  /** Stop answering at all: every request hangs, which is the client's timeout case. */
  setSilent(on) {
    this.silent = !!on;
    return this;
  }

  /** The requests received, oldest first, each `{method, path, email, secret, body}`. */
  callsMade() {
    return this.calls.slice();
  }

  /** Back to the defaults: the two contract answers, nothing protected, nothing recorded. */
  reset() {
    this.protectedSet = new Set();
    this.scriptMap = new Map();
    this.calls = [];
    this.silent = false;
    return this;
  }

  listen() {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => this.handle(req, res));
      this.server.once('error', reject);
      this.server.listen(0, '127.0.0.1', () => {
        this.port = this.server.address().port;
        resolve(this);
      });
    });
  }

  close() {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      const server = this.server;
      this.server = null;
      server.close(() => resolve());
    });
  }

  handle(req, res) {
    const where = new URL(req.url, 'http://127.0.0.1');
    const path = where.pathname;
    // Recorded the moment the request is seen, with the body filled in as it arrives: a test
    // reads the calls right after the response lands, and a record that only existed once the
    // body had been read would race with exactly that read.
    const record = {
      method: req.method,
      path,
      email: addressOf(req.headers[EMAIL_HEADER]),
      secret: req.headers[SECRET_HEADER] == null ? null : String(req.headers[SECRET_HEADER]),
      body: '',
      form: {},
    };
    readBody(req, record);
    this.calls.push(record);
    // Silent first, and the request is left open: the client gives up on its own timeout, which
    // is the outcome the "not sure" page exists for. The request is still recorded, because the
    // intake really did receive it.
    if (this.silent) return;
    const list = this.scriptMap.get(key(req.method, path));
    if (!list) {
      if (req.method === 'GET' && path === WHOAMI) {
        return json(res, 200, {
          ok: true,
          email: addressOf(req.headers[EMAIL_HEADER]),
          protected: this.protectedSet.has(addressOf(req.headers[EMAIL_HEADER])),
        });
      }
      if (req.method === 'POST' && path === DELETE) {
        return json(res, 202, { ok: true, status: 'accepted' });
      }
      // Nothing in the contract, so nothing the gate should have sent.
      return json(res, 400, { ok: false, error: 'unscripted' });
    }
    const res_ = list.length > 1 ? list.shift() : list[0];
    if (res_.none) return; // no answer
    if (res_.close) return req.destroy();
    if (res_.redirect) {
      res.writeHead(302, { location: res_.redirect });
      return res.end();
    }
    if (res_.json !== undefined) return json(res, res_.status || 200, res_.json);
    if (res_.text !== undefined) {
      res.writeHead(res_.status || 200, { 'content-type': 'text/plain' });
      return res.end(res_.text);
    }
    res.writeHead(res_.status || 200);
    return res.end();
  }
}

function key(method, path) {
  return `${method} ${path}`;
}

/** The body, read as far as it arrives, filled into the record the request already made. */
function readBody(req, record) {
  req.on('data', (chunk) => {
    record.body += chunk.toString();
  });
  req.on('end', () => {
    for (const [k, v] of new URLSearchParams(record.body)) record.form[k] = v;
  });
  req.on('error', () => {});
  return record;
}

function json(res, status, value) {
  const bytes = JSON.stringify(value);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(bytes) });
  res.end(bytes);
}

/** Start one on an ephemeral loopback port. */
function startIntake() {
  return new Intake().listen();
}

module.exports = { startIntake, Intake, WHOAMI, DELETE, SECRET_HEADER, EMAIL_HEADER };
