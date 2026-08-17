/**
 * External service isolation.
 *
 * Two independent layers, because either one alone can be defeated by an
 * ordinary mistake.
 *
 * LAYER 1, credential neutralisation (`neutraliseExternalServices`)
 *   Every outbound integration in this codebase already has a
 *   "not configured, skip" branch:
 *
 *     utils/emailService.js:440       !smtpUser || !smtpPass -> skipped, no send
 *     services/smsService.js:115      !isSmsConfigured()     -> no Equence call
 *     services/whatsappService.js:90  no WAHA_API_URL/KEY    -> no WAHA call
 *     services/rewardPortService.js:151  no REWARDPORT_*     -> not configured
 *     middleware/upload.js:194        no CLOUDINARY_URL      -> upload disabled
 *
 *   Setting these variables to "" makes the application take its own real
 *   skip path. That is better than a mock: it exercises the code that runs in
 *   a misconfigured production box, and there is no stub to drift out of sync.
 *
 *   The empty string matters. `dotenv.config()` does not overwrite a key that
 *   already exists in process.env, so pre-setting to "" stops the developer's
 *   real .env from repopulating live SMTP or Cloudinary credentials when
 *   server.js is imported. Deleting the keys instead would let .env win.
 *
 *   The list of keys to blank is taken FROM THE .env FILE ITSELF, not from a
 *   list maintained here. A hand-written list is fail-open: the first draft of
 *   this file enumerated the integrations it knew about and silently let
 *   SENTRY_DSN, REWARDPORT_USERNAME and REWARDPORT_PASSWORD through, because
 *   nobody had thought of them. Reading the key names off .env inverts that,
 *   a credential added tomorrow is neutralised without anyone remembering to
 *   update this file. Only key NAMES are read; no value is ever read, logged,
 *   or written anywhere.
 *
 * LAYER 2, egress blocking (`blockNetworkEgress`)
 *   Layer 1 depends on every integration having a config guard, now and
 *   after future edits. Layer 2 does not depend on the application at all: it
 *   intercepts the transport itself, so a new integration added next month
 *   that calls a hard-coded URL is still stopped.
 *
 *   Anything not bound for localhost throws, and the attempt is recorded so a
 *   test can assert on it. This is what makes "no real emails, no real SMS, no
 *   Cloudinary uploads, no Hubble debits" a checked property rather than a
 *   claim in a document.
 */

import http from 'node:http';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { Writable } from 'node:stream';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const backendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

/**
 * Keys that must survive: blanking them would break the harness itself.
 * NODE_ENV in particular is what the guard checks.
 */
const PROTECTED = new Set(['NODE_ENV', 'PATH', 'HOME', 'TEMP', 'TMP']);

/**
 * Key names defined by the local .env (or the .env.production fallback that
 * server.js uses when .env is absent). Values are never read.
 */
function dotenvKeyNames() {
  const keys = new Set();
  for (const file of ['.env', '.env.production']) {
    const full = path.join(backendRoot, file);
    if (!fs.existsSync(full)) continue;
    for (const line of fs.readFileSync(full, 'utf8').split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq <= 0) continue;
      keys.add(trimmed.slice(0, eq).trim().replace(/^export\s+/, ''));
    }
  }
  return keys;
}

/**
 * Integrations we blank even when .env does not mention them, so the harness
 * is still isolated on a machine whose credentials come from the shell.
 */
const NEUTRALISED = [
  // Email
  'SMTP_HOST', 'SMTP_PORT', 'SMTP_SECURE', 'SMTP_USER', 'SMTP_PASS',
  'EMAIL_USER', 'EMAIL_PASS', 'SENDER_EMAIL', 'ADMIN_NOTIFY_EMAIL',
  // SMS (Equence)
  'EQUENCE_USERNAME', 'EQUENCE_PASSWORD', 'EQUENCE_SENDER_ID', 'EQUENCE_PE_ID',
  'EQUENCE_BASE_URL', 'EQUENCE_OTP_TMPL_ID', 'EQUENCE_RESET_TMPL_ID',
  // WhatsApp (WAHA)
  'WAHA_API_URL', 'WAHA_API_KEY', 'WAHA_SESSION', 'WAHA_ADMIN_PHONE',
  // Image storage
  'CLOUDINARY_URL',
  // AI
  'GEMINI_API_KEY',
  // Rewards (Hubble)
  'HUBBLE_SDK_BASE_URL', 'HUBBLE_CLIENT_ID', 'HUBBLE_APP_SECRET',
  'HUBBLE_WEBHOOK_SECRET', 'HUBBLE_THEME',
  // Rewards catalog (RewardPort)
  'REWARDPORT_USERNAME', 'REWARDPORT_PASSWORD',
  // Error reporting, a live DSN would ship test stack traces to Sentry
  'SENTRY_DSN',
  // Misc outbound
  'REDIS_URL', 'DEALDIRECT_PAYMENT_QR_URL',
];

/**
 * Synthetic secrets. server.js fails fast without JWT_SECRET, and enforces a
 * 32-character minimum. These are fixed test values and are not secrets:
 * nothing outside this in-memory process ever validates a token signed here.
 */
const TEST_SECRETS = {
  JWT_SECRET: 'integration-test-jwt-secret-not-a-real-key-0000',
  COOKIE_SECRET: 'integration-test-cookie-secret-not-a-real-key-00',
  OTP_SECRET: 'integration-test-otp-secret-not-a-real-key-000000',
  AGREEMENT_SECRET_KEY: 'integration-test-agreement-secret-not-real-00000',
  PAYMENT_WEBHOOK_SECRET: 'integration-test-payment-webhook-secret-not-real',
  CLIENT_URL: 'http://localhost:3000',
  ADMIN_URL: 'http://localhost:5174',
};

/**
 * Must be called BEFORE server.js is imported, so dotenv finds these keys
 * already present and leaves them alone.
 */
export function neutraliseExternalServices() {
  // Fail-closed: everything .env would have supplied, blanked.
  for (const key of dotenvKeyNames()) {
    if (!PROTECTED.has(key)) process.env[key] = '';
  }
  // Plus the known integrations, in case they come from the shell instead.
  for (const key of NEUTRALISED) {
    process.env[key] = '';
  }
  // Then the synthetic values the app needs to boot at all.
  for (const [key, value] of Object.entries(TEST_SECRETS)) {
    process.env[key] = value;
  }
}

/**
 * Report which environment keys still hold a non-empty value after
 * neutralisation, excluding the synthetic test values. Used by the isolation
 * test to assert that nothing real survived.
 */
export function residualConfiguredKeys() {
  const synthetic = new Set([
    ...Object.keys(TEST_SECRETS),
    'MONGO_URI',
    // Repopulated by fakeProviders.js with values that address a loopback
    // server. The isolation suite asserts separately that EQUENCE_BASE_URL
    // resolves to 127.0.0.1, which is the claim that actually matters.
    'EQUENCE_BASE_URL', 'EQUENCE_USERNAME', 'EQUENCE_PASSWORD',
    'EQUENCE_SENDER_ID', 'EQUENCE_PE_ID',
    'EQUENCE_OTP_TMPL_ID', 'EQUENCE_RESET_TMPL_ID',
    // Also synthetic, see the note in fakeProviders.js. The isolation suite
    // asserts it is the fake value, not a real cloud.
    'CLOUDINARY_URL',
  ]);
  const suspect = [...dotenvKeyNames(), ...NEUTRALISED];
  return suspect.filter(
    (k) => !synthetic.has(k) && !PROTECTED.has(k) && process.env[k]
  );
}

// ---------------------------------------------------------------------------
// Egress blocking
// ---------------------------------------------------------------------------

const LOCAL = new Set(['127.0.0.1', 'localhost', '0.0.0.0', '::1', '::ffff:127.0.0.1']);

const attempts = [];
let installed = false;
let original = null;

function hostOf(input, options) {
  if (typeof input === 'string') {
    try { return new URL(input).hostname; } catch { return input; }
  }
  if (input && typeof input === 'object') {
    if (input.hostname) return input.hostname;
    if (input.host) return String(input.host).split(':')[0];
  }
  if (options && typeof options === 'object') {
    if (options.hostname) return options.hostname;
    if (options.host) return String(options.host).split(':')[0];
  }
  return 'unknown';
}

function isLocal(host) {
  return LOCAL.has(host) || host === 'unknown';
}

export class EgressBlockedError extends Error {
  constructor(scheme, host) {
    super(
      `[test-egress] Blocked outbound ${scheme} request to "${host}". ` +
      'Integration tests must not contact external services.'
    );
    this.name = 'EgressBlockedError';
    this.code = 'ETESTEGRESS';
    this.host = host;
  }
}

/**
 * A stand-in for the ClientRequest that http.request would have returned.
 *
 * Throwing synchronously from http.request looks like the strictest possible
 * block, but it is the wrong shape and it broke the harness: the Cloudinary
 * SDK's startup ping calls https.request inside a promise executor and only
 * handles the async 'error' event, so a synchronous throw escaped as an
 * uncaught exception and server.js's crash handler tore the process down. Every
 * suite then failed for that reason instead of its own.
 *
 * Node reports an unreachable host as an asynchronous 'error' event, so that is
 * what this emits. Callers with normal error handling degrade exactly as they
 * would with the network down, and a caller with NO error handling still fails
 * loudly, which is the behaviour worth keeping.
 *
 * It is a real Writable, not a bare EventEmitter, because callers pipe into a
 * ClientRequest and a plain emitter is not good enough for that. The Cloudinary
 * SDK does `upload_stream.pipe(post_request)` (uploader.js:597) and only then
 * attaches its own error handler; against a fake with no stream machinery the
 * blocked-egress error escaped as an unhandled 'error' and was reported as a
 * test crash rather than the clean upload failure the application would see.
 * The bug there was the harness, not the app, and a harness that misreports
 * which is which is worse than no harness.
 *
 * The emit is deferred to a macrotask so that callers which attach their error
 * handler on the line after `https.request(...)` have run first, which is what
 * a real socket's timing gives them.
 */
function blockedRequest(scheme, host) {
  const req = new Writable({
    write(_chunk, _encoding, callback) { callback(); },
    final(callback) { callback(); },
  });

  const self = () => req;
  Object.assign(req, {
    setHeader: self,
    getHeader: () => undefined,
    removeHeader: self,
    setTimeout: self,
    flushHeaders: self,
    abort: self,
    setNoDelay: self,
    setSocketKeepAlive: self,
    aborted: false,
  });

  setTimeout(() => {
    req.emit('error', new EgressBlockedError(scheme, host));
  }, 0);

  return req;
}

/**
 * Intercept http/https/fetch. Non-local destinations throw immediately and are
 * recorded. Local traffic passes so the in-memory mongod and Supertest's own
 * ephemeral socket keep working.
 */
export function blockNetworkEgress() {
  if (installed) return;

  original = {
    httpRequest: http.request,
    httpGet: http.get,
    httpsRequest: https.request,
    httpsGet: https.get,
    fetch: globalThis.fetch,
  };

  const wrap = (fn, scheme) => function (input, options, cb) {
    const host = hostOf(input, options);
    if (!isLocal(host)) {
      attempts.push({ scheme, host });
      return blockedRequest(scheme, host);
    }
    return fn.call(this, input, options, cb);
  };

  http.request = wrap(original.httpRequest, 'http');
  http.get = wrap(original.httpGet, 'http');
  https.request = wrap(original.httpsRequest, 'https');
  https.get = wrap(original.httpsGet, 'https');

  // The Gemini SDK and other modern clients use fetch, which does not go
  // through http.request, so it needs its own wrapper.
  globalThis.fetch = async (input, init) => {
    const host = hostOf(
      typeof input === 'string' ? input : input?.url || input,
      init
    );
    if (!isLocal(host)) {
      attempts.push({ scheme: 'fetch', host });
      // Rejecting IS how fetch reports a network failure, so this one needs no
      // special shape.
      throw new EgressBlockedError('fetch', host);
    }
    return original.fetch(input, init);
  };

  installed = true;
}

/** Restore the real network stack. */
export function restoreNetworkEgress() {
  if (!installed || !original) return;
  http.request = original.httpRequest;
  http.get = original.httpGet;
  https.request = original.httpsRequest;
  https.get = original.httpsGet;
  globalThis.fetch = original.fetch;
  installed = false;
}

/** Every blocked outbound attempt so far, for assertions. */
export function egressAttempts() {
  return [...attempts];
}

/** Clear the recorded attempts between tests. */
export function clearEgressAttempts() {
  attempts.length = 0;
}
