/**
 * Express application harness.
 *
 * Loads the REAL app from server.js and drives it with Supertest. Nothing is
 * stubbed: the request passes through helmet, CORS, cookie-parser, the rate
 * limiters, CSRF, the validators, the auth middleware, the controller, and
 * Mongoose. That is the point, a test that bypasses the middleware chain
 * cannot tell you whether authorisation actually holds.
 *
 * Supertest binds an ephemeral port on demand and tears it down per request,
 * so nothing listens on 9000 and parallel runs do not collide.
 *
 * IMPORT ORDER IS LOAD-BEARING
 * ----------------------------
 * server.js does three things at import time: it reads .env, it validates
 * required variables and calls process.exit(1) if any are missing, and (absent
 * the NODE_ENV seam) it would connect to Mongo and listen on 9000. So before
 * it is imported we must have:
 *
 *   1. asserted NODE_ENV === 'test'          (guard.js)
 *   2. blanked the outbound credentials      (externals.js), dotenv will not
 *                                             overwrite keys already present
 *   3. started the in-memory database        (db.js), which sets MONGO_URI,
 *                                             satisfying the required-vars check
 *
 * Only then is the dynamic import safe.
 */

import supertest from 'supertest';
import { assertTestEnvironment } from './guard.js';
import { startTestDatabase } from './db.js';
import { neutraliseExternalServices, blockNetworkEgress } from './externals.js';
import { startFakeProviders } from './fakeProviders.js';

let cachedApp = null;

/**
 * Boot the harness once per process and return the Express app.
 */
export async function getApp() {
  if (cachedApp) return cachedApp;

  assertTestEnvironment();
  neutraliseExternalServices();

  // Points EQUENCE_BASE_URL at a loopback server. Must also precede the
  // server.js import so dotenv does not overwrite it with the real endpoint.
  await startFakeProviders();

  // Must precede the server.js import: it populates MONGO_URI.
  // Also runs before egress blocking, because mongodb-memory-server may need
  // to download the mongod binary on a cold machine.
  await startTestDatabase();

  blockNetworkEgress();

  const mod = await import('../../../server.js');
  cachedApp = mod.app;

  if (!cachedApp) {
    throw new Error('[harness] server.js did not export `app`.');
  }

  await buildAllIndexes();

  return cachedApp;
}

/**
 * Force every model to finish creating its indexes before any test runs.
 *
 * Mongoose builds indexes lazily on first use, and `addProperty` writes inside
 * a transaction. When the two overlap MongoDB aborts the write with
 *
 *   Unable to write to collection ... due to catalog changes; please retry
 *
 * which surfaces as an intermittent 500 from property creation and looks
 * exactly like a product bug. It is not: it is the harness racing itself, and
 * it only appears once enough suites run to make the timing coincide, so it is
 * the kind of flake that shows up later and wastes an afternoon.
 *
 * Doing it up front costs a few hundred milliseconds once per process and makes
 * the suite deterministic. Truncation preserves indexes, so this happens once.
 */
async function buildAllIndexes() {
  const mongoose = (await import('mongoose')).default;

  // Per-model and tolerant, because at least one model cannot build its indexes
  // at all: models/Role.js declares `name` with `unique: true` and then adds
  // `roleSchema.index({ name: 1 })` at line 57, so two different specs compete
  // for the auto-generated name `name_1` and MongoDB rejects the second with
  // IndexKeySpecsConflict. That is a real (pre-existing, benign) defect in the
  // model, not something this harness should fix or hide behind a crash.
  //
  // Failing loudly here would block every suite over an index no test uses.
  // Failing silently would let a genuine index problem pass unnoticed. So each
  // failure is reported once and the run continues; a model that could not
  // build its indexes simply behaves as it did before, building them lazily.
  const failed = [];
  await Promise.all(mongoose.modelNames().map(async (name) => {
    try {
      await mongoose.model(name).init();
    } catch (err) {
      failed.push(`${name}: ${err.message.split('.')[0]}`);
    }
  }));

  if (failed.length) {
    console.warn(`[harness] index build skipped for ${failed.length} model(s):\n  ${failed.join('\n  ')}`);
  }
  return failed;
}

/** A Supertest client bound to the real app. */
export async function request() {
  return supertest(await getApp());
}

// ---------------------------------------------------------------------------
// Rate-limit isolation
// ---------------------------------------------------------------------------

let ipCounter = 0;

/**
 * A distinct client IP per caller.
 *
 * The auth limiter allows 5 requests per 15 minutes PER IP. Every Supertest
 * request originates from 127.0.0.1, so a login suite would exhaust the budget
 * after five requests and the rest would fail with 429 for reasons unrelated to
 * what they assert. Worse, a test could appear to pass because a 429 is
 * also "not 200".
 *
 * Outside production the app sets `trust proxy = 1`, so X-Forwarded-For decides
 * req.ip and therefore the limiter's key. Handing each test its own synthetic
 * IP gives it a fresh budget without touching application code or reaching into
 * the limiter's private store.
 *
 * Tests that mean to exercise rate limiting simply reuse one IP deliberately.
 */
export function uniqueClientIp() {
  ipCounter += 1;
  const a = 10;
  const b = Math.floor(ipCounter / 65536) % 256;
  const c = Math.floor(ipCounter / 256) % 256;
  const d = ipCounter % 256;
  return `${a}.${b}.${c}.${d}`;
}

/**
 * Wrap a Supertest request so it carries a fixed client IP and, when a session
 * is supplied, that session's cookies.
 */
export function withClient(req, { ip, cookies } = {}) {
  let r = req.set('X-Forwarded-For', ip || uniqueClientIp());
  if (cookies && cookies.length) {
    r = r.set('Cookie', cookies);
  }
  return r;
}

/**
 * Extract cookies from a response for reuse on later requests.
 * Returns the `name=value` pairs only, dropping attributes.
 */
export function cookiesFrom(res) {
  const raw = res.headers['set-cookie'] || [];
  return raw.map((c) => c.split(';')[0]);
}

/**
 * Merge two cookie jars, later entries winning by name.
 */
export function mergeCookies(...jars) {
  const map = new Map();
  for (const jar of jars) {
    for (const c of jar || []) {
      map.set(c.split('=')[0], c);
    }
  }
  return [...map.values()];
}
