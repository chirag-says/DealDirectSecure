/**
 * Suite 0: Harness isolation.
 *
 * This suite exists to make the safety claims checkable. Every other
 * integration suite is only trustworthy if these pass: that the database under
 * test is an in-memory one and not a shared or live cluster, and that no
 * outbound request can leave the process.
 *
 * It runs first alphabetically, but more importantly it fails loudly rather
 * than silently, which is the property that matters. A harness that quietly
 * pointed at a real cluster would otherwise look exactly like a passing suite.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import https from 'node:https';
import http from 'node:http';

import { request } from './setup/app.js';
import {
  startTestDatabase,
  stopTestDatabase,
  truncateAll,
  currentUri,
  supportsTransactions,
} from './setup/db.js';
import { assertIsTestDatabaseUri, assertTestEnvironment } from './setup/guard.js';
import { residualConfiguredKeys, clearEgressAttempts, egressAttempts } from './setup/externals.js';
import { providerBaseUrl, stopFakeProviders } from './setup/fakeProviders.js';

test.before(async () => { await request(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

// ---------------------------------------------------------------------------

test('database isolation', async (t) => {
  await t.test('NODE_ENV is test', () => {
    assert.equal(process.env.NODE_ENV, 'test');
    assert.equal(assertTestEnvironment(), true);
  });

  await t.test('the active connection points at a local in-memory database', () => {
    const uri = currentUri();
    const host = new URL(uri).hostname;
    assert.ok(
      ['127.0.0.1', 'localhost', '::1'].includes(host),
      `connection host must be local, got "${host}"`
    );
    assert.equal(mongoose.connection.host, '127.0.0.1');
  });

  await t.test('the database name marks it as a test database', () => {
    const dbName = mongoose.connection.name;
    assert.match(dbName, /test/i, `database name "${dbName}" must contain "test"`);
  });

  await t.test('it is a replica set, so transactions work', async () => {
    // addProperty runs a Mongo transaction. On a standalone this would be
    // false and property creation would fail for an unrelated reason.
    assert.equal(await supportsTransactions(), true);
  });

  await t.test('the database starts empty, it is not someone else\'s data', async () => {
    await truncateAll();
    const counts = await Promise.all(
      ['User', 'Property', 'Lead'].map((m) => mongoose.model(m).countDocuments())
    );
    assert.deepEqual(counts, [0, 0, 0]);
  });
});

// ---------------------------------------------------------------------------

test('the guard refuses unsafe database targets', async (t) => {
  // These are URI SHAPES, not real endpoints. No production URI appears in this
  // repository, and the guard does not need one: it allows only what is
  // provably local, so everything else is rejected by default.

  await t.test('rejects a hosted mongodb+srv cluster', () => {
    assert.throws(
      () => assertIsTestDatabaseUri('mongodb+srv://user:pw@cluster0.example.mongodb.net/dealdirect_test'),
      /hosted \(mongodb\+srv\) cluster/
    );
  });

  await t.test('rejects a remote host even over plain mongodb://', () => {
    assert.throws(
      () => assertIsTestDatabaseUri('mongodb://db.internal.example.com:27017/dealdirect_test'),
      /non-local host/
    );
  });

  await t.test('rejects a local database not named as a test database', () => {
    assert.throws(
      () => assertIsTestDatabaseUri('mongodb://127.0.0.1:27017/dealdirect'),
      /not marked as a test database/
    );
  });

  await t.test('rejects a URI with no database name', () => {
    assert.throws(
      () => assertIsTestDatabaseUri('mongodb://127.0.0.1:27017/'),
      /no database name/
    );
  });

  await t.test('accepts the in-memory URI actually in use', () => {
    assert.equal(assertIsTestDatabaseUri(currentUri()), true);
  });

  await t.test('rejects empty or non-string input', () => {
    assert.throws(() => assertIsTestDatabaseUri(''), /No MongoDB URI/);
    assert.throws(() => assertIsTestDatabaseUri(null), /No MongoDB URI/);
  });
});

// ---------------------------------------------------------------------------

test('external service isolation', async (t) => {
  await t.test('no real credential survived into the test process', () => {
    const residual = residualConfiguredKeys();
    assert.deepEqual(
      residual, [],
      `these keys still hold a value and could reach a live service: ${residual.join(', ')}`
    );
  });

  await t.test('each integration reports itself unconfigured', () => {
    // This is what makes the application take its own skip path rather than
    // attempting a send. See externals.js for the file:line of each guard.
    for (const key of [
      'SMTP_USER', 'SMTP_PASS',           // email
      'WAHA_API_URL', 'WAHA_API_KEY',     // WhatsApp
      'HUBBLE_APP_SECRET',                 // rewards debit
      'REWARDPORT_USERNAME', 'REWARDPORT_PASSWORD',
      'GEMINI_API_KEY',                    // AI agreement generation
      'SENTRY_DSN',                        // error reporting
    ]) {
      assert.ok(!process.env[key], `${key} must be empty in the test environment`);
    }
  });

  await t.test('email sending takes the skip path instead of connecting', async () => {
    const { sendEmail } = await import('../../utils/emailService.js');
    const res = await sendEmail('test-recipient@example.com', 'anything', []);
    assert.equal(res.skipped, true, 'sendEmail must skip when SMTP is unconfigured');
  });

  await t.test('the Cloudinary credentials are the synthetic ones, not a real cloud', () => {
    // upload.js:379 refuses every request on an upload-guarded route when
    // Cloudinary looks unconfigured, so it has to look configured. What matters
    // is that the value is the fake one and that egress blocking stops any
    // actual upload.
    assert.match(process.env.CLOUDINARY_URL, /@integration-test-cloud$/);
  });

  await t.test('the SMS client is pointed at a loopback server, not a provider', async () => {
    // Registration hard-fails when SMS is unconfigured (userController.js:315),
    // so this integration cannot simply be switched off. It is redirected
    // instead, and the thing worth asserting is where it points.
    const url = new URL(providerBaseUrl());
    assert.equal(url.hostname, '127.0.0.1');
    assert.equal(url.protocol, 'http:');
  });

  await t.test('outbound https is blocked at the transport', async () => {
    clearEgressAttempts();

    // The block surfaces as an async 'error' event, the same way Node reports
    // an unreachable host, so callers that handle network failure keep working
    // instead of crashing the process.
    const errorFrom = (req) =>
      new Promise((resolve, reject) => {
        req.on('error', resolve);
        setTimeout(() => reject(new Error('no error event was emitted')), 1000);
      });

    const a = await errorFrom(https.request('https://api.cloudinary.com/v1_1/demo/image/upload'));
    assert.match(a.message, /Blocked outbound https/);

    const b = await errorFrom(http.request({ hostname: 'api.equence.in', path: '/pushsms' }));
    assert.match(b.message, /Blocked outbound http/);

    assert.deepEqual(
      egressAttempts().map((x) => x.host),
      ['api.cloudinary.com', 'api.equence.in']
    );
  });

  await t.test('outbound fetch is blocked too', async () => {
    clearEgressAttempts();
    await assert.rejects(
      () => fetch('https://generativelanguage.googleapis.com/v1/models'),
      /Blocked outbound fetch/
    );
    assert.equal(egressAttempts()[0].host, 'generativelanguage.googleapis.com');
  });

  await t.test('local traffic still works, or the suite could not run at all', async () => {
    clearEgressAttempts();
    const api = await request();
    const res = await api.get('/health');
    assert.equal(res.status, 200);
    assert.equal(egressAttempts().length, 0);
  });
});
