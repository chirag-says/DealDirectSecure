/**
 * Suite 6: Upload validation with storage configured.
 *
 * The companion to upload-unavailable.test.js. That file proves a text-only
 * edit survives an outage; this one proves the relaxation did not cost
 * anything, by exercising the checks that only run when storage is available.
 *
 * The risk in the Phase 3A.1 change is specific and worth naming: moving the
 * configuration check below the "no files" return means file-carrying requests
 * now travel further through the middleware than they used to. If that reorder
 * had also moved it past magic-byte validation, or skipped validation for some
 * shape of request, the tests in the other file would still pass, because a
 * request refused for being unable to reach storage looks the same as one
 * refused for carrying a disguised executable.
 *
 * So the assertions here are about WHY something is rejected, not just that it
 * is: the response code distinguishes INVALID_FILE from STORAGE_NOT_CONFIGURED.
 *
 * Cloudinary is "configured" here with the synthetic credentials, which is what
 * lets a file reach validation at all. Files that PASS validation then attempt
 * a real upload, and that path is deliberately not asserted; see the note in
 * the middle of this file for why, and what was verified by hand instead.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeOwner, makeProperty, loginAs, seedTaxonomy } from './setup/factories.js';
import { NOT_AN_IMAGE, PNG_1x1 } from './setup/fixtures.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); await seedTaxonomy(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const Property = () => mongoose.model('Property');

async function ownerWithProperty(overrides = {}) {
  const owner = await makeOwner();
  const cookies = await loginAs(api, owner);
  const property = await makeProperty(owner, overrides);
  return { owner, cookies, property };
}

const putFile = (property, cookies, buffer, filename) =>
  api
    .put(`/api/properties/my-properties/${property._id}`)
    .set('X-Forwarded-For', uniqueClientIp())
    .set('Cookie', cookies)
    .field('title', 'Attempted With File')
    .attach('images', buffer, filename);

// ---------------------------------------------------------------------------

test('this suite runs with storage configured', async (t) => {
  await t.test('CLOUDINARY_URL is the synthetic value', () => {
    // The mirror of the guard in upload-unavailable.test.js. Without storage
    // configured, every case below would stop at the 503 and prove nothing
    // about validation.
    assert.match(String(process.env.CLOUDINARY_URL), /@integration-test-cloud$/);
  });
});

// ---------------------------------------------------------------------------

test('magic-byte validation still runs', async (t) => {
  await t.test('text renamed .jpg is rejected as an invalid file', async () => {
    const { cookies, property } = await ownerWithProperty({ title: 'Untouched' });

    const res = await putFile(property, cookies, NOT_AN_IMAGE, 'payload.jpg');

    assert.equal(res.status, 400, JSON.stringify(res.body).slice(0, 200));
    assert.equal(
      res.body.code, 'INVALID_FILE',
      'must be refused for its content, not for storage being unreachable'
    );
    assert.notEqual(res.body.code, 'STORAGE_NOT_CONFIGURED');
  });

  await t.test('a PNG named .jpg is caught by the extension check', async () => {
    // Valid image bytes, wrong extension: this exercises validateExtension,
    // which sits after the magic-byte check and before any upload.
    const { cookies, property } = await ownerWithProperty({ title: 'Untouched' });

    const res = await putFile(property, cookies, PNG_1x1, 'photo.jpg');

    assert.equal(res.status, 400, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.code, 'EXTENSION_MISMATCH');
  });

  await t.test('a rejected file leaves the property untouched', async () => {
    const { cookies, property } = await ownerWithProperty({ title: 'Untouched' });

    await putFile(property, cookies, NOT_AN_IMAGE, 'payload.jpg');

    const stored = await Property().findById(property._id).lean();
    assert.equal(stored.title, 'Untouched', 'the text part must not apply either');
    assert.deepEqual(stored.images ?? [], []);
  });
});

// ---------------------------------------------------------------------------

// NOT COVERED HERE: a valid image whose upload fails mid-flight.
//
// The obvious test is to attach a real JPEG, let the egress blocker refuse the
// outbound call, and assert the request fails without recording an image. The
// application does exactly that, verified by hand: it answers
// 500 {code: "UPLOAD_FAILED"}, writes no image, and leaves the listing alone.
//
// It cannot be asserted from node:test. `cloudinary.uploader.upload_stream`
// returns a Q promise that the SDK never settles on the failure path
// (uploader.js:595-607), so ANY failed upload, a refused connection in a test
// or a real Cloudinary outage in production, produces an unhandled rejection
// alongside the correctly handled callback. The test runner attributes that
// rejection to whichever test is in flight and fails it, however the assertions
// turn out. Suppressing unhandled rejections to get a green tick would blind
// the whole suite to a class of bug worth catching, so the coverage is skipped
// and the reason recorded instead.
//
// What matters for THIS change is covered above and in
// upload-unavailable.test.js: storage down plus a file is refused with 503,
// nothing is half-applied, and no image reference is stored. The mid-flight
// failure path is unchanged by Phase 3A.1; only the position of the
// configuration check moved.
//
// The SDK's leaked rejection is worth fixing on its own, and is reported
// separately. It is noisy rather than fatal: server.js's handler logs and
// reports without exiting (errorHandler.js:471-483).

// ---------------------------------------------------------------------------

test('text-only edits are unaffected by storage being configured', async (t) => {
  await t.test('a JSON update still succeeds', async () => {
    const { cookies, property } = await ownerWithProperty();

    const res = await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .send({ title: 'Configured And Fine', price: 777000 });

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    const stored = await Property().findById(property._id).lean();
    assert.equal(stored.title, 'Configured And Fine');
    assert.equal(stored.price, 777000);
  });

  await t.test('a multipart update with no file still succeeds', async () => {
    // The regression that hid behind the old 503: multer gives a multipart body
    // a null prototype, and sanitizePropertyData used data.hasOwnProperty(...).
    // With storage unconfigured the 503 masked it; with storage configured this
    // is the request that returned 500 from the edit screen.
    const { cookies, property } = await ownerWithProperty();

    const res = await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .field('title', 'Multipart Text Only')
      .field('price', '888000');

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    const stored = await Property().findById(property._id).lean();
    assert.equal(stored.title, 'Multipart Text Only');
    assert.equal(stored.price, 888000);
  });

  await t.test('a multipart body cannot smuggle an admin-only field', async () => {
    // sanitizePropertyData is what enforces this, and it is the function that
    // was throwing on multipart bodies. Worth pinning that it still filters
    // rather than merely stopping crashing.
    const { cookies, property } = await ownerWithProperty({ isApproved: false });

    const res = await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .field('title', 'Multipart Escalation')
      .field('isApproved', 'true')
      .field('views', '999999');

    assert.equal(res.status, 200);
    const stored = await Property().findById(property._id).lean();
    assert.equal(stored.title, 'Multipart Escalation');
    assert.notEqual(stored.isApproved, true, 'multipart must not be a way around the whitelist');
    assert.notEqual(stored.views, 999999);
  });
});
