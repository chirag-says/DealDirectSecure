/**
 * Suite 5: Property edits when image storage is unavailable.
 *
 * This file runs in a process where Cloudinary was never configured.
 * `upload.js` reads CLOUDINARY_URL once at import and captures the answer in a
 * module constant, so the unconfigured branch cannot be reached by unsetting a
 * variable mid-test. Node gives each test file its own process, which is what
 * makes this testable at all: the opt-out below is set before the harness boots.
 *
 * The defect being covered: `validateAndUploadToCloudinary` refused every
 * request on a guarded route when storage was unavailable, whether or not the
 * request carried a file. Property create and update both sit behind it, so an
 * image-service outage also blocked editing a price or a description.
 *
 * The fix has to hold two things apart that are easy to conflate:
 *
 *   no file  + storage down  ->  proceed. The request never needed storage.
 *   file     + storage down  ->  refuse. Accepting it would report success for
 *                                a listing whose photos went nowhere, which is
 *                                worse than an error the owner can act on.
 *
 * Both directions are asserted here. A fix that only relaxed the first would
 * pass a weaker suite while silently dropping images.
 */

process.env.HARNESS_DISABLE_CLOUDINARY = '1';

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeOwner, makeProperty, loginAs } from './setup/factories.js';
import { JPEG_1x1, NOT_AN_IMAGE } from './setup/fixtures.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const Property = () => mongoose.model('Property');

async function ownerWithProperty(overrides = {}) {
  const owner = await makeOwner();
  const cookies = await loginAs(api, owner);
  const property = await makeProperty(owner, overrides);
  return { owner, cookies, property };
}

// ---------------------------------------------------------------------------

test('the harness really has storage switched off', async (t) => {
  await t.test('CLOUDINARY_URL is empty in this process', () => {
    // Without this the rest of the file would be testing the configured path
    // and quietly proving nothing.
    assert.ok(
      !process.env.CLOUDINARY_URL,
      'this suite is meaningless unless Cloudinary is genuinely unconfigured here'
    );
  });
});

// ---------------------------------------------------------------------------

test('a text-only edit works while storage is down', async (t) => {
  await t.test('updating a title and price succeeds and persists', async () => {
    const { cookies, property } = await ownerWithProperty({ title: 'Before', price: 1000 });

    const res = await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .send({ title: 'Corrected Title', price: 4250000 });

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 300));

    const stored = await Property().findById(property._id).lean();
    assert.equal(stored.title, 'Corrected Title');
    assert.equal(stored.price, 4250000);
  });

  await t.test('the refusal is not merely deferred to the response body', async () => {
    // A 200 carrying {success: false} would be the same outage in disguise.
    const { cookies, property } = await ownerWithProperty();

    const res = await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .send({ description: 'A corrected description.' });

    assert.equal(res.status, 200);
    assert.notEqual(res.body?.code, 'STORAGE_NOT_CONFIGURED');
    assert.equal(
      (await Property().findById(property._id).lean()).description,
      'A corrected description.'
    );
  });

  await t.test('a multipart edit with no file attached also works', async () => {
    // The edit form posts multipart even when the owner changed only text, so
    // the content type alone must not trigger the storage requirement.
    const { cookies, property } = await ownerWithProperty();

    const res = await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .field('title', 'Multipart No File');

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 300));
    assert.equal((await Property().findById(property._id).lean()).title, 'Multipart No File');
  });

  await t.test('creating a listing without images still works', async () => {
    const owner = await makeOwner();
    const cookies = await loginAs(api, owner);

    const res = await api
      .post('/api/properties/add')
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .send({ title: 'No Images', listingType: 'Sell', price: 500000, latitude: 11.11, longitude: 77.77 });

    assert.equal(res.status, 201, JSON.stringify(res.body).slice(0, 300));
  });
});

// ---------------------------------------------------------------------------

test('an edit carrying a file fails safely while storage is down', async (t) => {
  await t.test('refuses with 503 and an actionable code', async () => {
    const { cookies, property } = await ownerWithProperty({ title: 'Untouched' });

    const res = await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .field('title', 'Should Not Apply')
      .attach('images', JPEG_1x1, 'photo.jpg');

    assert.equal(res.status, 503, JSON.stringify(res.body).slice(0, 300));
    assert.equal(res.body.code, 'STORAGE_NOT_CONFIGURED');
  });

  await t.test('does not apply the rest of the update as a consolation', async () => {
    // Half-applying would be the worst outcome: the owner sees an error, the
    // text changed anyway, and the image did not.
    const { cookies, property } = await ownerWithProperty({ title: 'Untouched' });

    await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .field('title', 'Should Not Apply')
      .attach('images', JPEG_1x1, 'photo.jpg');

    const stored = await Property().findById(property._id).lean();
    assert.equal(stored.title, 'Untouched', 'the request must be refused whole');
  });

  await t.test('stores no image reference', async () => {
    const { cookies, property } = await ownerWithProperty();

    await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .attach('images', JPEG_1x1, 'photo.jpg');

    const stored = await Property().findById(property._id).lean();
    assert.deepEqual(stored.images ?? [], [], 'no image may be recorded that was never stored');
  });

  await t.test('refuses a create carrying an image too', async () => {
    const owner = await makeOwner();
    const cookies = await loginAs(api, owner);

    const res = await api
      .post('/api/properties/add')
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .field('title', 'With Image')
      .field('listingType', 'Sell')
      .attach('images', JPEG_1x1, 'photo.jpg');

    assert.equal(res.status, 503);
    assert.equal(res.body.code, 'STORAGE_NOT_CONFIGURED');
    assert.equal(await Property().countDocuments({ owner: owner._id }), 0);
  });
});

// ---------------------------------------------------------------------------

test('storage being down does not become a way past the file checks', async (t) => {
  await t.test('a disguised non-image is still refused, not accepted', async () => {
    // The important property is the negative one: whatever the status, the
    // request must not succeed. Magic-byte validation runs after the storage
    // check, so with storage down this is refused earlier; if the ordering is
    // ever changed, it must still be refused here.
    const { cookies, property } = await ownerWithProperty({ title: 'Untouched' });

    const res = await api
      .put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp())
      .set('Cookie', cookies)
      .field('title', 'Should Not Apply')
      .attach('images', NOT_AN_IMAGE, 'payload.jpg');

    assert.ok(res.status >= 400, `a bogus file must never be accepted, got ${res.status}`);

    const stored = await Property().findById(property._id).lean();
    assert.equal(stored.title, 'Untouched');
    assert.deepEqual(stored.images ?? [], []);
  });
});
