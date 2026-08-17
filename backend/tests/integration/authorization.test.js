/**
 * Suite 2: Authorization.
 *
 * Two owners, two buyers, and the question that matters: can one reach the
 * other's records? Every case drives the real route with a real session cookie,
 * because ownership in this codebase is enforced in the controllers (there is
 * no policy layer), and a controller-level check is only observable through the
 * endpoint.
 *
 * The assertions are deliberately about the OUTCOME, not the status code. A
 * cross-owner update that returns 403 and a cross-owner update that returns 404
 * are both acceptable; a cross-owner update that returns 200, or that returns
 * 403 while still writing, is not. So each test checks the response is a
 * refusal AND that the stored document is unchanged. A test that only asserted
 * the status would pass against a controller that rejects and mutates anyway.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import {
  makeUser, makeOwner, makeBuyer, makeProperty, makeLead, makeNotification, loginAs,
} from './setup/factories.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

/** A request carrying a session and its own client IP. */
const as = (cookies) => ({
  get: (p) => api.get(p).set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies),
  put: (p) => api.put(p).set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies),
  post: (p) => api.post(p).set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies),
  patch: (p) => api.patch(p).set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies),
  delete: (p) => api.delete(p).set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies),
});

const anon = () => ({
  get: (p) => api.get(p).set('X-Forwarded-For', uniqueClientIp()),
  put: (p) => api.put(p).set('X-Forwarded-For', uniqueClientIp()),
  patch: (p) => api.patch(p).set('X-Forwarded-For', uniqueClientIp()),
  delete: (p) => api.delete(p).set('X-Forwarded-For', uniqueClientIp()),
});

/** Any 4xx is a refusal; 2xx is not. */
const assertRefused = (res, what) => {
  assert.ok(
    res.status >= 400 && res.status < 500,
    `${what}: expected a 4xx refusal, got ${res.status} ${JSON.stringify(res.body).slice(0, 200)}`
  );
};

// ---------------------------------------------------------------------------

test('property ownership', async (t) => {
  await t.test('an owner can read and update their own property', async () => {
    const owner = await makeOwner();
    const cookies = await loginAs(api, owner);
    const property = await makeProperty(owner);

    const read = await as(cookies).get(`/api/properties/my-properties/${property._id}`);
    assert.equal(read.status, 200, JSON.stringify(read.body));

    const update = await as(cookies)
      .put(`/api/properties/my-properties/${property._id}`)
      .send({ title: 'Updated By Owner' });
    assert.equal(update.status, 200, JSON.stringify(update.body));

    const stored = await mongoose.model('Property').findById(property._id);
    assert.equal(stored.title, 'Updated By Owner');
  });

  await t.test('an owner cannot read another owner\'s property through the owner route', async () => {
    const [a, b] = [await makeOwner(), await makeOwner()];
    const cookiesA = await loginAs(api, a);
    const propertyB = await makeProperty(b);

    const res = await as(cookiesA).get(`/api/properties/my-properties/${propertyB._id}`);
    assertRefused(res, 'cross-owner read');
  });

  await t.test('an owner cannot update another owner\'s property', async () => {
    const [a, b] = [await makeOwner(), await makeOwner()];
    const cookiesA = await loginAs(api, a);
    const propertyB = await makeProperty(b, { title: 'Belongs To B' });

    const res = await as(cookiesA)
      .put(`/api/properties/my-properties/${propertyB._id}`)
      .send({ title: 'Hijacked By A' });

    assertRefused(res, 'cross-owner update');

    const stored = await mongoose.model('Property').findById(propertyB._id);
    assert.equal(stored.title, 'Belongs To B', 'the document must be untouched');
  });

  await t.test('an owner cannot delete another owner\'s property', async () => {
    const [a, b] = [await makeOwner(), await makeOwner()];
    const cookiesA = await loginAs(api, a);
    const propertyB = await makeProperty(b);

    const res = await as(cookiesA).delete(`/api/properties/${propertyB._id}`);
    assertRefused(res, 'cross-owner delete');

    const stored = await mongoose.model('Property').findById(propertyB._id);
    assert.ok(stored, 'the property must still exist');
  });

  await t.test('my-properties lists only the caller\'s own listings', async () => {
    const [a, b] = [await makeOwner(), await makeOwner()];
    const cookiesA = await loginAs(api, a);
    await makeProperty(a, { title: 'A Listing' });
    await makeProperty(b, { title: 'B Listing' });

    const res = await as(cookiesA).get('/api/properties/my-properties');
    assert.equal(res.status, 200);

    const payload = JSON.stringify(res.body);
    assert.ok(payload.includes('A Listing'));
    assert.ok(!payload.includes('B Listing'), 'another owner\'s listing must not appear');
  });

  await t.test('an anonymous caller cannot reach any owner route', async () => {
    const owner = await makeOwner();
    const property = await makeProperty(owner);

    for (const res of [
      await anon().get('/api/properties/my-properties'),
      await anon().get(`/api/properties/my-properties/${property._id}`),
      await anon().put(`/api/properties/my-properties/${property._id}`).send({ title: 'x' }),
      await anon().delete(`/api/properties/${property._id}`),
    ]) {
      assert.equal(res.status, 401, 'owner routes must require a session');
    }
  });

  await t.test('a buyer cannot use the owner listing routes', async () => {
    const buyer = await makeBuyer();
    const cookies = await loginAs(api, buyer);

    const res = await as(cookies).get('/api/properties/my-properties');
    // getMyProperties has no role gate, so an empty result is the correct
    // outcome here; what must never happen is seeing someone else's listings.
    if (res.status === 200) {
      const owner = await makeOwner();
      await makeProperty(owner, { title: 'Owner Only Listing' });
      const again = await as(cookies).get('/api/properties/my-properties');
      assert.ok(
        !JSON.stringify(again.body).includes('Owner Only Listing'),
        'a buyer must not see an owner\'s listings'
      );
    } else {
      assertRefused(res, 'buyer on owner route');
    }
  });
});

// ---------------------------------------------------------------------------

test('lead access', async (t) => {
  await t.test('an owner sees leads on their own property', async () => {
    const owner = await makeOwner();
    const buyer = await makeBuyer();
    const cookies = await loginAs(api, owner);
    const property = await makeProperty(owner);
    await makeLead(property, buyer);

    const res = await as(cookies).get('/api/leads');
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.ok(JSON.stringify(res.body).includes(buyer.email));
  });

  await t.test('an owner does not see leads belonging to another owner', async () => {
    const [a, b] = [await makeOwner(), await makeOwner()];
    const buyerB = await makeBuyer();
    const cookiesA = await loginAs(api, a);

    const propertyB = await makeProperty(b);
    await makeLead(propertyB, buyerB);

    const res = await as(cookiesA).get('/api/leads');
    assert.equal(res.status, 200);
    assert.ok(
      !JSON.stringify(res.body).includes(buyerB.email),
      'another owner\'s lead must not leak, including the buyer\'s contact details'
    );
  });

  await t.test('an owner cannot read leads for a property they do not own', async () => {
    const [a, b] = [await makeOwner(), await makeOwner()];
    const buyerB = await makeBuyer();
    const cookiesA = await loginAs(api, a);
    const propertyB = await makeProperty(b);
    await makeLead(propertyB, buyerB);

    const res = await as(cookiesA).get(`/api/leads/property/${propertyB._id}`);
    if (res.status === 200) {
      assert.ok(
        !JSON.stringify(res.body).includes(buyerB.email),
        'must not return another owner\'s leads'
      );
    } else {
      assertRefused(res, 'cross-owner lead read');
    }
  });

  await t.test('an owner cannot change the status of another owner\'s lead', async () => {
    const [a, b] = [await makeOwner(), await makeOwner()];
    const buyerB = await makeBuyer();
    const cookiesA = await loginAs(api, a);
    const propertyB = await makeProperty(b);
    const lead = await makeLead(propertyB, buyerB, { status: 'new' });

    const res = await as(cookiesA).put(`/api/leads/${lead._id}/status`).send({ status: 'converted' });
    assertRefused(res, 'cross-owner lead status change');

    const stored = await mongoose.model('Lead').findById(lead._id);
    assert.equal(stored.status, 'new', 'the lead status must be unchanged');
  });

  await t.test('lead routes require a session', async () => {
    const res = await anon().get('/api/leads');
    assert.equal(res.status, 401);
  });
});

// ---------------------------------------------------------------------------

test('notification access', async (t) => {
  await t.test('a user sees only their own notifications', async () => {
    const [a, b] = await makeUserPair();
    const cookiesA = await loginAs(api, a);

    await makeNotification(a, { title: 'For A' });
    await makeNotification(b, { title: 'For B' });

    const res = await as(cookiesA).get('/api/notifications');
    assert.equal(res.status, 200, JSON.stringify(res.body));

    const payload = JSON.stringify(res.body);
    assert.ok(payload.includes('For A'));
    assert.ok(!payload.includes('For B'), 'another user\'s notification must not appear');
  });

  await t.test('a user cannot mark another user\'s notification as read', async () => {
    const [a, b] = await makeUserPair();
    const cookiesA = await loginAs(api, a);
    const notificationB = await makeNotification(b, { title: 'For B' });

    const res = await as(cookiesA).patch(`/api/notifications/${notificationB._id}/read`);
    assertRefused(res, 'cross-user notification read-marking');

    const stored = await mongoose.model('Notification').findById(notificationB._id);
    assert.notEqual(stored.isRead, true, 'the notification must remain unread');
  });

  await t.test('mark-all never touches another user\'s notifications', async () => {
    const [a, b] = await makeUserPair();
    const cookiesA = await loginAs(api, a);
    await makeNotification(a);
    const notificationB = await makeNotification(b);

    await as(cookiesA).patch('/api/notifications/mark-all/read');

    // The invariant holds whatever the endpoint does, including nothing.
    const stored = await mongoose.model('Notification').findById(notificationB._id);
    assert.notEqual(stored.isRead, true, 'another user\'s notification must stay unread');
  });

  await t.test('notification routes require a session', async () => {
    const res = await anon().get('/api/notifications');
    assert.equal(res.status, 401);
  });
});

/** Two distinct ordinary users. */
async function makeUserPair() {
  return [await makeUser(), await makeUser()];
}
