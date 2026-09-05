/**
 * The shortlist (Phase 1, F7).
 *
 * The invariant this collection exists to protect is the first thing tested:
 * saving a home privately must not create a Lead, must not notify the owner,
 * and must not consume one of the five enquiry slots. Everything else here is
 * the real-world shape of a list people keep for months: duplicates from two
 * devices, listings that sell out from under them, a local list handed over
 * at first sign-in, and a link shared with a spouse.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, withClient } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders, watchEmail, unwatchEmail, emailedAddresses, clearEmails, settleEmail } from './setup/fakeProviders.js';
import { buyerWithSession, ownerWithSession, makeProperty, makeBuyer, loginAs, TEST_PASSWORD } from './setup/factories.js';

let api;
const M = (name) => mongoose.model(name);

const get = (path, cookies) => withClient(api.get(path), { cookies });
const post = (path, cookies) => withClient(api.post(path), { cookies });
const del = (path, cookies) => withClient(api.delete(path), { cookies });
const patch = (path, cookies) => withClient(api.patch(path), { cookies });

test.before(async () => { api = await request(); watchEmail(); });
test.beforeEach(async () => { await truncateAll(); clearEmails(); });
test.after(async () => { unwatchEmail(); await stopFakeProviders(); await stopTestDatabase(); });

// ---------------------------------------------------------------------------

test('a shortlist is private', async (t) => {
  await t.test('saving creates no Lead, notifies nobody, and sends no email', async () => {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    const property = await makeProperty(o.owner, { isApproved: true });

    const res = await post('/api/shortlist', b.cookies).send({ propertyId: property._id });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    await settleEmail();

    assert.equal(await M('Lead').countDocuments({}), 0, 'a private save must never create a lead');
    assert.equal(await M('Notification').countDocuments({}), 0);
    assert.equal(emailedAddresses().length, 0);
    assert.equal(await M('Shortlist').countDocuments({ user: b.buyer._id }), 1);
  });

  await t.test('it does not consume an enquiry slot', async () => {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    const properties = await Promise.all(
      Array.from({ length: 8 }, () => makeProperty(o.owner, { isApproved: true }))
    );

    for (const p of properties) {
      const res = await post('/api/shortlist', b.cookies).send({ propertyId: p._id });
      assert.equal(res.status, 200, `saving ${p._id} must not be capped`);
    }

    const list = await get('/api/shortlist', b.cookies);
    assert.equal(list.body.data.length, 8, 'the shortlist is uncapped by design');

    // The enquiry cap is untouched: five separate slots still available.
    const saved = await get('/api/properties/saved', b.cookies);
    assert.equal(saved.status, 200);
    assert.equal((saved.body.data || saved.body.properties || []).length, 0);
  });

  await t.test('the controller imports neither Lead nor the notifier', async () => {
    // Structural, not behavioural: the absence of these imports is what stops
    // a future edit from wiring a save to the interest endpoint by accident.
    const { readFileSync } = await import('node:fs');
    const src = readFileSync(new URL('../../controllers/shortlistController.js', import.meta.url), 'utf8');
    assert.doesNotMatch(src, /models\/Lead\.js/);
    assert.doesNotMatch(src, /notificationService/);
  });
});

// ---------------------------------------------------------------------------

test('saving and unsaving', async (t) => {
  await t.test('saving twice is one row and keeps the original order', async () => {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    const property = await makeProperty(o.owner);

    const first = await post('/api/shortlist', b.cookies).send({ propertyId: property._id });
    const addedAt = first.body.data.addedAt;
    await new Promise((r) => setTimeout(r, 20));
    const second = await post('/api/shortlist', b.cookies).send({ propertyId: property._id, note: 'near the metro' });

    assert.equal(second.status, 200);
    assert.equal(await M('Shortlist').countDocuments({ user: b.buyer._id }), 1);
    const row = await M('Shortlist').findOne({ user: b.buyer._id }).lean();
    assert.equal(new Date(row.addedAt).toISOString(), new Date(addedAt).toISOString(), 'a re-save must not reorder the list');
    assert.equal(row.note, 'near the metro');
  });

  await t.test('a missing or malformed property is refused with a code', async () => {
    const b = await buyerWithSession(api);
    const bad = await post('/api/shortlist', b.cookies).send({ propertyId: 'nope' });
    assert.equal(bad.status, 400);
    assert.equal(bad.body.code, 'INVALID_ID');

    const gone = await post('/api/shortlist', b.cookies).send({ propertyId: new mongoose.Types.ObjectId() });
    assert.equal(gone.status, 404);
    assert.equal(gone.body.code, 'NOT_FOUND');
  });

  await t.test('removing something already gone is still a success', async () => {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    const property = await makeProperty(o.owner);
    await post('/api/shortlist', b.cookies).send({ propertyId: property._id });

    const first = await del(`/api/shortlist/${property._id}`, b.cookies);
    assert.equal(first.body.removed, true);
    assert.equal(first.body.total, 0);

    const second = await del(`/api/shortlist/${property._id}`, b.cookies);
    assert.equal(second.status, 200);
    assert.equal(second.body.removed, false, 'the caller wanted it gone, and it is gone');
  });

  await t.test('one person cannot see or remove another\'s saves', async () => {
    const o = await ownerWithSession(api);
    const mine = await buyerWithSession(api);
    const theirs = await buyerWithSession(api);
    const property = await makeProperty(o.owner);

    await post('/api/shortlist', mine.cookies).send({ propertyId: property._id });
    const theirList = await get('/api/shortlist', theirs.cookies);
    assert.equal(theirList.body.data.length, 0);

    await del(`/api/shortlist/${property._id}`, theirs.cookies);
    assert.equal(await M('Shortlist').countDocuments({ user: mine.buyer._id }), 1, 'someone else\'s delete must not touch my list');
  });

  await t.test('a session is required for every private route', async () => {
    for (const call of [get('/api/shortlist'), post('/api/shortlist'), del('/api/shortlist/x'), post('/api/shortlist/share')]) {
      const res = await call.send({});
      assert.equal(res.status, 401, res.request?.url);
    }
  });

  await t.test('notes are clipped and only reachable on a saved property', async () => {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    const property = await makeProperty(o.owner);

    const missing = await patch(`/api/shortlist/${property._id}`, b.cookies).send({ note: 'x' });
    assert.equal(missing.status, 404);
    assert.equal(missing.body.code, 'NOT_SHORTLISTED');

    await post('/api/shortlist', b.cookies).send({ propertyId: property._id });
    const long = await patch(`/api/shortlist/${property._id}`, b.cookies).send({ note: 'y'.repeat(500) });
    assert.equal(long.body.data.note.length, 300);
  });
});

// ---------------------------------------------------------------------------

test('the list survives the real world', async (t) => {
  await t.test('a sold listing stays on the list, marked, rather than vanishing', async () => {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    const property = await makeProperty(o.owner, { isApproved: true });
    await post('/api/shortlist', b.cookies).send({ propertyId: property._id });

    await M('Property').updateOne({ _id: property._id }, { $set: { status: 'sold' } });
    const list = await get('/api/shortlist', b.cookies);

    assert.equal(list.body.data.length, 1, 'a buyer wants to know the home went');
    assert.equal(list.body.data[0].available, false);
    assert.equal(list.body.data[0].unavailableReason, 'sold');
  });

  await t.test('a deleted listing is dropped from the response and cleaned up', async () => {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    const property = await makeProperty(o.owner);
    await post('/api/shortlist', b.cookies).send({ propertyId: property._id });

    await M('Property').deleteOne({ _id: property._id });
    const list = await get('/api/shortlist', b.cookies);
    assert.equal(list.body.data.length, 0, 'a pointer to nothing helps nobody');

    await new Promise((r) => setTimeout(r, 60));
    assert.equal(await M('Shortlist').countDocuments({ user: b.buyer._id }), 0, 'the orphan row is swept');
  });

  await t.test('the list paginates newest first', async () => {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    for (let i = 0; i < 5; i += 1) {
      const p = await makeProperty(o.owner);
      await post('/api/shortlist', b.cookies).send({ propertyId: p._id });
      await new Promise((r) => setTimeout(r, 5));
    }
    const page = await get('/api/shortlist?page=1&limit=2', b.cookies);
    assert.equal(page.body.data.length, 2);
    assert.equal(page.body.pagination.total, 5);
    assert.equal(page.body.pagination.pages, 3);
    assert.ok(new Date(page.body.data[0].addedAt) >= new Date(page.body.data[1].addedAt));
  });

  await t.test('the id sync returns exactly what is saved', async () => {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    const property = await makeProperty(o.owner);
    await post('/api/shortlist', b.cookies).send({ propertyId: property._id });

    const ids = await get('/api/shortlist/ids', b.cookies);
    assert.deepEqual(ids.body.data, [String(property._id)]);
  });

  await t.test('deleting the account takes the list and its links with it', async () => {
    const o = await ownerWithSession(api);
    const buyer = await makeBuyer();
    const cookies = await loginAs(api, buyer);
    const property = await makeProperty(o.owner);
    await post('/api/shortlist', cookies).send({ propertyId: property._id });
    await post('/api/shortlist/share', cookies).send({});

    const res = await del('/api/users/me', cookies).send({ password: TEST_PASSWORD });
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal(await M('Shortlist').countDocuments({ user: buyer._id }), 0);
    assert.equal(await M('ShortlistShare').countDocuments({ user: buyer._id }), 0);
  });
});

// ---------------------------------------------------------------------------

test('handing over a device list', async (t) => {
  await t.test('merges what exists, skips what does not, and never duplicates', async () => {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    const a1 = await makeProperty(o.owner);
    const a2 = await makeProperty(o.owner);
    await post('/api/shortlist', b.cookies).send({ propertyId: a1._id });

    const res = await post('/api/shortlist/merge', b.cookies).send({
      propertyIds: [String(a1._id), String(a2._id), String(new mongoose.Types.ObjectId()), 'garbage', String(a2._id)],
    });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.added, 2, 'both real ids, deduplicated');
    assert.equal(res.body.total, 2);
    assert.equal(await M('Shortlist').countDocuments({ user: b.buyer._id }), 2);
  });

  await t.test('an empty or junk payload is a no-op, not an error', async () => {
    const b = await buyerWithSession(api);
    assert.equal((await post('/api/shortlist/merge', b.cookies).send({})).body.added, 0);
    assert.equal((await post('/api/shortlist/merge', b.cookies).send({ propertyIds: 'no' })).body.added, 0);
  });

  await t.test('a runaway list is capped rather than refused', async () => {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    const ids = Array.from({ length: 300 }, () => String(new mongoose.Types.ObjectId()));
    const res = await post('/api/shortlist/merge', b.cookies).send({ propertyIds: ids });
    assert.equal(res.status, 200);
    assert.equal(res.body.added, 0);
    assert.ok(res.body.skipped > 0);
  });
});

// ---------------------------------------------------------------------------

test('sharing a list', async (t) => {
  async function shared() {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api, { name: 'Asha Menon' });
    const property = await makeProperty(o.owner, { isApproved: true });
    await post('/api/shortlist', b.cookies).send({ propertyId: property._id, note: 'my private note' });
    const res = await post('/api/shortlist/share', b.cookies).send({});
    return { ...b, property, token: res.body.data.token, res };
  }

  await t.test('a link is created, labelled with a first name only, and readable by anyone holding it', async () => {
    const s = await shared();
    assert.equal(s.res.status, 201, JSON.stringify(s.res.body));
    assert.equal(s.res.body.data.count, 1);

    const view = await withClient(api.get(`/api/shortlist/shared/${s.token}`));
    assert.equal(view.status, 200, JSON.stringify(view.body));
    assert.equal(view.body.data.label, 'Asha', 'a surname is not part of a share');
    assert.equal(view.body.data.properties.length, 1);
  });

  await t.test('the private notes are not part of the share', async () => {
    const s = await shared();
    const view = await withClient(api.get(`/api/shortlist/shared/${s.token}`));
    assert.equal(view.body.data.properties[0].note, undefined);
    assert.ok(!JSON.stringify(view.body).includes('my private note'));
  });

  await t.test('an empty shortlist cannot be shared', async () => {
    const b = await buyerWithSession(api);
    const res = await post('/api/shortlist/share', b.cookies).send({});
    assert.equal(res.status, 409);
    assert.equal(res.body.code, 'EMPTY_SHORTLIST');
  });

  await t.test('sharing again rotates the token and kills the old link', async () => {
    const s = await shared();
    const again = await post('/api/shortlist/share', s.cookies).send({});
    assert.notEqual(again.body.data.token, s.token);

    const old = await withClient(api.get(`/api/shortlist/shared/${s.token}`));
    assert.equal(old.status, 404);
    const fresh = await withClient(api.get(`/api/shortlist/shared/${again.body.data.token}`));
    assert.equal(fresh.status, 200);
  });

  await t.test('revoking, expiring and never existing all answer the same 404', async () => {
    const s = await shared();
    const revoke = await del('/api/shortlist/share', s.cookies).send({});
    assert.equal(revoke.body.revoked, 1);

    const revoked = await withClient(api.get(`/api/shortlist/shared/${s.token}`));
    const absent = await withClient(api.get(`/api/shortlist/shared/${'z'.repeat(32)}`));
    assert.equal(revoked.status, 404);
    assert.equal(absent.status, 404);
    assert.equal(revoked.body.code, absent.body.code, 'a dead link reveals nothing about why it died');
  });

  await t.test('an expired link stops working without anyone revoking it', async () => {
    const s = await shared();
    await M('ShortlistShare').updateOne({ token: s.token }, { $set: { expiresAt: new Date(Date.now() - 1000) } });
    const view = await withClient(api.get(`/api/shortlist/shared/${s.token}`));
    assert.equal(view.status, 404);
  });

  await t.test('a token of the wrong shape never reaches the database', async () => {
    for (const token of ['short', 'x'.repeat(200)]) {
      const res = await withClient(api.get(`/api/shortlist/shared/${token}`));
      assert.equal(res.status, 404);
    }
  });

  await t.test('the share is read-only: it exposes no route to change the list', async () => {
    const s = await shared();
    // The token is not a credential for anything else.
    const write = await withClient(api.post('/api/shortlist')).send({ propertyId: String(s.property._id), token: s.token });
    assert.equal(write.status, 401);
  });
});
