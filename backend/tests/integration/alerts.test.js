/**
 * The return spine (Phase 1, F8 + F9): saved-search alerts that honour their
 * flags, and price-drop alerts that reach the right people once.
 *
 * The flags are the headline. They have been stored, editable in two clients
 * and read by nothing: a person who turned email off kept receiving email.
 * Every combination is asserted here so that cannot silently return.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, withClient } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import {
  stopFakeProviders, clearPushBatches, pushBatchesSent,
  watchEmail, unwatchEmail, emailedAddresses, clearEmails, settleEmail,
} from './setup/fakeProviders.js';
import { buyerWithSession, ownerWithSession, makeProperty, makeBuyer } from './setup/factories.js';

import { notifySavedSearchMatches } from '../../services/notificationService.js';
import { scanPriceDrops } from '../../jobs/priceDropScan.js';
import { recordPriceChange } from '../../services/priceLogService.js';

let api;
const M = (name) => mongoose.model(name);
const settle = (ms = 150) => new Promise((r) => setTimeout(r, ms));

const post = (path, cookies) => withClient(api.post(path), { cookies });
const get = (path, cookies) => withClient(api.get(path), { cookies });

test.before(async () => { api = await request(); watchEmail(); });
test.beforeEach(async () => { await truncateAll(); clearPushBatches(); clearEmails(); });
test.after(async () => { unwatchEmail(); await stopFakeProviders(); await stopTestDatabase(); });

/** A saved search owned by a fresh buyer, with the flags under test. */
async function watcher(filters, flags = {}) {
  const buyer = await makeBuyer();
  const search = await M('SavedSearch').create({
    user: buyer._id,
    name: 'Watching',
    filters: { search: '', city: '', propertyType: '', priceRange: '', availableFor: '', ...filters },
    ...flags,
  });
  return { buyer, search };
}

const listing = (overrides = {}) => ({
  _id: new mongoose.Types.ObjectId(),
  title: 'A 2BHK in Wakad',
  price: 4000000,
  address: { city: 'Pune', area: 'Wakad' },
  ...overrides,
});

// ---------------------------------------------------------------------------

test('saved-search alert flags', async (t) => {
  await t.test('by default a match is an in-app row, an email and a push', async () => {
    const w = await watcher({ city: 'Pune' });
    await M('PushToken').create({ user: w.buyer._id, token: 'ExponentPushToken[matchmatchmatchmatch01]', platform: 'android' });

    await notifySavedSearchMatches(listing());
    await settleEmail();

    const rows = await M('Notification').find({ user: w.buyer._id }).lean();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].hidden, false);
    assert.equal(rows[0].data.kind, 'property');
    assert.equal(emailedAddresses().filter((a) => a === w.buyer.email).length, 1);
    assert.equal(pushBatchesSent().length, 1);
  });

  await t.test('notifyEmail false stops the email and keeps the row', async () => {
    const w = await watcher({ city: 'Pune' }, { notifyEmail: false });
    await notifySavedSearchMatches(listing());
    await settleEmail();

    assert.equal(await M('Notification').countDocuments({ user: w.buyer._id }), 1);
    assert.equal(emailedAddresses().filter((a) => a === w.buyer.email).length, 0);
  });

  await t.test('notifyPush false stops the push and keeps the rest', async () => {
    const w = await watcher({ city: 'Pune' }, { notifyPush: false });
    await M('PushToken').create({ user: w.buyer._id, token: 'ExponentPushToken[nopushnopushnopush01]', platform: 'ios' });

    await notifySavedSearchMatches(listing());
    await settle();

    assert.equal(await M('Notification').countDocuments({ user: w.buyer._id }), 1);
    assert.equal(pushBatchesSent().length, 0);
  });

  await t.test('notifyInApp false hides the row but still emails', async () => {
    const w = await watcher({ city: 'Pune' }, { notifyInApp: false, notifyEmail: true });
    const cookies = await (await import('./setup/factories.js')).loginAs(api, w.buyer);

    await notifySavedSearchMatches(listing());
    await settleEmail();

    assert.equal(await M('Notification').countDocuments({ user: w.buyer._id }), 1, 'the row carries the email');
    assert.equal(emailedAddresses().filter((a) => a === w.buyer.email).length, 1);

    const centre = await get('/api/notifications', cookies);
    assert.equal(centre.status, 200);
    assert.equal(centre.body.notifications.length, 0, 'and stays out of the notification centre');
  });

  await t.test('every channel off produces no row at all, and still records the match', async () => {
    const w = await watcher({ city: 'Pune' }, { notifyInApp: false, notifyEmail: false, notifyPush: false });
    await notifySavedSearchMatches(listing());
    await settleEmail();

    assert.equal(await M('Notification').countDocuments({ user: w.buyer._id }), 0);
    assert.equal(emailedAddresses().length, 0);
    const search = await M('SavedSearch').findById(w.search._id).lean();
    assert.equal(search.matchCount, 1, 'a muted search still shows that it is finding things');
    assert.ok(search.lastMatchAt);
  });

  await t.test('an inactive search hears nothing', async () => {
    const w = await watcher({ city: 'Pune' }, { isActive: false });
    await notifySavedSearchMatches(listing());
    assert.equal(await M('Notification').countDocuments({ user: w.buyer._id }), 0);
  });

  await t.test('a search in another city, or another budget, is not a match', async () => {
    const elsewhere = await watcher({ city: 'Mumbai' });
    const tooRich = await watcher({ city: 'Pune', priceRange: 'high' });
    await notifySavedSearchMatches(listing({ price: 4000000 }));

    assert.equal(await M('Notification').countDocuments({ user: elsewhere.buyer._id }), 0);
    assert.equal(await M('Notification').countDocuments({ user: tooRich.buyer._id }), 0);
  });

  await t.test('the API accepts and returns the push flag', async () => {
    const b = await buyerWithSession(api);
    const created = await post('/api/saved-searches', b.cookies).send({
      name: 'Wakad 2BHK', filters: { city: 'Pune' }, notifyPush: false,
    });
    assert.equal(created.status, 201, JSON.stringify(created.body).slice(0, 200));
    const row = await M('SavedSearch').findOne({ user: b.buyer._id }).lean();
    assert.equal(row.notifyPush, false);
    assert.equal(row.notifyEmail, true);
  });

  await t.test('one listing matching many searches is one insert and one push batch', async () => {
    const watchers = await Promise.all([watcher({ city: 'Pune' }), watcher({ city: 'Pune' }), watcher({ city: '' })]);
    for (const [i, w] of watchers.entries()) {
      await M('PushToken').create({ user: w.buyer._id, token: `ExponentPushToken[fanout${i}fanout${i}fanou]`, platform: 'android' });
    }

    await notifySavedSearchMatches(listing());
    await settle();

    assert.equal(await M('Notification').countDocuments({}), 3);
    assert.equal(pushBatchesSent().length, 1, 'the fan-out is one batch, not one per recipient');
    assert.equal(pushBatchesSent()[0].length, 3);
  });
});

// ---------------------------------------------------------------------------

test('the price log', async (t) => {
  await t.test('a listing writes its opening row, and an edit writes the change', async () => {
    const o = await ownerWithSession(api);
    const property = await makeProperty(o.owner, { price: 5000000, isApproved: true });

    await recordPriceChange({ property, from: null, to: 5000000, source: 'listed' });
    await recordPriceChange({ property, from: 5000000, to: 4500000, source: 'edit' });

    const rows = await M('PriceChange').find({ property: property._id }).sort({ at: 1 }).lean();
    assert.equal(rows.length, 2);
    assert.equal(rows[0].from, null);
    assert.equal(rows[1].deltaPct, -10);
    // The snapshot records the locality as it was when the price was set.
    assert.equal(rows[1].city, property.city || '');
    assert.equal(rows[1].listingType, property.listingType);
  });

  await t.test('an edit that does not move the price records nothing', async () => {
    const o = await ownerWithSession(api);
    const property = await makeProperty(o.owner, { price: 5000000 });
    assert.equal(await recordPriceChange({ property, from: 5000000, to: 5000000 }), null);
    assert.equal(await recordPriceChange({ property, from: 5000000.4, to: 5000000 }), null, 'a form round-trip is not a change');
    assert.equal(await M('PriceChange').countDocuments({ property: property._id }), 0);
  });

  await t.test('a missing or nonsensical price is refused rather than logged as zero', async () => {
    const o = await ownerWithSession(api);
    const property = await makeProperty(o.owner);
    assert.equal(await recordPriceChange({ property, from: 100, to: 0 }), null);
    assert.equal(await recordPriceChange({ property, from: 100, to: undefined }), null);
    assert.equal(await recordPriceChange({ property: null, from: 1, to: 2 }), null);
  });

  await t.test('an owner edit through the API is logged with both sides', async () => {
    const o = await ownerWithSession(api);
    const property = await makeProperty(o.owner, { price: 6000000, isApproved: true });

    const res = await withClient(api.put(`/api/properties/my-properties/${property._id}`), { cookies: o.cookies })
      .field('expectedPrice', '5400000');
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    await settle();

    const row = await M('PriceChange').findOne({ property: property._id, from: { $ne: null } }).lean();
    assert.ok(row, 'the owner edit path must log');
    assert.equal(row.from, 6000000);
    assert.equal(row.to, 5400000);
    assert.equal(row.deltaPct, -10);
    assert.equal(row.source, 'edit');
  });
});

// ---------------------------------------------------------------------------

test('price-drop alerts', async (t) => {
  async function droppedListing({ from = 16000000, to = 14000000, status = 'active' } = {}) {
    const o = await ownerWithSession(api);
    const property = await makeProperty(o.owner, { price: to, status, isApproved: true, city: 'Pune', locality: 'Wakad' });
    await M('Property').updateOne({ _id: property._id }, { $set: { address: { city: 'Pune', area: 'Wakad' } } });
    const fresh = await M('Property').findById(property._id).lean();
    await recordPriceChange({ property: fresh, from, to, source: 'edit' });
    return { owner: o.owner, ownerCookies: o.cookies, property: fresh };
  }

  await t.test('everyone who shortlisted it hears, once, and the owner never does', async () => {
    const d = await droppedListing();
    const b1 = await buyerWithSession(api);
    const b2 = await buyerWithSession(api);
    await post('/api/shortlist', b1.cookies).send({ propertyId: d.property._id });
    await post('/api/shortlist', b2.cookies).send({ propertyId: d.property._id });
    await M('Shortlist').create({ user: d.owner._id, property: d.property._id });

    const first = await scanPriceDrops({ now: new Date() });
    assert.equal(first.drops, 1);
    assert.equal(first.notified, 2, 'both watchers, and not the owner');

    for (const b of [b1.buyer, b2.buyer]) {
      const row = await M('Notification').findOne({ user: b._id, type: 'price_drop' }).lean();
      assert.ok(row, 'a watcher must hear');
      assert.equal(row.data.kind, 'property');
      assert.equal(String(row.data.propertyId), String(d.property._id));
      assert.match(row.message, /down/);
    }
    assert.equal(await M('Notification').countDocuments({ user: d.owner._id, type: 'price_drop' }), 0);

    const second = await scanPriceDrops({ now: new Date(), cursor: first.cursor });
    assert.equal(second.notified, 0, 'the same drop is never announced twice');
  });

  await t.test('a saved search the listing just moved into hears, even without a shortlist', async () => {
    const d = await droppedListing({ from: 16000000, to: 14000000 });
    const inBudget = await watcher({ city: 'Pune', priceRange: 'mid' });
    const alwaysWas = await watcher({ city: 'Pune', priceRange: 'high' });

    const result = await scanPriceDrops({ now: new Date() });
    assert.equal(result.notified, 1);
    assert.equal(await M('Notification').countDocuments({ user: inBudget.buyer._id, type: 'price_drop' }), 1);
    assert.equal(
      await M('Notification').countDocuments({ user: alwaysWas.buyer._id, type: 'price_drop' }), 0,
      'a watcher whose bucket the listing was already in is not re-announced to'
    );
  });

  await t.test('a drop below the threshold is not an event', async () => {
    const d = await droppedListing({ from: 10000000, to: 9900000 });
    const b = await buyerWithSession(api);
    await post('/api/shortlist', b.cookies).send({ propertyId: d.property._id });

    const result = await scanPriceDrops({ now: new Date() });
    assert.equal(result.drops, 0, 'one percent is noise, not news');
    assert.equal(result.notified, 0);
  });

  await t.test('a rise is never an alert', async () => {
    const d = await droppedListing({ from: 10000000, to: 12000000 });
    const b = await buyerWithSession(api);
    await post('/api/shortlist', b.cookies).send({ propertyId: d.property._id });
    const result = await scanPriceDrops({ now: new Date() });
    assert.equal(result.notified, 0);
  });

  await t.test('a listing that sold, or was hidden, between the edit and the scan says nothing', async () => {
    for (const status of ['sold', 'pending', 'inactive']) {
      await truncateAll();
      const d = await droppedListing({ status });
      const b = await buyerWithSession(api);
      await M('Shortlist').create({ user: b.buyer._id, property: d.property._id });
      const result = await scanPriceDrops({ now: new Date() });
      assert.equal(result.notified, 0, `a ${status} listing is not an opportunity`);
    }
  });

  await t.test('a price that moved again since the drop is not announced at the stale figure', async () => {
    const d = await droppedListing({ from: 16000000, to: 14000000 });
    const b = await buyerWithSession(api);
    await M('Shortlist').create({ user: b.buyer._id, property: d.property._id });
    // The owner changed their mind after the logged drop.
    await M('Property').updateOne({ _id: d.property._id }, { $set: { price: 15500000 } });

    const result = await scanPriceDrops({ now: new Date() });
    assert.equal(result.notified, 0, 'only what is currently true is announced');
  });

  await t.test('a first run does not announce the history of the platform', async () => {
    const d = await droppedListing();
    const b = await buyerWithSession(api);
    await M('Shortlist').create({ user: b.buyer._id, property: d.property._id });
    await M('PriceChange').updateMany({}, { $set: { at: new Date(Date.now() - 30 * 86400 * 1000) } });

    const result = await scanPriceDrops({ now: new Date(), cursor: null });
    assert.equal(result.notified, 0, 'the first run looks back one hour, not forever');
  });

  await t.test('a muted saved search is not woken by a price drop either', async () => {
    const d = await droppedListing({ from: 16000000, to: 14000000 });
    const muted = await watcher({ city: 'Pune', priceRange: 'mid' }, { notifyInApp: false, notifyEmail: false, notifyPush: false });
    const result = await scanPriceDrops({ now: new Date() });
    assert.equal(result.notified, 0);
    assert.equal(await M('Notification').countDocuments({ user: muted.buyer._id }), 0);
  });

  await t.test('nothing to scan is a clean, cheap no-op that still advances nothing', async () => {
    const result = await scanPriceDrops({ now: new Date() });
    assert.equal(result.drops, 0);
    assert.equal(result.notified, 0);
    assert.ok(result.cursor.at);
  });
});
