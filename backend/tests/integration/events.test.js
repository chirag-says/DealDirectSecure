/**
 * Phase 0: usage events, the nightly rollup, the admin funnel.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, withClient } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { buyerWithSession, adminWithSession, asAdmin } from './setup/factories.js';

import { rollupEvents, istDay } from '../../jobs/eventsRollup.js';
import { EVENT_NAMES } from '../../controllers/eventController.js';

let api;
const M = (name) => mongoose.model(name);

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

test('ingest', async (t) => {
  await t.test('accepts whitelisted names, drops the rest, filters props', async () => {
    const res = await withClient(api.post('/api/events')).send({
      platform: 'android',
      anon: 'install-1',
      events: [
        { name: 'search', props: { city: 'Pune', results: 12, secret: 'x', listingType: 'rent' } },
        { name: 'made_up', props: {} },
        { name: 'property_view', props: { propertyId: 'abc', source: 'detail' } },
        'garbage',
        null,
      ],
    });
    assert.equal(res.status, 202, JSON.stringify(res.body));
    assert.equal(res.body.accepted, 2);

    const rows = await M('Event').find({}).sort({ name: 1 }).lean();
    assert.equal(rows.length, 2);
    const search = rows.find((r) => r.name === 'search');
    assert.deepEqual(search.props, { city: 'Pune', listingType: 'rent', results: 12 });
    assert.equal(search.anon, 'install-1');
    assert.equal(search.user, null);
    assert.equal(search.platform, 'android');
  });

  await t.test('a signed-in batch is attributed to the user, not the anon id', async () => {
    const { buyer, cookies } = await buyerWithSession(api);
    const res = await withClient(api.post('/api/events'), { cookies }).send({
      platform: 'ios', anon: 'install-2', events: [{ name: 'session_start', props: { platform: 'ios' } }],
    });
    assert.equal(res.status, 202);
    const row = await M('Event').findOne({}).lean();
    assert.equal(String(row.user), String(buyer._id));
    assert.equal(row.anon, null);
  });

  await t.test('batches are capped at 50 and timestamps far from now are clamped', async () => {
    const events = Array.from({ length: 60 }, () => ({ name: 'search', props: {}, at: '1999-01-01T00:00:00.000Z' }));
    const res = await withClient(api.post('/api/events')).send({ platform: 'web', events });
    assert.equal(res.body.accepted, 50);
    const row = await M('Event').findOne({}).lean();
    assert.ok(Date.now() - new Date(row.at).getTime() < 60_000, 'a 1999 timestamp is replaced by now');
  });

  await t.test('long strings are truncated and objects rejected at the boundary', async () => {
    await withClient(api.post('/api/events')).send({
      platform: 'web', events: [{ name: 'search', props: { city: 'x'.repeat(500), results: { nested: true } } }],
    });
    const row = await M('Event').findOne({}).lean();
    assert.equal(row.props.city.length, 64);
    assert.equal(row.props.results, undefined);
  });

  await t.test('an empty or malformed body is accepted with zero, never a 500', async () => {
    assert.equal((await withClient(api.post('/api/events')).send({})).body.accepted, 0);
    assert.equal((await withClient(api.post('/api/events')).send({ events: 'nope' })).body.accepted, 0);
  });

  await t.test('every whitelisted name has an explicit prop list', () => {
    for (const [name, props] of Object.entries(EVENT_NAMES)) {
      assert.ok(Array.isArray(props), `${name} must declare its props`);
    }
  });
});

test('rollup and metrics', async (t) => {
  await t.test('yesterday is folded into one row per name, counting distinct users', async () => {
    const now = new Date('2026-09-05T03:00:00Z'); // 08:30 IST on the 5th
    const yesterday = new Date('2026-09-04T06:00:00Z'); // 11:30 IST on the 4th
    const u1 = new mongoose.Types.ObjectId();
    const u2 = new mongoose.Types.ObjectId();
    await M('Event').insertMany([
      { name: 'search', user: u1, at: yesterday, props: {} },
      { name: 'search', user: u1, at: yesterday, props: {} },
      { name: 'search', user: u2, at: yesterday, props: {} },
      { name: 'search', anon: 'a1', at: yesterday, props: {} },
      { name: 'property_view', user: u1, at: yesterday, props: {} },
      { name: 'search', user: u1, at: now, props: {} }, // today, not rolled
    ]);

    const result = await rollupEvents({ now, cursor: null });
    assert.equal(result.days, 1);
    assert.deepEqual(result.cursor, { day: '2026-09-04' });

    const rows = await M('EventRollup').find({}).sort({ name: 1 }).lean();
    assert.equal(rows.length, 2);
    const search = rows.find((r) => r.name === 'search');
    assert.equal(search.count, 4);
    assert.equal(search.users, 3);
    assert.equal(search.day, '2026-09-04');
  });

  await t.test('re-running the same day recomputes rather than doubling', async () => {
    const now = new Date('2026-09-05T03:00:00Z');
    await M('Event').create({ name: 'search', at: new Date('2026-09-04T06:00:00Z'), props: {} });
    await rollupEvents({ now, cursor: null });
    await rollupEvents({ now, cursor: null });
    const rows = await M('EventRollup').find({ name: 'search' }).lean();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].count, 1);
  });

  await t.test('a missed night is caught up from the cursor', async () => {
    const now = new Date('2026-09-07T03:00:00Z');
    await M('Event').insertMany([
      { name: 'search', at: new Date('2026-09-05T06:00:00Z'), props: {} },
      { name: 'search', at: new Date('2026-09-06T06:00:00Z'), props: {} },
    ]);
    const result = await rollupEvents({ now, cursor: { day: '2026-09-04' } });
    assert.equal(result.days, 2);
    assert.deepEqual(result.cursor, { day: '2026-09-06' });
    assert.equal(await M('EventRollup').countDocuments({}), 2);
  });

  await t.test('the admin funnel needs an admin session and adds today to the rollups', async () => {
    const { cookies } = await buyerWithSession(api);
    const asUser = await withClient(api.get('/api/admin/metrics'), { cookies });
    assert.equal(asUser.status, 401);

    await M('EventRollup').create({ day: istDay(new Date(Date.now() - 86400 * 1000)), name: 'session_start', count: 5, users: 4 });
    await M('Event').create({ name: 'session_start', anon: 'z', at: new Date(), props: {} });

    const session = await adminWithSession(api);
    const res = await asAdmin(api.get('/api/admin/metrics?days=7'), session);
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.data.funnel.sessions, 5);
    assert.equal(res.body.data.events.session_start.count, 6);
  });
});
