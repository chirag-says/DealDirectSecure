/**
 * Locality price data (Phase 4, E4 + F18 + F19).
 *
 * The sample floor is the subject of most of this file. Publishing a median
 * computed from three listings under DealDirect's name would be the single
 * most damaging thing these pages could do, and the floor is the only thing
 * standing between the aggregation and that. Every path out of the building
 * is checked against it: the page, the list, the guidance, and the "below the
 * locality median" line on a listing.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, withClient } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { ownerWithSession, makeProperty, buyerWithSession } from './setup/factories.js';

import { aggregateLocalities } from '../../jobs/localityAggregate.js';
import { localityMedianFor, priceGuidanceFor } from '../../services/localityService.js';
import { quarterOf, previousQuarter } from '../../utils/locality.js';
import { SAMPLE_FLOOR } from '../../models/LocalityStat.js';

let api;
const M = (name) => mongoose.model(name);
const NOW = new Date('2026-09-04T06:00:00Z');

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

/** `n` live listings in one locality at the given prices. */
async function seed(owner, { city = 'Pune', locality = 'Wakad', listingType = 'Sell', bhk = '2', prices = [], area = null } = {}) {
  const made = [];
  for (const price of prices) {
    const p = await makeProperty(owner, {
      price,
      listingType,
      bhk,
      city,
      locality,
      status: 'active',
      isApproved: true,
      ...(area ? { area: { carpetSqft: area } } : {}),
    });
    made.push(p);
  }
  return made;
}

// ---------------------------------------------------------------------------

test('the sample floor', async (t) => {
  await t.test(`below ${SAMPLE_FLOOR} listings the row is computed but not published`, async () => {
    const o = await ownerWithSession(api);
    await seed(o.owner, { prices: [3000000, 3200000, 3400000] });

    const result = await aggregateLocalities({ now: NOW });
    assert.equal(result.published, 0, 'three listings is a coincidence, not a market');

    const rows = await M('LocalityStat').find({}).lean();
    assert.ok(rows.length > 0, 'the numbers still exist for us');
    assert.equal(rows.every((r) => r.published === false), true);

    const page = await withClient(api.get('/api/localities/pune-wakad'));
    assert.equal(page.status, 404);
    assert.equal(page.body.code, 'LOCALITY_NOT_FOUND');
  });

  await t.test(`at ${SAMPLE_FLOOR} listings it publishes`, async () => {
    const o = await ownerWithSession(api);
    await seed(o.owner, { prices: [3000000, 3200000, 3400000, 3600000, 3800000] });

    const result = await aggregateLocalities({ now: NOW });
    assert.ok(result.published >= 1);

    const page = await withClient(api.get('/api/localities/pune-wakad'));
    assert.equal(page.status, 200, JSON.stringify(page.body).slice(0, 200));
    assert.equal(page.body.data.headline.count, 5);
    assert.equal(page.body.data.headline.medianAsking, 3400000);
    assert.equal(page.body.data.city, 'Pune');
    assert.equal(page.body.data.locality, 'Wakad');
    assert.equal(page.body.data.sampleFloor, SAMPLE_FLOOR);
  });

  await t.test('a locality that empties out is unpublished rather than left stale', async () => {
    const o = await ownerWithSession(api);
    const made = await seed(o.owner, { prices: [3000000, 3200000, 3400000, 3600000, 3800000] });
    await aggregateLocalities({ now: NOW });
    assert.equal((await withClient(api.get('/api/localities/pune-wakad'))).status, 200);

    // Four of the five come down.
    await M('Property').deleteMany({ _id: { $in: made.slice(1).map((p) => p._id) } });
    const later = new Date(NOW.getTime() + 86400 * 1000);
    const second = await aggregateLocalities({ now: later });
    assert.ok(second.unpublishedStale >= 1 || second.published === 0);

    const page = await withClient(api.get('/api/localities/pune-wakad'));
    assert.equal(page.status, 404, 'yesterday\'s median must not outlive its sample');
  });
});

// ---------------------------------------------------------------------------

test('what the aggregation counts', async (t) => {
  await t.test('the median, quartiles and per-square-foot are all recomputable by hand', async () => {
    const o = await ownerWithSession(api);
    await seed(o.owner, { prices: [1000000, 2000000, 3000000, 4000000, 5000000], area: 1000 });

    await aggregateLocalities({ now: NOW });
    const row = await M('LocalityStat').findOne({ slug: 'pune-wakad', bhk: 'all', listingType: 'sale' }).lean();

    assert.equal(row.count, 5);
    assert.equal(row.medianAsking, 3000000);
    assert.equal(row.p25, 2000000);
    assert.equal(row.p75, 4000000);
    assert.equal(row.medianPerSqft, 3000, 'the median of price ÷ carpet area');
    assert.equal(row.period, quarterOf(NOW));
  });

  await t.test('every listing counts once in its configuration and once in the headline', async () => {
    const o = await ownerWithSession(api);
    await seed(o.owner, { bhk: '2', prices: [3000000, 3100000, 3200000] });
    await seed(o.owner, { bhk: '3', prices: [5000000, 5100000, 5200000] });

    await aggregateLocalities({ now: NOW });
    const all = await M('LocalityStat').findOne({ slug: 'pune-wakad', bhk: 'all' }).lean();
    const two = await M('LocalityStat').findOne({ slug: 'pune-wakad', bhk: '2' }).lean();

    assert.equal(all.count, 6);
    assert.equal(two.count, 3);
    assert.equal(all.published, true, 'six clears the floor');
    assert.equal(two.published, false, 'three does not, even inside a published locality');
  });

  await t.test('rent and sale never mix', async () => {
    const o = await ownerWithSession(api);
    await seed(o.owner, { listingType: 'Sell', prices: [5000000, 5000000, 5000000, 5000000, 5000000] });
    await seed(o.owner, { listingType: 'Rent', prices: [20000, 21000, 22000, 23000, 24000] });

    await aggregateLocalities({ now: NOW });
    const sale = await M('LocalityStat').findOne({ slug: 'pune-wakad', bhk: 'all', listingType: 'sale' }).lean();
    const rent = await M('LocalityStat').findOne({ slug: 'pune-wakad', bhk: 'all', listingType: 'rent' }).lean();

    assert.equal(sale.medianAsking, 5000000);
    assert.equal(rent.medianAsking, 22000);

    const rentPage = await withClient(api.get('/api/localities/pune-wakad?listingType=rent'));
    assert.equal(rentPage.body.data.headline.medianAsking, 22000);
  });

  await t.test('hidden, unapproved, builder and priceless listings are not a market', async () => {
    const o = await ownerWithSession(api);
    await seed(o.owner, { prices: [3000000, 3000000, 3000000, 3000000, 3000000] });
    await makeProperty(o.owner, { price: 99000000, status: 'pending', city: 'Pune', locality: 'Wakad', bhk: '2' });
    await makeProperty(o.owner, { price: 99000000, isApproved: false, city: 'Pune', locality: 'Wakad', bhk: '2' });
    await makeProperty(o.owner, { price: 0, city: 'Pune', locality: 'Wakad', bhk: '2', isApproved: true });
    await M('Property').create({
      title: 'Builder tower', price: 99000000, builder: new mongoose.Types.ObjectId(), owner: null,
      city: 'Pune', locality: 'Wakad', bhk: '2', status: 'active', isApproved: true, listingType: 'Sell',
    });

    await aggregateLocalities({ now: NOW });
    const row = await M('LocalityStat').findOne({ slug: 'pune-wakad', bhk: 'all' }).lean();
    assert.equal(row.count, 5, 'only the five live owner listings count');
    assert.equal(row.medianAsking, 3000000);
  });

  await t.test('a listing with no locality lands in no bucket rather than a blank one', async () => {
    const o = await ownerWithSession(api);
    await makeProperty(o.owner, { price: 3000000, city: 'Pune', locality: '', isApproved: true, status: 'active' });
    const result = await aggregateLocalities({ now: NOW });
    assert.equal(result.buckets, 0);
  });

  await t.test('the quarter-on-quarter line compares like with like', async () => {
    const o = await ownerWithSession(api);
    const period = quarterOf(NOW);
    await M('LocalityStat').create({
      city: 'Pune', locality: 'Wakad', slug: 'pune-wakad', listingType: 'sale', bhk: 'all',
      period: previousQuarter(period), count: 10, medianAsking: 3000000, published: true,
    });
    await seed(o.owner, { prices: [3300000, 3300000, 3300000, 3300000, 3300000] });

    await aggregateLocalities({ now: NOW });
    const row = await M('LocalityStat').findOne({ slug: 'pune-wakad', bhk: 'all', period }).lean();
    assert.equal(row.qoqPct, 10, '3,000,000 to 3,300,000 is ten percent');
  });

  await t.test('re-running the same night recomputes rather than doubling', async () => {
    const o = await ownerWithSession(api);
    await seed(o.owner, { prices: [3000000, 3200000, 3400000, 3600000, 3800000] });
    await aggregateLocalities({ now: NOW });
    await aggregateLocalities({ now: new Date(NOW.getTime() + 1000) });

    const rows = await M('LocalityStat').find({ slug: 'pune-wakad', bhk: 'all', listingType: 'sale' }).lean();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].count, 5);
  });
});

// ---------------------------------------------------------------------------

test('the public surfaces', async (t) => {
  async function published() {
    const o = await ownerWithSession(api);
    await seed(o.owner, { bhk: '2', prices: [3000000, 3200000, 3400000, 3600000, 3800000] });
    await seed(o.owner, { bhk: '3', prices: [5000000, 5200000, 5400000, 5600000, 5800000] });
    await aggregateLocalities({ now: NOW });
    return o;
  }

  await t.test('the page carries the headline, each configuration and a trend', async () => {
    await published();
    const res = await withClient(api.get('/api/localities/pune-wakad'));
    assert.equal(res.status, 200);
    const d = res.body.data;
    assert.equal(d.headline.count, 10);
    assert.equal(d.byConfiguration.length, 2);
    assert.deepEqual(d.byConfiguration.map((c) => c.bhk), ['2', '3']);
    assert.equal(d.trend.length, 1);
    assert.equal(d.trend[0].period, quarterOf(NOW));
  });

  await t.test('the list gives one row per locality, newest quarter first', async () => {
    await published();
    const res = await withClient(api.get('/api/localities?city=Pune'));
    assert.equal(res.status, 200);
    assert.equal(res.body.data.length, 1);
    assert.equal(res.body.data[0].slug, 'pune-wakad');
    assert.equal(res.body.data[0].medianAsking, 4400000);
  });

  await t.test('a slug that is not a slug is a 404, never a query', async () => {
    for (const slug of ['../etc', 'Pune Wakad', 'a'.repeat(200), '$where']) {
      const res = await withClient(api.get(`/api/localities/${encodeURIComponent(slug)}`));
      assert.equal(res.status, 404, slug);
    }
  });

  await t.test('the pages are public: no session, no cookie, no auth error', async () => {
    await published();
    const page = await withClient(api.get('/api/localities/pune-wakad'));
    const list = await withClient(api.get('/api/localities'));
    assert.equal(page.status, 200);
    assert.equal(list.status, 200);
  });

  await t.test('guidance answers with a range, and 200-with-null when it cannot', async () => {
    await published();
    const good = await withClient(api.get('/api/localities/guidance?city=Pune&locality=Wakad&listingType=Sell&bhk=2 BHK'));
    assert.equal(good.status, 200);
    assert.equal(good.body.data.bhk, '2');
    assert.equal(good.body.data.low, 3200000);
    assert.equal(good.body.data.median, 3400000);
    assert.equal(good.body.data.high, 3600000);

    const unknown = await withClient(api.get('/api/localities/guidance?city=Pune&locality=Nowhere'));
    assert.equal(unknown.status, 200, 'a new locality is a normal answer, not an error');
    assert.equal(unknown.body.data, null);

    const missing = await withClient(api.get('/api/localities/guidance?city=Pune'));
    assert.equal(missing.status, 400);
    assert.equal(missing.body.code, 'LOCATION_REQUIRED');
  });

  await t.test('guidance falls back from an unpublished configuration to the locality headline', async () => {
    const o = await ownerWithSession(api);
    await seed(o.owner, { bhk: '2', prices: [3000000, 3200000, 3400000] });
    await seed(o.owner, { bhk: '3', prices: [5000000, 5200000, 5400000] });
    await aggregateLocalities({ now: NOW });

    const res = await priceGuidanceFor({ city: 'Pune', locality: 'Wakad', listingType: 'Sell', bhk: '2', at: NOW });
    assert.ok(res, 'six listings publish the headline even though neither configuration does');
    assert.equal(res.scope, 'locality');
    assert.equal(res.bhk, 'all');
  });
});

// ---------------------------------------------------------------------------

test('price intelligence on a listing (F19)', async (t) => {
  await t.test('the detail carries history, days listed and the delta against the median', async () => {
    const o = await ownerWithSession(api);
    await seed(o.owner, { bhk: '2', prices: [4000000, 4000000, 4000000, 4000000, 4000000] });
    const subject = (await seed(o.owner, { bhk: '2', prices: [3600000] }))[0];
    await aggregateLocalities({ now: NOW });

    const { recordPriceChange } = await import('../../services/priceLogService.js');
    const fresh = await M('Property').findById(subject._id).lean();
    const listedAt = new Date(Date.now() - 40 * 86400 * 1000);
    await recordPriceChange({ property: fresh, from: null, to: 4000000, source: 'listed', at: listedAt });
    await recordPriceChange({ property: fresh, from: 4000000, to: 3600000, source: 'edit' });

    const res = await withClient(api.get(`/api/properties/${subject._id}`));
    assert.equal(res.status, 200);
    const pi = res.body.priceIntelligence;
    assert.ok(pi, 'the detail must carry price intelligence');
    assert.equal(pi.daysListed, 40);
    assert.equal(pi.changes.length, 1);
    assert.equal(pi.lastDrop.deltaPct, -10);
    assert.equal(pi.market.medianAsking, 4000000);
    assert.ok(pi.market.deltaPct < 0, 'this listing asks below the median');
    assert.equal(pi.market.scope, 'configuration');
  });

  await t.test('an unpublished locality yields no market comparison at all', async () => {
    const o = await ownerWithSession(api);
    const subject = (await seed(o.owner, { prices: [3600000, 3700000] }))[0];
    await aggregateLocalities({ now: NOW });

    const res = await withClient(api.get(`/api/properties/${subject._id}`));
    assert.equal(res.status, 200);
    assert.equal(res.body.priceIntelligence.market, null, 'silence beats a median of two');
  });

  await t.test('a listing with no price history still answers, with nulls', async () => {
    const o = await ownerWithSession(api);
    const subject = await makeProperty(o.owner, { price: 3000000, isApproved: true, status: 'active' });
    const res = await withClient(api.get(`/api/properties/${subject._id}`));
    assert.equal(res.status, 200);
    assert.equal(res.body.priceIntelligence.daysListed, null);
    assert.deepEqual(res.body.priceIntelligence.changes, []);
    assert.equal(res.body.priceIntelligence.lastDrop, null);
  });

  await t.test('localityMedianFor refuses a listing it cannot place', async () => {
    assert.equal(await localityMedianFor({ city: '', locality: '', listingType: 'Sell' }), null);
    assert.equal(await localityMedianFor({ city: 'Pune', locality: 'Wakad', listingType: 'lease' }), null);
  });
});
