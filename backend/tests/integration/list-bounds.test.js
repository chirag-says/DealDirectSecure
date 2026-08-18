/**
 * Suite 20: bounds on the public property list endpoints (Phase 4.3 / 4.4).
 *
 * WHAT WAS UNBOUNDED, exactly.
 *
 *   /properties/list         `parseInt(req.query.limit) || 0`, and 0 means NO
 *                            LIMIT in Mongoose. So the default was every
 *                            approved listing, and `?limit=200000` was honoured
 *                            literally.
 *   /properties/property-list  no limit clause at all. The home feed.
 *   /properties/filter       no limit clause at all, and no caller anywhere.
 *   /properties/search       already clamped to 12 default / 60 max. Untouched.
 *
 * THE NUMBERS ARE TAKEN FROM THE CODEBASE, NOT INVENTED.
 *
 *   /list default 50   — its own primary caller asks for `?limit=50`
 *                        (client-next/src/app/properties/page.js)
 *   /list max 5000     — `sitemap.js` asks for `?limit=5000`, so a lower cap
 *                        would silently shorten the sitemap
 *   /property-list 200 — no caller passes a limit; 200 clears the 47-document
 *                        corpus comfortably, so behaviour is unchanged today
 *
 * WHY `validatePagination` IS NOT MOUNTED HERE. It caps `limit` at 100 and
 * rejects anything larger with a 400. Mounting it on `/list` would break the
 * sitemap outright. It stays where its semantics fit.
 *
 * RESPONSE SHAPES ARE PRESERVED. `/list` returns a BARE ARRAY — mobile's type
 * definitions say so explicitly — so its bound is reported in headers rather
 * than by wrapping the body in an envelope. `/property-list` already returns
 * `{ success, data }`, so it gains an additive `pagination` key that old
 * clients ignore.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeOwner, makeProperty, seedTaxonomy } from './setup/factories.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); await seedTaxonomy(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const get = (path) => api.get(path).set('X-Forwarded-For', uniqueClientIp());

/**
 * N approved, owner-posted listings — what both feeds select for.
 *
 * Bulk-inserted rather than looped through `makeProperty`. Some cases here need
 * 210 documents to see a 200-row cap bite, and creating those one at a time was
 * slow enough to starve the shared in-memory replica set when the whole suite
 * runs in parallel — other files began timing out. The documents are identical
 * in shape to the factory's.
 *
 * `createdAt` is staggered explicitly because ordering is asserted below and a
 * bulk insert would otherwise give every document the same timestamp.
 */
async function seedListings(n) {
  const owner = await makeOwner();
  const Property = mongoose.model('Property');
  const base = Date.now() - n * 1000;

  const docs = Array.from({ length: n }, (_, i) => ({
    title: `Listing ${String(i).padStart(3, '0')}`,
    description: `Synthetic fixture property ${i}.`,
    owner: owner._id,
    price: 2500000,
    listingType: 'Sell',
    status: 'active',
    isApproved: true,
    location: { city: 'Testville', state: 'Test State', locality: `Sector ${i}` },
    createdAt: new Date(base + i * 1000),
    updatedAt: new Date(base + i * 1000),
  }));

  return Property.insertMany(docs, { timestamps: false });
}

const bodyList = (res) => (Array.isArray(res.body) ? res.body : res.body?.data || []);

// ---------------------------------------------------------------------------

test('/properties/list is bounded', async (t) => {
  await t.test('a default request is capped, not unbounded', async () => {
    await seedListings(60);
    const res = await get('/api/properties/list');

    assert.equal(res.status, 200);
    assert.equal(bodyList(res).length, 50, 'the default must not be "everything"');
  });

  await t.test('an explicit valid limit is honoured', async () => {
    await seedListings(30);
    const res = await get('/api/properties/list?limit=10');
    assert.equal(bodyList(res).length, 10);
  });

  await t.test('an oversized limit is capped rather than rejected', async () => {
    // The endpoint answers unauthenticated public traffic and the sitemap.
    // Clamping keeps both working; a 400 would break the sitemap.
    await seedListings(20);
    const res = await get('/api/properties/list?limit=200000');

    assert.equal(res.status, 200, 'an absurd limit should clamp, not fail');
    assert.equal(bodyList(res).length, 20, 'all 20 exist, so all 20 come back — bounded by the cap, not truncated below it');
  });

  await t.test('the cap itself is applied, not just the row count', async () => {
    // Seeding more rows than LIST_MAX to observe the clamp would mean 5000
    // fixtures. The effective limit is reported in the header, so the cap can
    // be asserted directly and cheaply. Without this, removing
    // `Math.min(rawLimit, LIST_MAX)` passes every other test in this file.
    await seedListings(3);
    const res = await get('/api/properties/list?limit=200000');
    assert.equal(res.headers['x-limit'], '5000', 'the requested limit was not clamped to LIST_MAX');
  });

  await t.test('a limit below the cap is reported as asked for', async () => {
    await seedListings(3);
    const res = await get('/api/properties/list?limit=25');
    assert.equal(res.headers['x-limit'], '25');
  });

  await t.test('the sitemap limit still works', async () => {
    // sitemap.js asks for 5000. A cap below that would silently shorten it.
    await seedListings(5);
    const res = await get('/api/properties/list?limit=5000');
    assert.equal(res.status, 200);
    assert.equal(bodyList(res).length, 5);
  });

  await t.test('limit=0 no longer means unbounded', async () => {
    // The original defect: `parseInt(limit) || 0` and 0 disables the limit.
    await seedListings(60);
    const res = await get('/api/properties/list?limit=0');
    assert.ok(bodyList(res).length <= 50, `got ${bodyList(res).length}`);
  });

  await t.test('a nonsense limit falls back to the default', async () => {
    await seedListings(60);
    const res = await get('/api/properties/list?limit=abc');
    assert.equal(res.status, 200);
    assert.equal(bodyList(res).length, 50);
  });

  await t.test('a negative limit falls back to the default', async () => {
    await seedListings(60);
    const res = await get('/api/properties/list?limit=-5');
    assert.equal(bodyList(res).length, 50);
  });

  await t.test('the response is still a BARE ARRAY', async () => {
    // Mobile's type definitions record this explicitly. Wrapping it would be a
    // breaking change dressed up as an improvement.
    await seedListings(3);
    const res = await get('/api/properties/list');
    assert.ok(Array.isArray(res.body), `got ${typeof res.body}: ${JSON.stringify(res.body).slice(0, 80)}`);
  });

  await t.test('the bound is reported in headers, since the body cannot carry it', async () => {
    await seedListings(60);
    const res = await get('/api/properties/list');
    assert.equal(res.headers['x-limit'], '50');
    assert.equal(res.headers['x-total-count'], '60');
    assert.equal(res.headers['x-has-more'], 'true');
  });

  await t.test('ordering is preserved — newest first', async () => {
    await seedListings(5);
    const res = await get('/api/properties/list');
    const dates = bodyList(res).map((p) => new Date(p.createdAt).getTime());
    assert.deepEqual(dates, [...dates].sort((a, b) => b - a));
  });

  await t.test('the builder-exclusion filter is preserved', async () => {
    const owner = await makeOwner();
    await makeProperty(owner, { isApproved: true, title: 'Owner listing' });
    await makeProperty(owner, {
      isApproved: true, title: 'Builder listing', builder: new mongoose.Types.ObjectId(),
    });

    const res = await get('/api/properties/list');
    const titles = bodyList(res).map((p) => p.title);
    assert.ok(titles.includes('Owner listing'));
    assert.ok(!titles.includes('Builder listing'), 'builder listings belong on /projects');
  });
});

// ---------------------------------------------------------------------------

test('/properties/property-list is bounded', async (t) => {
  await t.test('a default request is capped', async () => {
    await seedListings(210);
    const res = await get('/api/properties/property-list');
    assert.equal(res.status, 200);
    assert.equal(bodyList(res).length, 200);
  });

  await t.test('today\'s corpus is unaffected — behaviour is preserved', async () => {
    // 47 listings in production. The cap is 200, so every live caller sees
    // exactly what it saw before. That is what makes this deploy-safe.
    await seedListings(47);
    const res = await get('/api/properties/property-list');
    assert.equal(bodyList(res).length, 47);
    assert.equal(res.body.pagination.hasMore, false);
  });

  await t.test('an explicit limit is honoured and an oversized one clamps', async () => {
    await seedListings(30);
    assert.equal(bodyList(await get('/api/properties/property-list?limit=10')).length, 10);
    assert.equal(bodyList(await get('/api/properties/property-list?limit=999999')).length, 30);
  });

  await t.test('the envelope is preserved and pagination is additive', async () => {
    await seedListings(3);
    const res = await get('/api/properties/property-list');

    assert.equal(res.body.success, true, 'the existing envelope must not change');
    assert.ok(Array.isArray(res.body.data), 'data must still be the array callers read');
    assert.deepEqual(res.body.pagination, { total: 3, limit: 200, page: 1, hasMore: false });
  });

  await t.test('page 2 returns the next slice', async () => {
    await seedListings(15);
    const first = await get('/api/properties/property-list?limit=10&page=1');
    const second = await get('/api/properties/property-list?limit=10&page=2');

    assert.equal(bodyList(first).length, 10);
    assert.equal(bodyList(second).length, 5);
    const ids = new Set(bodyList(first).map((p) => p._id));
    assert.ok(bodyList(second).every((p) => !ids.has(p._id)), 'pages must not overlap');
  });

  await t.test('hasMore is honest', async () => {
    await seedListings(15);
    assert.equal((await get('/api/properties/property-list?limit=10&page=1')).body.pagination.hasMore, true);
    assert.equal((await get('/api/properties/property-list?limit=10&page=2')).body.pagination.hasMore, false);
  });

  await t.test('ordering is preserved — newest first', async () => {
    await seedListings(6);
    const res = await get('/api/properties/property-list');
    const dates = bodyList(res).map((p) => new Date(p.createdAt).getTime());
    assert.deepEqual(dates, [...dates].sort((a, b) => b - a));
  });
});

// ---------------------------------------------------------------------------

test('/properties/search keeps the bounds it already had', async (t) => {
  await t.test('default 12', async () => {
    await seedListings(20);
    const res = await get('/api/properties/search');
    assert.ok(bodyList(res).length <= 12, `got ${bodyList(res).length}`);
  });

  await t.test('capped at 60', async () => {
    await seedListings(70);
    const res = await get('/api/properties/search?limit=200000');
    assert.ok(bodyList(res).length <= 60, `got ${bodyList(res).length}`);
  });
});

// ---------------------------------------------------------------------------

test('/properties/filter is gone', async (t) => {
  await t.test('the route answers 410 Gone, not 404 and not 500', async () => {
    // Deleting the registration outright was not enough: the path then falls
    // through to the "/:id" wildcard, getPropertyById tries to cast "filter"
    // to an ObjectId, and that currently surfaces as a 500. A retired endpoint
    // saying "retired" is more useful than a server error, and far more useful
    // than a 404 that looks like a typo.
    const res = await get('/api/properties/filter');
    assert.equal(res.status, 410, JSON.stringify(res.body).slice(0, 140));
    assert.equal(res.body.code, 'ENDPOINT_RETIRED');
  });

  await t.test('the handler is gone from the controller', async () => {
    const { readFileSync } = await import('node:fs');
    const src = readFileSync(new URL('../../controllers/propertyController.js', import.meta.url), 'utf8');
    assert.doesNotMatch(src, /export const filterProperties/);
  });

  await t.test('the route no longer reaches a handler', async () => {
    // The registration deliberately survives as a tombstone returning 410 —
    // see the status test above. What must be gone is any path from it to
    // filterProperties.
    const { readFileSync } = await import('node:fs');
    const src = readFileSync(new URL('../../routes/propertyRoutes.js', import.meta.url), 'utf8');
    assert.doesNotMatch(src, /filterProperties/, 'the retired handler is wired up again');
    assert.match(src, /ENDPOINT_RETIRED/, 'the tombstone is what keeps this off the /:id wildcard');
  });

  await t.test('the search-rate-limit mount for it is gone too', async () => {
    // server.js mounted searchLimiter on /api/properties/filter. Leaving that
    // behind would be a limiter guarding nothing.
    const { readFileSync } = await import('node:fs');
    const src = readFileSync(new URL('../../server.js', import.meta.url), 'utf8');
    assert.doesNotMatch(src, /app\.use\("\/api\/properties\/filter"/);
  });

  await t.test('the endpoints it overlapped with still work', async () => {
    // Deleting /filter must not remove filtering as a capability — /search is
    // where that lives, and it is what the client migrated to.
    await seedListings(3);
    const res = await get('/api/properties/search?q=Listing');
    assert.equal(res.status, 200);
  });
});

// ---------------------------------------------------------------------------

test('no public list endpoint can be made to return everything', async (t) => {
  // The requirement, stated directly: whatever a client sends, the response is
  // bounded.
  const ATTACKS = [
    '/api/properties/list?limit=200000',
    '/api/properties/list?limit=0',
    '/api/properties/list?limit=-1',
    '/api/properties/list?limit=1e9',
    '/api/properties/property-list?limit=200000',
    '/api/properties/property-list?limit=0',
    '/api/properties/search?limit=200000',
  ];

  await t.test('each attempt returns a bounded response', async () => {
    await seedListings(120);
    for (const path of ATTACKS) {
      const res = await get(path);
      const n = bodyList(res).length;
      assert.ok(res.status === 200, `${path} -> ${res.status}`);
      assert.ok(n <= 200, `${path} returned ${n} documents`);
    }
  });
});
