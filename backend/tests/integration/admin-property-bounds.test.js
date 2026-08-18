/**
 * Suite 21: bounds on the admin property manager (Phase 4.7).
 *
 * `getAdminProperties` served `/properties/admin/all` with `Property.find(query)`,
 * FOUR populates, a sort, and no limit or skip anywhere. It is the page an admin
 * opens routinely, and it returned every property in the database — approved and
 * rejected both, which is 47 today.
 *
 * TWO CONSUMERS, and they want different things.
 *
 *   AllProperty.jsx        the manager table. Filters, searches and sorts
 *                          server-side already. Paginates now.
 *   PopularProperties.jsx  a selection screen that fetches, then filters
 *                          CLIENT-side on `isApproved` and `isPopular`. It
 *                          genuinely needs the corpus, so it asks for an
 *                          explicit limit rather than relying on the default.
 *                          Bounded, but at the ceiling.
 *
 * NUMBERS FROM THE CODEBASE, NOT INVENTED. The default of 20 matches
 * BookingManagement.jsx, the sibling admin table, which requests `limit: 20`.
 * The 5000 ceiling is the LIST_MAX already established in Phase 4.3. The
 * `pagination` envelope matches ContactInquiries.jsx, which already returns
 * `{ page, limit, total, pages }`.
 *
 * `validatePagination` is not used here for the same reason as 4.3: its 100
 * cap would stop PopularProperties fetching the set it filters over.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { adminWithSession, asAdmin, makeOwner, seedTaxonomy } from './setup/factories.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); await seedTaxonomy(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

/**
 * N properties, bulk-inserted with staggered timestamps so ordering can be
 * asserted. Looping through the factory was slow enough to starve the shared
 * replica set when the whole suite runs in parallel.
 */
async function seedProperties(n, overrides = () => ({})) {
  const owner = await makeOwner();
  const Property = mongoose.model('Property');
  const base = Date.now() - n * 1000;

  return Property.insertMany(
    Array.from({ length: n }, (_, i) => ({
      title: `Admin Property ${String(i).padStart(3, '0')}`,
      description: `Fixture ${i}.`,
      owner: owner._id,
      price: 2500000,
      listingType: 'Sell',
      status: 'active',
      isApproved: i % 2 === 0,
      location: { city: 'Testville', state: 'Test State', locality: `Sector ${i}` },
      createdAt: new Date(base + i * 1000),
      updatedAt: new Date(base + i * 1000),
      ...overrides(i),
    })),
    { timestamps: false }
  );
}

const fetchAdmin = async (session, query = '') =>
  asAdmin(api.get(`/api/properties/admin/all${query}`), session).send();

// ---------------------------------------------------------------------------

test('the admin list is bounded', async (t) => {
  await t.test('a default request returns one page, not everything', async () => {
    const session = await adminWithSession(api);
    await seedProperties(50);

    const res = await fetchAdmin(session);

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 160));
    assert.equal(res.body.data.length, 20, 'the default page size is 20, matching BookingManagement');
  });

  await t.test('an explicit limit is honoured', async () => {
    const session = await adminWithSession(api);
    await seedProperties(30);
    const res = await fetchAdmin(session, '?limit=5');
    assert.equal(res.body.data.length, 5);
  });

  await t.test('an oversized limit is clamped, not honoured', async () => {
    const session = await adminWithSession(api);
    await seedProperties(3);
    const res = await fetchAdmin(session, '?limit=200000');

    assert.equal(res.status, 200, 'clamping beats a 400 on an admin screen');
    assert.equal(res.body.pagination.limit, 5000, 'the requested limit was not clamped to the ceiling');
  });

  await t.test('a nonsense limit falls back to the default', async () => {
    const session = await adminWithSession(api);
    await seedProperties(30);
    assert.equal((await fetchAdmin(session, '?limit=abc')).body.data.length, 20);
    assert.equal((await fetchAdmin(session, '?limit=-4')).body.data.length, 20);
    assert.equal((await fetchAdmin(session, '?limit=0')).body.data.length, 20);
  });

  await t.test('a nonsense page falls back to page 1', async () => {
    const session = await adminWithSession(api);
    await seedProperties(30);
    const res = await fetchAdmin(session, '?page=abc');
    assert.equal(res.body.pagination.page, 1);
  });
});

// ---------------------------------------------------------------------------

test('paging is correct and loses nothing', async (t) => {
  await t.test('pages partition the set — no gaps, no duplicates', async () => {
    // The property that matters most on a management screen: an admin paging
    // through must see every record exactly once.
    const session = await adminWithSession(api);
    await seedProperties(45);

    const seen = [];
    for (let page = 1; page <= 3; page += 1) {
      const res = await fetchAdmin(session, `?page=${page}&limit=20`);
      seen.push(...res.body.data.map((p) => String(p._id)));
    }

    assert.equal(seen.length, 45, 'three pages of 20 should cover all 45');
    assert.equal(new Set(seen).size, 45, 'a record appeared on more than one page');
  });

  await t.test('the last page is short, not padded', async () => {
    const session = await adminWithSession(api);
    await seedProperties(45);
    const res = await fetchAdmin(session, '?page=3&limit=20');
    assert.equal(res.body.data.length, 5);
  });

  await t.test('a page past the end is empty rather than an error', async () => {
    const session = await adminWithSession(api);
    await seedProperties(5);
    const res = await fetchAdmin(session, '?page=99&limit=20');
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.data, []);
  });

  await t.test('total and pages describe the whole matching set', async () => {
    const session = await adminWithSession(api);
    await seedProperties(45);
    const res = await fetchAdmin(session, '?limit=20');

    assert.equal(res.body.pagination.total, 45, 'total must count the filter, not the page');
    assert.equal(res.body.pagination.pages, 3);
    assert.equal(res.body.pagination.hasMore, true);
  });

  await t.test('hasMore is false on the final page', async () => {
    const session = await adminWithSession(api);
    await seedProperties(45);
    const res = await fetchAdmin(session, '?page=3&limit=20');
    assert.equal(res.body.pagination.hasMore, false);
  });

  await t.test('ordering is preserved across pages — newest first', async () => {
    const session = await adminWithSession(api);
    await seedProperties(40);

    const all = [];
    for (let page = 1; page <= 2; page += 1) {
      const res = await fetchAdmin(session, `?page=${page}&limit=20`);
      all.push(...res.body.data.map((p) => new Date(p.createdAt).getTime()));
    }
    assert.deepEqual(all, [...all].sort((a, b) => b - a), 'sort order broke at a page boundary');
  });
});

// ---------------------------------------------------------------------------

test('every existing filter still works, and applies across pages', async (t) => {
  await t.test('status=listed narrows to approved, and total reflects it', async () => {
    const session = await adminWithSession(api);
    await seedProperties(40); // even indices approved -> 20 approved

    const res = await fetchAdmin(session, '?status=listed&limit=20');

    assert.equal(res.body.pagination.total, 20, 'total must count filtered documents only');
    assert.ok(res.body.data.every((p) => p.isApproved === true));
  });

  await t.test('status=rejected narrows the other way', async () => {
    const session = await adminWithSession(api);
    await seedProperties(40);
    const res = await fetchAdmin(session, '?status=rejected&limit=20');
    assert.equal(res.body.pagination.total, 20);
    assert.ok(res.body.data.every((p) => p.isApproved === false));
  });

  await t.test('search is preserved and partitions correctly', async () => {
    const session = await adminWithSession(api);
    await seedProperties(30);

    const res = await fetchAdmin(session, '?search=Admin Property 01&limit=20');
    assert.ok(res.body.pagination.total > 0);
    assert.ok(res.body.data.every((p) => /Admin Property 01/.test(p.title)));
  });

  await t.test('a filtered set pages without gaps or duplicates', async () => {
    const session = await adminWithSession(api);
    await seedProperties(60); // 30 approved

    const seen = [];
    for (let page = 1; page <= 3; page += 1) {
      const res = await fetchAdmin(session, `?status=listed&page=${page}&limit=10`);
      seen.push(...res.body.data.map((p) => String(p._id)));
    }
    assert.equal(seen.length, 30);
    assert.equal(new Set(seen).size, 30, 'the filter must be applied identically on every page');
  });

  await t.test('the date-range filter is preserved', async () => {
    const session = await adminWithSession(api);
    await seedProperties(10);
    const res = await fetchAdmin(session, '?startDate=2099-01-01&limit=20');
    assert.equal(res.body.pagination.total, 0, 'a future start date should match nothing');
  });
});

// ---------------------------------------------------------------------------

test('the response stays compatible', async (t) => {
  await t.test('success and data are unchanged', async () => {
    const session = await adminWithSession(api);
    await seedProperties(5);
    const res = await fetchAdmin(session);

    assert.equal(res.body.success, true);
    assert.ok(Array.isArray(res.body.data), 'extractList reads resData.data and must keep working');
  });

  await t.test('count still means "documents in this response"', async () => {
    // Its meaning is unchanged; what changed is that the response is a page.
    const session = await adminWithSession(api);
    await seedProperties(45);
    const res = await fetchAdmin(session, '?limit=20');
    assert.equal(res.body.count, res.body.data.length);
  });

  await t.test('pagination is additive and matches the Admin convention', async () => {
    const session = await adminWithSession(api);
    await seedProperties(45);
    const res = await fetchAdmin(session, '?limit=20&page=2');

    assert.deepEqual(res.body.pagination, {
      total: 45, limit: 20, page: 2, pages: 3, hasMore: true,
    });
  });
});

// ---------------------------------------------------------------------------

test('no admin request can produce an unbounded query', async (t) => {
  await t.test('every hostile limit is bounded', async () => {
    const session = await adminWithSession(api);
    await seedProperties(60);

    for (const q of ['?limit=200000', '?limit=0', '?limit=-1', '?limit=1e9', '?limit=Infinity']) {
      const res = await fetchAdmin(session, q);
      assert.equal(res.status, 200, `${q} -> ${res.status}`);
      assert.ok(res.body.data.length <= 5000, `${q} returned ${res.body.data.length}`);
      assert.ok(res.body.pagination.limit <= 5000, `${q} reported limit ${res.body.pagination.limit}`);
    }
  });

  await t.test('the endpoint still requires an admin session', async () => {
    // Bounding must not have loosened the guard.
    const res = await api.get('/api/properties/admin/all');
    assert.equal(res.status, 401);
  });
});
