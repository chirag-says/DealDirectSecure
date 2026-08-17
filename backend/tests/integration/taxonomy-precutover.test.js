/**
 * Suite 11: does the Phase 3B code survive the pre-migration data?
 *
 * Between deploying the new code and running the migration there is a window in
 * which production holds the OLD data shape and the NEW code. This file
 * reproduces that window exactly and asks what actually breaks.
 *
 * The fixture is deliberately the production shape and nothing else:
 *
 *   - the legacy taxonomy only: 19 category rows that are really property
 *     types plus three listing intents, and three property-type rows that are
 *     really categories
 *   - NO canonical taxonomy, because the seed has not run yet
 *   - 25 properties carrying references to "Residential Plot" / "Commercial
 *     Land" and "Plot" / "Commercial", 22 carrying none
 *
 * A test that seeded the canonical taxonomy here would be testing the state
 * AFTER the migration and would say nothing about the window.
 *
 * The distinction that matters throughout: reads must survive, and writes must
 * refuse rather than corrupt. A write that fails during a write freeze costs
 * nothing. A write that succeeds and stores another wrong reference undoes the
 * migration that is about to run.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeOwner, loginAs } from './setup/factories.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const Property = () => mongoose.model('Property');
const Category = () => mongoose.model('Category');
const PropertyType = () => mongoose.model('PropertyType');

/** Production's taxonomy and reference state, immediately before the migration. */
async function seedPreCutoverState() {
  // `categories` holds property types and listing intents.
  const legacyCategoryNames = [
    'Agricultural Land', 'Apartment', 'Buy', 'Co-working', 'Commercial Land',
    'Independent House', 'Industrial Land', 'Industrial Shed', 'Office Space',
    'Office space', 'Penthouse', 'Plots', 'Rent', 'Rental', 'Residential Plot',
    'Shop / Showroom', 'Studio Apartment', 'Villa', 'Warehouse/Godown',
  ];
  const legacyCategories = await Category().insertMany(legacyCategoryNames.map((name) => ({ name })));
  const byName = new Map(legacyCategories.map((c) => [c.name, c._id]));

  // `propertytypes` holds the category level. These rows have no parent, which
  // the new schema requires, so they are inserted below validation.
  const legacyTypes = await PropertyType().collection.insertMany([
    { name: 'Residential', createdAt: new Date(), updatedAt: new Date() },
    { name: 'Commercial', createdAt: new Date(), updatedAt: new Date() },
    { name: 'Plot', createdAt: new Date(), updatedAt: new Date() },
  ]);
  const typeIds = Object.values(legacyTypes.insertedIds);
  const plotType = typeIds[2];
  const commercialType = typeIds[1];

  const owner = await makeOwner();
  const rows = [
    ['Residential', 'Apartment / Flat', 'stale'],
    ['Residential', 'Independent House', 'stale'],
    ['Residential', 'Villa', 'null'],
    ['Residential', 'Penthouse', 'stale'],
    ['Commercial', 'Office Space', 'stale'],
    ['Commercial', 'Showroom', 'null'],
    ['Commercial', 'Warehouse / Godown', 'null'],
    ['Commercial', 'Commercial Building / Floor', 'stale'],
  ];

  const created = [];
  for (const [categoryName, propertyTypeName, refState] of rows) {
    const stale = refState === 'stale';
    created.push(await Property().create({
      title: `${propertyTypeName} listing`,
      description: 'Pre-cutover fixture.',
      owner: owner._id,
      price: 2500000,
      listingType: 'Sell',
      status: 'active',
      city: 'Testville',
      categoryName,
      propertyTypeName,
      ...(stale ? {
        category: byName.get(categoryName === 'Residential' ? 'Residential Plot' : 'Commercial Land'),
        propertyType: categoryName === 'Commercial' && propertyTypeName === 'Commercial Building / Floor'
          ? commercialType : plotType,
      } : {}),
    }));
  }

  return { owner, created, byName, staleCount: rows.filter((r) => r[2] === 'stale').length };
}

const anon = (p) => api.get(p).set('X-Forwarded-For', uniqueClientIp());

// ---------------------------------------------------------------------------

test('the fixture really is the pre-migration state', async (t) => {
  await t.test('legacy taxonomy present, canonical absent', async () => {
    await seedPreCutoverState();
    assert.equal(await Category().countDocuments(), 19);
    assert.equal(await PropertyType().countDocuments(), 3);
    assert.equal(await Category().countDocuments({ name: 'Residential' }), 0, 'canonical category must not exist yet');
    assert.equal(await PropertyType().countDocuments({ name: 'Apartment / Flat' }), 0, 'canonical type must not exist yet');
  });

  await t.test('references are stale or null, exactly as in production', async () => {
    const { created, staleCount } = await seedPreCutoverState();
    const props = await Property().find({}).lean();
    assert.equal(props.length, created.length);
    assert.equal(props.filter((p) => p.category || p.propertyType).length, staleCount);
    assert.equal(props.filter((p) => !p.category && !p.propertyType).length, created.length - staleCount);
  });
});

// ---------------------------------------------------------------------------

test('READ paths survive the pre-migration data', async (t) => {
  await t.test('the public property list does not crash on stale or null refs', async () => {
    await seedPreCutoverState();
    const res = await anon('/api/properties/list?limit=100');
    assert.ok(res.status < 500, `list returned ${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`);
  });

  await t.test('property details resolve for a stale-ref listing', async () => {
    const { created } = await seedPreCutoverState();
    const stale = await Property().findOne({ category: { $ne: null } }).lean();
    const res = await anon(`/api/properties/${stale._id}`);
    assert.ok(res.status < 500, `details returned ${res.status}`);
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
  });

  await t.test('property details resolve for a null-ref listing', async () => {
    await seedPreCutoverState();
    const nul = await Property().findOne({ category: null }).lean();
    const res = await anon(`/api/properties/${nul._id}`);
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
  });

  await t.test('search by name still works', async () => {
    await seedPreCutoverState();
    const res = await anon('/api/properties/search?categoryName=Residential&limit=100');
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    const list = res.body.properties || res.body.data || [];
    assert.ok(list.length > 0, 'name filters must keep working before the migration');
  });

  await t.test('the owner dashboard lists the owner\'s properties', async () => {
    const { owner } = await seedPreCutoverState();
    const cookies = await loginAs(api, owner);
    const res = await api.get('/api/properties/my-properties')
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies);
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
  });

  await t.test('the owner edit screen can load a stale-ref listing', async () => {
    const { owner } = await seedPreCutoverState();
    const cookies = await loginAs(api, owner);
    const stale = await Property().findOne({ category: { $ne: null } }).lean();
    const res = await api.get(`/api/properties/my-properties/${stale._id}`)
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies);
    assert.equal(res.status, 200, 'an owner must be able to open a listing that has not been migrated yet');
  });
});

// ---------------------------------------------------------------------------

test('WRITE paths refuse rather than corrupt', async (t) => {
  await t.test('creating a listing is refused while the canonical taxonomy is absent', async () => {
    // This is the important one. The old code would have resolved
    // "Residential" to the legacy "Residential Plot" row by substring and
    // stored another wrong reference. Refusing is the correct behaviour during
    // the window: a failed create costs one retry, a successful one undoes the
    // migration that is about to run.
    const { owner } = await seedPreCutoverState();
    const other = await makeOwner();
    const cookies = await loginAs(api, other);

    const res = await api.post('/api/properties/add')
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies)
      .send({ title: 'During window', listingType: 'Sell', latitude: 11.1, longitude: 77.1,
              categoryName: 'Residential', propertyTypeName: 'Apartment / Flat' });

    assert.equal(res.status, 400, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.code, 'TAXONOMY_UNKNOWN_NAME');
    assert.equal(await Property().countDocuments({ owner: other._id }), 0, 'nothing stored');
  });

  await t.test('no legacy row can be resolved into a new reference', async () => {
    const { byName } = await seedPreCutoverState();
    const other = await makeOwner();
    const cookies = await loginAs(api, other);

    // "Residential Plot" is a real row, and it is exactly what the old
    // substring matcher used to pick for "Residential".
    const res = await api.post('/api/properties/add')
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies)
      .send({ title: 'Legacy attempt', listingType: 'Sell', latitude: 11.1, longitude: 77.1,
              categoryName: 'Residential Plot', propertyTypeName: 'Apartment' });

    assert.equal(res.status, 400);
    assert.equal(await Property().countDocuments({ owner: other._id }), 0);
  });

  await t.test('an edit that does not touch taxonomy still succeeds', async () => {
    // Owners must be able to fix a price or a description during the window.
    const { owner } = await seedPreCutoverState();
    const cookies = await loginAs(api, owner);
    const stale = await Property().findOne({ category: { $ne: null } }).lean();

    const res = await api.put(`/api/properties/my-properties/${stale._id}`)
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies)
      .send({ title: 'Corrected during window', price: 3100000 });

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    const after = await Property().findById(stale._id).lean();
    assert.equal(after.title, 'Corrected during window');
    assert.equal(String(after.category), String(stale.category), 'the stale ref must be left exactly as it was');
  });

  await t.test('an edit that touches taxonomy is refused, and changes nothing', async () => {
    const { owner } = await seedPreCutoverState();
    const cookies = await loginAs(api, owner);
    const stale = await Property().findOne({ category: { $ne: null } }).lean();

    const res = await api.put(`/api/properties/my-properties/${stale._id}`)
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies)
      .send({ title: 'Should not apply', categoryName: 'Residential', propertyTypeName: 'Villa' });

    assert.equal(res.status, 400);
    const after = await Property().findById(stale._id).lean();
    assert.equal(after.title, stale.title, 'the whole request must be refused');
  });
});

// ---------------------------------------------------------------------------

test('taxonomy selectors during the window', async (t) => {
  await t.test('the category and type lists are EMPTY until the seed runs', async () => {
    // Recorded rather than worked around. The active filter admits only
    // canonical documents, and before the seed there are none, so both
    // dropdowns are empty and the create form cannot be completed.
    //
    // That is the correct behaviour for an allow-list, and it is precisely why
    // the deploy and the migration cannot be separated by a long gap: the
    // create form is unusable in between. The runbook covers this with a write
    // freeze rather than with a code change, because the alternative, showing
    // legacy rows until the seed lands, would let someone pick "Buy" as a
    // category during the window.
    await seedPreCutoverState();

    const cats = await anon('/api/categories/list-category');
    const types = await anon('/api/propertyTypes/list-propertytype');

    assert.equal(cats.status, 200, 'the endpoint must answer, not error');
    assert.equal(types.status, 200);
    assert.deepEqual(cats.body.data ?? cats.body, [], 'no canonical category exists yet');
    assert.deepEqual(types.body.data ?? types.body, [], 'no canonical type exists yet');
  });

  await t.test('no legacy row leaks into the selectors', async () => {
    await seedPreCutoverState();
    const cats = await anon('/api/categories/list-category');
    const names = (cats.body.data ?? cats.body ?? []).map((c) => c.name);
    for (const legacy of ['Buy', 'Rent', 'Rental', 'Apartment', 'Residential Plot']) {
      assert.ok(!names.includes(legacy), `"${legacy}" must never be selectable`);
    }
  });
});
