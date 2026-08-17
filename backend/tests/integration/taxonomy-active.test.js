/**
 * Suite 10: the active taxonomy, and parent-scoped uniqueness.
 *
 * The migration was additive on purpose: it seeded the canonical documents and
 * left the obsolete ones alone, because deleting them is a separate reviewed
 * stage. That leaves a gap between "exists in the collection" and "is offered
 * to a user", and this file is about that gap.
 *
 * Every case here seeds real legacy rows alongside the canonical ones, because
 * a test that only seeds the good data cannot tell the difference between
 * filtering correctly and not filtering at all.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeOwner, loginAs, seedTaxonomy } from './setup/factories.js';
import { CANONICAL_TAXONOMY, OBSOLETE_TAXONOMY_NAMES } from '../../config/taxonomy.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); await seedTaxonomy(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const Category = () => mongoose.model('Category');
const PropertyType = () => mongoose.model('PropertyType');

/**
 * Recreate the legacy rows the real database still carries: listing intents and
 * property-type names sitting in `categories`, and the old parent-level names
 * sitting in `propertytypes`.
 */
async function seedLegacyRows() {
  const legacyCategories = await Category().insertMany([
    { name: 'Buy' }, { name: 'Rental' }, { name: 'Rent' },
    { name: 'Apartment' }, { name: 'Office space' }, { name: 'Shop / Showroom' }, { name: 'Plots' },
  ]);
  // The old parent level, which had no category of its own. A property type with
  // no parent cannot be active under any rule.
  const orphanParent = await Category().create({ name: 'Legacy Parent Holder' });
  const legacyTypes = await PropertyType().insertMany([
    { name: 'Residential', category: orphanParent._id },
    { name: 'Commercial', category: orphanParent._id },
    { name: 'Plot', category: orphanParent._id },
  ]);
  return { legacyCategories, legacyTypes, orphanParent };
}

const list = (body) => (Array.isArray(body) ? body : body?.data || []);

// ---------------------------------------------------------------------------

test('active taxonomy endpoints exclude legacy rows', async (t) => {
  await t.test('the category list offers only the canonical categories', async () => {
    await seedLegacyRows();
    const res = await api.get('/api/categories/list-category').set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 200);

    const names = list(res.body).map((c) => c.name);
    assert.deepEqual(names, Object.keys(CANONICAL_TAXONOMY), 'exact set, in canonical order');

    for (const legacy of ['Buy', 'Rental', 'Rent', 'Apartment', 'Office space', 'Shop / Showroom', 'Plots']) {
      assert.ok(!names.includes(legacy), `"${legacy}" is still offered as a category`);
    }
  });

  await t.test('every retired name from the decision document is absent', async () => {
    await seedLegacyRows();
    const res = await api.get('/api/categories/list-category').set('X-Forwarded-For', uniqueClientIp());
    const names = list(res.body).map((c) => c.name);
    for (const retired of OBSOLETE_TAXONOMY_NAMES) {
      assert.ok(!names.includes(retired), `"${retired}" should not be selectable`);
    }
  });

  await t.test('the property type list offers only the canonical twenty', async () => {
    await seedLegacyRows();
    const res = await api.get('/api/propertyTypes/list-propertytype').set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 200);

    const names = list(res.body).map((t) => t.name).sort();
    assert.deepEqual(names, [...Object.values(CANONICAL_TAXONOMY).flat()].sort());
    for (const legacy of ['Residential', 'Commercial', 'Plot']) {
      assert.ok(!names.includes(legacy), `"${legacy}" is a category, not a property type`);
    }
  });

  await t.test('a canonical name under a non-canonical parent is still excluded', async () => {
    // The case a name-only filter would miss: the right string, the wrong
    // parent. This is the shape of the corruption the phase removed, so the
    // active filter has to reject it rather than pass it through.
    const { orphanParent } = await seedLegacyRows();
    await PropertyType().create({ name: 'Villa', category: orphanParent._id });

    const res = await api.get('/api/propertyTypes/list-propertytype').set('X-Forwarded-For', uniqueClientIp());
    const villas = list(res.body).filter((t) => t.name === 'Villa');
    assert.equal(villas.length, 1, 'only the Villa under Residential may be offered');

    const parent = await Category().findById(villas[0].category).lean();
    assert.equal(parent.name, 'Residential');
  });

  await t.test('the legacy documents are still physically present', async () => {
    // The whole point of the additive migration: hidden, not deleted. If this
    // ever fails, something ran the destructive stage early.
    await seedLegacyRows();
    assert.ok(await Category().findOne({ name: 'Buy' }), 'legacy row was deleted');
    assert.ok(await PropertyType().findOne({ name: 'Plot' }), 'legacy row was deleted');
  });
});

// ---------------------------------------------------------------------------

test('the write contract also refuses retired taxonomy', async (t) => {
  const create = async (body) => {
    const owner = await makeOwner();
    const cookies = await loginAs(api, owner);
    const res = await api.post('/api/properties/add')
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies)
      .send({ title: 'Active Suite', listingType: 'Sell', latitude: 11.11, longitude: 77.77, ...body });
    return { res, doc: await mongoose.model('Property').findOne({ owner: owner._id }).lean() };
  };

  await t.test('a legacy category name is rejected even though the row exists', async () => {
    await seedLegacyRows();
    // "Apartment" is a real document in `categories`. Before the active filter
    // it resolved, which meant a listing could be filed under a category that
    // is really a property type.
    const { res, doc } = await create({ categoryName: 'Apartment', propertyTypeName: 'Villa' });
    assert.equal(res.status, 400, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.code, 'TAXONOMY_UNKNOWN_NAME');
    assert.equal(doc, null);
  });

  await t.test('a listing intent is rejected as a category', async () => {
    await seedLegacyRows();
    const { res } = await create({ categoryName: 'Rent', propertyTypeName: 'Villa' });
    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'TAXONOMY_UNKNOWN_NAME');
  });

  await t.test('a legacy id is refused with a distinct code', async () => {
    const { legacyCategories } = await seedLegacyRows();
    const buy = legacyCategories.find((c) => c.name === 'Buy');
    const { res } = await create({ categoryName: 'Buy', category: String(buy._id), propertyTypeName: 'Villa' });
    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'TAXONOMY_RETIRED', 'the id resolves, but the document is not offered');
  });
});

// ---------------------------------------------------------------------------

test('property type uniqueness is scoped to the parent category', async (t) => {
  await t.test('the same name under two different categories is allowed', async () => {
    // The reason the global unique index had to go. Nothing in the product
    // requires a type name to be unique across the whole taxonomy, and the
    // target model explicitly allows it.
    const residential = await Category().findOne({ name: 'Residential' });
    const commercial = await Category().findOne({ name: 'Commercial' });

    await PropertyType().create({ name: 'Shared Type Name', category: residential._id });
    const second = await PropertyType().create({ name: 'Shared Type Name', category: commercial._id });

    assert.ok(second._id);
    assert.equal(await PropertyType().countDocuments({ name: 'Shared Type Name' }), 2);
  });

  await t.test('the same name under the same category is rejected', async () => {
    const residential = await Category().findOne({ name: 'Residential' });
    await PropertyType().create({ name: 'Duplicate Check', category: residential._id });

    await assert.rejects(
      () => PropertyType().create({ name: 'Duplicate Check', category: residential._id }),
      (err) => err.code === 11000,
      'the compound unique index should reject it'
    );
  });

  await t.test('the legacy global unique index on name is gone', async () => {
    const indexes = await PropertyType().collection.indexes();
    const names = indexes.map((i) => i.name);

    assert.ok(!names.includes('name_1'), 'the global unique index on name must be dropped');
    assert.ok(names.includes('category_1_name_1'), 'the parent-scoped index must exist');

    const compound = indexes.find((i) => i.name === 'category_1_name_1');
    assert.equal(compound.unique, true, 'and it must be unique');
  });

  await t.test('category names remain globally unique', async () => {
    // Categories are the top level, so there is no parent to scope them to.
    await assert.rejects(
      () => Category().create({ name: 'Residential' }),
      (err) => err.code === 11000
    );
  });
});
