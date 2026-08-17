/**
 * Suite 9: the taxonomy migration itself.
 *
 * Runs UP and DOWN against the in-memory database, on a corpus shaped like the
 * real one: some properties carrying the stale references the old client wrote,
 * some carrying none. Both cohorts have to survive the round trip, and the
 * stale one is the harder case, because "restore" means back to the wrong
 * reference it had before, not back to a sensible one.
 *
 * The migration is deliberately not clever. It applies a literal mapping table
 * and aborts on anything it does not recognise, so the tests here are mostly
 * about what happens at the edges: an unmapped pair, a second run, a rollback,
 * and a rollback followed by another run.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeOwner } from './setup/factories.js';
import {
  migrateUp, migrateDown, status, planRepoint, seedCanonicalTaxonomy, assertSafeTarget,
} from '../../scripts/taxonomy-migration.js';

test.before(async () => { await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const Property = () => mongoose.model('Property');
const Category = () => mongoose.model('Category');
const PropertyType = () => mongoose.model('PropertyType');

/**
 * A corpus in the pre-migration shape: correct name columns, references that
 * are either absent or point at the wrong documents entirely.
 */
async function seedLegacyCorpus() {
  const owner = await makeOwner();

  // The two documents every stale reference pointed at, recreated so the
  // rollback has something real to restore.
  const wrongCategory = await Category().create({ name: 'Residential Plot' });
  const wrongType = await PropertyType().create({ name: 'Plot', category: wrongCategory._id });

  const rows = [
    ['Residential', 'Apartment / Flat', true],
    ['Residential', 'Apartment / Flat', false],
    ['Residential', 'Independent House', true],
    ['Residential', 'Villa', false],
    ['Residential', 'Penthouse', true],
    ['Commercial', 'Office Space', true],
    ['Commercial', 'Showroom', false],
    ['Commercial', 'Warehouse / Godown', false],
    ['Commercial', 'Shop / Retail', true],
    ['Commercial', 'Restaurant / Cafe', false],
  ];

  const created = [];
  for (const [categoryName, propertyTypeName, stale] of rows) {
    created.push(await Property().create({
      title: `${propertyTypeName} listing`,
      owner: owner._id,
      listingType: 'Sell',
      categoryName,
      propertyTypeName,
      ...(stale ? { category: wrongCategory._id, propertyType: wrongType._id } : {}),
    }));
  }
  return { owner, created, wrongCategory, wrongType, staleCount: rows.filter((r) => r[2]).length };
}

/** The reference state of the corpus, for before/after comparison. */
async function snapshot() {
  const docs = await Property().find({}, { category: 1, propertyType: 1, subcategory: 1, categoryName: 1, propertyTypeName: 1 })
    .sort({ _id: 1 }).lean();
  return docs.map((d) => ({
    _id: String(d._id),
    category: d.category ? String(d.category) : null,
    propertyType: d.propertyType ? String(d.propertyType) : null,
    subcategory: d.subcategory ? String(d.subcategory) : null,
    categoryName: d.categoryName,
    propertyTypeName: d.propertyTypeName,
  }));
}

// ---------------------------------------------------------------------------

test('the migration refuses to run against an unexpected database', async (t) => {
  await t.test('the test database is on the allow-list', () => {
    assert.equal(assertSafeTarget(mongoose.connection), mongoose.connection.name);
  });

  await t.test('a production-shaped database name is refused', () => {
    // The allow-list is positive: a name that is not on it fails, so a new
    // production cluster cannot slip through a stale block-list.
    assert.throws(
      () => assertSafeTarget({ name: 'Deal-Direct' }),
      /Refusing to run against database "Deal-Direct"/
    );
  });
});

// ---------------------------------------------------------------------------

test('migration UP', async (t) => {
  await t.test('seeds the canonical taxonomy and repoints every property', async () => {
    const { created, staleCount } = await seedLegacyCorpus();
    const before = await status();
    assert.equal(before.consistent, 0, 'nothing should be consistent beforehand');

    const result = await migrateUp();

    assert.equal(result.seeded.categories, 3);
    assert.equal(result.seeded.propertyTypes, 20);
    assert.equal(result.written, created.length);

    const after = await status();
    assert.equal(after.consistent, created.length, JSON.stringify(after.sample));
    assert.equal(after.broken, 0);
    assert.equal(after.nullRefs, 0, 'the previously null cohort must now be resolved');
    assert.ok(staleCount > 0, 'the fixture should include stale references');
  });

  await t.test('every property satisfies the three invariants', async () => {
    await seedLegacyCorpus();
    await migrateUp();

    const props = await Property().find({}).populate('category', 'name').populate('propertyType', 'name category').lean();
    for (const p of props) {
      assert.equal(p.category.name, p.categoryName, `${p.title}: category name`);
      assert.equal(p.propertyType.name, p.propertyTypeName, `${p.title}: type name`);
      assert.equal(String(p.propertyType.category), String(p.category._id), `${p.title}: parent`);
    }
  });

  await t.test('name columns are never rewritten', async () => {
    const { created } = await seedLegacyCorpus();
    const namesBefore = (await snapshot()).map((d) => `${d.categoryName}|${d.propertyTypeName}`);
    await migrateUp();
    const namesAfter = (await snapshot()).map((d) => `${d.categoryName}|${d.propertyTypeName}`);
    assert.deepEqual(namesAfter, namesBefore, 'the reconstruction input must survive untouched');
    assert.equal(namesAfter.length, created.length);
  });

  await t.test('is idempotent: a second run changes nothing', async () => {
    await seedLegacyCorpus();
    await migrateUp();
    const afterFirst = await snapshot();

    const second = await migrateUp();
    assert.equal(second.written, 0, 'nothing left to write');
    assert.equal(second.seeded.categories, 0);
    assert.equal(second.seeded.propertyTypes, 0);
    assert.deepEqual(await snapshot(), afterFirst);
  });

  await t.test('aborts on a pair the mapping table does not cover', async () => {
    const { owner } = await seedLegacyCorpus();
    await Property().create({
      title: 'Unmapped', owner: owner._id, listingType: 'Sell',
      categoryName: 'Residential', propertyTypeName: 'Houseboat',
    });

    await assert.rejects(() => migrateUp(), /ABORT: 1 property\(ies\) have no mapping/);

    // And nothing was repointed on the way to that decision.
    const plan = await planRepoint();
    assert.equal(plan.unknown.length, 1);
    assert.equal(plan.unknown[0].pair, 'Residential|Houseboat');
  });
});

// ---------------------------------------------------------------------------

test('migration DOWN', async (t) => {
  await t.test('restores the exact previous reference state, wrong values included', async () => {
    await seedLegacyCorpus();
    const before = await snapshot();

    await migrateUp();
    const migrated = await snapshot();
    assert.notDeepEqual(migrated, before, 'UP should have changed something');

    await migrateDown();
    assert.deepEqual(await snapshot(), before, 'DOWN must restore byte-for-byte, not approximately');
  });

  await t.test('the previously-null cohort goes back to null, not to a sensible value', async () => {
    await seedLegacyCorpus();
    const before = await snapshot();
    const wereNull = before.filter((d) => d.category === null).map((d) => d._id);
    assert.ok(wereNull.length > 0, 'fixture precondition');

    await migrateUp();
    await migrateDown();

    const after = await snapshot();
    for (const id of wereNull) {
      const row = after.find((d) => d._id === id);
      assert.equal(row.category, null, 'a null reference must come back null');
      assert.equal(row.propertyType, null);
    }
  });

  await t.test('the stale cohort goes back to the same wrong documents', async () => {
    const { wrongCategory, wrongType } = await seedLegacyCorpus();
    const before = await snapshot();
    const wereStale = before.filter((d) => d.category !== null).map((d) => d._id);

    await migrateUp();
    await migrateDown();

    const after = await snapshot();
    for (const id of wereStale) {
      const row = after.find((d) => d._id === id);
      assert.equal(row.category, String(wrongCategory._id));
      assert.equal(row.propertyType, String(wrongType._id));
    }
  });

  await t.test('clears its log so a later rollback cannot replay it twice', async () => {
    await seedLegacyCorpus();
    await migrateUp();
    await migrateDown();

    const log = mongoose.connection.db.collection('taxonomy_migration_log');
    assert.equal(await log.countDocuments(), 0);

    const again = await migrateDown();
    assert.equal(again.restored, 0);
    assert.match(String(again.note), /nothing to roll back/);
  });

  await t.test('leaves the seeded taxonomy in place: DOWN is not a taxonomy delete', async () => {
    await seedLegacyCorpus();
    await migrateUp();
    await migrateDown();

    // Deliberate. Stages 1 and 2 are additive and removing taxonomy documents
    // is the separate destructive stage, so rollback restores references only.
    assert.ok(await Category().findOne({ name: 'Land & Plots' }), 'seeded categories remain');
    assert.ok(await PropertyType().findOne({ name: 'Apartment / Flat' }), 'seeded types remain');
  });
});

// ---------------------------------------------------------------------------

test('UP, DOWN, UP reaches the same final state', async (t) => {
  await t.test('the second UP produces exactly what the first did', async () => {
    await seedLegacyCorpus();

    await migrateUp();
    const firstUp = await snapshot();

    await migrateDown();
    await migrateUp();
    const secondUp = await snapshot();

    assert.deepEqual(secondUp, firstUp);
    const final = await status();
    assert.equal(final.broken, 0);
    assert.equal(final.consistent, firstUp.length);
  });
});

// ---------------------------------------------------------------------------

test('seeding is safe to repeat on its own', async (t) => {
  await t.test('a second seed creates nothing', async () => {
    const first = await seedCanonicalTaxonomy();
    assert.equal(first.created.categories, 3);
    assert.equal(first.created.propertyTypes, 20);

    const second = await seedCanonicalTaxonomy();
    assert.equal(second.created.categories, 0);
    assert.equal(second.created.propertyTypes, 0);

    assert.equal(await Category().countDocuments(), 3);
    assert.equal(await PropertyType().countDocuments(), 20);
  });
});
