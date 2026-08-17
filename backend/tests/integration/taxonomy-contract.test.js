/**
 * Suite 8: the taxonomy consistency contract, and search equivalence.
 *
 * Two claims, tested end to end through the real endpoints.
 *
 * The contract. A request may not describe the same fact two ways and have the
 * server pick one. An id and a name must agree; a name must resolve exactly; a
 * property type must belong to the category it is filed under. Anything else is
 * a 400 rather than a quiet correction, because quiet correction is what
 * produced a corpus where 25 of 47 listings carried references describing a
 * different property and no read path noticed for months.
 *
 * Search equivalence. `?categoryName=X` and `?category=<id of X>` must return
 * the same property ids. This is the assertion that would have caught the
 * original bug on the day it shipped: the name filter worked, the id filter
 * returned the wrong set, and nothing compared them. Everything else in this
 * file can pass while the product is still broken for users; this cannot.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeOwner, loginAs, seedTaxonomy } from './setup/factories.js';
import { CANONICAL_TAXONOMY } from '../../config/taxonomy.js';

let api;
let taxonomy;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); taxonomy = await seedTaxonomy(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const Property = () => mongoose.model('Property');

async function ownerSession() {
  const owner = await makeOwner();
  return { owner, cookies: await loginAs(api, owner) };
}

/** Create through the real endpoint. `mode` picks JSON or multipart. */
async function create(body, { mode = 'json', session } = {}) {
  const s = session || (await ownerSession());
  const base = { title: 'Contract Suite', listingType: 'Sell', latitude: 11.11, longitude: 77.77, ...body };
  let req = api.post('/api/properties/add')
    .set('X-Forwarded-For', uniqueClientIp())
    .set('Cookie', s.cookies);

  if (mode === 'multipart') {
    for (const [k, v] of Object.entries(base)) req = req.field(k, String(v));
  } else {
    req = req.send(base);
  }
  const res = await req;
  return { res, owner: s.owner, doc: await Property().findOne({ owner: s.owner._id }).lean() };
}

// ---------------------------------------------------------------------------

test('the taxonomy endpoints the forms depend on still work', async (t) => {
  // Added because they broke and nothing noticed. Inverting the parent
  // relationship removed `propertyType` from the Category schema while
  // categoryController still called .populate("propertyType"), which throws
  // StrictPopulateError and took the endpoint to a 500. Every category dropdown
  // in the web and Admin forms is fed by it, so the whole create flow was dead
  // while the migration itself looked perfectly healthy.

  await t.test('GET /api/categories/list-category returns the canonical categories', async () => {
    const res = await api.get('/api/categories/list-category').set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    const names = (res.body.data || res.body || []).map((c) => c.name);
    for (const expected of Object.keys(CANONICAL_TAXONOMY)) {
      assert.ok(names.includes(expected), `"${expected}" missing from the category list`);
    }
  });

  await t.test('GET /api/propertyTypes/list-propertytype returns the canonical types', async () => {
    const res = await api.get('/api/propertyTypes/list-propertytype').set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    const names = (res.body.data || res.body || []).map((t) => t.name);
    for (const expected of Object.values(CANONICAL_TAXONOMY).flat()) {
      assert.ok(names.includes(expected), `"${expected}" missing from the type list`);
    }
  });

  await t.test('the retired subcategory API is unmounted', async () => {
    const res = await api.get('/api/subcategories/list').set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 404, 'the retired routes must not answer');
  });
});

// ---------------------------------------------------------------------------

test('data invariants hold on every created property', async (t) => {
  await t.test('category.name === categoryName and propertyType.name === propertyTypeName', async () => {
    for (const [categoryName, types] of Object.entries(CANONICAL_TAXONOMY)) {
      for (const propertyTypeName of types) {
        const { res, doc } = await create({ categoryName, propertyTypeName });
        assert.equal(res.status, 201, `${categoryName}/${propertyTypeName}: ${JSON.stringify(res.body).slice(0, 150)}`);

        const category = await mongoose.model('Category').findById(doc.category).lean();
        const type = await mongoose.model('PropertyType').findById(doc.propertyType).lean();

        assert.equal(category.name, doc.categoryName, `${propertyTypeName}: category name`);
        assert.equal(type.name, doc.propertyTypeName, `${propertyTypeName}: type name`);
        assert.equal(String(type.category), String(category._id), `${propertyTypeName}: parent`);
      }
    }
  });

  await t.test('subcategory is never set, whatever a client sends', async () => {
    const other = new mongoose.Types.ObjectId();
    const { res, doc } = await create({
      categoryName: 'Residential', propertyTypeName: 'Villa',
      subcategory: String(other), subcategoryName: 'Anything',
    });
    assert.equal(res.status, 201);
    assert.ok(!doc.subcategory, 'the retired level must not be repopulated');
    assert.ok(!doc.subcategoryName);
  });
});

// ---------------------------------------------------------------------------

for (const mode of ['json', 'multipart']) {
  test(`consistency contract over ${mode}`, async (t) => {
    const ids = async () => {
      const category = await mongoose.model('Category').findOne({ name: 'Residential' }).lean();
      const type = await mongoose.model('PropertyType').findOne({ name: 'Villa', category: category._id }).lean();
      const otherCategory = await mongoose.model('Category').findOne({ name: 'Commercial' }).lean();
      const otherType = await mongoose.model('PropertyType').findOne({ name: 'Office Space', category: otherCategory._id }).lean();
      return { category, type, otherCategory, otherType };
    };

    await t.test('a matching id and name is accepted', async () => {
      const { category, type } = await ids();
      const { res, doc } = await create({
        categoryName: 'Residential', propertyTypeName: 'Villa',
        category: String(category._id), propertyType: String(type._id),
      }, { mode });
      assert.equal(res.status, 201, JSON.stringify(res.body).slice(0, 200));
      assert.equal(String(doc.category), String(category._id));
    });

    await t.test('a mismatching category id and name is rejected', async () => {
      const { otherCategory } = await ids();
      const { res, doc } = await create({
        categoryName: 'Residential', propertyTypeName: 'Villa',
        category: String(otherCategory._id),
      }, { mode });
      assert.equal(res.status, 400, JSON.stringify(res.body).slice(0, 200));
      assert.equal(res.body.code, 'TAXONOMY_MISMATCH');
      assert.equal(doc, null, 'nothing may be stored');
    });

    await t.test('a mismatching property type id and name is rejected', async () => {
      const { category, otherType } = await ids();
      const { res, doc } = await create({
        categoryName: 'Residential', propertyTypeName: 'Villa',
        category: String(category._id), propertyType: String(otherType._id),
      }, { mode });
      assert.equal(res.status, 400);
      assert.equal(res.body.code, 'TAXONOMY_MISMATCH');
      assert.equal(doc, null);
    });

    await t.test('an id supplied without its name is rejected', async () => {
      const { category } = await ids();
      const { res } = await create({ category: String(category._id) }, { mode });
      assert.equal(res.status, 400);
      assert.equal(res.body.code, 'TAXONOMY_NAME_REQUIRED');
    });

    await t.test('an id that resolves to nothing is rejected', async () => {
      const { res } = await create({
        categoryName: 'Residential', propertyTypeName: 'Villa',
        category: String(new mongoose.Types.ObjectId()),
      }, { mode });
      assert.equal(res.status, 400);
      assert.equal(res.body.code, 'TAXONOMY_UNKNOWN_ID');
    });

    await t.test('names alone are accepted and resolved', async () => {
      const { res, doc } = await create({ categoryName: 'Commercial', propertyTypeName: 'Showroom' }, { mode });
      assert.equal(res.status, 201, JSON.stringify(res.body).slice(0, 200));
      assert.ok(doc.category && doc.propertyType);
    });

    await t.test('an unknown category name is rejected', async () => {
      const { res } = await create({ categoryName: 'Residental', propertyTypeName: 'Villa' }, { mode });
      assert.equal(res.status, 400);
      assert.equal(res.body.code, 'TAXONOMY_UNKNOWN_NAME');
    });

    await t.test('an unknown property type name is rejected', async () => {
      const { res } = await create({ categoryName: 'Residential', propertyTypeName: 'Apartment' }, { mode });
      assert.equal(res.status, 400, 'the old DB spelling is not the canonical one');
      assert.equal(res.body.code, 'TAXONOMY_UNKNOWN_NAME');
    });

    await t.test('a case variant is rejected rather than folded', async () => {
      const { res } = await create({ categoryName: 'residential', propertyTypeName: 'Villa' }, { mode });
      assert.equal(res.status, 400);
      assert.equal(res.body.code, 'TAXONOMY_UNKNOWN_NAME');
    });

    await t.test('a type filed under the wrong category is rejected', async () => {
      // Both halves resolve; only the relationship is wrong. This is the case
      // the other two checks cannot see on their own.
      const { res, doc } = await create({
        categoryName: 'Residential', propertyTypeName: 'Office Space',
      }, { mode });
      assert.equal(res.status, 400, JSON.stringify(res.body).slice(0, 200));
      assert.equal(res.body.code, 'TAXONOMY_PARENT_MISMATCH');
      assert.equal(doc, null);
    });
  });
}

test('JSON and multipart reach identical outcomes', async (t) => {
  await t.test('the same bodies produce the same statuses and codes', async () => {
    const cases = [
      { categoryName: 'Residential', propertyTypeName: 'Villa' },
      { categoryName: 'Residential', propertyTypeName: 'Office Space' },
      { categoryName: 'Nope', propertyTypeName: 'Villa' },
      { categoryName: 'residential', propertyTypeName: 'Villa' },
    ];
    for (const body of cases) {
      const j = await create(body, { mode: 'json' });
      const m = await create(body, { mode: 'multipart' });
      assert.equal(
        `${j.res.status}/${j.res.body.code ?? '-'}`,
        `${m.res.status}/${m.res.body.code ?? '-'}`,
        `JSON and multipart disagree for ${JSON.stringify(body)}`
      );
    }
  });
});

// ---------------------------------------------------------------------------

test('the contract applies to owner edits, not just creation', async (t) => {
  async function ownedProperty() {
    const s = await ownerSession();
    const { doc } = await create({ categoryName: 'Residential', propertyTypeName: 'Villa' }, { session: s });
    return { ...s, property: doc };
  }

  const put = (property, cookies, body) =>
    api.put(`/api/properties/my-properties/${property._id}`)
      .set('X-Forwarded-For', uniqueClientIp()).set('Cookie', cookies).send(body);

  await t.test('a valid taxonomy change is applied', async () => {
    const { cookies, property } = await ownedProperty();
    const res = await put(property, cookies, { categoryName: 'Commercial', propertyTypeName: 'Showroom' });
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));

    const stored = await Property().findById(property._id).lean();
    const category = await mongoose.model('Category').findById(stored.category).lean();
    const type = await mongoose.model('PropertyType').findById(stored.propertyType).lean();
    assert.equal(category.name, 'Commercial');
    assert.equal(type.name, 'Showroom');
    assert.equal(String(type.category), String(category._id));
  });

  await t.test('a mismatched edit is rejected and changes nothing', async () => {
    const { cookies, property } = await ownedProperty();
    const before = await Property().findById(property._id).lean();

    const other = await mongoose.model('Category').findOne({ name: 'Commercial' }).lean();
    const res = await put(property, cookies, {
      categoryName: 'Residential', propertyTypeName: 'Villa', category: String(other._id),
    });

    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'TAXONOMY_MISMATCH');
    const after = await Property().findById(property._id).lean();
    assert.equal(String(after.category), String(before.category), 'stored document must be untouched');
  });

  await t.test('an edit cannot resurrect a subcategory', async () => {
    const { cookies, property } = await ownedProperty();
    await put(property, cookies, { subcategory: String(new mongoose.Types.ObjectId()) });
    const after = await Property().findById(property._id).lean();
    assert.ok(!after.subcategory);
  });
});

// ---------------------------------------------------------------------------

test('search equivalence: name filters and id filters agree', async (t) => {
  /** Build one listing for every canonical pair, then compare the two filters. */
  async function corpus() {
    const made = [];
    for (const [categoryName, types] of Object.entries(CANONICAL_TAXONOMY)) {
      for (const propertyTypeName of types) {
        const { res, doc } = await create({ categoryName, propertyTypeName });
        assert.equal(res.status, 201, `${categoryName}/${propertyTypeName}`);
        made.push(doc);
      }
    }
    return made;
  }

  const search = async (params) => {
    const res = await api.get('/api/properties/search')
      .query({ limit: 100, ...params })
      .set('X-Forwarded-For', uniqueClientIp());
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    const list = res.body.properties || res.body.data || [];
    return list.map((p) => String(p._id)).sort();
  };

  await t.test('every category returns the same ids by name and by id', async () => {
    await corpus();
    for (const categoryName of Object.keys(CANONICAL_TAXONOMY)) {
      const category = await mongoose.model('Category').findOne({ name: categoryName }).lean();
      const byName = await search({ categoryName });
      const byId = await search({ category: String(category._id) });
      assert.deepEqual(byId, byName, `"${categoryName}" disagrees: name=${byName.length} id=${byId.length}`);
      assert.ok(byName.length > 0, `"${categoryName}" should match at least one listing`);
    }
  });

  await t.test('every property type returns the same ids by name and by id', async () => {
    await corpus();
    for (const [categoryName, types] of Object.entries(CANONICAL_TAXONOMY)) {
      const category = await mongoose.model('Category').findOne({ name: categoryName }).lean();
      for (const propertyTypeName of types) {
        const type = await mongoose.model('PropertyType')
          .findOne({ name: propertyTypeName, category: category._id }).lean();
        const byName = await search({ propertyTypeName });
        const byId = await search({ propertyType: String(type._id) });
        assert.deepEqual(byId, byName, `"${propertyTypeName}" disagrees: name=${byName.length} id=${byId.length}`);
      }
    }
  });
});
