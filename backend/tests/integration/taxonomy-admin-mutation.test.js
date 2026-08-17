/**
 * Suite 12: what an authenticated admin can do to the taxonomy.
 *
 * Phase 3B made the taxonomy a contract. `applyTaxonomy` resolves a property's
 * category and type against real documents by exact name, and the active
 * filters offer only names present in CANONICAL_TAXONOMY. Both read the same
 * constant, so both depend on the documents in the database continuing to carry
 * exactly those names.
 *
 * Four admin endpoints can change them:
 *
 *   PUT    /api/categories/edit/:id
 *   DELETE /api/categories/delete/:id
 *   PUT    /api/propertyTypes/edit/:id
 *   DELETE /api/propertyTypes/delete/:id
 *
 * None of them knew the contract existed. Renaming `Residential` does not
 * produce an error anywhere: the document is still there, still valid, still
 * referenced by 37 properties. It simply stops matching the allow-list, so it
 * vanishes from every dropdown and every create against it starts returning
 * TAXONOMY_UNKNOWN_NAME. That is the failure mode this suite exists to prevent,
 * and it is worse than a crash because nothing reports it.
 *
 * The guard has to be narrow. Admins still need to delete the nineteen obsolete
 * rows the additive migration left behind, so freezing the whole collection
 * would block the cleanup stage that is already planned. Canonical documents are
 * protected; history stays editable.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { adminWithSession, asAdmin, seedTaxonomy, makeOwner, makeProperty } from './setup/factories.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); await seedTaxonomy(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const Category = () => mongoose.model('Category');
const PropertyType = () => mongoose.model('PropertyType');

const list = (body) => (Array.isArray(body) ? body : body?.data || []);

const activeCategories = async () =>
  list((await api.get('/api/categories/list-category')).body).map((c) => c.name);
const activePropertyTypes = async () =>
  list((await api.get('/api/propertyTypes/list-propertytype')).body).map((t) => t.name);

// ---------------------------------------------------------------------------

test('the admin fixture actually authenticates', async (t) => {
  await t.test('an admin session reaches a protected taxonomy route', async () => {
    const session = await adminWithSession(api);
    const res = await asAdmin(
      api.post('/api/categories/add-category'), session
    ).send({ name: 'Some New Category' });

    assert.equal(res.status, 201, JSON.stringify(res.body).slice(0, 200));
  });

  await t.test('without the session the same call is refused', async () => {
    const res = await api.post('/api/categories/add-category').send({ name: 'Nope' });
    assert.equal(res.status, 401);
  });
});

// ---------------------------------------------------------------------------

test('canonical categories cannot be renamed or deleted', async (t) => {
  await t.test('renaming Residential is refused', async () => {
    const session = await adminWithSession(api);
    const residential = await Category().findOne({ name: 'Residential' });

    const res = await asAdmin(
      api.put(`/api/categories/edit/${residential._id}`), session
    ).send({ name: 'Residential Properties' });

    assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.code, 'TAXONOMY_PROTECTED');

    const after = await Category().findById(residential._id);
    assert.equal(after.name, 'Residential', 'the document must be untouched');
    assert.ok((await activeCategories()).includes('Residential'));
  });

  await t.test('deleting Residential is refused', async () => {
    const session = await adminWithSession(api);
    const residential = await Category().findOne({ name: 'Residential' });

    const res = await asAdmin(
      api.delete(`/api/categories/delete/${residential._id}`), session
    ).send();

    assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.code, 'TAXONOMY_PROTECTED');
    assert.ok(await Category().findById(residential._id), 'the document must survive');
  });

  await t.test('every canonical category is protected, not just the first', async () => {
    const session = await adminWithSession(api);
    for (const name of ['Residential', 'Commercial', 'Land & Plots']) {
      const doc = await Category().findOne({ name });
      const res = await asAdmin(
        api.delete(`/api/categories/delete/${doc._id}`), session
      ).send();
      assert.equal(res.status, 409, `${name} was deletable`);
    }
    assert.equal((await activeCategories()).length, 3);
  });
});

// ---------------------------------------------------------------------------

test('canonical property types cannot be renamed, deleted or reparented', async (t) => {
  await t.test('renaming Apartment / Flat is refused', async () => {
    const session = await adminWithSession(api);
    const type = await PropertyType().findOne({ name: 'Apartment / Flat' });

    const res = await asAdmin(
      api.put(`/api/propertyTypes/edit/${type._id}`), session
    ).send({ name: 'Flat' });

    assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 200));
    assert.equal((await PropertyType().findById(type._id)).name, 'Apartment / Flat');
  });

  await t.test('deleting Villa is refused', async () => {
    const session = await adminWithSession(api);
    const type = await PropertyType().findOne({ name: 'Villa' });

    const res = await asAdmin(
      api.delete(`/api/propertyTypes/delete/${type._id}`), session
    ).send();

    assert.equal(res.status, 409);
    assert.ok(await PropertyType().findById(type._id));
  });

  await t.test('moving a canonical type to another category is refused', async () => {
    // Reparenting is the subtle one: the name never changes, so a name-only
    // guard would pass it through. It recreates the exact parent mismatch the
    // migration existed to fix, since the type would then be canonical under a
    // category it does not belong to.
    const session = await adminWithSession(api);
    const villa = await PropertyType().findOne({ name: 'Villa' });
    const commercial = await Category().findOne({ name: 'Commercial' });

    const res = await asAdmin(
      api.put(`/api/propertyTypes/edit/${villa._id}`), session
    ).send({ category: String(commercial._id) });

    assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 200));

    const after = await PropertyType().findById(villa._id);
    const residential = await Category().findOne({ name: 'Residential' });
    assert.equal(String(after.category), String(residential._id));
  });

  await t.test('all 20 canonical types survive an attempt on each', async () => {
    const session = await adminWithSession(api);
    const before = await activePropertyTypes();
    assert.equal(before.length, 20);

    for (const doc of await PropertyType().find({})) {
      await asAdmin(api.delete(`/api/propertyTypes/delete/${doc._id}`), session).send();
    }

    assert.equal((await activePropertyTypes()).length, 20);
  });
});

// ---------------------------------------------------------------------------

test('history stays editable', async (t) => {
  await t.test('an obsolete category can still be renamed and deleted', async () => {
    // The additive migration left nineteen of these behind and the destructive
    // cleanup stage has to be able to remove them. A guard that froze the whole
    // collection would block work that is already planned.
    const session = await adminWithSession(api);
    const legacy = await Category().create({ name: 'Buy' });

    const renamed = await asAdmin(
      api.put(`/api/categories/edit/${legacy._id}`), session
    ).send({ name: 'Buy (retired)' });
    assert.equal(renamed.status, 200, JSON.stringify(renamed.body).slice(0, 200));

    const deleted = await asAdmin(
      api.delete(`/api/categories/delete/${legacy._id}`), session
    ).send();
    assert.equal(deleted.status, 200);
    assert.equal(await Category().findById(legacy._id), null);
  });

  await t.test('a canonical NAME under a legacy parent is still history', async () => {
    // The case that decides whether the guard keys on the name or on the name
    // and its parent. A row called `Villa` filed under a legacy category is not
    // the canonical Villa, it is history that happens to share a string, and
    // the destructive cleanup stage has to be able to delete it. A name-only
    // guard would protect it forever.
    const session = await adminWithSession(api);
    const legacyParent = await Category().create({ name: 'Apartment' });
    const impostor = await PropertyType().create({ name: 'Villa', category: legacyParent._id });

    const res = await asAdmin(
      api.delete(`/api/propertyTypes/delete/${impostor._id}`), session
    ).send();

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal(await PropertyType().findById(impostor._id), null);

    // And the real one is untouched.
    const residential = await Category().findOne({ name: 'Residential' });
    assert.ok(await PropertyType().findOne({ name: 'Villa', category: residential._id }));
  });

  await t.test('an admin-created category can be removed again', async () => {
    const session = await adminWithSession(api);
    const created = await asAdmin(
      api.post('/api/categories/add-category'), session
    ).send({ name: 'Temporary' });

    const res = await asAdmin(
      api.delete(`/api/categories/delete/${created.body.data._id}`), session
    ).send();
    assert.equal(res.status, 200);
  });
});

// ---------------------------------------------------------------------------

test('referenced taxonomy cannot be deleted out from under a listing', async (t) => {
  await t.test('a category with listings is refused even when not canonical', async () => {
    const session = await adminWithSession(api);
    const owner = await makeOwner();
    const legacy = await Category().create({ name: 'Legacy In Use' });
    await makeProperty(owner, { category: legacy._id });

    const res = await asAdmin(
      api.delete(`/api/categories/delete/${legacy._id}`), session
    ).send();

    assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.code, 'TAXONOMY_IN_USE');
    assert.ok(await Category().findById(legacy._id));
  });

  await t.test('a property type with listings is refused', async () => {
    const session = await adminWithSession(api);
    const owner = await makeOwner();
    const holder = await Category().create({ name: 'Legacy Holder' });
    const legacyType = await PropertyType().create({ name: 'Legacy Type', category: holder._id });
    await makeProperty(owner, { propertyType: legacyType._id });

    const res = await asAdmin(
      api.delete(`/api/propertyTypes/delete/${legacyType._id}`), session
    ).send();

    assert.equal(res.status, 409);
    assert.equal(res.body.code, 'TAXONOMY_IN_USE');
  });

  await t.test('an unreferenced legacy row still deletes', async () => {
    const session = await adminWithSession(api);
    const unused = await Category().create({ name: 'Never Used' });

    const res = await asAdmin(
      api.delete(`/api/categories/delete/${unused._id}`), session
    ).send();
    assert.equal(res.status, 200);
  });
});

// ---------------------------------------------------------------------------

test('property type creation matches the parent-scoped index', async (t) => {
  await t.test('the same type name is allowed under a different category', async () => {
    // The compound unique index is { category, name }, so this is exactly what
    // the schema was changed to permit. The controller was still checking the
    // name globally, which refused it and left the index enforcing one rule
    // while the endpoint enforced another.
    const session = await adminWithSession(api);
    const holder = await Category().create({ name: 'Holder A' });

    const res = await asAdmin(
      api.post('/api/propertyTypes/add-property-type'), session
    ).send({ name: 'Villa', category: String(holder._id) });

    assert.equal(res.status, 201, JSON.stringify(res.body).slice(0, 200));
  });

  await t.test('a duplicate within the same category is still refused', async () => {
    const session = await adminWithSession(api);
    const residential = await Category().findOne({ name: 'Residential' });

    const res = await asAdmin(
      api.post('/api/propertyTypes/add-property-type'), session
    ).send({ name: 'Villa', category: String(residential._id) });

    assert.equal(res.status, 400, JSON.stringify(res.body).slice(0, 200));
  });

  await t.test('a property type with no category is a 400, not a 500', async () => {
    const session = await adminWithSession(api);
    const res = await asAdmin(
      api.post('/api/propertyTypes/add-property-type'), session
    ).send({ name: 'Parentless' });

    assert.equal(res.status, 400, JSON.stringify(res.body).slice(0, 200));
  });
});
