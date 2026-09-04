/**
 * Suite 16: aggregate-root deletion.
 *
 * Five named functions replace deletion logic that had grown independently at
 * each call site. The consolidation is not cosmetic: Property had TWO delete
 * handlers, `deleteProperty` (admin) and `deleteMyProperty` (owner), each with
 * its own copy of the Cloudinary cleanup and NEITHER with any dependency check.
 * A third path, the bulk `Property.deleteMany({ owner })` inside account
 * deletion, had no per-property check at all.
 *
 * So a property could be destroyed from three directions while carrying a
 * pending TransactionVerification. That orphan is the sharpest failure in the
 * whole dependency graph: admin approve and reject both populate the property,
 * so both throw afterwards, and the buyer's reward becomes permanently
 * unclaimable with no interface able to resolve it.
 *
 * ORDERING IS THE POINT. Every refusal runs before any destructive work,
 * including before Cloudinary. A guard that fires after the images are gone is
 * not a guard, and Cloudinary deletion does not roll back. Several tests below
 * assert the ordering rather than just the status code.
 *
 * WHAT IS DELIBERATELY UNCHANGED: the account cascade still deletes the same
 * twelve collections and retains the same six. That split is a product and
 * legal decision (DEALDIRECT-DELETION-AND-RBAC-DECISION.md §1.6) and is parked.
 * The tests here pin the CURRENT behaviour so the decision, when it lands, is a
 * deliberate change to a documented baseline rather than a silent drift.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, withClient } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import {
  adminWithSession, asAdmin, ownerWithSession, buyerWithSession,
  makeProperty, makeLead, TEST_PASSWORD,
} from './setup/factories.js';
import { USER_CASCADE } from '../../utils/aggregateDelete.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const M = (n) => mongoose.model(n);

const verificationFor = (property, owner, buyer, status = 'pending') =>
  M('TransactionVerification').create({
    property: property._id, owner: owner._id, buyer: buyer._id,
    closingType: 'sold', status,
    documentUrls: ['https://res.cloudinary.com/demo/image/upload/v1/dealdirect/proof.pdf'],
  });

const deleteAsOwner = (session, id) =>
  withClient(api.delete(`/api/properties/${id}`), session).send();

const deleteAsAdmin = (session, id) =>
  asAdmin(api.delete(`/api/properties/delete/${id}`), session).send();

// ---------------------------------------------------------------------------

test('a property carrying deal evidence cannot be deleted', async (t) => {
  for (const status of ['pending', 'approved']) {
    await t.test(`a ${status} verification blocks the owner path`, async () => {
      const { owner, cookies } = await ownerWithSession(api);
      const { buyer } = await buyerWithSession(api);
      const property = await makeProperty(owner);
      await verificationFor(property, owner, buyer, status);

      const res = await deleteAsOwner({ cookies }, property._id);

      assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 250));
      assert.equal(res.body.code, 'DELETE_BLOCKED_DEPENDENTS');
      assert.ok(await M('Property').findById(property._id), 'the listing must survive');
    });

    await t.test(`a ${status} verification blocks the admin path too`, async () => {
      // Two handlers, one rule. Before consolidation each had its own copy of
      // the cleanup and neither had any check at all.
      const admin = await adminWithSession(api);
      const { owner } = await ownerWithSession(api);
      const { buyer } = await buyerWithSession(api);
      const property = await makeProperty(owner);
      await verificationFor(property, owner, buyer, status);

      const res = await deleteAsAdmin(admin, property._id);

      assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 250));
      assert.ok(await M('Property').findById(property._id));
    });
  }

  await t.test('a rejected verification does NOT block deletion', async () => {
    // Rejected means the deal did not happen. Blocking on it would make every
    // failed close permanently undeletable, which is not integrity, it is a leak.
    const { owner, cookies } = await ownerWithSession(api);
    const { buyer } = await buyerWithSession(api);
    const property = await makeProperty(owner);
    await verificationFor(property, owner, buyer, 'rejected');

    const res = await deleteAsOwner({ cookies }, property._id);

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 250));
    assert.equal(await M('Property').findById(property._id), null);
  });

  await t.test('the refusal names the orphan consequence, not just a count', async () => {
    const { owner, cookies } = await ownerWithSession(api);
    const { buyer } = await buyerWithSession(api);
    const property = await makeProperty(owner);
    await verificationFor(property, owner, buyer, 'pending');

    const res = await deleteAsOwner({ cookies }, property._id);
    assert.match(res.body.message, /reward|approve|orphan/i);
  });
});

// ---------------------------------------------------------------------------

test('a property under a binding agreement cannot be deleted', async (t) => {
  // Inserted through the driver rather than the model. Agreement declares
  // thirteen required fields including a content hash, an HMAC signature and an
  // idempotency key, and fabricating those would be inventing a legal document
  // to test a delete guard. The guard queries property and status only, so
  // those are the only fields that need to be real.
  const agreementFor = (property, owner, buyer, status) =>
    M('Agreement').collection.insertOne({
      property: property._id, owner: owner._id, buyer: buyer._id,
      agreementType: 'RENTAL_AGREEMENT', status, createdAt: new Date(),
    });

  for (const status of ['signed', 'active', 'pending_owner_signature']) {
    await t.test(`a ${status} agreement blocks deletion`, async () => {
      const { owner, cookies } = await ownerWithSession(api);
      const { buyer } = await buyerWithSession(api);
      const property = await makeProperty(owner);
      await agreementFor(property, owner, buyer, status);

      const res = await deleteAsOwner({ cookies }, property._id);

      assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 250));
      assert.ok(await M('Property').findById(property._id));
    });
  }

  for (const status of ['cancelled', 'terminated', 'expired', 'draft']) {
    await t.test(`a ${status} agreement does not block deletion`, async () => {
      const { owner, cookies } = await ownerWithSession(api);
      const { buyer } = await buyerWithSession(api);
      const property = await makeProperty(owner);
      await agreementFor(property, owner, buyer, status);

      const res = await deleteAsOwner({ cookies }, property._id);
      assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 250));
    });
  }
});

// ---------------------------------------------------------------------------

test('nothing destructive happens before a refusal', async (t) => {
  await t.test('the images survive a blocked delete', async () => {
    // The ordering assertion. Cloudinary deletion does not roll back, so a
    // refusal that fires after the cleanup has already run is not a refusal.
    const { owner, cookies } = await ownerWithSession(api);
    const { buyer } = await buyerWithSession(api);
    const property = await makeProperty(owner, {
      images: ['https://res.cloudinary.com/demo/image/upload/v1/dealdirect/properties/a.jpg'],
    });
    await verificationFor(property, owner, buyer, 'pending');

    await deleteAsOwner({ cookies }, property._id);

    const after = await M('Property').findById(property._id).lean();
    assert.ok(after, 'the document survives');
    assert.deepEqual(after.images, property.images, 'the image list is untouched');
  });

  await t.test('Cloudinary is never called when the delete is refused', async () => {
    // The assertion that actually pins the ordering. Checking the document is
    // not enough: deletePropertyAssets destroys remote assets and does not
    // touch the images array, so moving it above the guard leaves the database
    // looking identical while the pictures are already gone. Only counting the
    // destroy calls can tell.
    const { cloudinary } = await import('../../middleware/upload.js');
    const original = cloudinary.uploader.destroy;
    let destroyCalls = 0;
    cloudinary.uploader.destroy = async (...args) => {
      destroyCalls += 1;
      return { result: 'ok' };
    };

    try {
      const { owner, cookies } = await ownerWithSession(api);
      const { buyer } = await buyerWithSession(api);
      const property = await makeProperty(owner, {
        images: ['https://res.cloudinary.com/demo/image/upload/v1/dealdirect/properties/c.jpg'],
      });
      await verificationFor(property, owner, buyer, 'pending');

      const blocked = await deleteAsOwner({ cookies }, property._id);
      assert.equal(blocked.status, 409);
      assert.equal(destroyCalls, 0, 'assets were destroyed before the refusal fired');

      // And the same asset IS destroyed once the blocker is gone, so the
      // assertion above is about ordering rather than about cleanup being dead.
      await M('TransactionVerification').deleteMany({ property: property._id });
      const allowed = await deleteAsOwner({ cookies }, property._id);
      assert.equal(allowed.status, 200, JSON.stringify(allowed.body).slice(0, 200));
      assert.equal(destroyCalls, 1, 'cleanup must still run on a permitted delete');
    } finally {
      cloudinary.uploader.destroy = original;
    }
  });

  await t.test('a blocked delete leaves the verification intact', async () => {
    const { owner, cookies } = await ownerWithSession(api);
    const { buyer } = await buyerWithSession(api);
    const property = await makeProperty(owner);
    const verification = await verificationFor(property, owner, buyer, 'pending');

    await deleteAsOwner({ cookies }, property._id);

    const after = await M('TransactionVerification').findById(verification._id).lean();
    assert.equal(after.status, 'pending', 'the deal is still resolvable by an admin');
  });
});

// ---------------------------------------------------------------------------

test('an unencumbered property still deletes, images and all', async (t) => {
  await t.test('the owner path removes the document', async () => {
    const { owner, cookies } = await ownerWithSession(api);
    const property = await makeProperty(owner, {
      images: ['https://res.cloudinary.com/demo/image/upload/v1/dealdirect/properties/b.jpg'],
    });

    const res = await deleteAsOwner({ cookies }, property._id);

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 250));
    assert.equal(await M('Property').findById(property._id), null);
  });

  await t.test('a lead pointing at it does not block deletion', async () => {
    // Leads are retained rather than protective. The existing behaviour keeps
    // them and this change does not alter it; anonymising them is the parked
    // decision, and blocking on one would make any enquired-upon listing
    // permanently undeletable.
    const { owner, cookies } = await ownerWithSession(api);
    const { buyer } = await buyerWithSession(api);
    const property = await makeProperty(owner);
    const lead = await makeLead(property, buyer, { propertyOwner: owner._id });

    const res = await deleteAsOwner({ cookies }, property._id);

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 250));
    assert.ok(await M('Lead').findById(lead._id), 'the lead is retained, not cascaded');
  });
});

// ---------------------------------------------------------------------------

test('the earlier builder-chain guards are unchanged', async (t) => {
  async function chain(adminId, n) {
    const builder = await M('Builder').create({
      name: `Agg Builder ${n}`, phone: `94444${String(10000 + n).slice(-5)}`,
      email: `agg-${n}@example.invalid`, createdBy: adminId,
    });
    const project = await M('Project').create({ name: 'Agg Project', builder: builder._id, createdBy: adminId });
    const unitType = await M('UnitType').create({ project: project._id, builder: builder._id, createdBy: adminId });
    return { builder, project, unitType };
  }

  await t.test('a project with unit types still refuses with 400', async () => {
    // Status code deliberately preserved. Changing it is client-visible and
    // this consolidation does not need to make that change.
    const admin = await adminWithSession(api);
    const c = await chain(admin.admin._id, 1);

    const res = await asAdmin(api.delete(`/api/projects/${c.project._id}`), admin).send();

    assert.equal(res.status, 400);
    assert.match(res.body.message, /unit type/i);
  });

  await t.test('a project with a live booking still refuses with 409', async () => {
    const admin = await adminWithSession(api);
    const c = await chain(admin.admin._id, 2);
    await M('ProjectBooking').create({
      project: c.project._id, unitType: c.unitType._id, builder: c.builder._id,
      clientName: 'X', clientPhone: '9444400000', status: 'confirmed',
    });
    await M('UnitType').deleteOne({ _id: c.unitType._id });

    const res = await asAdmin(api.delete(`/api/projects/${c.project._id}`), admin).send();
    assert.equal(res.status, 409);
  });

  await t.test('a unit type with a campaign still refuses', async () => {
    const admin = await adminWithSession(api);
    const c = await chain(admin.admin._id, 3);
    await M('GroupBuyCampaign').create({
      unitType: c.unitType._id, project: c.project._id, builder: c.builder._id,
      createdBy: admin.admin._id, basics: { name: 'C' }, buyerTargets: { minBuyers: 5 },
      duration: { startDate: new Date('2026-01-01'), endDate: new Date('2099-12-31') },
      discountPerBuyer: 1000, status: 'completed',
    });

    const res = await asAdmin(api.delete(`/api/unit-types/${c.unitType._id}`), admin).send();
    assert.equal(res.status, 409);
  });

  await t.test('a clean unit type still deletes and still decrements the counter', async () => {
    const admin = await adminWithSession(api);
    const c = await chain(admin.admin._id, 4);
    await M('Project').findByIdAndUpdate(c.project._id, { unitTypeCount: 1 });

    const res = await asAdmin(api.delete(`/api/unit-types/${c.unitType._id}`), admin).send();

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 250));
    assert.equal((await M('Project').findById(c.project._id)).unitTypeCount, 0);
  });

  await t.test('a builder with approved properties still refuses, and is not deleted', async () => {
    const admin = await adminWithSession(api);
    const c = await chain(admin.admin._id, 5);
    const { owner } = await ownerWithSession(api);
    await makeProperty(owner, { builder: c.builder._id, isApproved: true });

    const res = await asAdmin(api.delete(`/api/builders/${c.builder._id}`), admin).send();

    assert.equal(res.status, 400, JSON.stringify(res.body).slice(0, 250));
    assert.equal((await M('Builder').findById(c.builder._id)).isActive, true);
  });

  await t.test('a clean builder is DEACTIVATED, not removed', async () => {
    const admin = await adminWithSession(api);
    const c = await chain(admin.admin._id, 6);

    const res = await asAdmin(api.delete(`/api/builders/${c.builder._id}`), admin).send();

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 250));
    const after = await M('Builder').findById(c.builder._id);
    assert.ok(after, 'a builder is soft-deleted; the whole chain hangs off this reference');
    assert.equal(after.isActive, false);
  });
});

// ---------------------------------------------------------------------------

test('account deletion keeps its documented collection split', async (t) => {
  async function deleteAccount(cookies) {
    return withClient(api.delete('/api/users/me'), { cookies })
      .send({ password: TEST_PASSWORD });
  }

  await t.test('the deleted and retained lists are what the code claims', () => {
    // Pins the parked decision. When the policy lands, this test is what makes
    // the change deliberate rather than silent.
    // 12 originally; LoginTracker left with the streak mechanic (Phase 0, F1)
    // and PushToken, OutboundLog and Event arrived with push and usage events.
    assert.equal(USER_CASCADE.deleted.length, 14);
    for (const name of ['PushToken', 'OutboundLog', 'Event']) {
      assert.ok(USER_CASCADE.deleted.includes(name), `${name} must be deleted with the account`);
    }
    assert.ok(!USER_CASCADE.deleted.includes('LoginTracker'), 'LoginTracker no longer exists');
    assert.equal(USER_CASCADE.retained.length, 5);
    assert.ok(USER_CASCADE.retained.includes('Lead'));
    assert.ok(USER_CASCADE.retained.includes('Agreement'));
    assert.ok(USER_CASCADE.deleted.includes('Reward'));
  });

  await t.test('an unencumbered account is deleted with its listings', async () => {
    const { owner, cookies } = await ownerWithSession(api);
    const property = await makeProperty(owner);

    const res = await deleteAccount(cookies);

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 250));
    assert.equal(await M('User').findById(owner._id), null);
    assert.equal(await M('Property').findById(property._id), null);
  });

  await t.test('retained collections survive, as they did before', async () => {
    const { owner, cookies } = await ownerWithSession(api);
    const { buyer } = await buyerWithSession(api);
    const property = await makeProperty(owner);
    const lead = await makeLead(property, buyer, { propertyOwner: owner._id });

    await deleteAccount(cookies);

    assert.ok(await M('Lead').findById(lead._id), 'the buyer\'s enquiry belongs to the owner\'s record too');
  });

  await t.test('a listing tied to a live deal is kept, and reported', async () => {
    // The one behavioural consequence of routing the bulk delete through the
    // per-property guard. Previously deleteMany destroyed it without a word.
    const { owner, cookies } = await ownerWithSession(api);
    const { buyer } = await buyerWithSession(api);
    const property = await makeProperty(owner);
    await verificationFor(property, owner, buyer, 'pending');

    const res = await deleteAccount(cookies);

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 250));
    assert.equal(res.body.retainedListings, 1, 'the user must be told a listing was kept');
    assert.ok(await M('Property').findById(property._id), 'the deal evidence survives');
    assert.equal(await M('User').findById(owner._id), null, 'the account still goes');
  });

  await t.test('the password gate still runs before anything is destroyed', async () => {
    const { owner, cookies } = await ownerWithSession(api);
    const property = await makeProperty(owner);

    const res = await withClient(api.delete('/api/users/me'), { cookies })
      .send({ password: 'WrongPassword!99' });

    assert.equal(res.status, 401);
    assert.ok(await M('User').findById(owner._id), 'the account survives');
    assert.ok(await M('Property').findById(property._id), 'and so does everything under it');
  });
});
