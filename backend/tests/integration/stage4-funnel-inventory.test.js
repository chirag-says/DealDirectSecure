/**
 * Stage 4 — demand capture and inventory integrity.
 *
 *   1. ENQUIRE. The only buyer CTA on a project opened with a QR code and a
 *      demand for money. Seven projects have produced zero bookings. An
 *      enquiry now creates the same ProjectBooking with source:"enquiry" and
 *      no payment framing.
 *   2. PIPELINE. ProjectBooking gains contactHistory[] and assignedTo, so an
 *      admin can record a call and own a lead — adminNotes was a single
 *      overwrite-prone string.
 *   3. INVENTORY. The invariant is enforced on every writer, and admin
 *      corrections become deltas with a reason instead of blind overwrites.
 *   4. LEGACY STRATUM. Interest on a builder-feed property created no lead and
 *      notified nobody; the tap went nowhere. It is refused, with a pointer to
 *      the projects vertical where those listings now live.
 *   5. VIEWS. Project had no view counter at all, so nothing could distinguish
 *      "nobody looks" from "people look and do not enquire".
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, uniqueClientIp } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import {
  makeUser, makeOwner, makeProperty, adminWithSession, asAdmin,
  seedTaxonomy, TEST_PASSWORD,
} from './setup/factories.js';

import {
  inventoryProblems, applyInventoryDelta, InventoryError,
} from '../../utils/inventoryInvariant.js';

let api;
test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); await seedTaxonomy(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const M = (n) => mongoose.model(n);
const ORIGIN = 'http://localhost:3000';

async function loginUser() {
  const user = await makeUser({ role: 'user' });
  const res = await api.post('/api/users/login')
    .set('X-Forwarded-For', uniqueClientIp())
    .send({ email: user.email, password: TEST_PASSWORD });
  assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 150));
  const jar = (res.headers['set-cookie'] || []).map((c) => c.split(';')[0]);
  const csrf = decodeURIComponent((jar.join('; ').match(/csrf_token=([^;]+)/) || [])[1] || '');
  return { user, cookie: jar.join('; '), csrf };
}

const guarded = (path, s) =>
  api.post(path).set('X-Forwarded-For', uniqueClientIp())
    .set('Cookie', s.cookie).set('Origin', ORIGIN).set('X-CSRF-Token', s.csrf);

async function makeChain(unitOverrides = {}) {
  const builder = await M('Builder').create({
    name: 'B', phone: `9${String(Date.now()).slice(-9)}`, isActive: true,
  });
  const admin = await M('Admin').collection.insertOne({
    name: 'S', email: `s-${Date.now()}-${process.hrtime()[1]}@example.com`, createdAt: new Date(),
  });
  const project = await M('Project').create({
    builder: builder._id, createdBy: admin.insertedId,
    basics: { name: 'P', category: 'Residential' }, location: { city: 'Pune' },
  });
  const unitType = await M('UnitType').create({
    project: project._id, builder: builder._id, createdBy: admin.insertedId,
    config: { name: '2 BHK' }, area: { carpetSqft: 900 },
    pricing: { basePrice: 5_000_000 },
    inventory: { totalUnits: 10, availableUnits: 10, bookedUnits: 0, blockedUnits: 0 },
    paymentTerms: { bookingAmount: 50_000 },
    ...unitOverrides,
  });
  return { builder, project, unitType };
}

// ---------------------------------------------------------------------------
// 1. Enquire
// ---------------------------------------------------------------------------

test('a buyer can enquire without being asked for money', async (t) => {
  const body = (project, unitType, extra = {}) => ({
    projectId: String(project._id), unitTypeId: String(unitType._id),
    clientName: 'Buyer', clientPhone: '9876543210', ...extra,
  });

  await t.test('an enquiry is created and marked as one', async () => {
    const { project, unitType } = await makeChain();
    const s = await loginUser();

    const res = await guarded('/api/bookings', s).send(body(project, unitType, { intent: 'enquiry' }));
    assert.equal(res.status, 201, JSON.stringify(res.body).slice(0, 200));

    const doc = await M('ProjectBooking').findById(res.body.data.bookingId).lean();
    assert.equal(doc.source, 'enquiry');
    assert.equal(doc.status, 'enquiry');
  });

  await t.test('a booking is still marked as a booking', async () => {
    const { project, unitType } = await makeChain();
    const s = await loginUser();
    const res = await guarded('/api/bookings', s).send(body(project, unitType));
    const doc = await M('ProjectBooking').findById(res.body.data.bookingId).lean();
    assert.equal(doc.source, 'booking', 'the default source changed');
  });

  await t.test('an enquiry does NOT require a configured booking amount', async () => {
    // The whole point: asking a question must not be gated on the thing that
    // gates paying. 3 of 8 real unit types have no booking amount, and those
    // are exactly the ones an admin most needs to hear demand about.
    const { project, unitType } = await makeChain({ paymentTerms: {} });
    const s = await loginUser();

    const res = await guarded('/api/bookings', s).send(body(project, unitType, { intent: 'enquiry' }));
    assert.equal(res.status, 201,
      `an enquiry was refused for an unpriced unit: ${JSON.stringify(res.body).slice(0, 200)}`);
  });

  await t.test('but a BOOKING still is', async () => {
    const { project, unitType } = await makeChain({ paymentTerms: {} });
    const s = await loginUser();
    const res = await guarded('/api/bookings', s).send(body(project, unitType));
    assert.equal(res.status, 400, 'the ₹0-token guard was weakened by the enquiry path');
  });

  await t.test('an enquiry still respects sold-out inventory', async () => {
    const { project, unitType } = await makeChain({
      inventory: { totalUnits: 5, availableUnits: 0, bookedUnits: 5, blockedUnits: 0 },
    });
    const s = await loginUser();
    const res = await guarded('/api/bookings', s).send(body(project, unitType, { intent: 'enquiry' }));
    assert.equal(res.status, 400);
  });
});

// ---------------------------------------------------------------------------
// 2. Pipeline: contact history and ownership
// ---------------------------------------------------------------------------

test('an admin can work an enquiry like a lead', async (t) => {
  async function anEnquiry() {
    const { project, unitType } = await makeChain();
    const s = await loginUser();
    const res = await guarded('/api/bookings', s).send({
      projectId: String(project._id), unitTypeId: String(unitType._id),
      clientName: 'Buyer', clientPhone: '9876543210', intent: 'enquiry',
    });
    return res.body.data.bookingId;
  }

  await t.test('a contact attempt is recorded', async () => {
    const id = await anEnquiry();
    const admin = await adminWithSession(api);

    const res = await asAdmin(api.post(`/api/bookings/${id}/contact`), admin)
      .send({ action: 'called', note: 'no answer, will retry' });
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));

    const doc = await M('ProjectBooking').findById(id).lean();
    assert.equal(doc.contactHistory.length, 1);
    assert.equal(doc.contactHistory[0].action, 'called');
    assert.equal(doc.contactHistory[0].note, 'no answer, will retry');
    assert.ok(doc.contactHistory[0].by, 'the admin who called was not recorded');
  });

  await t.test('THE DEFECT: history accumulates, it does not overwrite', async () => {
    // adminNotes was one mutable string; each verification cycle destroyed the
    // previous note.
    const id = await anEnquiry();
    const admin = await adminWithSession(api);

    for (const note of ['first call', 'second call', 'third call']) {
      await asAdmin(api.post(`/api/bookings/${id}/contact`), admin)
        .send({ action: 'called', note });
    }

    const doc = await M('ProjectBooking').findById(id).lean();
    assert.equal(doc.contactHistory.length, 3, 'contact history is overwriting itself');
    assert.deepEqual(doc.contactHistory.map((c) => c.note),
      ['first call', 'second call', 'third call']);
  });

  await t.test('an empty contact record is refused', async () => {
    // A history entry with no note records that someone clicked a button, not
    // that anything happened. Found by mutation testing — nothing covered it.
    const id = await anEnquiry();
    const admin = await adminWithSession(api);

    for (const body of [{ action: 'called' }, { action: 'called', note: '   ' }]) {
      const res = await asAdmin(api.post(`/api/bookings/${id}/contact`), admin).send(body);
      assert.equal(res.status, 400, `an empty contact note was accepted (${res.status})`);
    }
    assert.equal((await M('ProjectBooking').findById(id).lean()).contactHistory.length, 0);
  });

  await t.test('an unknown action is refused', async () => {
    const id = await anEnquiry();
    const admin = await adminWithSession(api);
    const res = await asAdmin(api.post(`/api/bookings/${id}/contact`), admin)
      .send({ action: 'telepathy', note: 'thought about them' });
    assert.equal(res.status, 400);
  });

  await t.test('assigning to an admin that does not exist is refused', async () => {
    // Otherwise the queue shows an owner who cannot be contacted, and the
    // populate silently yields null. Also found by mutation testing.
    const id = await anEnquiry();
    const admin = await adminWithSession(api);

    const res = await asAdmin(api.put(`/api/bookings/${id}/assign`), admin)
      .send({ adminId: new mongoose.Types.ObjectId().toString() });
    assert.equal(res.status, 400, `assigned to a non-existent admin (${res.status})`);
    assert.equal((await M('ProjectBooking').findById(id).lean()).assignedTo, null);
  });

  await t.test('an enquiry can be assigned to an admin', async () => {
    const id = await anEnquiry();
    const admin = await adminWithSession(api);

    const res = await asAdmin(api.put(`/api/bookings/${id}/assign`), admin)
      .send({ adminId: String(admin.admin._id) });
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal(
      String((await M('ProjectBooking').findById(id).lean()).assignedTo),
      String(admin.admin._id)
    );
  });

  await t.test('assignment can be cleared', async () => {
    const id = await anEnquiry();
    const admin = await adminWithSession(api);
    await asAdmin(api.put(`/api/bookings/${id}/assign`), admin)
      .send({ adminId: String(admin.admin._id) });

    await asAdmin(api.put(`/api/bookings/${id}/assign`), admin).send({ adminId: null });
    assert.equal((await M('ProjectBooking').findById(id).lean()).assignedTo, null);
  });

  await t.test('a user cannot write contact history', async () => {
    const id = await anEnquiry();
    const s = await loginUser();
    const res = await guarded(`/api/bookings/${id}/contact`, s)
      .send({ action: 'called', note: 'I called myself' });
    assert.ok([401, 403].includes(res.status), `a buyer wrote to the admin pipeline (${res.status})`);
  });

  await t.test('admins can filter the queue by source', async () => {
    const { project, unitType } = await makeChain();
    const s1 = await loginUser();
    const s2 = await loginUser();
    await guarded('/api/bookings', s1).send({
      projectId: String(project._id), unitTypeId: String(unitType._id),
      clientName: 'A', clientPhone: '9876543210', intent: 'enquiry',
    });
    await guarded('/api/bookings', s2).send({
      projectId: String(project._id), unitTypeId: String(unitType._id),
      clientName: 'B', clientPhone: '9876543211',
    });

    const admin = await adminWithSession(api);
    const res = await asAdmin(api.get('/api/bookings?source=enquiry'), admin);
    assert.equal(res.status, 200);
    assert.equal(res.body.data.length, 1, 'the source filter does not work');
    assert.equal(res.body.data[0].source, 'enquiry');
  });
});

// ---------------------------------------------------------------------------
// 3. Inventory
// ---------------------------------------------------------------------------

test('the inventory invariant', async (t) => {
  await t.test('a balanced inventory is valid', () => {
    assert.deepEqual(
      inventoryProblems({ totalUnits: 10, availableUnits: 7, bookedUnits: 2, blockedUnits: 1 }), []
    );
  });

  await t.test('an unbalanced one is not', () => {
    const p = inventoryProblems({ totalUnits: 10, availableUnits: 9, bookedUnits: 5, blockedUnits: 0 });
    assert.equal(p.length > 0, true);
    assert.match(p.join(' '), /does not match totalUnits/);
  });

  await t.test('negative values are rejected', () => {
    assert.ok(inventoryProblems({ totalUnits: 10, availableUnits: -1 }).length > 0);
  });

  await t.test('an unconfigured unit type is a draft, not an error', () => {
    // The publish gate refuses to SELL it; arithmetic has nothing to say.
    assert.deepEqual(inventoryProblems({}), []);
  });

  await t.test('a tower split cannot exceed the total', () => {
    const p = inventoryProblems({
      totalUnits: 10, availableUnits: 10,
      towerAllocation: [{ tower: 'A', units: 6 }, { tower: 'B', units: 6 }],
    });
    assert.match(p.join(' '), /allocates 12 units but only 10/);
  });

  await t.test('duplicate tower names are rejected', () => {
    const p = inventoryProblems({
      totalUnits: 10, availableUnits: 10,
      towerAllocation: [{ tower: 'A', units: 4 }, { tower: 'a', units: 4 }],
    });
    assert.match(p.join(' '), /more than once/);
  });

  await t.test('more towers than the project declares is rejected', () => {
    const p = inventoryProblems({
      totalUnits: 10, availableUnits: 10,
      towerAllocation: [{ tower: 'A', units: 5 }, { tower: 'B', units: 5 }],
    }, { totalTowers: 1 });
    assert.match(p.join(' '), /project declares 1/);
  });
});

test('inventory corrections are deltas, not overwrites', async (t) => {
  const base = { totalUnits: 10, availableUnits: 7, bookedUnits: 2, blockedUnits: 1 };

  await t.test('blocking a unit TAKES IT OUT of available', () => {
    // The design point. An isolated increment can never keep the books
    // balanced — holding a unit back does not conjure an eleventh unit.
    const { inventory } = applyInventoryDelta(base, { field: 'blockedUnits', delta: 1 });
    assert.equal(inventory.blockedUnits, 2);
    assert.equal(inventory.availableUnits, 6, 'blocking did not come out of available');
    assert.equal(inventory.totalUnits, 10, 'blocking changed the total');
    assert.deepEqual(inventoryProblems(inventory), []);
  });

  await t.test('releasing a held unit puts it back', () => {
    const { inventory } = applyInventoryDelta(base, { field: 'blockedUnits', delta: -1 });
    assert.equal(inventory.blockedUnits, 0);
    assert.equal(inventory.availableUnits, 8);
    assert.deepEqual(inventoryProblems(inventory), []);
  });

  await t.test('correcting a booked miscount transfers, it does not invent stock', () => {
    const { inventory } = applyInventoryDelta(base, { field: 'bookedUnits', delta: -1 });
    assert.equal(inventory.bookedUnits, 1);
    assert.equal(inventory.availableUnits, 8);
    assert.equal(inventory.totalUnits, 10);
    assert.deepEqual(inventoryProblems(inventory), []);
  });

  await t.test('adding stock lands in available', () => {
    // "We got two more units" means two more SELLABLE units.
    const { inventory } = applyInventoryDelta(base, { field: 'totalUnits', delta: 2 });
    assert.equal(inventory.totalUnits, 12);
    assert.equal(inventory.availableUnits, 9);
    assert.deepEqual(inventoryProblems(inventory), []);
  });

  await t.test('units sold elsewhere leave the project entirely', () => {
    // The builder's other channels: those units are gone, not merely off-market.
    const { inventory } = applyInventoryDelta(base, { field: 'availableUnits', delta: -3 });
    assert.equal(inventory.availableUnits, 4);
    assert.equal(inventory.totalUnits, 7);
    assert.deepEqual(inventoryProblems(inventory), []);
  });

  await t.test('a delta that would go negative is refused', () => {
    assert.throws(
      () => applyInventoryDelta(base, { field: 'bookedUnits', delta: -5 }),
      (e) => e instanceof InventoryError && e.code === 'INVENTORY_NEGATIVE'
    );
  });

  await t.test('and so is one whose COUNTERPART would go negative', () => {
    // Blocking eight units when only seven are available.
    assert.throws(
      () => applyInventoryDelta(base, { field: 'blockedUnits', delta: 8 }),
      (e) => e instanceof InventoryError && e.code === 'INVENTORY_NEGATIVE'
    );
  });

  await t.test('every result satisfies the invariant, by construction', () => {
    // The property that matters more than any single case.
    for (const field of ['totalUnits', 'availableUnits', 'bookedUnits', 'blockedUnits']) {
      for (const delta of [-1, 1, 2]) {
        let out;
        try { out = applyInventoryDelta(base, { field, delta }); }
        catch (e) { assert.ok(e instanceof InventoryError); continue; }
        assert.deepEqual(inventoryProblems(out.inventory), [],
          `${field} ${delta > 0 ? '+' : ''}${delta} left the books unbalanced`);
      }
    }
  });

  await t.test('an unknown field is refused', () => {
    assert.throws(
      () => applyInventoryDelta(base, { field: 'somethingElse', delta: 1 }),
      (e) => e.code === 'INVENTORY_BAD_FIELD'
    );
  });

  await t.test('a zero delta is refused', () => {
    assert.throws(
      () => applyInventoryDelta(base, { field: 'blockedUnits', delta: 0 }),
      (e) => e.code === 'INVENTORY_BAD_DELTA'
    );
  });

  await t.test('adjusting an unconfigured unit type says so', () => {
    assert.throws(
      () => applyInventoryDelta({}, { field: 'availableUnits', delta: 1 }),
      (e) => e.code === 'INVENTORY_UNSET'
    );
  });
});

test('the inventory adjust endpoint', async (t) => {
  await t.test('an admin can block a unit, with a reason', async () => {
    const { unitType } = await makeChain();
    const admin = await adminWithSession(api);

    const res = await asAdmin(api.post(`/api/unit-types/${unitType._id}/inventory/adjust`), admin)
      .send({ field: 'blockedUnits', delta: 1, reason: 'held for the builder' });
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 250));

    const fresh = await M('UnitType').findById(unitType._id).lean();
    assert.equal(fresh.inventory.blockedUnits, 1);
    assert.equal(fresh.inventory.availableUnits, 9, 'blocking did not come out of available');
  });

  await t.test('a reason is required', async () => {
    const { unitType } = await makeChain();
    const admin = await adminWithSession(api);
    const res = await asAdmin(api.post(`/api/unit-types/${unitType._id}/inventory/adjust`), admin)
      .send({ field: 'blockedUnits', delta: 1 });
    assert.equal(res.status, 400, 'an unexplained inventory correction was accepted');
  });

  await t.test('and it is audited', async () => {
    const { unitType } = await makeChain();
    const admin = await adminWithSession(api);
    await asAdmin(api.post(`/api/unit-types/${unitType._id}/inventory/adjust`), admin)
      .send({ field: 'blockedUnits', delta: 1, reason: 'held for the builder' });

    const entry = await M('AuditLog').findOne({ action: 'unit_inventory_adjusted' }).lean();
    assert.ok(entry, 'an inventory correction left no audit record');
    assert.equal(entry.metadata?.reason, 'held for the builder');
  });

  await t.test('THE DEFECT: the wholesale overwrite path is gone', async () => {
    // updateUnitType used to accept an entire `inventory` object, which could
    // silently contradict the confirmed bookings the engine had counted.
    const { unitType } = await makeChain();
    const admin = await adminWithSession(api);

    await asAdmin(api.put(`/api/unit-types/${unitType._id}`), admin)
      .field('inventory', JSON.stringify({
        totalUnits: 999, availableUnits: 999, bookedUnits: 0, blockedUnits: 0,
      }));

    const fresh = await M('UnitType').findById(unitType._id).lean();
    assert.equal(fresh.inventory.totalUnits, 10,
      'inventory was overwritten wholesale through the update form');
  });
});

// ---------------------------------------------------------------------------
// 4. The legacy builder-feed stratum
// ---------------------------------------------------------------------------

test('interest on a legacy builder-feed property no longer vanishes', async (t) => {
  async function builderProperty() {
    const owner = await makeOwner();
    const builder = await M('Builder').create({
      name: 'Legacy', phone: `9${String(Date.now()).slice(-9)}`, isActive: true,
    });
    const property = await makeProperty(owner, { isApproved: true });
    // The stratum: owner cleared, builder set — excluded from every feed.
    await M('Property').updateOne(
      { _id: property._id }, { $set: { builder: builder._id }, $unset: { owner: '' } }
    );
    return property;
  }

  await t.test('THE DEFECT: it used to record the tap and tell nobody', async () => {
    const property = await builderProperty();
    const s = await loginUser();

    const res = await guarded(`/api/properties/interested/${property._id}`, s).send({});
    assert.equal(res.status, 400, `the silent void is still reachable (${res.status})`);
    assert.match(JSON.stringify(res.body), /project/i,
      'the refusal does not point the buyer anywhere');
  });

  await t.test('and no lead was created either way', async () => {
    const property = await builderProperty();
    const s = await loginUser();
    await guarded(`/api/properties/interested/${property._id}`, s).send({});
    assert.equal(await M('Lead').countDocuments({ property: property._id }), 0);
  });

  await t.test('interest on a normal owner property still works', async () => {
    // The guard must not catch the 99% case.
    const owner = await makeOwner();
    const property = await makeProperty(owner, { isApproved: true });
    const s = await loginUser();

    const res = await guarded(`/api/properties/interested/${property._id}`, s).send({});
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal(await M('Lead').countDocuments({ property: property._id }), 1,
      'the lead that should be created was not');
  });
});

// ---------------------------------------------------------------------------
// 5. Demand instrumentation
// ---------------------------------------------------------------------------

test('project views are counted', async (t) => {
  async function published() {
    const { project, unitType } = await makeChain();
    const admin = await adminWithSession(api);
    await M('Project').updateOne({ _id: project._id }, {
      $set: {
        'media.exteriorImages': ['https://res.cloudinary.com/x/a.jpg'],
        'publication.status': 'published',
      },
    });
    return { project, unitType, admin };
  }

  await t.test('a public read increments the counter', async () => {
    const { project } = await published();
    await api.get(`/api/projects/${project._id}`).set('X-Forwarded-For', uniqueClientIp());
    const fresh = await M('Project').findById(project._id).lean();
    assert.equal(fresh.views, 1, 'nothing counts project views');
  });

  await t.test('an admin preview does not', async () => {
    // Otherwise the funnel measures the team, not the market.
    const { project, admin } = await published();
    await asAdmin(api.get(`/api/projects/${project._id}`), admin);
    const fresh = await M('Project').findById(project._id).lean();
    assert.ok(!fresh.views, `admin views are inflating the counter (${fresh.views})`);
  });

  await t.test('counting never breaks the page', async () => {
    // A failed counter write must not 500 a listing.
    const { project } = await published();
    for (let i = 0; i < 3; i++) {
      const res = await api.get(`/api/projects/${project._id}`).set('X-Forwarded-For', uniqueClientIp());
      assert.equal(res.status, 200);
    }
    assert.equal((await M('Project').findById(project._id).lean()).views, 3);
  });
});
