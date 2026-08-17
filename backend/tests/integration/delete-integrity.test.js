/**
 * Suite 13: refusal guards on the builder chain.
 *
 * Two verified holes, both narrower than the audit claimed. The chain is
 * already defended: a builder is soft-deleted and refuses when approved
 * properties exist, a project refuses when unit types exist, a unit type
 * refuses when campaigns are active. What follows are the two gaps in that
 * defence, not the absence of one.
 *
 * HOLE 1 — the unit type guard counts the wrong thing.
 *
 * `UnitType.activeCampaignCount` is a DENORMALISED counter that only counts
 * campaigns in state `active`. A campaign that has completed still owns its
 * `CampaignMember` documents, including members at `tokenStatus: paid`, and
 * those members paid by UPI with the reference and screenshot stored on the
 * document. There is no payment gateway behind any of this: that reference and
 * that screenshot ARE the receipt. So a completed campaign leaves the counter
 * at zero, the unit type deletes cleanly, and the money evidence is stranded
 * with nothing pointing at it.
 *
 * Being denormalised, the counter can also simply be wrong. A safety check
 * that trusts a cached number is not a safety check, so every guard here reads
 * `countDocuments` and the tests below deliberately set the counter to lie in
 * both directions.
 *
 * HOLE 2 — `ProjectBooking` is a barrier to nothing.
 *
 * It references Project, UnitType and Builder and carries the UTR number and
 * the payment screenshot, and no delete path has ever consulted it. A project
 * with zero unit types but live bookings passes the existing guard.
 *
 * Refusal, not cascade. Deleting is irreversible and these documents are
 * payment evidence; refusing is a 409 someone can act on.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { adminWithSession, asAdmin, makeBuyer } from './setup/factories.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const M = (n) => mongoose.model(n);

/**
 * A builder, project and unit type, wired together.
 *
 * Built through the models rather than the API because the API path needs an
 * admin session per step and what is under test is the delete guard, not the
 * create flow.
 */
async function makeChain(adminId) {
  const builder = await M('Builder').create({
    name: 'Test Builder', phone: '9999900000', createdBy: adminId,
  });
  const project = await M('Project').create({
    name: 'Test Project', builder: builder._id, createdBy: adminId,
  });
  const unitType = await M('UnitType').create({
    name: '2 BHK', project: project._id, builder: builder._id, createdBy: adminId,
  });
  return { builder, project, unitType };
}

async function makeCampaign(chain, adminId, overrides = {}) {
  return M('GroupBuyCampaign').create({
    unitType: chain.unitType._id,
    project: chain.project._id,
    builder: chain.builder._id,
    createdBy: adminId,
    basics: { name: 'Test Campaign' },
    buyerTargets: { minBuyers: 5 },
    duration: { startDate: new Date('2026-01-01'), endDate: new Date('2026-12-31') },
    discountPerBuyer: 50000,
    ...overrides,
  });
}

async function makeBooking(chain, overrides = {}) {
  return M('ProjectBooking').create({
    project: chain.project._id,
    unitType: chain.unitType._id,
    builder: chain.builder._id,
    clientName: 'Test Client',
    clientPhone: '9999911111',
    ...overrides,
  });
}

const del = (session, path) => asAdmin(api.delete(path), session).send();

// ---------------------------------------------------------------------------

test('unit type deletion refuses when a campaign exists, in any state', async (t) => {
  for (const status of ['active', 'paused', 'completed', 'expired', 'cancelled']) {
    await t.test(`a ${status} campaign blocks deletion`, async () => {
      const session = await adminWithSession(api);
      const chain = await makeChain(session.admin._id);
      await makeCampaign(chain, session.admin._id, { status });

      const res = await del(session, `/api/unit-types/${chain.unitType._id}`);

      assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 200));
      assert.equal(res.body.code, 'DELETE_BLOCKED_DEPENDENTS');
      assert.ok(await M('UnitType').findById(chain.unitType._id), 'the unit type must survive');
    });
  }
});

// ---------------------------------------------------------------------------

test('unit type deletion refuses when money is at stake', async (t) => {
  await t.test('a paid campaign member blocks deletion even though the campaign completed', async () => {
    // The exact hole. A completed campaign leaves activeCampaignCount at 0, so
    // the old guard let this through and stranded the payment evidence.
    const session = await adminWithSession(api);
    const chain = await makeChain(session.admin._id);
    const campaign = await makeCampaign(chain, session.admin._id, { status: 'completed' });
    const buyer = await makeBuyer();

    await M('CampaignMember').create({
      campaign: campaign._id,
      user: buyer._id,
      tokenStatus: 'paid',
      paymentReference: 'UPI-TXN-123456',
      paymentProofUrl: 'https://res.cloudinary.com/demo/proof.png',
    });

    const res = await del(session, `/api/unit-types/${chain.unitType._id}`);

    assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 200));
    assert.ok(await M('CampaignMember').findOne({ campaign: campaign._id }), 'payment evidence must survive');
  });

  await t.test('the refusal names money rather than just counting dependents', async () => {
    const session = await adminWithSession(api);
    const chain = await makeChain(session.admin._id);
    const campaign = await makeCampaign(chain, session.admin._id, { status: 'completed' });
    const buyer = await makeBuyer();
    await M('CampaignMember').create({ campaign: campaign._id, user: buyer._id, tokenStatus: 'paid' });

    const res = await del(session, `/api/unit-types/${chain.unitType._id}`);
    assert.match(res.body.message, /paid/i, 'an operator should learn that money is the reason');
  });
});

// ---------------------------------------------------------------------------

test('unit type deletion refuses when a live booking exists', async (t) => {
  for (const status of ['enquiry', 'payment_submitted', 'confirmed', 'completed']) {
    await t.test(`a ${status} booking blocks deletion`, async () => {
      const session = await adminWithSession(api);
      const chain = await makeChain(session.admin._id);
      await makeBooking(chain, { status });

      const res = await del(session, `/api/unit-types/${chain.unitType._id}`);
      assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 200));
    });
  }

  await t.test('a cancelled booking does not block deletion', async () => {
    // Cancelled is the one state with no live obligation behind it. If this
    // blocked too, the guard would be "never delete anything", which is not a
    // policy, it is an outage.
    const session = await adminWithSession(api);
    const chain = await makeChain(session.admin._id);
    await makeBooking(chain, { status: 'cancelled' });

    const res = await del(session, `/api/unit-types/${chain.unitType._id}`);
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
  });
});

// ---------------------------------------------------------------------------

test('project deletion refuses when a live booking exists', async (t) => {
  await t.test('a booking blocks deletion even with no unit types left', async () => {
    // The existing guard only counts unit types. Remove them and a project with
    // live bookings deleted clean, taking the UTR numbers with it.
    const session = await adminWithSession(api);
    const chain = await makeChain(session.admin._id);
    await makeBooking(chain, { status: 'confirmed' });
    await M('UnitType').deleteOne({ _id: chain.unitType._id });

    const res = await del(session, `/api/projects/${chain.project._id}`);

    assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.code, 'DELETE_BLOCKED_DEPENDENTS');
    assert.ok(await M('Project').findById(chain.project._id));
  });

  await t.test('the existing unit-type guard still works', async () => {
    const session = await adminWithSession(api);
    const chain = await makeChain(session.admin._id);

    const res = await del(session, `/api/projects/${chain.project._id}`);
    assert.equal(res.status, 400, 'the pre-existing guard and its status code are unchanged');
    assert.match(res.body.message, /unit type/i);
  });

  await t.test('a cancelled booking does not block deletion', async () => {
    const session = await adminWithSession(api);
    const chain = await makeChain(session.admin._id);
    await makeBooking(chain, { status: 'cancelled' });
    await M('UnitType').deleteOne({ _id: chain.unitType._id });

    const res = await del(session, `/api/projects/${chain.project._id}`);
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
  });
});

// ---------------------------------------------------------------------------

test('a clean delete still succeeds', async (t) => {
  await t.test('a unit type with no dependents deletes', async () => {
    const session = await adminWithSession(api);
    const chain = await makeChain(session.admin._id);

    const res = await del(session, `/api/unit-types/${chain.unitType._id}`);

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal(await M('UnitType').findById(chain.unitType._id), null);
  });

  await t.test('the parent project unit-type counter is still decremented', async () => {
    // Existing behaviour that the new guard must not displace.
    const session = await adminWithSession(api);
    const chain = await makeChain(session.admin._id);
    await M('Project').findByIdAndUpdate(chain.project._id, { unitTypeCount: 1 });

    await del(session, `/api/unit-types/${chain.unitType._id}`);

    const project = await M('Project').findById(chain.project._id);
    assert.equal(project.unitTypeCount, 0);
  });

  await t.test('a project with no unit types and no bookings deletes', async () => {
    const session = await adminWithSession(api);
    const chain = await makeChain(session.admin._id);
    await M('UnitType').deleteOne({ _id: chain.unitType._id });

    const res = await del(session, `/api/projects/${chain.project._id}`);
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
  });
});

// ---------------------------------------------------------------------------

test('denormalised counters are irrelevant to the safety decision', async (t) => {
  await t.test('a counter reading zero does not permit deletion when a campaign exists', async () => {
    // The failure mode in production: the counter says nothing is there and a
    // campaign is. The guard must believe the collection, not the cache.
    const session = await adminWithSession(api);
    const chain = await makeChain(session.admin._id);
    await makeCampaign(chain, session.admin._id, { status: 'active' });
    await M('UnitType').findByIdAndUpdate(chain.unitType._id, { activeCampaignCount: 0 });

    const res = await del(session, `/api/unit-types/${chain.unitType._id}`);

    assert.equal(res.status, 409, 'the guard trusted a stale counter over the data');
    assert.ok(await M('GroupBuyCampaign').findOne({ unitType: chain.unitType._id }));
  });

  await t.test('a counter reading high does not block deletion when nothing is there', async () => {
    // The inverse. A guard keyed on a drifted counter refuses forever and the
    // only fix is a database edit, which is its own kind of outage.
    const session = await adminWithSession(api);
    const chain = await makeChain(session.admin._id);
    await M('UnitType').findByIdAndUpdate(chain.unitType._id, { activeCampaignCount: 7 });

    const res = await del(session, `/api/unit-types/${chain.unitType._id}`);

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal(await M('UnitType').findById(chain.unitType._id), null);
  });

  await t.test('the project guard counts unit types rather than reading unitTypeCount', async () => {
    const session = await adminWithSession(api);
    const chain = await makeChain(session.admin._id);
    await M('Project').findByIdAndUpdate(chain.project._id, { unitTypeCount: 0 });

    const res = await del(session, `/api/projects/${chain.project._id}`);
    assert.notEqual(res.status, 200, 'a real unit type exists; the cached zero must not permit deletion');
  });
});
