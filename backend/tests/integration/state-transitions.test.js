/**
 * Suite 15: lifecycle state transitions.
 *
 * Audited every status enum in the 31 models in one pass. Most are already
 * guarded: ProjectBooking has a real transition table, TransactionVerification
 * refuses anything but `pending`, Property refuses a second close-deal on a
 * sold or rented listing, and CampaignMember was fixed in b14ecf1. Three
 * defects were left, and this file covers all three.
 *
 * 1. LEAD HAD NO TRANSITION VALIDATION ON EITHER PATH.
 *    `updateLeadStatus` (owner) checked enum membership only. Its admin twin,
 *    `updateAdminLeadStatus`, had no whitelist at all and assigned
 *    `lead.status` straight from the request. Neither read the current status,
 *    so every state was reachable from every other one: `converted → new`
 *    erased the record of a closed deal, and `lost → converted` turned a dead
 *    enquiry into a conversion statistic.
 *
 * 2. THE DEAL FLOW NEVER WROTE `Lead.status = "converted"`.
 *    Nothing did, anywhere. So `conversionRate` measured a field owners set by
 *    hand rather than deals that actually closed.
 *
 * 3. `expired` WAS NEVER SET ON A CAMPAIGN.
 *    It has been in the enum since the model was written. A campaign past its
 *    end date stayed `active` in every listing, and the only thing stopping a
 *    join was a date check inside `joinCampaign`.
 *
 * Deliberately NOT changed here, and why:
 *   - Lead moves freely among its working states. Pipelines go backwards for
 *     real reasons and forbidding that protects nothing.
 *   - An approved TransactionVerification has no correction path. Adding one
 *     needs a policy for a reward that may already have been claimed.
 *   - Campaign paused/cancelled transitions need the refund decision first.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, withClient } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import {
  adminWithSession, asAdmin, ownerWithSession, buyerWithSession, makeProperty, makeLead,
} from './setup/factories.js';
import { LEAD_TRANSITIONS } from '../../utils/leadState.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const M = (n) => mongoose.model(n);

const ownerSetsStatus = (session, leadId, status) =>
  withClient(api.put(`/api/leads/${leadId}/status`), session).send({ status });

const adminSetsStatus = (session, leadId, status) =>
  asAdmin(api.put(`/api/admin/leads/${leadId}`), session).send({ status });

async function leadInState(state) {
  const { owner, cookies } = await ownerWithSession(api);
  const { buyer } = await buyerWithSession(api);
  const property = await makeProperty(owner);
  const lead = await makeLead(property, buyer, { propertyOwner: owner._id, status: state });
  return { owner, cookies, buyer, property, lead };
}

const statusOf = async (id) => (await M('Lead').findById(id).lean()).status;

// ---------------------------------------------------------------------------

test('a converted lead is terminal', async (t) => {
  await t.test('the owner cannot move it back to new', async () => {
    const { cookies, lead } = await leadInState('converted');

    const res = await ownerSetsStatus({ cookies }, lead._id, 'new');

    assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 200));
    assert.equal(res.body.code, 'ILLEGAL_LEAD_TRANSITION');
    assert.equal(await statusOf(lead._id), 'converted', 'a closed deal must not be erased');
  });

  await t.test('an admin cannot either', async () => {
    // The admin path had no whitelist at all, so it was the wider hole.
    const admin = await adminWithSession(api, { permissions: ['leads:update'] });
    const { lead } = await leadInState('converted');

    const res = await adminSetsStatus(admin, lead._id, 'lost');

    assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 200));
    assert.equal(await statusOf(lead._id), 'converted');
  });

  await t.test('resubmitting the same status is a no-op, not an error', async () => {
    const { cookies, lead } = await leadInState('converted');
    const res = await ownerSetsStatus({ cookies }, lead._id, 'converted');
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
  });
});

// ---------------------------------------------------------------------------

test('a lost lead reopens, but does not become a conversion', async (t) => {
  await t.test('lost cannot jump straight to converted', async () => {
    const { cookies, lead } = await leadInState('lost');

    const res = await ownerSetsStatus({ cookies }, lead._id, 'converted');

    assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 200));
    assert.equal(await statusOf(lead._id), 'lost');
  });

  await t.test('lost can reopen to contacted', async () => {
    const { cookies, lead } = await leadInState('lost');

    const res = await ownerSetsStatus({ cookies }, lead._id, 'contacted');

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal(await statusOf(lead._id), 'contacted');
  });
});

// ---------------------------------------------------------------------------

test('the working states still move freely', async (t) => {
  // Pipelines go backwards for real reasons. Over-constraining this generates
  // support tickets and protects nothing.
  for (const [from, to] of [
    ['new', 'contacted'], ['contacted', 'interested'], ['interested', 'negotiating'],
    ['negotiating', 'contacted'], ['interested', 'new'], ['negotiating', 'converted'],
    ['new', 'lost'],
  ]) {
    await t.test(`${from} → ${to} is allowed`, async () => {
      const { cookies, lead } = await leadInState(from);
      const res = await ownerSetsStatus({ cookies }, lead._id, to);
      assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
      assert.equal(await statusOf(lead._id), to);
    });
  }

  await t.test('a value outside the enum is a 400, not a 409', async () => {
    const { cookies, lead } = await leadInState('new');
    const res = await ownerSetsStatus({ cookies }, lead._id, 'definitely_not_a_status');
    assert.equal(res.status, 400);
  });

  await t.test('the table has an entry for every status', () => {
    const statuses = M('Lead').schema.path('status').enumValues;
    for (const s of statuses) {
      assert.ok(LEAD_TRANSITIONS[s], `no transition rule for "${s}"`);
    }
  });
});

// ---------------------------------------------------------------------------

test('approving a deal converts the lead', async (t) => {
  async function pendingVerification() {
    const admin = await adminWithSession(api);
    const { owner } = await ownerWithSession(api);
    const { buyer } = await buyerWithSession(api);
    const property = await makeProperty(owner, { status: 'pending_verification' });
    const lead = await makeLead(property, buyer, { propertyOwner: owner._id, status: 'negotiating' });
    const verification = await M('TransactionVerification').create({
      property: property._id, owner: owner._id, buyer: buyer._id,
      closingType: 'sold', status: 'pending',
      documentUrls: ['https://res.cloudinary.com/demo/proof.pdf'],
    });
    return { admin, owner, buyer, property, lead, verification };
  }

  await t.test('the buyer\'s lead becomes converted on approval', async () => {
    // Nothing wrote this status before, from anywhere, so conversionRate
    // measured a field owners set by hand.
    const { admin, lead, verification } = await pendingVerification();

    const res = await asAdmin(
      api.post(`/api/admin/verifications/${verification._id}/approve`), admin
    ).send({ adminNotes: 'verified' });

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    assert.equal(await statusOf(lead._id), 'converted');
  });

  await t.test('a lost lead is still converted by an approved deal', async () => {
    // The system write bypasses the table on purpose. An approved verification
    // is the authoritative record that the property changed hands, so a lead
    // sitting in `lost` is stale data rather than a veto.
    const { admin, buyer, property, verification } = await pendingVerification();
    const lead = await M('Lead').findOneAndUpdate(
      { user: buyer._id, property: property._id }, { status: 'lost' }, { new: true }
    );

    await asAdmin(api.post(`/api/admin/verifications/${verification._id}/approve`), admin).send({});

    assert.equal(await statusOf(lead._id), 'converted');
  });

  await t.test('another buyer\'s lead on the same property is untouched', async () => {
    const { admin, property, verification } = await pendingVerification();
    const other = await buyerWithSession(api);
    const otherLead = await makeLead(property, other.buyer, {
      propertyOwner: property.owner, status: 'interested',
    });

    await asAdmin(api.post(`/api/admin/verifications/${verification._id}/approve`), admin).send({});

    assert.equal(await statusOf(otherLead._id), 'interested', 'only the deal buyer converts');
  });

  await t.test('rejecting a verification converts nothing', async () => {
    const { admin, lead, verification } = await pendingVerification();

    await asAdmin(
      api.post(`/api/admin/verifications/${verification._id}/reject`), admin
    ).send({ adminNotes: 'documents unclear' });

    assert.equal(await statusOf(lead._id), 'negotiating');
  });
});

// ---------------------------------------------------------------------------

test('a campaign past its end date reports itself expired', async (t) => {
  async function campaignEnding(endDate, status = 'active') {
    const admin = await adminWithSession(api);
    const builder = await M('Builder').create({
      name: 'Expiry Builder', phone: `95555${String(Math.floor(Math.random() * 90000) + 10000)}`,
      email: `expiry-${Date.now()}@example.invalid`, createdBy: admin.admin._id,
    });
    const project = await M('Project').create({ name: 'Expiry Project', builder: builder._id, createdBy: admin.admin._id });
    const unitType = await M('UnitType').create({ project: project._id, builder: builder._id, createdBy: admin.admin._id });
    const campaign = await M('GroupBuyCampaign').create({
      unitType: unitType._id, project: project._id, builder: builder._id, createdBy: admin.admin._id,
      basics: { name: 'Expiry Campaign' }, buyerTargets: { minBuyers: 5 },
      duration: { startDate: new Date('2020-01-01'), endDate }, discountPerBuyer: 50000, status,
    });
    return { admin, unitType, project, campaign };
  }

  const PAST = new Date('2020-06-01');
  const FUTURE = new Date('2099-01-01');

  await t.test('fetching it flips active to expired', async () => {
    const { campaign } = await campaignEnding(PAST);

    const res = await api.get(`/api/campaigns/${campaign._id}`);

    assert.equal(res.status, 200);
    assert.equal(res.body.data.status, 'expired', 'the response must not report it as active');
    assert.equal((await M('GroupBuyCampaign').findById(campaign._id)).status, 'expired', 'and it must persist');
  });

  await t.test('listing by unit type expires it too', async () => {
    const { unitType, campaign } = await campaignEnding(PAST);

    const res = await api.get(`/api/campaigns/unit-type/${unitType._id}`);

    assert.equal(res.body.data[0].status, 'expired');
    assert.equal((await M('GroupBuyCampaign').findById(campaign._id)).status, 'expired');
  });

  await t.test('listing by project expires it too', async () => {
    const { project, campaign } = await campaignEnding(PAST);

    const res = await api.get(`/api/campaigns/project/${project._id}`);

    assert.equal(res.body.data[0].status, 'expired');
    assert.equal((await M('GroupBuyCampaign').findById(campaign._id)).status, 'expired');
  });

  await t.test('a campaign still running is left alone', async () => {
    const { campaign } = await campaignEnding(FUTURE);

    const res = await api.get(`/api/campaigns/${campaign._id}`);

    assert.equal(res.body.data.status, 'active');
    assert.equal((await M('GroupBuyCampaign').findById(campaign._id)).status, 'active');
  });

  for (const status of ['paused', 'completed', 'cancelled']) {
    await t.test(`an end date passing does not override "${status}"`, async () => {
      // These are decisions somebody made. A date is not an argument against
      // them, and overwriting them would lose why the campaign stopped.
      const { campaign } = await campaignEnding(PAST, status);

      const res = await api.get(`/api/campaigns/${campaign._id}`);

      assert.equal(res.body.data.status, status);
      assert.equal((await M('GroupBuyCampaign').findById(campaign._id)).status, status);
    });
  }

  await t.test('an expired campaign cannot be joined', async () => {
    const { campaign } = await campaignEnding(PAST);
    const { cookies } = await buyerWithSession(api);

    await api.get(`/api/campaigns/${campaign._id}`); // trigger the expiry

    const res = await withClient(api.post(`/api/campaigns/${campaign._id}/join`), { cookies }).send({});
    assert.equal(res.status, 400, JSON.stringify(res.body).slice(0, 200));
  });
});
