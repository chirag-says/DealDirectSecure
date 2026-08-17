/**
 * Suite 14: CampaignMember state integrity.
 *
 * Two contradictory states were reachable, both involving money.
 *
 * DEFECT 1 — a paid member could self-exit.
 *
 * `exitCampaign` filtered on `status: "active"` and never looked at
 * `tokenStatus`. A user who had paid could exit their own campaign: the
 * membership went to `exited`, the post-save hook dropped `paidMemberCount`,
 * and the response promised "Refund (if applicable) will be processed
 * manually" while writing that obligation precisely nowhere. The resulting
 * document — `tokenStatus: paid` alongside `status: exited` — was the only
 * evidence money was owed, and nothing surfaced it.
 *
 * Under the current product policy (option C) a paid member cannot self-exit
 * at all. Support handles it. No refund record is invented here, because there
 * is no refund system yet and writing a fake one is worse than writing none.
 *
 * DEFECT 2 — the booking sync ran forward only.
 *
 * `syncBookingToCampaign` auto-enrols a user as a PAID campaign member when
 * their booking is verified or completed. Cancelling that booking restored unit
 * inventory and appended to statusHistory but never touched the member it had
 * created, so a cancelled booking left a paid member inflating
 * `paidMemberCount` forever.
 *
 * WHICH cancellations reverse, and which do not.
 *
 * A member is only ever enrolled from `confirmed` (via verifyPayment) or
 * `completed`. So cancelling out of those two states invalidates a membership
 * that exists; cancelling out of `enquiry` or `payment_submitted` invalidates
 * nothing, because nobody was enrolled. That is the same set as
 * STATUSES_HOLDING_INVENTORY, and not a coincidence: the states that hold a
 * unit are the states that made someone a paid member.
 *
 * Reversal is not a refund. It records that the membership is no longer valid
 * and stops it being counted. Whether money goes back is the booking's
 * business, and ProjectBooking is the authoritative payment record.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { readFileSync } from 'node:fs';

import { request, withClient } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { adminWithSession, asAdmin, buyerWithSession } from './setup/factories.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const M = (n) => mongoose.model(n);

let chainSeq = 0;

async function makeChain(adminId) {
  // Unique phone AND email per chain. `builders.phone_1` is unique, and
  // `builders.email_1` is deployed unique and non-sparse despite the schema
  // declaring it sparse — see the index drift recorded in
  // DEALDIRECT-REFUND-POLICY-DECISION.md §7. A test that needs two builders
  // hits both constraints.
  const n = ++chainSeq;
  const builder = await M('Builder').create({
    name: `State Builder ${n}`,
    phone: `91111${String(10000 + n).slice(-5)}`,
    email: `state-builder-${n}@example.invalid`,
    createdBy: adminId,
  });
  const project = await M('Project').create({ name: 'State Project', builder: builder._id, createdBy: adminId });
  const unitType = await M('UnitType').create({
    project: project._id, builder: builder._id, createdBy: adminId,
    inventory: { totalUnits: 10, availableUnits: 10, bookedUnits: 1 },
  });
  return { builder, project, unitType };
}

const makeCampaign = (chain, adminId, status = 'active') => M('GroupBuyCampaign').create({
  unitType: chain.unitType._id, project: chain.project._id, builder: chain.builder._id,
  createdBy: adminId,
  basics: { name: 'State Campaign' },
  buyerTargets: { minBuyers: 5 },
  duration: { startDate: new Date('2026-01-01'), endDate: new Date('2026-12-31') },
  discountPerBuyer: 50000,
  status,
});

const makeMember = (campaign, userId, overrides = {}) => M('CampaignMember').create({
  campaign: campaign._id, user: userId, status: 'active', tokenStatus: 'pending', ...overrides,
});

const makeBooking = (chain, userId, overrides = {}) => M('ProjectBooking').create({
  project: chain.project._id, unitType: chain.unitType._id, builder: chain.builder._id,
  user: userId, clientName: 'State Client', clientPhone: '9111122222',
  payment: { tokenAmount: 100000, utrNumber: 'UTR-STATE-1' },
  ...overrides,
});

const exitAs = (session, campaignId) =>
  withClient(api.post(`/api/campaigns/${campaignId}/exit`), session).send({ reason: 'changed my mind' });

const cancelBooking = (session, bookingId, note = 'cancelled by admin') =>
  asAdmin(api.put(`/api/bookings/${bookingId}/status`), session).send({ status: 'cancelled', adminNotes: note });

const reload = (id) => M('CampaignMember').findById(id).lean();
const campaignOf = (id) => M('GroupBuyCampaign').findById(id).lean();

// ---------------------------------------------------------------------------

test('self-exit is allowed only while nothing has been paid', async (t) => {
  await t.test('an unpaid active member can exit', async () => {
    const admin = await adminWithSession(api);
    const { buyer, cookies } = await buyerWithSession(api);
    const chain = await makeChain(admin.admin._id);
    const campaign = await makeCampaign(chain, admin.admin._id);
    const member = await makeMember(campaign, buyer._id, { tokenStatus: 'pending' });

    const res = await exitAs({ cookies }, campaign._id);

    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    const after = await reload(member._id);
    assert.equal(after.status, 'exited');
    assert.equal(after.tokenStatus, 'pending', 'exiting must not invent a payment state');
  });

  await t.test('a paid active member cannot self-exit', async () => {
    const admin = await adminWithSession(api);
    const { buyer, cookies } = await buyerWithSession(api);
    const chain = await makeChain(admin.admin._id);
    const campaign = await makeCampaign(chain, admin.admin._id);
    const member = await makeMember(campaign, buyer._id, {
      tokenStatus: 'paid', tokenPaidAt: new Date(), paymentReference: 'UTR-PAID-1',
    });

    const res = await exitAs({ cookies }, campaign._id);

    assert.equal(res.status, 409, JSON.stringify(res.body).slice(0, 200));

    const after = await reload(member._id);
    assert.equal(after.status, 'active', 'the membership must be untouched');
    assert.equal(after.tokenStatus, 'paid');
    assert.equal(after.exitedAt, undefined, 'no exit may be recorded');
  });

  await t.test('the refusal is typed and points at support', async () => {
    const admin = await adminWithSession(api);
    const { buyer, cookies } = await buyerWithSession(api);
    const chain = await makeChain(admin.admin._id);
    const campaign = await makeCampaign(chain, admin.admin._id);
    await makeMember(campaign, buyer._id, { tokenStatus: 'paid' });

    const res = await exitAs({ cookies }, campaign._id);

    assert.equal(res.body.code, 'CAMPAIGN_MEMBER_PAYMENT_PROTECTED');
    assert.match(res.body.message, /support|admin/i, 'the user needs to know who can help');
  });

  await t.test('the paid-member count is not disturbed by a refused exit', async () => {
    const admin = await adminWithSession(api);
    const { buyer, cookies } = await buyerWithSession(api);
    const chain = await makeChain(admin.admin._id);
    const campaign = await makeCampaign(chain, admin.admin._id);
    await makeMember(campaign, buyer._id, { tokenStatus: 'paid' });

    await exitAs({ cookies }, campaign._id);

    assert.equal((await campaignOf(campaign._id)).paidMemberCount, 1);
  });
});

// ---------------------------------------------------------------------------

test('cancelling a booking reverses the membership it created', async (t) => {
  for (const from of ['confirmed', 'completed']) {
    await t.test(`cancelling from ${from} exits the derived member`, async () => {
      const admin = await adminWithSession(api);
      const { buyer } = await buyerWithSession(api);
      const chain = await makeChain(admin.admin._id);
      const campaign = await makeCampaign(chain, admin.admin._id);
      const member = await makeMember(campaign, buyer._id, {
        tokenStatus: 'paid', tokenPaidAt: new Date(), paymentReference: 'UTR-STATE-1',
      });
      const booking = await makeBooking(chain, buyer._id, { status: from });

      const res = await cancelBooking(admin, booking._id);
      assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));

      const after = await reload(member._id);
      assert.equal(after.status, 'exited', 'the derived membership must be reversed');
      assert.ok(after.exitedAt, 'the reversal must be timestamped');
      assert.match(after.exitReason, /booking/i, 'the reason must name the booking');
    });
  }

  await t.test('the member document survives — nothing is deleted', async () => {
    const admin = await adminWithSession(api);
    const { buyer } = await buyerWithSession(api);
    const chain = await makeChain(admin.admin._id);
    const campaign = await makeCampaign(chain, admin.admin._id);
    const member = await makeMember(campaign, buyer._id, { tokenStatus: 'paid', paymentReference: 'UTR-STATE-1' });
    const booking = await makeBooking(chain, buyer._id, { status: 'confirmed' });

    await cancelBooking(admin, booking._id);

    const after = await reload(member._id);
    assert.ok(after, 'the record is evidence and must not be deleted');
    assert.equal(after.paymentReference, 'UTR-STATE-1', 'the payment reference must survive');
    assert.equal(after.tokenStatus, 'paid', 'what was paid stays recorded as paid');
  });

  await t.test('a cancelled booking no longer contributes to paid-member counts', async () => {
    const admin = await adminWithSession(api);
    const { buyer } = await buyerWithSession(api);
    const chain = await makeChain(admin.admin._id);
    const campaign = await makeCampaign(chain, admin.admin._id);
    await makeMember(campaign, buyer._id, { tokenStatus: 'paid' });
    const booking = await makeBooking(chain, buyer._id, { status: 'confirmed' });

    assert.equal((await campaignOf(campaign._id)).paidMemberCount, 1, 'precondition');

    await cancelBooking(admin, booking._id);

    const campaignAfter = await campaignOf(campaign._id);
    assert.equal(campaignAfter.paidMemberCount, 0, 'an invalidated membership must stop counting');
    assert.equal(campaignAfter.memberCount, 0);
  });

  for (const from of ['enquiry', 'payment_submitted']) {
    await t.test(`cancelling from ${from} reverses nothing, because nobody was enrolled`, async () => {
      // Not every cancellation invalidates a membership. Enrolment only happens
      // at confirmed or completed, so cancelling before that must leave an
      // unrelated membership alone.
      const admin = await adminWithSession(api);
      const { buyer } = await buyerWithSession(api);
      const chain = await makeChain(admin.admin._id);
      const campaign = await makeCampaign(chain, admin.admin._id);
      const member = await makeMember(campaign, buyer._id, { tokenStatus: 'paid' });
      const booking = await makeBooking(chain, buyer._id, { status: from });

      await cancelBooking(admin, booking._id);

      const after = await reload(member._id);
      assert.equal(after.status, 'active', `cancelling from ${from} must not touch a membership`);
      assert.equal((await campaignOf(campaign._id)).paidMemberCount, 1);
    });
  }

  await t.test("the same user's membership in an unrelated campaign is untouched", async () => {
    // Scoping by user alone is not enough. One person can hold paid
    // memberships in several campaigns, and cancelling a booking for one unit
    // must not exit them from a campaign on a different project entirely.
    const admin = await adminWithSession(api);
    const { buyer } = await buyerWithSession(api);

    const chain = await makeChain(admin.admin._id);
    const campaign = await makeCampaign(chain, admin.admin._id);
    const affected = await makeMember(campaign, buyer._id, { tokenStatus: 'paid' });

    const otherChain = await makeChain(admin.admin._id);
    const otherCampaign = await makeCampaign(otherChain, admin.admin._id);
    const untouched = await makeMember(otherCampaign, buyer._id, { tokenStatus: 'paid' });

    const booking = await makeBooking(chain, buyer._id, { status: 'confirmed' });
    await cancelBooking(admin, booking._id);

    assert.equal((await reload(affected._id)).status, 'exited', 'the booked campaign reverses');
    assert.equal(
      (await reload(untouched._id)).status, 'active',
      'a campaign on another project must not be reversed by this booking'
    );
    assert.equal((await campaignOf(otherCampaign._id)).paidMemberCount, 1);
  });

  await t.test('another user in the same campaign is unaffected', async () => {
    const admin = await adminWithSession(api);
    const { buyer } = await buyerWithSession(api);
    const other = await buyerWithSession(api);
    const chain = await makeChain(admin.admin._id);
    const campaign = await makeCampaign(chain, admin.admin._id);
    const mine = await makeMember(campaign, buyer._id, { tokenStatus: 'paid' });
    const theirs = await makeMember(campaign, other.buyer._id, { tokenStatus: 'paid' });
    const booking = await makeBooking(chain, buyer._id, { status: 'confirmed' });

    await cancelBooking(admin, booking._id);

    assert.equal((await reload(mine._id)).status, 'exited');
    assert.equal((await reload(theirs._id)).status, 'active', 'only the booking owner is reversed');
    assert.equal((await campaignOf(campaign._id)).paidMemberCount, 1);
  });
});

// ---------------------------------------------------------------------------

test('no refund is invented anywhere', async (t) => {
  await t.test('tokenStatus is never written as refunded', async () => {
    // `refunded` is reserved for a manual refund flow that does not exist. A
    // reversal that quietly claimed the money went back would be a lie in the
    // one record anyone would check.
    const admin = await adminWithSession(api);
    const { buyer, cookies } = await buyerWithSession(api);
    const chain = await makeChain(admin.admin._id);
    const campaign = await makeCampaign(chain, admin.admin._id);
    await makeMember(campaign, buyer._id, { tokenStatus: 'paid' });
    const booking = await makeBooking(chain, buyer._id, { status: 'confirmed' });

    await exitAs({ cookies }, campaign._id);
    await cancelBooking(admin, booking._id);

    assert.equal(await M('CampaignMember').countDocuments({ tokenStatus: 'refunded' }), 0);
  });

  await t.test('the source files write no refund state', () => {
    // Comments are stripped first. The assertion is about code, and these files
    // deliberately discuss `tokenStatus: "refunded"` in prose to explain why
    // nothing writes it — a check that could not tell those apart would forbid
    // documenting the decision.
    const read = (p) =>
      readFileSync(new URL(p, import.meta.url), 'utf8')
        .replace(new RegExp('/\\*[\\s\\S]*?\\*/', 'g'), '')
        .replace(new RegExp('//[^\\r\\n]*', 'g'), '');
    for (const file of [
      '../../controllers/campaignController.js',
      '../../controllers/bookingController.js',
      '../../utils/campaignMemberState.js',
    ]) {
      assert.doesNotMatch(
        read(file), /tokenStatus\s*[:=]\s*["']refunded["']/,
        `${file} writes a refund state that no refund process backs`
      );
    }
  });
});

// ---------------------------------------------------------------------------

test('the a1651e9 delete guards are still intact', async (t) => {
  await t.test('a unit type with a paid member still refuses deletion', async () => {
    // The reversal introduces an `exited` paid member. The guard counts paid
    // members regardless of membership status, so it must still refuse.
    const admin = await adminWithSession(api);
    const { buyer } = await buyerWithSession(api);
    const chain = await makeChain(admin.admin._id);
    const campaign = await makeCampaign(chain, admin.admin._id);
    await makeMember(campaign, buyer._id, { tokenStatus: 'paid' });
    const booking = await makeBooking(chain, buyer._id, { status: 'confirmed' });

    await cancelBooking(admin, booking._id);

    const res = await asAdmin(api.delete(`/api/unit-types/${chain.unitType._id}`), admin).send();
    assert.equal(res.status, 409, 'money evidence must still block deletion after a reversal');
    assert.equal(res.body.code, 'DELETE_BLOCKED_DEPENDENTS');
  });
});
