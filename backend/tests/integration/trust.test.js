/**
 * Phase 3: the payout hold and linkage flags, attestations, non-cashable
 * milestones, verified-deal reviews with simultaneous reveal, badges, and the
 * buyer seriousness card.
 *
 * The reward policy is environment-driven; tests set the variables they
 * need and restore them, so the default (nothing changes) is also asserted.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, withClient } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import {
  ownerWithSession, buyerWithSession, makeProperty, makeLead, makeBuyer, adminWithSession, asAdmin, loginAs,
} from './setup/factories.js';

import { linkageFlags } from '../../utils/fraudLinkage.js';
import { awardMilestone, getOrCreateWallet } from '../../services/rewardService.js';
import { publishExpiredReviews } from '../../jobs/reviewPublish.js';
import { buyerContextsFor } from '../../utils/buyerContext.js';

let api;
const M = (name) => mongoose.model(name);
const H = 3600 * 1000;
const POLICY_KEYS = ['MILESTONE_REWARDS_ENABLED', 'CLOSE_PAYOUT_FIXED_POINTS', 'PAYOUT_HOLD_DAYS', 'PAYOUT_HOLD_DAYS_FLAGGED'];

function withPolicy(values) {
  const saved = {};
  for (const k of POLICY_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  for (const [k, v] of Object.entries(values)) process.env[k] = v;
  return () => { for (const k of POLICY_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } };
}

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const get = (path, cookies) => withClient(api.get(path), { cookies });
const post = (path, cookies) => withClient(api.post(path), { cookies });
const put = (path, cookies) => withClient(api.put(path), { cookies });

async function closedDealFixture({ ageDays = 30 } = {}) {
  const created = new Date(Date.now() - ageDays * 86400 * 1000);
  const o = await ownerWithSession(api, { createdAt: created });
  const b = await buyerWithSession(api, { createdAt: created });
  await M('User').updateMany({ _id: { $in: [o.owner._id, b.buyer._id] } }, { $set: { createdAt: created } });
  const property = await makeProperty(o.owner);
  const lead = await makeLead(property, b.buyer);
  // A second enquiry so the buyer is not "first_action_close".
  await makeLead(await makeProperty(o.owner), b.buyer);
  const verification = await M('TransactionVerification').create({
    property: property._id, owner: o.owner._id, buyer: b.buyer._id, closingType: 'sold', documentUrls: ['https://example.com/deed.pdf'],
  });
  await M('Lead').updateOne({ _id: lead._id }, { $set: { verification: verification._id } });
  return { owner: o.owner, ownerCookies: o.cookies, buyer: b.buyer, buyerCookies: b.cookies, property, lead, verification };
}

async function approve(verificationId) {
  const session = await adminWithSession(api);
  const res = await asAdmin(api.post(`/api/admin/verifications/${verificationId}/approve`), session).send({ adminNotes: 'ok' });
  assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
  return session;
}

// ---------------------------------------------------------------------------

test('linkage flags', async (t) => {
  await t.test('a clean close raises only the missing attestation', async () => {
    const f = await closedDealFixture();
    const flags = await linkageFlags({ verification: await M('TransactionVerification').findById(f.verification._id).lean() });
    assert.deepEqual(flags, ['attestation_missing']);
  });

  await t.test('a shared device and a shared address are each a flag', async () => {
    // A shared phone cannot be staged: the unique index on User.phone refuses
    // it, which is the first line of defence. The flag stays as belt and
    // braces for data that predates the index.
    const f = await closedDealFixture();
    await M('User').updateOne({ _id: f.owner._id }, { $set: { deviceHashes: ['device-shared-0001'], 'security.lastLoginIp': '10.0.0.9' } });
    await M('User').updateOne({ _id: f.buyer._id }, { $set: { deviceHashes: ['device-shared-0001', 'other'], 'security.lastLoginIp': '10.0.0.9' } });
    const flags = await linkageFlags({ verification: await M('TransactionVerification').findById(f.verification._id).lean() });
    for (const expected of ['same_device', 'same_ip']) assert.ok(flags.includes(expected), expected);
    assert.ok(!flags.includes('same_phone'));
  });

  await t.test('young accounts, a first-action close and owner velocity are flagged', async () => {
    const f = await closedDealFixture({ ageDays: 3 });
    await M('Lead').deleteMany({ user: f.buyer._id, _id: { $ne: f.lead._id } });
    for (let i = 0; i < 3; i += 1) {
      await M('TransactionVerification').create({
        property: (await makeProperty(f.owner))._id, owner: f.owner._id, buyer: (await makeBuyer())._id, closingType: 'rented', documentUrls: ['x'], status: 'approved',
      });
    }
    const flags = await linkageFlags({ verification: await M('TransactionVerification').findById(f.verification._id).lean() });
    for (const expected of ['young_account', 'first_action_close', 'owner_velocity']) assert.ok(flags.includes(expected), expected);
  });

  await t.test('the device route records an opaque id, capped at ten, and refuses junk', async () => {
    const { buyer, cookies } = await buyerWithSession(api);
    assert.equal((await post('/api/users/device', cookies).send({ deviceHash: 'short' })).status, 400);
    for (let i = 0; i < 12; i += 1) {
      const res = await post('/api/users/device', cookies).send({ deviceHash: `install-${String(i).padStart(12, '0')}-abcd` });
      assert.equal(res.status, 200);
    }
    const user = await M('User').findById(buyer._id).select('+deviceHashes').lean();
    assert.equal(user.deviceHashes.length, 10);
    assert.ok(user.deviceHashes[0].includes('000000000002'), 'oldest dropped');
    const plain = await M('User').findById(buyer._id).lean();
    assert.equal(plain.deviceHashes, undefined, 'hidden from default reads');
  });
});

// ---------------------------------------------------------------------------

test('approval, hold and claim', async (t) => {
  await t.test('by default a clean close has no hold and claims at once', async () => {
    const restore = withPolicy({});
    try {
      const f = await closedDealFixture();
      await post(`/api/deals/${f.lead._id}/attest`, f.buyerCookies).send({ statement: 'confirm' });
      await approve(f.verification._id);
      const v = await M('TransactionVerification').findById(f.verification._id).lean();
      assert.deepEqual(v.fraudFlags, []);
      assert.equal(v.payoutHoldUntil, null);
      const claim = await post(`/api/properties/claim-deal-reward/${f.verification._id}`, f.buyerCookies).send({});
      assert.equal(claim.status, 200, JSON.stringify(claim.body).slice(0, 200));
      assert.ok(claim.body.reward.pointsAwarded > 0);
      assert.equal(await M('Notification').countDocuments({ user: f.buyer._id, type: 'review_request' }), 1);
    } finally { restore(); }
  });

  await t.test('a flagged close gets the long hold and the claim is refused until then', async () => {
    const restore = withPolicy({ PAYOUT_HOLD_DAYS: '0', PAYOUT_HOLD_DAYS_FLAGGED: '45' });
    try {
      const f = await closedDealFixture();
      await M('User').updateMany({ _id: { $in: [f.owner._id, f.buyer._id] } }, { $set: { deviceHashes: ['same-phone-device-01'] } });
      await approve(f.verification._id);
      const v = await M('TransactionVerification').findById(f.verification._id).lean();
      assert.ok(v.fraudFlags.includes('same_device'));
      const days = (new Date(v.payoutHoldUntil) - new Date(v.reviewedAt)) / 86400000;
      assert.equal(Math.round(days), 45);

      const claim = await post(`/api/properties/claim-deal-reward/${f.verification._id}`, f.ownerCookies).send({});
      assert.equal(claim.status, 409);
      assert.equal(claim.body.code, 'PAYOUT_ON_HOLD');
      assert.ok(claim.body.holdUntil);
      assert.equal((await M('TransactionVerification').findById(f.verification._id).lean()).ownerClaimed, false);

      const note = await M('Notification').findOne({ user: f.owner._id, type: 'deal_reward' }).lean();
      assert.match(note.message, /unlocks on/);

      // The admin sees why.
      const session = await adminWithSession(api);
      const list = await asAdmin(api.get('/api/admin/verifications?status=approved'), session);
      assert.equal(list.status, 200);
      const row = list.body.verifications.find((x) => String(x._id) === String(f.verification._id));
      assert.ok(row.fraudFlagDetails.some((d) => d.flag === 'same_device' && /device/i.test(d.description)));
    } finally { restore(); }
  });

  await t.test('a clean close honours the configured clean hold', async () => {
    const restore = withPolicy({ PAYOUT_HOLD_DAYS: '7' });
    try {
      const f = await closedDealFixture();
      await post(`/api/deals/${f.lead._id}/attest`, f.buyerCookies).send({ statement: 'confirm' });
      await approve(f.verification._id);
      const v = await M('TransactionVerification').findById(f.verification._id).lean();
      assert.deepEqual(v.fraudFlags, []);
      assert.equal(Math.round((new Date(v.payoutHoldUntil) - new Date(v.reviewedAt)) / 86400000), 7);
    } finally { restore(); }
  });

  await t.test('a fixed close base is added on top of the draw when configured', async () => {
    const restore = withPolicy({ CLOSE_PAYOUT_FIXED_POINTS: '2000' });
    try {
      const f = await closedDealFixture();
      await post(`/api/deals/${f.lead._id}/attest`, f.buyerCookies).send({ statement: 'confirm' });
      await approve(f.verification._id);
      const claim = await post(`/api/properties/claim-deal-reward/${f.verification._id}`, f.buyerCookies).send({});
      assert.equal(claim.status, 200);
      assert.ok(claim.body.reward.pointsAwarded >= 2000, `got ${claim.body.reward.pointsAwarded}`);
      const wallet = await getOrCreateWallet(f.buyer._id);
      const txn = wallet.transactions.find((x) => x.action === 'complete_deal');
      assert.equal(txn.metadata.guaranteedPoints, 2000);
      assert.ok(txn.metadata.drawPoints > 0);
    } finally { restore(); }
  });

  await t.test('the public policy explainer reflects the configuration', async () => {
    const restore = withPolicy({ MILESTONE_REWARDS_ENABLED: 'true' });
    try {
      const res = await withClient(api.get('/api/rewards/policy'));
      assert.equal(res.status, 200);
      assert.equal(res.body.data.milestones.length, 2);
      assert.equal(res.body.data.close.holdDaysFlagged, 60);
    } finally { restore(); }
  });
});

// ---------------------------------------------------------------------------

test('attestations', async (t) => {
  await t.test('each side speaks once; a dispute and a mismatch become flags', async () => {
    const f = await closedDealFixture();
    const none = await post(`/api/deals/${f.lead._id}/attest`, f.buyerCookies).send({ statement: 'maybe' });
    assert.equal(none.status, 400);

    const ok = await post(`/api/deals/${f.lead._id}/attest`, f.buyerCookies).send({ statement: 'dispute', note: 'I never bought this' });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    const twice = await post(`/api/deals/${f.lead._id}/attest`, f.buyerCookies).send({ statement: 'confirm' });
    assert.equal(twice.body.code, 'ALREADY_ATTESTED');

    await post(`/api/deals/${f.lead._id}/attest`, f.ownerCookies).send({ statement: 'confirm' });
    const v = await M('TransactionVerification').findById(f.verification._id).lean();
    assert.equal(v.attestations.buyer.statement, 'dispute');
    assert.equal(v.attestations.owner.statement, 'confirm');
    assert.ok(v.fraudFlags.includes('attestation_dispute'));
    assert.ok(v.fraudFlags.includes('attestation_mismatch'));

    const view = await get(`/api/deals/${f.lead._id}`, f.buyerCookies);
    assert.equal(view.body.data.verification.attestation.mine.statement, 'dispute');
    assert.equal(view.body.data.verification.attestation.counterpartDone, true);
  });

  await t.test('no verification, no attestation', async () => {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    const lead = await makeLead(await makeProperty(o.owner), b.buyer);
    const res = await post(`/api/deals/${lead._id}/attest`, b.cookies).send({ statement: 'confirm' });
    assert.equal(res.status, 409);
    assert.equal(res.body.code, 'NO_VERIFICATION');
  });
});

// ---------------------------------------------------------------------------

test('milestones are non-cashable and off by default', async (t) => {
  await t.test('off: awardMilestone is a silent no-op', async () => {
    const restore = withPolicy({});
    try {
      const buyer = await makeBuyer();
      const r = await awardMilestone(buyer._id, 'visit_completed', { leadId: new mongoose.Types.ObjectId() });
      assert.equal(r.success, false);
      assert.equal(r.reason, 'milestones_disabled');
      assert.equal(await M('Reward').countDocuments({ user: buyer._id }), 0);
    } finally { restore(); }
  });

  await t.test('on: points lock, count for tier, never enter the available balance, once per lead', async () => {
    const restore = withPolicy({ MILESTONE_REWARDS_ENABLED: 'true' });
    try {
      const buyer = await makeBuyer();
      const leadId = new mongoose.Types.ObjectId();
      const first = await awardMilestone(buyer._id, 'visit_completed', { leadId });
      assert.equal(first.success, true);
      assert.equal(first.pointsAwarded, 100);
      assert.equal(first.cashable, false);
      const again = await awardMilestone(buyer._id, 'visit_completed', { leadId });
      assert.equal(again.pointsAwarded, 0);
      const wallet = await M('Reward').findOne({ user: buyer._id }).lean();
      assert.equal(wallet.lockedPoints, 100);
      assert.equal(wallet.availablePoints, 0);
      assert.equal(wallet.totalPoints, 100);
      assert.equal(wallet.transactions[0].metadata.cashable, false);
    } finally { restore(); }
  });

  await t.test('both parties marking a visit done pays both, once', async () => {
    const restore = withPolicy({ MILESTONE_REWARDS_ENABLED: 'true' });
    try {
      const o = await ownerWithSession(api);
      const b = await buyerWithSession(api);
      const lead = await makeLead(await makeProperty(o.owner), b.buyer, {
        visits: [{ scheduledAt: new Date(Date.now() - 3 * H), status: 'confirmed', proposedBy: b.buyer._id }],
      });
      const visitId = (await M('Lead').findById(lead._id).lean()).visits[0]._id;
      const url = `/api/deals/${lead._id}/visits/${visitId}`;

      const ownerDone = await put(url, o.cookies).send({ action: 'done' });
      assert.equal(ownerDone.status, 200, JSON.stringify(ownerDone.body));
      assert.equal(ownerDone.body.milestone, null, 'one confirmation is not the milestone');

      const ownerAgain = await put(url, o.cookies).send({ action: 'done' });
      assert.equal(ownerAgain.body.code, 'ALREADY_CONFIRMED');

      const buyerDone = await put(url, b.cookies).send({ action: 'done' });
      assert.equal(buyerDone.status, 200, JSON.stringify(buyerDone.body));
      assert.equal(buyerDone.body.milestone.pointsAwarded, 100);

      for (const id of [o.owner._id, b.buyer._id]) {
        const w = await M('Reward').findOne({ user: id }).lean();
        assert.equal(w.lockedPoints, 100, `wallet of ${id}`);
        assert.equal(w.availablePoints, 0);
      }
      const after = await M('Lead').findById(lead._id).lean();
      assert.ok(after.visits[0].milestoneAwardedAt);
    } finally { restore(); }
  });
});

// ---------------------------------------------------------------------------

test('verified-deal reviews', async (t) => {
  const ratings = { accuracy: 5, responsiveness: 4, seriousness: 5 };

  await t.test('only parties of an approved close may review, once, with whole-number ratings', async () => {
    const f = await closedDealFixture();
    const early = await post('/api/reviews', f.buyerCookies).send({ verificationId: f.verification._id, ratings });
    assert.equal(early.status, 409);
    assert.equal(early.body.code, 'NOT_VERIFIED');

    await approve(f.verification._id);

    const stranger = await buyerWithSession(api);
    assert.equal((await post('/api/reviews', stranger.cookies).send({ verificationId: f.verification._id, ratings })).status, 403);
    assert.equal((await post('/api/reviews', f.buyerCookies).send({ verificationId: f.verification._id, ratings: { ...ratings, accuracy: 4.5 } })).body.code, 'INVALID_RATING');
    assert.equal((await post('/api/reviews', f.buyerCookies).send({ verificationId: f.verification._id, ratings: { ...ratings, accuracy: 6 } })).body.code, 'INVALID_RATING');

    const ok = await post('/api/reviews', f.buyerCookies).send({ verificationId: f.verification._id, ratings, text: 'x'.repeat(1000) });
    assert.equal(ok.status, 201, JSON.stringify(ok.body));
    assert.equal(ok.body.data.status, 'pending', 'one side alone stays hidden');
    const stored = await M('Review').findOne({ author: f.buyer._id }).lean();
    assert.equal(stored.text.length, 600);
    assert.equal(stored.authorRole, 'buyer');
    assert.equal(String(stored.subject), String(f.owner._id));

    const dup = await post('/api/reviews', f.buyerCookies).send({ verificationId: f.verification._id, ratings });
    assert.equal(dup.status, 409);
    assert.equal(dup.body.code, 'ALREADY_REVIEWED');

    // Nothing is public yet, and the owner was asked for theirs.
    const pub = await withClient(api.get(`/api/reviews/user/${f.owner._id}`));
    assert.equal(pub.body.data.length, 0);
    assert.equal(await M('Notification').countDocuments({ user: f.owner._id, type: 'review_request' }), 2, 'approval + the counterpart nudge');
  });

  await t.test('the second review publishes both at once', async () => {
    const f = await closedDealFixture();
    await approve(f.verification._id);
    await post('/api/reviews', f.buyerCookies).send({ verificationId: f.verification._id, ratings });
    const second = await post('/api/reviews', f.ownerCookies).send({ verificationId: f.verification._id, ratings: { accuracy: 3, responsiveness: 3, seriousness: 4 }, text: 'Serious buyer' });
    assert.equal(second.status, 201);
    assert.equal(second.body.data.status, 'published');

    const ownerPage = await withClient(api.get(`/api/reviews/user/${f.owner._id}`));
    assert.equal(ownerPage.body.data.length, 1);
    assert.equal(ownerPage.body.summary.count, 1);
    assert.equal(ownerPage.body.summary.overall, 4.7);
    assert.equal(ownerPage.body.data[0].author.name, f.buyer.name);

    const buyerPage = await withClient(api.get(`/api/reviews/user/${f.buyer._id}`));
    assert.equal(buyerPage.body.data[0].text, 'Serious buyer');
    assert.equal(await M('Notification').countDocuments({ type: 'review_published' }), 2);

    const mine = await get('/api/reviews/mine', f.buyerCookies);
    assert.equal(mine.body.data.written.length, 1);
    assert.equal(mine.body.data.received.length, 1);

    const view = await get(`/api/deals/${f.lead._id}`, f.buyerCookies);
    assert.equal(view.body.data.verification.review.submitted, true);
    assert.equal(view.body.data.verification.review.status, 'published');
  });

  await t.test('a lone review publishes when the window closes, by the job', async () => {
    const f = await closedDealFixture();
    await approve(f.verification._id);
    await post('/api/reviews', f.buyerCookies).send({ verificationId: f.verification._id, ratings });
    const before = await publishExpiredReviews({ now: new Date() });
    assert.equal(before.published, 0);
    const after = await publishExpiredReviews({ now: new Date(Date.now() + 15 * 86400 * 1000) });
    assert.equal(after.published, 1);
    const again = await publishExpiredReviews({ now: new Date(Date.now() + 16 * 86400 * 1000) });
    assert.equal(again.published, 0);
    const pub = await withClient(api.get(`/api/reviews/user/${f.owner._id}`));
    assert.equal(pub.body.data.length, 1);
  });

  await t.test('eligibility answers before and after', async () => {
    const f = await closedDealFixture();
    await approve(f.verification._id);
    const before = await get(`/api/reviews/eligibility/${f.verification._id}`, f.ownerCookies);
    assert.equal(before.body.data.eligible, true);
    assert.equal(before.body.data.role, 'owner');
    await post('/api/reviews', f.ownerCookies).send({ verificationId: f.verification._id, ratings });
    const after = await get(`/api/reviews/eligibility/${f.verification._id}`, f.ownerCookies);
    assert.equal(after.body.data.eligible, false);
    assert.equal(after.body.data.submitted, true);
    const stranger = await buyerWithSession(api);
    assert.equal((await get(`/api/reviews/eligibility/${f.verification._id}`, stranger.cookies)).status, 403);
  });

  await t.test('the public listing carries the owner review summary', async () => {
    const f = await closedDealFixture();
    await approve(f.verification._id);
    await post('/api/reviews', f.buyerCookies).send({ verificationId: f.verification._id, ratings });
    await post('/api/reviews', f.ownerCookies).send({ verificationId: f.verification._id, ratings });
    const listing = await makeProperty(f.owner, { isApproved: true });
    const res = await withClient(api.get(`/api/properties/${listing._id}`));
    assert.equal(res.status, 200);
    assert.equal(res.body.ownerStats.reviews.count, 1);
    assert.equal(res.body.ownerStats.reviews.overall, 4.7);
  });
});

// ---------------------------------------------------------------------------

test('badges and buyer context', async (t) => {
  await t.test('an admin sets the badge; it shows on listings and in the deal room', async () => {
    const f = await closedDealFixture();
    const session = await adminWithSession(api);
    const bad = await asAdmin(api.put(`/api/admin/users/${f.owner._id}/verification`), session).send({});
    assert.equal(bad.status, 400);
    const res = await asAdmin(api.put(`/api/admin/users/${f.owner._id}/verification`), session).send({ identity: true, documents: true });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.data.verification.identity, true);

    const asUser = await put(`/api/admin/users/${f.owner._id}/verification`, f.ownerCookies).send({ identity: true });
    assert.equal(asUser.status, 401, 'users cannot badge themselves');

    const listing = await makeProperty(f.owner, { isApproved: true });
    const pub = await withClient(api.get(`/api/properties/${listing._id}`));
    assert.equal(pub.body.ownerStats.verified, true);
    assert.equal(pub.body.ownerStats.documentsVerified, true);

    const view = await get(`/api/deals/${f.lead._id}`, f.buyerCookies);
    assert.equal(view.body.data.counterpart.verified, true);
  });

  await t.test('the owner sees aggregate buyer context, never browsing history', async () => {
    const o = await ownerWithSession(api);
    const buyer = await makeBuyer();
    // Mongoose strips createdAt from updates; the raw driver does not.
    await M('User').collection.updateOne({ _id: buyer._id }, { $set: { createdAt: new Date(Date.now() - 21 * 86400 * 1000) } });
    const prices = [2000000, 2200000, 2400000];
    for (const price of prices) {
      const p = await makeProperty(await ownerWithSession(api).then((x) => x.owner), { price });
      await M('Lead').create({
        property: p._id, propertyOwner: p.owner, user: buyer._id,
        userSnapshot: { name: buyer.name, email: buyer.email }, propertySnapshot: { price },
        visits: [{ scheduledAt: new Date(Date.now() - 5 * H), status: 'done', proposedBy: buyer._id }],
      });
    }
    const mine = await makeProperty(o.owner, { price: 2300000 });
    const lead = await M('Lead').create({
      property: mine._id, propertyOwner: o.owner._id, user: buyer._id,
      userSnapshot: { name: buyer.name, email: buyer.email }, propertySnapshot: { price: 2300000 },
    });

    const contexts = await buyerContextsFor([buyer._id], new Map([[String(buyer._id), 2300000]]));
    const ctx = contexts.get(String(buyer._id));
    assert.equal(ctx.enquiries, 4);
    assert.equal(ctx.visitsDone, 3);
    assert.equal(ctx.activeWeeks, 3);
    assert.equal(ctx.budgetFit, 'within');

    const list = await get('/api/leads', o.cookies);
    assert.equal(list.status, 200, JSON.stringify(list.body).slice(0, 200));
    const row = list.body.data.find((l) => String(l._id) === String(lead._id));
    assert.deepEqual(row.buyerContext, ctx);
    assert.equal(Object.keys(row.buyerContext).length, 4, 'four aggregate numbers, nothing else');

    const view = await get(`/api/deals/${lead._id}`, o.cookies);
    assert.equal(view.body.data.buyerContext.budgetFit, 'within');

    const far = await buyerContextsFor([buyer._id], new Map([[String(buyer._id), 9000000]]));
    assert.equal(far.get(String(buyer._id)).budgetFit, 'above');

    const fresh = await makeBuyer();
    const none = await buyerContextsFor([fresh._id]);
    assert.deepEqual(none.get(String(fresh._id)), { activeWeeks: 0, enquiries: 0, visitsDone: 0, budgetFit: null });
  });
});
