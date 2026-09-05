/**
 * The lifetime-value loop (Phase 5, F21): the rental renewal clock, the
 * referral offer at the reward moment, and points that lapse on inactivity.
 *
 * Two of these three touch people who are not currently using the product,
 * which is precisely why the guards matter more than the features: a renewal
 * nudge sent twice, or a balance taken from someone who was active last week,
 * is worse than never having built either.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request, withClient } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders, clearPushBatches } from './setup/fakeProviders.js';
import { ownerWithSession, buyerWithSession, makeProperty, makeBuyer, adminWithSession, asAdmin } from './setup/factories.js';

import { runRentalClock } from '../../jobs/rentalClock.js';
import { expirePoints } from '../../jobs/pointsExpiry.js';
import { getOrCreateWallet } from '../../services/rewardService.js';
import { generateReferralCode, randomReferralCode } from '../../utils/referralCode.js';

let api;
const M = (name) => mongoose.model(name);
const DAY = 86400 * 1000;

const post = (path, cookies) => withClient(api.post(path), { cookies });
const get = (path, cookies) => withClient(api.get(path), { cookies });

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); clearPushBatches(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

/** An approved rental close, verified `monthsAgo` months ago. */
async function verifiedRental({ monthsAgo = 10, closingType = 'rented' } = {}) {
  const o = await ownerWithSession(api);
  const b = await buyerWithSession(api);
  const property = await makeProperty(o.owner, { listingType: 'Rent', isApproved: true });
  const reviewedAt = new Date();
  reviewedAt.setUTCMonth(reviewedAt.getUTCMonth() - monthsAgo);

  const verification = await M('TransactionVerification').create({
    property: property._id,
    owner: o.owner._id,
    buyer: b.buyer._id,
    closingType,
    documentUrls: ['https://example.com/agreement.pdf'],
    status: 'approved',
    reviewedAt,
  });
  return { owner: o.owner, ownerCookies: o.cookies, buyer: b.buyer, buyerCookies: b.cookies, property, verification };
}

// ---------------------------------------------------------------------------

test('the rental renewal clock', async (t) => {
  await t.test('at month ten both sides hear, each told what to do next', async () => {
    const r = await verifiedRental({ monthsAgo: 10 });
    const result = await runRentalClock({ now: new Date() });

    assert.equal(result.verifications, 1);
    assert.equal(result.nudged, 2, 'the owner and the tenant');

    const ownerNote = await M('Notification').findOne({ user: r.owner._id, type: 'rental_renewal' }).lean();
    const tenantNote = await M('Notification').findOne({ user: r.buyer._id, type: 'rental_renewal' }).lean();

    assert.ok(ownerNote && tenantNote);
    assert.equal(ownerNote.data.role, 'owner');
    assert.equal(tenantNote.data.role, 'tenant');
    assert.match(ownerNote.message, /relist/i, 'the owner is told to renew or relist');
    assert.match(tenantNote.message, /find you the next one/i, 'the tenant is offered the next search');
    assert.equal(ownerNote.data.kind, 'property');
    assert.notEqual(ownerNote.message, tenantNote.message, 'the two sides are not sent the same words');
  });

  await t.test('it fires exactly once, whatever the job does afterwards', async () => {
    await verifiedRental({ monthsAgo: 10 });
    const first = await runRentalClock({ now: new Date() });
    const second = await runRentalClock({ now: new Date() });
    const third = await runRentalClock({ now: new Date(Date.now() + 30 * DAY) });

    assert.equal(first.nudged, 2);
    assert.equal(second.nudged, 0);
    assert.equal(third.nudged, 0);
    assert.equal(await M('Notification').countDocuments({ type: 'rental_renewal' }), 2);
  });

  await t.test('the mark is written before the send, so a crash costs a nudge rather than duplicating one', async () => {
    const r = await verifiedRental({ monthsAgo: 10 });
    await runRentalClock({ now: new Date() });
    const v = await M('TransactionVerification').findById(r.verification._id).lean();
    assert.ok(v.renewalNudgedAt);
  });

  await t.test('a rental too young is left alone', async () => {
    await verifiedRental({ monthsAgo: 6 });
    const result = await runRentalClock({ now: new Date() });
    assert.equal(result.nudged, 0);
  });

  await t.test('an old rental that was never nudged still gets its one message', async () => {
    await verifiedRental({ monthsAgo: 15 });
    const result = await runRentalClock({ now: new Date() });
    assert.equal(result.nudged, 2, 'a backlog from before this job existed is cleared once');
  });

  await t.test('a sale is not a rental, and a pending verification is not a close', async () => {
    await verifiedRental({ monthsAgo: 12, closingType: 'sold' });
    const pending = await verifiedRental({ monthsAgo: 12 });
    await M('TransactionVerification').updateOne({ _id: pending.verification._id }, { $set: { status: 'pending', reviewedAt: null } });

    const result = await runRentalClock({ now: new Date() });
    assert.equal(result.nudged, 0);
  });

  await t.test('the message names a date the reader can act on', async () => {
    const r = await verifiedRental({ monthsAgo: 10 });
    await runRentalClock({ now: new Date() });
    const note = await M('Notification').findOne({ user: r.buyer._id }).lean();
    assert.match(note.message, /\d{1,2} [A-Z][a-z]+/, 'a day and a month, not "soon"');
  });
});

// ---------------------------------------------------------------------------

test('the referral offer at the reward moment', async (t) => {
  async function approvedClose() {
    const o = await ownerWithSession(api);
    const b = await buyerWithSession(api);
    // Aged accounts and a second enquiry, so the Phase 3 linkage check finds
    // nothing to flag: `young_account` and `first_action_close` would each put
    // the payout on the long hold, which is correct and not what this tests.
    const created = new Date(Date.now() - 60 * DAY);
    await M('User').collection.updateMany(
      { _id: { $in: [o.owner._id, b.buyer._id] } },
      { $set: { createdAt: created } }
    );
    const property = await makeProperty(o.owner, { isApproved: true });
    await M('Lead').create({
      property: property._id, propertyOwner: o.owner._id, user: b.buyer._id,
      userSnapshot: { name: b.buyer.name, email: b.buyer.email },
    });
    const other = await makeProperty(o.owner, { isApproved: true });
    await M('Lead').create({
      property: other._id, propertyOwner: o.owner._id, user: b.buyer._id,
      userSnapshot: { name: b.buyer.name, email: b.buyer.email },
    });
    const verification = await M('TransactionVerification').create({
      property: property._id, owner: o.owner._id, buyer: b.buyer._id,
      closingType: 'sold', documentUrls: ['https://example.com/deed.pdf'],
    });
    // The buyer confirms the close before the admin approves. Without it the
    // Phase 3 linkage check raises `attestation_missing` and the payout goes
    // on the long hold, which is correct behaviour and not what this test is
    // about.
    const lead = await M('Lead').findOne({ property: property._id, user: b.buyer._id }).lean();
    await M('Lead').updateOne({ _id: lead._id }, { $set: { verification: verification._id } });
    const attest = await post(`/api/deals/${lead._id}/attest`, b.cookies).send({ statement: 'confirm' });
    assert.equal(attest.status, 200, JSON.stringify(attest.body).slice(0, 200));

    const session = await adminWithSession(api);
    const res = await asAdmin(api.post(`/api/admin/verifications/${verification._id}/approve`), session).send({ adminNotes: 'ok' });
    assert.equal(res.status, 200, JSON.stringify(res.body).slice(0, 200));
    return { ...b, verification };
  }

  await t.test('a claim returns a code the client can share immediately', async () => {
    const c = await approvedClose();
    const claim = await post(`/api/properties/claim-deal-reward/${c.verification._id}`, c.cookies).send({});

    assert.equal(claim.status, 200, JSON.stringify(claim.body).slice(0, 200));
    assert.ok(claim.body.referral, 'the invitation belongs at the high point, not in settings');
    assert.match(claim.body.referral.code, /^DD[A-Z0-9]{4}$/);
    assert.ok(claim.body.referral.message.length > 10);

    const user = await M('User').findById(c.buyer._id).lean();
    assert.equal(user.referralCode, claim.body.referral.code, 'and it is the account\'s real code');
  });

  await t.test('an account that already has a code keeps it', async () => {
    const c = await approvedClose();
    await M('User').updateOne({ _id: c.buyer._id }, { $set: { referralCode: 'DDKEEP' } });
    const claim = await post(`/api/properties/claim-deal-reward/${c.verification._id}`, c.cookies).send({});
    assert.equal(claim.body.referral.code, 'DDKEEP');
  });

  await t.test('the reward itself is unaffected by the referral block', async () => {
    const c = await approvedClose();
    const claim = await post(`/api/properties/claim-deal-reward/${c.verification._id}`, c.cookies).send({});
    assert.ok(claim.body.reward.pointsAwarded > 0);
    assert.equal(claim.body.alreadyClaimed, false);
  });

  await t.test('generated codes avoid the characters people misread', async () => {
    for (let i = 0; i < 50; i += 1) {
      const code = randomReferralCode();
      assert.match(code, /^DD[A-HJ-NP-Z2-9]{4}$/, `${code} must avoid O/0 and I/1`);
    }
  });

  await t.test('a code is never handed out twice', async () => {
    const taken = randomReferralCode();
    const buyer = await makeBuyer();
    await M('User').updateOne({ _id: buyer._id }, { $set: { referralCode: taken } });
    for (let i = 0; i < 20; i += 1) {
      const code = await generateReferralCode();
      assert.notEqual(code, taken);
    }
  });
});

// ---------------------------------------------------------------------------

test('points lapse on inactivity', async (t) => {
  const KEY = 'POINTS_INACTIVITY_DAYS';
  let saved;
  const withDays = (days) => { saved = process.env[KEY]; process.env[KEY] = String(days); };
  const restore = () => { if (saved === undefined) delete process.env[KEY]; else process.env[KEY] = saved; };

  /** A wallet with points, last active `daysAgo` days ago. */
  async function wallet(daysAgo, points = 500) {
    const user = await makeBuyer();
    const w = await getOrCreateWallet(user._id);
    w.addTransaction({ type: 'earn', action: 'report_property', points, basePoints: points, multiplier: 1, description: 'fixture' });
    await w.save();
    await M('Reward').collection.updateOne(
      { _id: w._id },
      { $set: { updatedAt: new Date(Date.now() - daysAgo * DAY) } }
    );
    return { user, wallet: w };
  }

  await t.test('with the policy unset, nothing happens to anybody', async () => {
    await wallet(400);
    const result = await expirePoints({ now: new Date() });
    assert.equal(result.disabled, true);
    assert.equal(result.expired, 0);
    assert.equal(result.nudged, 0);
    assert.equal(await M('Notification').countDocuments({}), 0);
  });

  await t.test('the warning goes out before the lapse, naming the amount and the date', async () => {
    withDays(180);
    try {
      const w = await wallet(170);
      const result = await expirePoints({ now: new Date() });
      assert.equal(result.nudged, 1);
      assert.equal(result.expired, 0, 'a warning is not a forfeit');

      const note = await M('Notification').findOne({ user: w.user._id, type: 'points_expiring' }).lean();
      assert.match(note.message, /500 points/);
      assert.match(note.message, /₹\d+/);
      assert.match(note.message, /\d{1,2} [A-Z][a-z]+/);
      assert.equal(note.data.kind, 'dealReward');
    } finally { restore(); }
  });

  await t.test('the same person is not warned every night', async () => {
    withDays(180);
    try {
      await wallet(170);
      const first = await expirePoints({ now: new Date() });
      const second = await expirePoints({ now: new Date() });
      assert.equal(first.nudged, 1);
      assert.equal(second.nudged, 0);
    } finally { restore(); }
  });

  await t.test('past the window the balance is forfeited with a row that explains it', async () => {
    withDays(180);
    try {
      const w = await wallet(200);
      const result = await expirePoints({ now: new Date() });
      assert.equal(result.expired, 1);

      const after = await M('Reward').findOne({ user: w.user._id }).lean();
      assert.equal(after.availablePoints, 0);
      const forfeit = after.transactions.find((tx) => tx.action === 'points_expired');
      assert.ok(forfeit, 'a balance never vanishes without a row');
      assert.equal(forfeit.type, 'forfeit');
      assert.equal(forfeit.points, -500);
      assert.match(forfeit.description, /lapsed after 180 days/);
      assert.equal(after.totalPoints, 500, 'lifetime points and the tier they earned are not rewritten');
    } finally { restore(); }
  });

  await t.test('any activity resets the clock, which is the whole mechanic', async () => {
    withDays(180);
    try {
      const w = await wallet(200);
      // The person came back and earned something the same day.
      const live = await getOrCreateWallet(w.user._id);
      live.addTransaction({ type: 'earn', action: 'report_property', points: 100, basePoints: 100, multiplier: 1, description: 'came back' });
      await live.save();

      const result = await expirePoints({ now: new Date() });
      assert.equal(result.expired, 0, 'someone who used the product last week has abandoned nothing');
      const after = await M('Reward').findOne({ user: w.user._id }).lean();
      assert.equal(after.availablePoints, 600);
    } finally { restore(); }
  });

  await t.test('an empty wallet is never nudged and never forfeited', async () => {
    withDays(180);
    try {
      const user = await makeBuyer();
      const w = await getOrCreateWallet(user._id);
      await M('Reward').collection.updateOne({ _id: w._id }, { $set: { updatedAt: new Date(Date.now() - 400 * DAY) } });
      const result = await expirePoints({ now: new Date() });
      assert.equal(result.nudged, 0);
      assert.equal(result.expired, 0);
    } finally { restore(); }
  });

  await t.test('the forfeit tells the person, so a balance never disappears silently', async () => {
    withDays(180);
    try {
      const w = await wallet(200);
      await expirePoints({ now: new Date() });
      const notes = await M('Notification').find({ user: w.user._id, type: 'points_expiring' }).lean();
      assert.ok(notes.length >= 1);
      assert.ok(notes.some((n) => /expired/i.test(n.message)));
    } finally { restore(); }
  });

  await t.test('a nonsense policy value is treated as off, not as zero days', async () => {
    withDays('soon');
    try {
      await wallet(400);
      const result = await expirePoints({ now: new Date() });
      assert.equal(result.disabled, true);
      assert.equal(result.expired, 0);
    } finally { restore(); }
  });
});
