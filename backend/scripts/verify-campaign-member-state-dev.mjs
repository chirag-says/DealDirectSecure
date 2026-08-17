/**
 * Verify the CampaignMember state contract against dealdirect_dev.
 *
 *   node scripts/verify-campaign-member-state-dev.mjs
 *
 * The integration suite proves this through HTTP against an in-memory replica
 * set. This exercises the real flow — the real post-save counter hook, the real
 * indexes, the real connection — against the development database.
 *
 * Refuses to run anywhere but dealdirect_dev. Every fixture it creates is
 * removed before it exits, and it reports the database back to baseline.
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';

import Builder from '../models/Builder.js';
import Project from '../models/Project.js';
import UnitType from '../models/UnitType.js';
import GroupBuyCampaign from '../models/GroupBuyCampaign.js';
import CampaignMember from '../models/CampaignMember.js';
import ProjectBooking from '../models/ProjectBooking.js';
import User from '../models/userModel.js';

import {
  assertSelfExitAllowed,
  reverseMembershipForCancelledBooking,
  CampaignMemberStateError,
  BOOKING_STATES_WITH_ENROLMENT,
} from '../utils/campaignMemberState.js';
import { assertUnitTypeDeletable, DeleteBlockedError } from '../utils/deleteGuard.js';

dotenv.config({ path: '.env.development', quiet: true });

const ALLOWED_DATABASE = 'dealdirect_dev';
const MARKER = 'CAMPAIGN_STATE_VERIFY';

await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 20000 });
const dbName = mongoose.connection.name;
console.log(`connected: database=${dbName} host=${mongoose.connection.host}\n`);

if (dbName !== ALLOWED_DATABASE) {
  console.error(`REFUSING: expected "${ALLOWED_DATABASE}", got "${dbName}".`);
  await mongoose.disconnect();
  process.exit(1);
}

const baseline = {};
for (const [k, M] of Object.entries({
  builders: Builder, projects: Project, unittypes: UnitType,
  campaigns: GroupBuyCampaign, members: CampaignMember, bookings: ProjectBooking,
})) baseline[k] = await M.countDocuments();
console.log('baseline:', JSON.stringify(baseline), '\n');

let pass = 0, fail = 0;
const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? '  — ' + detail : ''}`);
  ok ? (pass += 1) : (fail += 1);
};

const user = await User.findOne({}).lean();
const otherUser = await User.findOne({ _id: { $ne: user._id } }).lean();
const adminId = new mongoose.Types.ObjectId();

let seq = 0;
const chains = [];

async function makeChain() {
  const n = ++seq;
  const builder = await Builder.create({
    name: `${MARKER} ${n}`, phone: `93333${String(10000 + n).slice(-5)}`,
    email: `${MARKER.toLowerCase()}-${n}@example.invalid`, createdBy: adminId,
  });
  const project = await Project.create({ name: MARKER, builder: builder._id, createdBy: adminId });
  const unitType = await UnitType.create({ project: project._id, builder: builder._id, createdBy: adminId });
  const chain = { builder, project, unitType };
  chains.push(chain);
  return chain;
}

const makeCampaign = (chain) => GroupBuyCampaign.create({
  unitType: chain.unitType._id, project: chain.project._id, builder: chain.builder._id,
  createdBy: adminId,
  basics: { name: MARKER }, buyerTargets: { minBuyers: 5 },
  duration: { startDate: new Date('2026-01-01'), endDate: new Date('2026-12-31') },
  discountPerBuyer: 50000, status: 'active',
});

const makeMember = (campaign, userId, tokenStatus) =>
  CampaignMember.create({ campaign: campaign._id, user: userId, status: 'active', tokenStatus });

const makeBooking = (chain, userId, status) => ProjectBooking.create({
  project: chain.project._id, unitType: chain.unitType._id, builder: chain.builder._id,
  user: userId, clientName: MARKER, clientPhone: '9333300000',
  payment: { tokenAmount: 100000, utrNumber: `${MARKER}-UTR` }, status,
});

try {
  console.log('Self-exit contract');
  {
    const chain = await makeChain();
    const campaign = await makeCampaign(chain);
    const unpaid = await makeMember(campaign, user._id, 'pending');
    let threw = false;
    try { assertSelfExitAllowed(unpaid); } catch { threw = true; }
    check('an unpaid member may self-exit', !threw);

    const paid = await makeMember(campaign, otherUser._id, 'paid');
    try {
      assertSelfExitAllowed(paid);
      check('a paid member is refused', false, 'the guard permitted it');
    } catch (err) {
      check('a paid member is refused', err instanceof CampaignMemberStateError && err.code === 'CAMPAIGN_MEMBER_PAYMENT_PROTECTED',
        `${err.code} / ${err.status}`);
    }
  }

  console.log('\nBooking cancellation reverses only what it enrolled');
  for (const from of BOOKING_STATES_WITH_ENROLMENT) {
    const chain = await makeChain();
    const campaign = await makeCampaign(chain);
    const member = await makeMember(campaign, user._id, 'paid');
    const booking = await makeBooking(chain, user._id, from);

    const before = (await GroupBuyCampaign.findById(campaign._id)).paidMemberCount;
    const reversed = await reverseMembershipForCancelledBooking(booking, from);
    const after = await CampaignMember.findById(member._id).lean();
    const campaignAfter = await GroupBuyCampaign.findById(campaign._id).lean();

    check(`cancelling from ${from} reverses the derived member`,
      reversed === 1 && after.status === 'exited' && after.tokenStatus === 'paid',
      `paidMemberCount ${before} → ${campaignAfter.paidMemberCount}`);
    check(`  ...and it stops counting`, campaignAfter.paidMemberCount === 0);
    check(`  ...and tokenStatus is NOT refunded`, after.tokenStatus === 'paid');
  }

  for (const from of ['enquiry', 'payment_submitted']) {
    const chain = await makeChain();
    const campaign = await makeCampaign(chain);
    const member = await makeMember(campaign, user._id, 'paid');
    const booking = await makeBooking(chain, user._id, from);

    const reversed = await reverseMembershipForCancelledBooking(booking, from);
    const after = await CampaignMember.findById(member._id).lean();
    check(`cancelling from ${from} reverses nothing`, reversed === 0 && after.status === 'active');
  }

  console.log('\nScoping');
  {
    const chain = await makeChain();
    const campaign = await makeCampaign(chain);
    const mine = await makeMember(campaign, user._id, 'paid');

    const otherChain = await makeChain();
    const otherCampaign = await makeCampaign(otherChain);
    const unrelated = await makeMember(otherCampaign, user._id, 'paid');

    const booking = await makeBooking(chain, user._id, 'confirmed');
    await reverseMembershipForCancelledBooking(booking, 'confirmed');

    check('the booked campaign reverses', (await CampaignMember.findById(mine._id).lean()).status === 'exited');
    check("the same user's unrelated campaign is untouched",
      (await CampaignMember.findById(unrelated._id).lean()).status === 'active');
  }

  console.log('\nThe a1651e9 delete guards still hold after a reversal');
  {
    const chain = await makeChain();
    const campaign = await makeCampaign(chain);
    await makeMember(campaign, user._id, 'paid');
    const booking = await makeBooking(chain, user._id, 'confirmed');
    await reverseMembershipForCancelledBooking(booking, 'confirmed');

    try {
      await assertUnitTypeDeletable(chain.unitType._id);
      check('a reversed-but-paid member still blocks deletion', false, 'deletion was permitted');
    } catch (err) {
      check('a reversed-but-paid member still blocks deletion', err instanceof DeleteBlockedError, err.blockers?.join(' | '));
    }
  }

  console.log('\nNo refund state anywhere');
  check('zero CampaignMember documents are marked refunded',
    (await CampaignMember.countDocuments({ tokenStatus: 'refunded' })) === 0);
} finally {
  const builderIds = chains.map((c) => c.builder._id);
  const campaignIds = (await GroupBuyCampaign.find({ builder: { $in: builderIds } }, { _id: 1 }).lean()).map((c) => c._id);

  const removed = {
    members: (await CampaignMember.deleteMany({ campaign: { $in: campaignIds } })).deletedCount,
    campaigns: (await GroupBuyCampaign.deleteMany({ builder: { $in: builderIds } })).deletedCount,
    bookings: (await ProjectBooking.deleteMany({ builder: { $in: builderIds } })).deletedCount,
    unittypes: (await UnitType.deleteMany({ builder: { $in: builderIds } })).deletedCount,
    projects: (await Project.deleteMany({ builder: { $in: builderIds } })).deletedCount,
    builders: (await Builder.deleteMany({ _id: { $in: builderIds } })).deletedCount,
  };
  console.log('\ncleanup:', JSON.stringify(removed));

  const final = {};
  for (const [k, M] of Object.entries({
    builders: Builder, projects: Project, unittypes: UnitType,
    campaigns: GroupBuyCampaign, members: CampaignMember, bookings: ProjectBooking,
  })) final[k] = await M.countDocuments();

  const drift = Object.keys(baseline).filter((k) => baseline[k] !== final[k]);
  console.log('final   :', JSON.stringify(final));
  console.log(drift.length ? `*** DRIFT in: ${drift.join(', ')} ***` : 'back to baseline exactly');

  console.log(`\nRESULT: ${pass} pass, ${fail} fail`);
  await mongoose.disconnect();
  process.exitCode = fail === 0 && drift.length === 0 ? 0 : 1;
}
