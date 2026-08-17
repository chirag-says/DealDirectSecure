/**
 * Verify the delete refusal guards against dealdirect_dev.
 *
 *   node scripts/verify-delete-guards-dev.mjs
 *
 * The integration suite proves the guards through the HTTP layer, but it runs
 * against an in-memory replica set. This exercises the same functions against
 * the real development database, so the result also covers the real indexes,
 * the real Mongoose connection and the real model registration order.
 *
 * Writes are scoped to fixtures this script creates and deletes. It refuses to
 * run anywhere but dealdirect_dev, and it never touches pre-existing documents:
 * every fixture carries a marker field and cleanup deletes on that marker only.
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';

import Builder from '../models/Builder.js';
import Project from '../models/Project.js';
import UnitType from '../models/UnitType.js';
import GroupBuyCampaign from '../models/GroupBuyCampaign.js';
import CampaignMember from '../models/CampaignMember.js';
import ProjectBooking from '../models/ProjectBooking.js';
import Admin from '../models/Admin.js';
import User from '../models/userModel.js';

import {
  assertUnitTypeDeletable, assertProjectDeletable, DeleteBlockedError,
} from '../utils/deleteGuard.js';

dotenv.config({ path: '.env.development', quiet: true });

const ALLOWED_DATABASE = 'dealdirect_dev';
const MARKER = 'DELETE_GUARD_VERIFY_FIXTURE';

await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 20000 });

const dbName = mongoose.connection.name;
console.log(`connected: database=${dbName} host=${mongoose.connection.host}\n`);

if (dbName !== ALLOWED_DATABASE) {
  console.error(`REFUSING: expected "${ALLOWED_DATABASE}", got "${dbName}".`);
  await mongoose.disconnect();
  process.exit(1);
}

let pass = 0;
let fail = 0;

const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? '  — ' + detail : ''}`);
  ok ? (pass += 1) : (fail += 1);
};

/** Run a guard and report whether it refused. */
async function refuses(label, fn) {
  try {
    await fn();
    check(label, false, 'the guard permitted the delete');
  } catch (err) {
    if (err instanceof DeleteBlockedError) {
      check(label, true, err.blockers.join(' | '));
    } else {
      check(label, false, `unexpected error: ${err.message}`);
    }
  }
}

async function permits(label, fn) {
  try {
    await fn();
    check(label, true);
  } catch (err) {
    check(label, false, `refused: ${err.message}`);
  }
}

let seq = 0;

async function makeChain(adminId) {
  // Unique phone AND email per fixture. `builders.email_1` is deployed UNIQUE
  // and NOT sparse in both dealdirect_dev and production, even though the
  // schema declares it `{ sparse: true }` and non-unique, so a second document
  // with a null email collides. Reported separately; worked around here.
  const n = ++seq;
  const builder = await Builder.create({
    name: `${MARKER} ${n}`,
    phone: `90000${String(10000 + n).slice(-5)}`,
    email: `delete-guard-verify-${n}@example.invalid`,
    createdBy: adminId,
  });
  const project = await Project.create({ name: MARKER, builder: builder._id, createdBy: adminId });
  const unitType = await UnitType.create({ project: project._id, builder: builder._id, createdBy: adminId });
  return { builder, project, unitType };
}

const campaignFor = (chain, adminId, status) => GroupBuyCampaign.create({
  unitType: chain.unitType._id, project: chain.project._id, builder: chain.builder._id,
  createdBy: adminId,
  basics: { name: MARKER },
  buyerTargets: { minBuyers: 5 },
  duration: { startDate: new Date('2026-01-01'), endDate: new Date('2026-12-31') },
  discountPerBuyer: 50000,
  status,
});

const bookingFor = (chain, status) => ProjectBooking.create({
  project: chain.project._id, unitType: chain.unitType._id, builder: chain.builder._id,
  clientName: MARKER, clientPhone: '9000000002', status,
});

// `createdBy` is a ref and Mongoose does not verify that the target exists, so
// a synthetic id is enough. dealdirect_dev carries no admin accounts: the
// anonymised copy deliberately left them out, and inventing one here would put
// a login-capable document into the database to satisfy a foreign key.
const existingAdmin = await Admin.findOne({}).lean();
const admin = existingAdmin || { _id: new mongoose.Types.ObjectId() };
console.log(existingAdmin
  ? 'using an existing admin as createdBy'
  : 'no admin in dealdirect_dev — using a synthetic createdBy id (never persisted as an Admin)');

const user = await User.findOne({}).lean();
if (!user) {
  console.error('dealdirect_dev has no user to reference. Aborting.');
  await mongoose.disconnect();
  process.exit(1);
}
console.log('');

const created = [];
const track = (chain) => { created.push(chain); return chain; };

try {
  console.log('UnitType — a campaign in any state must block deletion');
  for (const status of ['active', 'paused', 'completed', 'expired', 'cancelled']) {
    const chain = track(await makeChain(admin._id));
    await campaignFor(chain, admin._id, status);
    await refuses(`${status} campaign`, () => assertUnitTypeDeletable(chain.unitType._id));
  }

  console.log('\nUnitType — paid money must block deletion');
  {
    const chain = track(await makeChain(admin._id));
    const campaign = await campaignFor(chain, admin._id, 'completed');
    await CampaignMember.create({
      campaign: campaign._id, user: user._id, tokenStatus: 'paid',
      paymentReference: MARKER, paymentProofUrl: 'https://example.invalid/proof.png',
    });
    await refuses('paid member under a COMPLETED campaign', () => assertUnitTypeDeletable(chain.unitType._id));
  }

  console.log('\nUnitType — a live booking must block deletion');
  for (const status of ['enquiry', 'payment_submitted', 'confirmed', 'completed']) {
    const chain = track(await makeChain(admin._id));
    await bookingFor(chain, status);
    await refuses(`${status} booking`, () => assertUnitTypeDeletable(chain.unitType._id));
  }
  {
    const chain = track(await makeChain(admin._id));
    await bookingFor(chain, 'cancelled');
    await permits('cancelled booking does not block', () => assertUnitTypeDeletable(chain.unitType._id));
  }

  console.log('\nProject — a live booking must block deletion');
  {
    const chain = track(await makeChain(admin._id));
    await bookingFor(chain, 'confirmed');
    await refuses('confirmed booking', () => assertProjectDeletable(chain.project._id));
  }
  {
    const chain = track(await makeChain(admin._id));
    await bookingFor(chain, 'cancelled');
    await permits('cancelled booking does not block', () => assertProjectDeletable(chain.project._id));
  }

  console.log('\nClean fixtures must still be deletable');
  {
    const chain = track(await makeChain(admin._id));
    await permits('unit type with no dependents', () => assertUnitTypeDeletable(chain.unitType._id));
    await permits('project with no bookings', () => assertProjectDeletable(chain.project._id));
  }

  console.log('\nDenormalised counters must not decide the outcome');
  {
    const chain = track(await makeChain(admin._id));
    await campaignFor(chain, admin._id, 'active');
    await UnitType.findByIdAndUpdate(chain.unitType._id, { activeCampaignCount: 0 });
    await refuses('counter says 0, a campaign exists', () => assertUnitTypeDeletable(chain.unitType._id));
  }
  {
    const chain = track(await makeChain(admin._id));
    await UnitType.findByIdAndUpdate(chain.unitType._id, { activeCampaignCount: 9 });
    await permits('counter says 9, nothing exists', () => assertUnitTypeDeletable(chain.unitType._id));
  }
} finally {
  // Cleanup, marker-scoped. Campaign members go first so nothing is orphaned
  // even if this script is interrupted partway.
  const builderIds = created.map((c) => c.builder._id);
  const projectIds = created.map((c) => c.project._id);
  const unitTypeIds = created.map((c) => c.unitType._id);
  const campaigns = await GroupBuyCampaign.find({ builder: { $in: builderIds } }, { _id: 1 }).lean();

  const removed = {
    campaignMembers: (await CampaignMember.deleteMany({ campaign: { $in: campaigns.map((c) => c._id) } })).deletedCount,
    campaigns: (await GroupBuyCampaign.deleteMany({ builder: { $in: builderIds } })).deletedCount,
    bookings: (await ProjectBooking.deleteMany({ builder: { $in: builderIds } })).deletedCount,
    unitTypes: (await UnitType.deleteMany({ _id: { $in: unitTypeIds } })).deletedCount,
    projects: (await Project.deleteMany({ _id: { $in: projectIds } })).deletedCount,
    builders: (await Builder.deleteMany({ _id: { $in: builderIds } })).deletedCount,
  };

  console.log('\ncleanup:', JSON.stringify(removed));
  const leaked = await Builder.countDocuments({ name: { $regex: "^" + MARKER } });
  console.log(`fixtures remaining: ${leaked}`);

  console.log(`\nRESULT: ${pass} pass, ${fail} fail`);
  await mongoose.disconnect();
  process.exitCode = fail === 0 && leaked === 0 ? 0 : 1;
}
