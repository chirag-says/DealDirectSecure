/**
 * Verify the aggregate delete functions against dealdirect_dev.
 *
 *   node scripts/verify-aggregate-delete-dev.mjs
 *
 * Exercises the real functions against the real development database, so the
 * result covers the deployed indexes, the real connection and the real model
 * registration order. Refuses to run anywhere but dealdirect_dev, removes every
 * fixture it creates, and fails if the database does not return to baseline.
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';

import Property from '../models/Property.js';
import Builder from '../models/Builder.js';
import Project from '../models/Project.js';
import UnitType from '../models/UnitType.js';
import TransactionVerification from '../models/TransactionVerification.js';
import Agreement from '../models/Agreement.js';
import User from '../models/userModel.js';

import {
  assertPropertyDeletable, deletePropertyAggregate, deleteUnitTypeAggregate,
  deleteProjectAggregate, deleteBuilderAggregate, USER_CASCADE, DeleteBlockedError,
} from '../utils/aggregateDelete.js';

dotenv.config({ path: '.env.development', quiet: true });

const ALLOWED_DATABASE = 'dealdirect_dev';
const MARKER = 'AGG_DELETE_VERIFY';

await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 20000 });
const dbName = mongoose.connection.name;
console.log(`connected: database=${dbName} host=${mongoose.connection.host}\n`);

if (dbName !== ALLOWED_DATABASE) {
  console.error(`REFUSING: expected "${ALLOWED_DATABASE}", got "${dbName}".`);
  await mongoose.disconnect();
  process.exit(1);
}

const COUNTED = {
  properties: Property, builders: Builder, projects: Project, unittypes: UnitType,
  verifications: TransactionVerification, agreements: Agreement,
};
const baseline = {};
for (const [k, M] of Object.entries(COUNTED)) baseline[k] = await M.countDocuments();
console.log('baseline:', JSON.stringify(baseline), '\n');

let pass = 0, fail = 0;
const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? '  — ' + detail : ''}`);
  ok ? (pass += 1) : (fail += 1);
};

async function refuses(label, fn) {
  try { await fn(); check(label, false, 'the guard permitted it'); }
  catch (err) { check(label, err instanceof DeleteBlockedError, err.blockers?.join(' | ') || err.message); }
}
async function permits(label, fn) {
  try { await fn(); check(label, true); }
  catch (err) { check(label, false, `refused: ${err.message}`); }
}

const user = await User.findOne({}).lean();
const otherUser = await User.findOne({ _id: { $ne: user._id } }).lean();
const adminId = new mongoose.Types.ObjectId();

let seq = 0;
const made = { properties: [], builders: [], projects: [], unitTypes: [] };

const makeProp = async () => {
  const p = await Property.create({
    title: `${MARKER} ${++seq}`, owner: user._id, categoryName: 'Residential',
    propertyTypeName: 'Apartment / Flat', city: 'Testville', price: 1000000,
  });
  made.properties.push(p._id);
  return p;
};

async function makeChain() {
  const n = ++seq;
  const builder = await Builder.create({
    name: `${MARKER} ${n}`, phone: `96666${String(10000 + n).slice(-5)}`,
    email: `${MARKER.toLowerCase()}-${n}@example.invalid`, createdBy: adminId,
  });
  const project = await Project.create({ name: MARKER, builder: builder._id, createdBy: adminId });
  const unitType = await UnitType.create({ project: project._id, builder: builder._id, createdBy: adminId });
  made.builders.push(builder._id); made.projects.push(project._id); made.unitTypes.push(unitType._id);
  return { builder, project, unitType };
}

try {
  console.log('Property — deal and legal evidence blocks deletion');
  for (const status of ['pending', 'approved']) {
    const p = await makeProp();
    await TransactionVerification.create({
      property: p._id, owner: user._id, buyer: otherUser._id, closingType: 'sold',
      status, documentUrls: ['https://res.cloudinary.com/demo/image/upload/v1/x.pdf'],
    });
    await refuses(`${status} verification blocks`, () => assertPropertyDeletable(p._id));
  }
  {
    const p = await makeProp();
    await TransactionVerification.create({
      property: p._id, owner: user._id, buyer: otherUser._id, closingType: 'sold',
      status: 'rejected', documentUrls: ['https://res.cloudinary.com/demo/image/upload/v1/x.pdf'],
    });
    await permits('a rejected verification does not block', () => assertPropertyDeletable(p._id));
  }
  {
    const p = await makeProp();
    await Agreement.collection.insertOne({
      property: p._id, owner: user._id, buyer: otherUser._id, status: 'signed', createdAt: new Date(),
      // Unique per fixture: agreements.idempotencyKey_1 is deployed UNIQUE and
      // NOT sparse, so a second null collides. Same drift class as
      // builders.email_1; both belong to the deferred index-cleanup workstream.
      idempotencyKey: `${MARKER}-${seq}-signed`,
    });
    await refuses('a signed agreement blocks', () => assertPropertyDeletable(p._id));
  }
  {
    const p = await makeProp();
    await Agreement.collection.insertOne({
      property: p._id, owner: user._id, buyer: otherUser._id, status: 'terminated', createdAt: new Date(),
      idempotencyKey: `${MARKER}-${seq}-terminated`,
    });
    await permits('a terminated agreement does not block', () => assertPropertyDeletable(p._id));
  }

  console.log('\nProperty — a clean listing deletes through the aggregate');
  {
    const p = await makeProp();
    await deletePropertyAggregate(p);
    check('the document is gone', (await Property.findById(p._id)) === null);
  }

  console.log('\nBuilder chain — the a1651e9 guards still hold through the aggregates');
  {
    const c = await makeChain();
    await refuses('project with a unit type refuses', async () => {
      try { await deleteProjectAggregate(c.project._id); }
      catch (e) { if (e.code === 'DELETE_BLOCKED_UNIT_TYPES') throw new DeleteBlockedError([e.message]); throw e; }
    });
    await permits('unit type with nothing attached deletes', () => deleteUnitTypeAggregate(c.unitType._id));
    await permits('then the project deletes', () => deleteProjectAggregate(c.project._id));
  }
  {
    const c = await makeChain();
    const p = await Property.create({
      title: `${MARKER} approved`, owner: user._id, builder: c.builder._id, isApproved: true,
      categoryName: 'Residential', propertyTypeName: 'Villa', city: 'Testville', price: 1,
    });
    made.properties.push(p._id);
    let blocked = false;
    try { await deleteBuilderAggregate(c.builder._id); } catch (e) { blocked = e.code === 'DELETE_BLOCKED_PROPERTIES'; }
    check('builder with an approved property refuses', blocked);
    check('  ...and is NOT deactivated', (await Builder.findById(c.builder._id)).isActive === true);
  }
  {
    const c = await makeChain();
    const r = await deleteBuilderAggregate(c.builder._id);
    const after = await Builder.findById(c.builder._id);
    check('a clean builder is deactivated, not deleted', r?.deactivated === true && after && after.isActive === false);
  }

  console.log('\nUser cascade split is unchanged');
  check('12 deleted, 5 retained', USER_CASCADE.deleted.length === 12 && USER_CASCADE.retained.length === 5,
    `retained: ${USER_CASCADE.retained.join(', ')}`);
} finally {
  const removed = {
    verifications: (await TransactionVerification.deleteMany({ property: { $in: made.properties } })).deletedCount,
    agreements: (await Agreement.deleteMany({ property: { $in: made.properties } })).deletedCount,
    properties: (await Property.deleteMany({ _id: { $in: made.properties } })).deletedCount,
    unittypes: (await UnitType.deleteMany({ _id: { $in: made.unitTypes } })).deletedCount,
    projects: (await Project.deleteMany({ _id: { $in: made.projects } })).deletedCount,
    builders: (await Builder.deleteMany({ _id: { $in: made.builders } })).deletedCount,
  };
  console.log('\ncleanup:', JSON.stringify(removed));

  const final = {};
  for (const [k, M] of Object.entries(COUNTED)) final[k] = await M.countDocuments();
  const drift = Object.keys(baseline).filter((k) => baseline[k] !== final[k]);
  console.log('final   :', JSON.stringify(final));
  console.log(drift.length ? `*** DRIFT in: ${drift.join(', ')} ***` : 'back to baseline exactly');

  console.log(`\nRESULT: ${pass} pass, ${fail} fail`);
  await mongoose.disconnect();
  process.exitCode = fail === 0 && drift.length === 0 ? 0 : 1;
}
