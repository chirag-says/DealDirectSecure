/**
 * Verify the Phase 5 batch-1 cleanup against dealdirect_dev.
 *
 *   node scripts/verify-phase5-cleanup-dev.mjs
 *
 * Two of the five items are observable at runtime and worth checking against
 * real data rather than fixtures:
 *
 *   5.10  the locality facet — the old path returned nothing, so the proof is
 *         that the new one returns something on data nobody wrote for this test
 *   5.4   the duplicate index declarations — the proof is the boot warnings
 *
 * This run is READ-ONLY. It creates nothing and deletes nothing; the counts at
 * the end are asserted equal to the counts at the start as a check on that
 * claim, not as cleanup.
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config({ path: '.env.development', quiet: true });

const ALLOWED_DATABASE = 'dealdirect_dev';
process.env.NODE_ENV = 'development';

// Capture duplicate-index warnings before any model is imported. Mongoose emits
// them at schema-compile time, which happens on the first import below.
const warnings = [];
process.on('warning', (w) => {
  if (/[Dd]uplicate schema index/.test(w.message)) warnings.push(w.message);
});

await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 20000 });
const dbName = mongoose.connection.name;
console.log(`connected: database=${dbName}  (read-only)\n`);
if (dbName !== ALLOWED_DATABASE) {
  console.error(`REFUSING: expected "${ALLOWED_DATABASE}", got "${dbName}".`);
  process.exit(1);
}

const Property = (await import('../models/Property.js')).default;
await import('../models/Admin.js');
await import('../models/userModel.js');
await import('../models/Role.js');
await import('../models/AdminSession.js');
await import('../models/UserSession.js');

const before = {
  properties: await Property.countDocuments(),
  users: await mongoose.connection.db.collection('users').countDocuments(),
};
console.log('baseline:', JSON.stringify(before), '\n');

let pass = 0, fail = 0;
const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? '  — ' + detail : ''}`);
  ok ? (pass += 1) : (fail += 1);
};

// -- 5.10 ------------------------------------------------------------------
console.log('5.10  the locality facet, on real dev data');

const withTop = await Property.countDocuments({ locality: { $exists: true, $ne: null, $ne: '' } });
const withNested = await Property.countDocuments({ 'address.locality': { $exists: true } });
console.log(`    properties with a top-level locality : ${withTop}`);
console.log(`    properties with address.locality     : ${withNested}`);
check('the data lives at the top level, as production also shows',
  withTop > 0 && withNested === 0,
  `top=${withTop} nested=${withNested}`);

// Take a real locality and query it the way the fixed controller does.
const sample = await Property.findOne({ locality: { $exists: true, $ne: null, $ne: '' } })
  .select('locality address.city').lean();

if (!sample) {
  check('a sample locality exists to query', false, 'dev has no locality data');
} else {
  const prefix = String(sample.locality).slice(0, 3);
  const regex = new RegExp(`^${prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'i');

  const fixed = await Property.aggregate([
    { $match: { locality: regex } },
    { $group: { _id: '$locality', city: { $first: '$address.city' } } },
    { $limit: 5 },
  ]);
  const old = await Property.aggregate([
    { $match: { 'address.locality': regex } },
    { $group: { _id: '$address.locality', city: { $first: '$address.city' } } },
    { $limit: 5 },
  ]);

  console.log(`    query prefix "${prefix}"`);
  console.log(`    old path (address.locality) returned : ${old.length}`);
  console.log(`    new path (locality) returned         : ${fixed.length}  ${JSON.stringify(fixed.map((f) => f._id))}`);
  check('the old path returned nothing', old.length === 0);
  check('the new path returns real localities', fixed.length > 0);

  // The free-text $or clause, isolated from address.area which can echo it.
  const bySearch = await Property.countDocuments({ locality: regex });
  check('the search clause matches on locality', bySearch > 0, `${bySearch} properties`);
}

// -- 5.4 -------------------------------------------------------------------
console.log('\n5.4  duplicate index declarations');
await new Promise((r) => setImmediate(r)); // let queued warnings flush
console.log(`    duplicate-index warnings emitted : ${warnings.length}`);
for (const w of warnings) console.log(`      ${w}`);
check('no model declares an index twice', warnings.length === 0);

// Both models must now DECLARE a TTL exactly once. That is what this batch
// changed, and it is the part that is in scope.
for (const [name, file] of [['AdminSession', 'AdminSession.js'], ['UserSession', 'UserSession.js']]) {
  // Comments stripped: each model now explains where its TTL lives, and the
  // explanation names expireAfterSeconds.
  const src = (await import('node:fs')).readFileSync(new URL(`../models/${file}`, import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
  const decls = [...src.matchAll(/expireAfterSeconds:\s*0/g)].length;
  check(`${name}: declares its TTL exactly once`, decls === 1, `${decls} declarations`);
}

// The DEPLOYED indexes are a separate matter, and this is where the duplicate
// declarations turn out not to have been cosmetic.
//
// AdminSession used to declare expiresAt twice: `index: true` inline AND an
// explicit TTL. Mongoose creates the inline one first, as a plain index. The
// TTL that follows has the same key with different options, so MongoDB refuses
// it (IndexOptionsConflict) and Mongoose never retries. UserSession declared
// its TTL inline, so nothing shadowed it.
//
// The result is visible below: two collections, same intent, different indexes.
// Admin sessions have never auto-expired here. Removing the duplicate
// declaration fixes what a FRESH environment builds; it cannot alter an index
// that already exists, because Mongoose only ever creates.
console.log('\n  deployed TTL state (reported, not changed):');
for (const [name, coll] of [['AdminSession', 'adminsessions'], ['UserSession', 'usersessions']]) {
  const idx = await mongoose.connection.db.collection(coll).indexes().catch(() => []);
  const e = idx.find((i) => i.name === 'expiresAt_1');
  const ttl = e && e.expireAfterSeconds !== undefined;
  console.log(`    ${name.padEnd(13)} expiresAt_1 = ${e ? (ttl ? `TTL(${e.expireAfterSeconds})` : 'PLAIN — expired rows are never removed') : 'ABSENT'}`);
}
console.log('    Correcting a deployed index is a database change, excluded from this batch.');

// -- read-only assertion ---------------------------------------------------
const after = {
  properties: await Property.countDocuments(),
  users: await mongoose.connection.db.collection('users').countDocuments(),
};
const drift = Object.keys(before).filter((k) => before[k] !== after[k]);
console.log('\nfinal   :', JSON.stringify(after));
console.log(drift.length ? `*** DRIFT in: ${drift.join(', ')} ***` : 'unchanged — the run wrote nothing');

console.log(`\nRESULT: ${pass} pass, ${fail} fail`);
await mongoose.disconnect();
process.exit(fail === 0 && drift.length === 0 ? 0 : 1);
