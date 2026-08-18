/**
 * Measure the reward read projection against dealdirect_dev (Phase 4.5).
 *
 *   node scripts/verify-reward-projection-dev.mjs
 *
 * Reports BSON size loaded per read, with and without the transaction array,
 * and confirms which reads still hydrate it. Read-only apart from one
 * trackDailyLogin call, which is what the projected save has to be proven safe
 * on — the wallet it touches is restored afterwards and the run asserts the
 * database is unchanged.
 *
 * No timings are taken and no latency claim is made.
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { BSON } from 'bson';

dotenv.config({ path: '.env.development', quiet: true });

const ALLOWED_DATABASE = 'dealdirect_dev';
process.env.NODE_ENV = 'development';

await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 20000 });
const dbName = mongoose.connection.name;
console.log(`connected: database=${dbName}\n`);
if (dbName !== ALLOWED_DATABASE) {
  console.error(`REFUSING: expected "${ALLOWED_DATABASE}", got "${dbName}".`);
  process.exit(1);
}

const Reward = (await import('../models/Reward.js')).default;
const { getOrCreateWallet, trackDailyLogin } = await import('../services/rewardService.js');

const baseline = {
  wallets: await Reward.countDocuments(),
  transactions: (await Reward.aggregate([
    { $group: { _id: null, n: { $sum: { $size: { $ifNull: ['$transactions', []] } } } } },
  ]))[0]?.n ?? 0,
};
console.log('baseline:', JSON.stringify(baseline), '\n');

let pass = 0, fail = 0;
const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? '  — ' + detail : ''}`);
  ok ? (pass += 1) : (fail += 1);
};

const sizeOf = (doc) => BSON.calculateObjectSize(JSON.parse(JSON.stringify(doc)));
const kb = (n) => `${(n / 1024).toFixed(2)} KB`;

// The busiest wallet is where a projection matters most.
const [busiest] = await Reward.aggregate([
  { $project: { user: 1, n: { $size: { $ifNull: ['$transactions', []] } } } },
  { $sort: { n: -1 } },
  { $limit: 1 },
]);

if (!busiest) {
  console.error('dealdirect_dev holds no reward wallets. Nothing to measure.');
  await mongoose.disconnect();
  process.exit(1);
}

console.log(`busiest wallet: ${busiest.n} transactions\n`);

console.log('Bytes loaded per read');
{
  const full = await Reward.findOne({ user: busiest.user });
  const projected = await Reward.findOne({ user: busiest.user }, { transactions: 0 });

  const fullBytes = sizeOf(full.toObject());
  const projectedBytes = sizeOf(projected.toObject());

  console.log(`    full read       ${String(full.transactions.length).padStart(3)} transactions   ${kb(fullBytes).padStart(10)}`);
  console.log(`    projected read  ${String(projected.transactions?.length ?? 0).padStart(3)} transactions   ${kb(projectedBytes).padStart(10)}`);
  console.log(`    saved           ${kb(fullBytes - projectedBytes).padStart(10)}  (${(100 * (1 - projectedBytes / fullBytes)).toFixed(1)}% smaller)`);

  check('the projected read carries no transactions',
    (projected.transactions?.length ?? 0) === 0);
  check('the projected read is smaller', projectedBytes < fullBytes,
    `${kb(projectedBytes)} vs ${kb(fullBytes)}`);
  check('the fields the summary paths need survive',
    projected.totalPoints !== undefined && projected.tier !== undefined,
    `totalPoints=${projected.totalPoints} tier=${projected.tier}`);
}

console.log('\nWhat each accessor now loads');
{
  const withT = await getOrCreateWallet(busiest.user);
  const withoutT = await getOrCreateWallet(busiest.user, { withTransactions: false });

  console.log(`    getOrCreateWallet()                          transactions=${withT.transactions.length}`);
  console.log(`    getOrCreateWallet({withTransactions:false})   transactions=${withoutT.transactions?.length ?? 0}`);

  check('the default still hydrates', withT.transactions.length === busiest.n);
  check('the opt-out does not', (withoutT.transactions?.length ?? 0) === 0);
}

console.log('\nThe projected save does not destroy history');
{
  const before = await Reward.findOne({ user: busiest.user }).lean();
  const savedLoginDate = before.lastLoginDate;

  // Force the write path rather than the already-tracked early return.
  await Reward.updateOne({ user: busiest.user }, { $set: { lastLoginDate: '1970-01-01' } });
  await trackDailyLogin(busiest.user);

  const after = await Reward.findOne({ user: busiest.user }).lean();
  check('every transaction survived a projected save',
    after.transactions.length === before.transactions.length,
    `${before.transactions.length} before, ${after.transactions.length} after`);
  check('points and tier are unchanged',
    after.totalPoints === before.totalPoints && after.tier === before.tier);

  // Restore the field this check had to move.
  await Reward.updateOne(
    { user: busiest.user },
    savedLoginDate === undefined
      ? { $unset: { lastLoginDate: '' }, $set: { monthlyLoginDays: before.monthlyLoginDays } }
      : { $set: { lastLoginDate: savedLoginDate, monthlyLoginDays: before.monthlyLoginDays } }
  );
  const restored = await Reward.findOne({ user: busiest.user }).lean();
  check('the wallet was restored', restored.lastLoginDate === savedLoginDate,
    `lastLoginDate=${restored.lastLoginDate}`);
}

const final = {
  wallets: await Reward.countDocuments(),
  transactions: (await Reward.aggregate([
    { $group: { _id: null, n: { $sum: { $size: { $ifNull: ['$transactions', []] } } } } },
  ]))[0]?.n ?? 0,
};
const drift = Object.keys(baseline).filter((k) => baseline[k] !== final[k]);
console.log('\nfinal   :', JSON.stringify(final));
console.log(drift.length ? `*** DRIFT in: ${drift.join(', ')} ***` : 'back to baseline exactly');

console.log(`\nRESULT: ${pass} pass, ${fail} fail`);
await mongoose.disconnect();
process.exit(fail === 0 && drift.length === 0 ? 0 : 1);
