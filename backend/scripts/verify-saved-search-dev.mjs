/**
 * Exercise saved-search matching against dealdirect_dev (Phase 4.2).
 *
 *   node scripts/verify-saved-search-dev.mjs
 *
 * dealdirect_dev holds zero saved searches, so this creates temporary ones,
 * runs the real matching path, and removes them. It checks recipients for false
 * positives and false negatives, and measures how many candidate documents the
 * database returns — which is the change: the city test now runs in Mongo, so
 * non-matching watchers no longer cross the wire.
 *
 * Fixtures are marker-scoped and the run asserts the database returns to
 * baseline.
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';

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

const SavedSearch = (await import('../models/SavedSearch.js')).default;
const Notification = (await import('../models/Notification.js')).default;
const User = (await import('../models/userModel.js')).default;
const emailService = await import('../utils/emailService.js');
const { notifySavedSearchMatches } = await import('../services/notificationService.js');

const MARKER = 'SS_PREDICATE_VERIFY';

const baseline = {
  savedSearches: await SavedSearch.countDocuments(),
  notifications: await Notification.countDocuments(),
};
console.log('baseline:', JSON.stringify(baseline), '\n');

let pass = 0, fail = 0;
const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? '  — ' + detail : ''}`);
  ok ? (pass += 1) : (fail += 1);
};

// Never mail an anonymised dev address.
emailService.__setSendGeneralNotificationForTests(async () => ({ success: true }));

const made = { searches: [], notifications: [] };

try {
  const users = await User.find({}).select('_id').limit(12).lean();
  if (users.length < 12) throw new Error(`need 12 users in dev, found ${users.length}`);

  // 4 watch Verifyville, 4 watch Othertown, 2 watch nothing, 2 are inactive.
  const plan = [
    ...users.slice(0, 4).map((u) => ({ u, city: 'Verifyville', isActive: true })),
    ...users.slice(4, 8).map((u) => ({ u, city: 'Othertown', isActive: true })),
    ...users.slice(8, 10).map((u) => ({ u, city: '', isActive: true })),
    ...users.slice(10, 12).map((u) => ({ u, city: 'Verifyville', isActive: false })),
  ];

  for (const p of plan) {
    const s = await SavedSearch.create({
      user: p.u._id, name: `${MARKER} ${p.city || 'anywhere'}`,
      isActive: p.isActive, filters: { city: p.city },
    });
    made.searches.push(s._id);
  }
  console.log(`fixtures: ${made.searches.length} saved searches ` +
    `(4 Verifyville, 4 Othertown, 2 unfiltered, 2 inactive)\n`);

  // Count what the database actually returns as candidates.
  let candidates = 0;
  const originalFind = SavedSearch.find.bind(SavedSearch);
  SavedSearch.find = (...args) => {
    const q = originalFind(...args);
    const originalThen = q.then.bind(q);
    q.then = (res, rej) => originalThen((docs) => { candidates = docs.length; return res(docs); }, rej);
    return q;
  };

  const before = await Notification.countDocuments({ type: 'saved-search-match' });
  const docs = await notifySavedSearchMatches({
    _id: new mongoose.Types.ObjectId(),
    title: `${MARKER} property`,
    address: { city: 'verifyVILLE' }, // deliberately mixed case
    price: 9_000_000,
  });
  SavedSearch.find = originalFind;
  made.notifications.push(...docs.map((d) => d._id));

  console.log('Candidate documents returned by the query');
  console.log(`    active saved searches in the collection : 10`);
  console.log(`    candidates returned to Node             : ${candidates}`);
  console.log(`    (4 Verifyville + 2 unfiltered = 6 could possibly match)`);
  check('the database filtered the city, not JavaScript', candidates === 6,
    `${candidates} crossed the wire; 6 is the correct candidate set`);

  console.log('\nRecipients');
  const notified = (await Notification.find({
    type: 'saved-search-match', _id: { $in: made.notifications },
  }).lean()).map((n) => String(n.user));

  const expected = [...users.slice(0, 4), ...users.slice(8, 10)].map((u) => String(u._id));

  check('correct recipient count', notified.length === 6, `${notified.length} notified`);
  check('no duplicates', new Set(notified).size === notified.length);
  check('no false positives', notified.every((id) => expected.includes(id)),
    'someone watching Othertown or inactive was notified');
  check('no false negatives', expected.every((id) => notified.includes(id)),
    'a Verifyville or unfiltered watcher was missed');
  check('case-insensitive match worked', notified.length === 6,
    'the property city was "verifyVILLE", the searches say "Verifyville"');
  check('the notification count moved by exactly six',
    (await Notification.countDocuments({ type: 'saved-search-match' })) === before + 6);
} finally {
  emailService.__setSendGeneralNotificationForTests(null);

  const removed = {
    notifications: (await Notification.deleteMany({ _id: { $in: made.notifications } })).deletedCount,
    savedSearches: (await SavedSearch.deleteMany({ _id: { $in: made.searches } })).deletedCount,
  };
  console.log('\ncleanup:', JSON.stringify(removed));

  const final = {
    savedSearches: await SavedSearch.countDocuments(),
    notifications: await Notification.countDocuments(),
  };
  const drift = Object.keys(baseline).filter((k) => baseline[k] !== final[k]);
  console.log('final   :', JSON.stringify(final));
  console.log(drift.length ? `*** DRIFT in: ${drift.join(', ')} ***` : 'back to baseline exactly');

  console.log(`\nRESULT: ${pass} pass, ${fail} fail`);
  await mongoose.disconnect();
  process.exit(fail === 0 && drift.length === 0 ? 0 : 1);
}
