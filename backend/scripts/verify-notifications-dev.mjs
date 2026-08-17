/**
 * Exercise the notification pipeline against dealdirect_dev.
 *
 *   node scripts/verify-notifications-dev.mjs
 *
 * Counts recipient queries and delivery attempts against the real database, so
 * the N+1 claim and its fix are measured rather than asserted from source.
 * Delivery is stubbed: dealdirect_dev shares no SMTP credentials and this must
 * never mail a real anonymised address.
 *
 * Refuses to run anywhere but dealdirect_dev and fails if the database does not
 * return to baseline.
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';

import Notification from '../models/Notification.js';
import SavedSearch from '../models/SavedSearch.js';
import User from '../models/userModel.js';
import * as emailService from '../utils/emailService.js';
import { notifyUser, notifyUsers, notifySavedSearchMatches } from '../services/notificationService.js';

dotenv.config({ path: '.env.development', quiet: true });

const ALLOWED_DATABASE = 'dealdirect_dev';
const MARKER = 'NOTIFY_VERIFY';

await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 20000 });
const dbName = mongoose.connection.name;
console.log(`connected: database=${dbName} host=${mongoose.connection.host}\n`);

if (dbName !== ALLOWED_DATABASE) {
  console.error(`REFUSING: expected "${ALLOWED_DATABASE}", got "${dbName}".`);
  await mongoose.disconnect();
  process.exit(1);
}

const COUNTED = { notifications: Notification, savedSearches: SavedSearch, users: User };
const baseline = {};
for (const [k, M] of Object.entries(COUNTED)) baseline[k] = await M.countDocuments();
console.log('baseline:', JSON.stringify(baseline), '\n');

let pass = 0, fail = 0;
const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? '  — ' + detail : ''}`);
  ok ? (pass += 1) : (fail += 1);
};

// Instrument: count sends, and count recipient queries on the real model.
const stats = { sends: 0, recipients: [], userQueries: 0 };
emailService.__setSendGeneralNotificationForTests(async (email) => {
  stats.sends += 1;
  stats.recipients.push(email);
  return { success: true };
});
const origFindById = User.findById.bind(User);
const origFind = User.find.bind(User);
User.findById = (...a) => { stats.userQueries += 1; return origFindById(...a); };
User.find = (...a) => { stats.userQueries += 1; return origFind(...a); };

const settle = () => new Promise((r) => setTimeout(r, 200));
const made = { notifications: [], savedSearches: [] };

try {
  const users = await User.find({}).select('_id email').limit(30).lean();
  if (users.length < 20) throw new Error(`need 20 users in dev, found ${users.length}`);

  console.log('Single notification');
  {
    stats.sends = 0; stats.userQueries = 0; stats.recipients = [];
    const doc = await notifyUser(users[0]._id, { title: MARKER, message: 'one', type: MARKER });
    made.notifications.push(doc._id);
    await settle();
    check('one record written', !!(await Notification.findById(doc._id)));
    check('one email attempted', stats.sends === 1, `sends=${stats.sends}`);
    check('one recipient query', stats.userQueries === 1, `queries=${stats.userQueries}`);
  }

  console.log('\nUpdating it sends nothing');
  {
    const before = stats.sends;
    const doc = await Notification.findById(made.notifications[0]);
    doc.isRead = true;
    await doc.save();
    await settle();
    check('no additional email on update', stats.sends === before, `sends=${stats.sends}`);
  }

  console.log('\nBulk fan-out is batched, not N+1');
  {
    stats.sends = 0; stats.userQueries = 0;
    const batch = users.slice(0, 20).map((u) => ({
      user: u._id, title: MARKER, message: 'bulk', type: MARKER,
    }));
    const docs = await notifyUsers(batch);
    made.notifications.push(...docs.map((d) => d._id));
    await settle();

    check('20 records written', docs.length === 20);
    check('20 emails attempted', stats.sends === 20, `sends=${stats.sends}`);
    check('recipient lookup is ONE query, not 20',
      stats.userQueries === 1, `queries=${stats.userQueries} for 20 recipients`);
  }

  console.log('\nSaved-search fan-out end to end');
  {
    stats.sends = 0; stats.userQueries = 0;
    for (const u of users.slice(0, 15)) {
      const s = await SavedSearch.create({
        user: u._id, name: `${MARKER} watch`, isActive: true,
        filters: { city: 'Verifyville' },
      });
      made.savedSearches.push(s._id);
    }

    const docs = await notifySavedSearchMatches({
      _id: new mongoose.Types.ObjectId(),
      title: `${MARKER} property`,
      address: { city: 'Verifyville' },
      price: 1000000,
    });
    made.notifications.push(...docs.map((d) => d._id));
    await settle();

    check('15 matching watchers notified', docs.length === 15, `docs=${docs.length}`);
    check('15 emails attempted', stats.sends === 15, `sends=${stats.sends}`);
    check('still one recipient query', stats.userQueries === 1, `queries=${stats.userQueries}`);
  }

  console.log('\nDelivery failure does not undo persistence');
  {
    emailService.__setSendGeneralNotificationForTests(async () => { throw new Error('SMTP down'); });
    const doc = await notifyUser(users[0]._id, { title: MARKER, message: 'fail', type: MARKER });
    made.notifications.push(doc._id);
    await settle();
    check('the record survives a failed send', !!(await Notification.findById(doc._id)));
    emailService.__setSendGeneralNotificationForTests(async (email) => {
      stats.sends += 1; stats.recipients.push(email); return { success: true };
    });
  }

  console.log('\nTransport is a shared, pooled singleton');
  {
    const src = (await import('node:fs')).readFileSync('utils/emailService.js', 'utf8');
    check('pooled', /pool:\s*true/.test(src));
    check('no per-send verify()', !/await transporter\.verify\(\)/.test(src));
    check('single accessor', /getTransporter/.test(src));
  }
} finally {
  emailService.__setSendGeneralNotificationForTests(null);
  User.findById = origFindById;
  User.find = origFind;

  const removed = {
    notifications: (await Notification.deleteMany({ _id: { $in: made.notifications } })).deletedCount,
    savedSearches: (await SavedSearch.deleteMany({ _id: { $in: made.savedSearches } })).deletedCount,
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
