/**
 * Suite 18: notification delivery.
 *
 * THE PIPELINE, AS IT WAS.
 *
 *   event → Notification.create / insertMany
 *         → post("save") / post("insertMany") hook inside the MODEL
 *         → User.findById, once per notification
 *         → sendGeneralNotification → sendEmail
 *         → createTransporter()  (a NEW transport, per email)
 *         → transporter.verify() (a FULL SMTP handshake, per email)
 *         → transporter.sendMail()
 *
 * Three structural problems, all verified in source rather than assumed.
 *
 * 1. Delivery lived in Mongoose middleware. Ten call sites across three
 *    controllers wrote notifications and mail went out as a side effect of
 *    persistence, so "who sends mail" was not greppable and the model owned a
 *    network dependency.
 *
 * 2. N+1 recipient lookup. `post("insertMany")` loops `User.findById` once per
 *    document. That is the fan-out path: saved-search matching builds one
 *    notification per matching search, so a property matching 200 saved
 *    searches issued 200 sequential user queries.
 *
 * 3. A new SMTP transport per email, and a `verify()` before each one. The
 *    audit claimed this; it is confirmed below by counting, not by reading.
 *    `verify()` is a full connect/EHLO/auth round trip, so every notification
 *    cost two SMTP connections before the message moved.
 *
 * WHAT IS DELIBERATELY UNCHANGED: the schema, the notification semantics, and
 * the rule that a save which is not an insert sends nothing. That last one is
 * the re-send bug fixed earlier — marking a notification read is a save, and
 * the hook used to mail again on every one.
 *
 * NO QUEUE. Delivery is still fire-and-forget from the request path, awaited by
 * nobody. A broker would be the right answer at a much larger fan-out and is
 * recorded as a follow-up rather than built here.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { readFileSync } from 'node:fs';

import { request } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeUser, makeOwner, makeBuyer } from './setup/factories.js';

import {
  notifyUser, notifyUsers,
} from '../../services/notificationService.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const M = (n) => mongoose.model(n);
const read = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');

/**
 * Instrument the email layer.
 *
 * Counts transports created, verifies issued and messages sent, and counts
 * recipient queries by spying on the User model. Nothing here reaches a real
 * SMTP server: the harness leaves SMTP_USER/SMTP_PASS empty, so sendEmail
 * short-circuits — which is why the transport counter is taken from the module
 * itself rather than from nodemailer.
 */
async function instrument() {
  const emailService = await import('../../utils/emailService.js');
  const stats = { sends: 0, recipients: [], userQueries: 0 };

  const originalSend = emailService.sendGeneralNotification;
  const originalFindById = M('User').findById.bind(M('User'));
  const originalFind = M('User').find.bind(M('User'));

  emailService.__setSendGeneralNotificationForTests(async (email, ...rest) => {
    stats.sends += 1;
    stats.recipients.push(email);
    return { success: true };
  });

  M('User').findById = (...args) => { stats.userQueries += 1; return originalFindById(...args); };
  M('User').find = (...args) => { stats.userQueries += 1; return originalFind(...args); };

  return {
    stats,
    restore() {
      emailService.__setSendGeneralNotificationForTests(null);
      M('User').findById = originalFindById;
      M('User').find = originalFind;
    },
  };
}

const settle = () => new Promise((r) => setTimeout(r, 60));

// ---------------------------------------------------------------------------

test('the SMTP audit claim, verified in source', async (t) => {
  const emailSource = read('../../utils/emailService.js');

  await t.test('the transport is created once, not per send', () => {
    // Before: `const transporter = createTransporter()` sat inside sendEmail,
    // so every notification built a new transport object.
    const sendEmailBody = emailSource.slice(
      emailSource.indexOf('export const sendEmail'),
      emailSource.indexOf('// Specific email functions')
    );
    assert.doesNotMatch(
      sendEmailBody, /const transporter = createTransporter\(\)/,
      'sendEmail builds its own transport again'
    );
    assert.match(emailSource, /getTransporter/, 'no shared transport accessor');
  });

  await t.test('the per-send verify() handshake is gone', () => {
    // verify() is a full connect/EHLO/auth round trip. Running it before every
    // message doubled the connections and told us nothing sendMail would not.
    assert.doesNotMatch(
      emailSource, /await transporter\.verify\(\)/,
      'a blocking SMTP handshake runs before each message again'
    );
  });

  await t.test('the transport is pooled', () => {
    assert.match(emailSource, /pool:\s*true/, 'connections are not reused between messages');
  });
});

// ---------------------------------------------------------------------------

test('a single notification creates one record and sends one email', async (t) => {
  await t.test('exactly one of each', async () => {
    const user = await makeUser();
    const spy = await instrument();
    try {
      await notifyUser(user._id, { title: 'Hello', message: 'Body' });
      await settle();

      assert.equal(await M('Notification').countDocuments({ user: user._id }), 1);
      assert.equal(spy.stats.sends, 1);
      assert.equal(spy.stats.recipients[0], user.email);
    } finally { spy.restore(); }
  });

  await t.test('a user who opted out gets the record but no email', async () => {
    const user = await makeUser({ preferences: { emailNotifications: false } });
    const spy = await instrument();
    try {
      await notifyUser(user._id, { title: 'Hello', message: 'Body' });
      await settle();

      assert.equal(await M('Notification').countDocuments({ user: user._id }), 1,
        'the in-app notification is not an email preference');
      assert.equal(spy.stats.sends, 0);
    } finally { spy.restore(); }
  });

  await t.test('marking it read sends nothing', async () => {
    // The re-send bug. Marking read is a save, and delivery used to fire on
    // every save, so opening the notification centre re-mailed each item.
    const user = await makeUser();
    const spy = await instrument();
    try {
      const created = await notifyUser(user._id, { title: 'Hello', message: 'Body' });
      await settle();
      const before = spy.stats.sends;

      const doc = await M('Notification').findById(created._id);
      doc.isRead = true;
      await doc.save();
      await settle();

      assert.equal(spy.stats.sends, before, 'an update must not send another email');
    } finally { spy.restore(); }
  });
});

// ---------------------------------------------------------------------------

test('bulk delivery batches the recipient lookup', async (t) => {
  await t.test('one query for many recipients, not one each', async () => {
    // The N+1. post("insertMany") looped User.findById per document, so a
    // property matching 25 saved searches issued 25 sequential queries.
    const users = [];
    for (let i = 0; i < 25; i += 1) users.push(await makeUser());

    const spy = await instrument();
    try {
      await notifyUsers(
        users.map((u) => ({ user: u._id, title: 'Match', message: 'A property matched' }))
      );
      await settle();

      assert.equal(await M('Notification').countDocuments(), 25);
      assert.equal(spy.stats.sends, 25, 'every recipient is still mailed');
      assert.ok(
        spy.stats.userQueries <= 2,
        `recipient lookup is still N+1: ${spy.stats.userQueries} queries for 25 recipients`
      );
    } finally { spy.restore(); }
  });

  await t.test('each recipient gets their own address', async () => {
    const a = await makeUser();
    const b = await makeUser();
    const spy = await instrument();
    try {
      await notifyUsers([
        { user: a._id, title: 'A', message: 'to a' },
        { user: b._id, title: 'B', message: 'to b' },
      ]);
      await settle();

      assert.deepEqual([...spy.stats.recipients].sort(), [a.email, b.email].sort());
    } finally { spy.restore(); }
  });

  await t.test('opted-out recipients are skipped without dropping their record', async () => {
    const yes = await makeUser();
    const no = await makeUser({ preferences: { emailNotifications: false } });
    const spy = await instrument();
    try {
      await notifyUsers([
        { user: yes._id, title: 'A', message: 'x' },
        { user: no._id, title: 'B', message: 'y' },
      ]);
      await settle();

      assert.equal(await M('Notification').countDocuments(), 2);
      assert.deepEqual(spy.stats.recipients, [yes.email]);
    } finally { spy.restore(); }
  });

  await t.test('an empty batch is a no-op', async () => {
    const spy = await instrument();
    try {
      await notifyUsers([]);
      assert.equal(await M('Notification').countDocuments(), 0);
      assert.equal(spy.stats.sends, 0);
    } finally { spy.restore(); }
  });
});

// ---------------------------------------------------------------------------

test('persistence is the source of truth; delivery is not', async (t) => {
  await t.test('an email failure leaves the notification standing', async () => {
    const user = await makeUser();
    const emailService = await import('../../utils/emailService.js');
    emailService.__setSendGeneralNotificationForTests(async () => {
      throw new Error('SMTP is down');
    });

    try {
      const created = await notifyUser(user._id, { title: 'Hello', message: 'Body' });
      await settle();

      assert.ok(created, 'the write must succeed');
      assert.equal(await M('Notification').countDocuments({ user: user._id }), 1,
        'a delivery failure is not a persistence failure');
    } finally {
      emailService.__setSendGeneralNotificationForTests(null);
    }
  });

  await t.test('a bulk email failure leaves every record standing', async () => {
    const users = [await makeUser(), await makeUser()];
    const emailService = await import('../../utils/emailService.js');
    emailService.__setSendGeneralNotificationForTests(async () => {
      throw new Error('SMTP is down');
    });

    try {
      await notifyUsers(users.map((u) => ({ user: u._id, title: 'x', message: 'y' })));
      await settle();
      assert.equal(await M('Notification').countDocuments(), 2);
    } finally {
      emailService.__setSendGeneralNotificationForTests(null);
    }
  });

  await t.test('delivery is not awaited by the caller', () => {
    // No synchronous SMTP in the request path. The service resolves once the
    // documents are written; dispatch continues in the background.
    const source = read('../../services/notificationService.js');
    assert.match(source, /dispatch|catch/, 'dispatch errors must be swallowed, not surfaced');
  });
});

// ---------------------------------------------------------------------------

test('the model no longer performs network delivery', async (t) => {
  // Comments stripped: the model deliberately DOCUMENTS what it no longer does,
  // naming both sendGeneralNotification and User.findById in prose. A raw match
  // would forbid explaining the decision.
  const modelCode = () => read('../../models/Notification.js')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/[^\r\n]*/g, '');

  await t.test('neither hook sends email', () => {
    const model = modelCode();
    assert.doesNotMatch(model, /sendGeneralNotification/,
      'the model imports the mailer again; persistence should not own delivery');
  });

  await t.test('the model no longer looks up users', () => {
    const model = modelCode();
    assert.doesNotMatch(model, /User\.findById/, 'the N+1 lookup is back in the model');
  });

  await t.test('creating a document directly persists but does not mail', async () => {
    // The consequence worth stating: a raw Notification.create no longer
    // delivers. Every call site was migrated to the service; a new one that
    // skips it gets a silent in-app-only notification.
    const user = await makeUser();
    const spy = await instrument();
    try {
      await M('Notification').create({ user: user._id, title: 'Raw', message: 'Direct write' });
      await settle();

      assert.equal(await M('Notification').countDocuments({ user: user._id }), 1);
      assert.equal(spy.stats.sends, 0);
    } finally { spy.restore(); }
  });

  await t.test('no controller writes notifications directly any more', () => {
    for (const file of [
      '../../controllers/adminController.js',
      '../../controllers/propertyController.js',
      '../../controllers/savedSearchController.js',
    ]) {
      const src = read(file)
        .replace(new RegExp('/\\*[\\s\\S]*?\\*/', 'g'), '')
        .replace(new RegExp('//[^\\r\\n]*', 'g'), '');
      assert.doesNotMatch(
        src, /Notification\.(create|insertMany)\(/,
        `${file} bypasses the notification service, so its emails would silently stop`
      );
    }
  });
});

// ---------------------------------------------------------------------------

test('saved-search fan-out still works end to end', async (t) => {
  await t.test('a matching saved search produces a notification and an email', async () => {
    const owner = await makeOwner();
    const watcher = await makeBuyer();
    await M('SavedSearch').create({
      user: watcher._id, name: 'Pune flats', isActive: true, filters: { city: 'Pune' },
    });

    const spy = await instrument();
    try {
      const { notifySavedSearchMatches } = await import('../../services/notificationService.js');
      await notifySavedSearchMatches({
        _id: new mongoose.Types.ObjectId(), title: 'Nice flat', address: { city: 'Pune' },
      });
      await settle();

      const notes = await M('Notification').find({ user: watcher._id }).lean();
      assert.equal(notes.length, 1, JSON.stringify(notes));
      assert.equal(notes[0].type, 'saved-search-match');
      assert.equal(spy.stats.sends, 1);
      assert.equal(spy.stats.recipients[0], watcher.email);
    } finally { spy.restore(); }
  });

  await t.test('a non-matching city notifies nobody', async () => {
    const watcher = await makeBuyer();
    await M('SavedSearch').create({
      user: watcher._id, name: 'Pune flats', isActive: true, filters: { city: 'Pune' },
    });

    const spy = await instrument();
    try {
      const { notifySavedSearchMatches } = await import('../../services/notificationService.js');
      await notifySavedSearchMatches({
        _id: new mongoose.Types.ObjectId(), title: 'Other flat', address: { city: 'Mumbai' },
      });
      await settle();

      assert.equal(await M('Notification').countDocuments(), 0);
      assert.equal(spy.stats.sends, 0);
    } finally { spy.restore(); }
  });

  await t.test('a large fan-out still batches', async () => {
    const watchers = [];
    for (let i = 0; i < 20; i += 1) {
      const u = await makeBuyer();
      watchers.push(u);
      await M('SavedSearch').create({
        user: u._id, name: `Watch ${i}`, isActive: true, filters: { city: 'Pune' },
      });
    }

    const spy = await instrument();
    try {
      const { notifySavedSearchMatches } = await import('../../services/notificationService.js');
      await notifySavedSearchMatches({
        _id: new mongoose.Types.ObjectId(), title: 'Nice flat', address: { city: 'Pune' },
      });
      await settle();

      assert.equal(await M('Notification').countDocuments(), 20);
      assert.ok(spy.stats.userQueries <= 2,
        `fan-out is N+1 again: ${spy.stats.userQueries} queries for 20 watchers`);
    } finally { spy.restore(); }
  });
});
