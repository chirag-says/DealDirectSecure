/**
 * Notification duplicate-send invariant
 *
 * INVARIANT: a notification sends its email exactly once, when it is created.
 * Saving it again — which is what marking it read does — must send nothing.
 *
 * These drive the real registered hooks on the real schema (no database, no
 * stubbed copy of the logic), so the assertions fail if the guard is removed
 * or the hook is rewired.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §16.2 F-N2.
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import Notification from '../models/Notification.js';

const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
const read = (rel) => stripComments(readFileSync(new URL(rel, import.meta.url), 'utf8'));

const notificationModel = read('../models/Notification.js');
const notificationController = read('../controllers/notificationController.js');

const hooks = Notification.schema.s.hooks;
const runPreSave = (doc) =>
  new Promise((resolve, reject) =>
    hooks.execPre('save', doc, [], (err) => (err ? reject(err) : resolve()))
  );

const makeDoc = () =>
  new Notification({
    user: '507f1f77bcf86cd799439011',
    title: 'Claim Your Reward',
    message: 'Your deal was verified.',
    data: { actionUrl: '/notifications' },
  });

/** The guard the post('save') hook applies before sending. */
const wouldSendEmail = (doc) => Boolean(doc.$locals?.wasNew);

describe('notification email fires once, on creation', () => {
  let doc;
  beforeEach(() => {
    doc = makeDoc();
  });

  test('a newly created notification is marked as an insert', async () => {
    assert.equal(doc.isNew, true);
    await runPreSave(doc);
    assert.equal(doc.$locals.wasNew, true);
    assert.equal(wouldSendEmail(doc), true, 'creation must send exactly one email');
  });

  test('re-saving the same document sends nothing', async () => {
    await runPreSave(doc);
    assert.equal(wouldSendEmail(doc), true);

    // Mongoose clears isNew once the insert lands; this is the state a
    // subsequent save sees.
    doc.isNew = false;

    doc.isRead = true; // what markNotificationRead does
    await runPreSave(doc);
    assert.equal(doc.$locals.wasNew, false);
    assert.equal(wouldSendEmail(doc), false, 'marking read must not re-send the email');
  });

  test('reading the same notification repeatedly sends nothing each time', async () => {
    await runPreSave(doc);
    doc.isNew = false;

    let sends = 0;
    for (let i = 0; i < 5; i++) {
      doc.isRead = true;
      await runPreSave(doc);
      if (wouldSendEmail(doc)) sends += 1;
    }
    assert.equal(sends, 0, 'K read-toggles previously produced K extra emails');
  });

  test('one create plus K reads yields exactly one email', async () => {
    let sends = 0;

    await runPreSave(doc);
    if (wouldSendEmail(doc)) sends += 1;
    doc.isNew = false;

    for (let i = 0; i < 3; i++) {
      await runPreSave(doc);
      if (wouldSendEmail(doc)) sends += 1;
    }
    assert.equal(sends, 1);
  });

  test('a second, genuinely new notification does send', async () => {
    // Guards against over-correcting into "never send".
    await runPreSave(doc);
    assert.equal(wouldSendEmail(doc), true);

    const another = makeDoc();
    await runPreSave(another);
    assert.equal(wouldSendEmail(another), true);
  });

  test('the marker does not leak between documents', async () => {
    const a = makeDoc();
    const b = makeDoc();
    await runPreSave(a);
    a.isNew = false;
    await runPreSave(a);
    await runPreSave(b);
    assert.equal(wouldSendEmail(a), false);
    assert.equal(wouldSendEmail(b), true);
  });
});

describe('the guard is wired, not merely present', () => {
  test('a pre-save hook records whether the save was an insert', () => {
    assert.match(notificationModel, /pre\(\s*["']save["']/);
    assert.match(notificationModel, /\$locals\.wasNew\s*=\s*this\.isNew/);
  });

  test('the post-save hook returns early when it was not an insert', () => {
    const post = notificationModel.slice(notificationModel.indexOf('post("save"'));
    assert.match(post, /if\s*\(\s*!doc\.\$locals\?\.wasNew\s*\)\s*return;/);
  });

  test('the guard precedes the user lookup and the send', () => {
    const post = notificationModel.slice(notificationModel.indexOf('post("save"'));
    const guardAt = post.indexOf('wasNew');
    const lookupAt = post.indexOf('User.findById');
    const sendAt = post.indexOf('sendGeneralNotification');
    assert.ok(guardAt !== -1 && lookupAt !== -1 && sendAt !== -1);
    assert.ok(guardAt < lookupAt, 'guard must run before the N+1 user lookup');
    assert.ok(guardAt < sendAt, 'guard must run before the SMTP send');
  });

  test('bulk creation still emails — insertMany is always an insert', () => {
    assert.match(notificationModel, /post\(\s*["']insertMany["']/);
    const bulk = notificationModel.slice(notificationModel.indexOf('insertMany'));
    assert.match(bulk, /sendGeneralNotification/, 'saved-search fan-out must keep working');
    assert.doesNotMatch(
      bulk,
      /\$locals\?\.wasNew/,
      'insertMany bypasses document middleware; a wasNew guard there would silence it entirely'
    );
  });
});

describe('the caller that caused the duplicates', () => {
  test('markNotificationRead still saves the document', () => {
    // If this ever stops using .save(), the guard is moot but harmless. Recorded
    // so the relationship between the two files stays visible.
    const fn = notificationController.slice(
      notificationController.indexOf('markNotificationRead')
    );
    assert.match(fn, /isRead\s*=\s*true/);
    assert.match(fn, /\.save\(\)/);
  });

  test('mark-all-read still uses updateMany and bypasses hooks', () => {
    assert.match(notificationController, /updateMany/);
  });
});
