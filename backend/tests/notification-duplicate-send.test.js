/**
 * Notification duplicate-send invariant
 *
 * INVARIANT, UNCHANGED: a notification sends its email exactly once, when it is
 * created. Saving it again — which is what marking it read does — must send
 * nothing. One create plus K reads is one email, not K+1.
 *
 * HOW IT IS ENFORCED CHANGED IN PHASE 3E.
 *
 * It used to be a `$locals.wasNew` flag set in a pre-save hook and read by a
 * post-save hook that did the sending. That worked, and this file drove those
 * hooks directly. But delivery living in the model was the reason for the
 * fan-out N+1 and the per-message SMTP handshake, so delivery moved to
 * services/notificationService.js.
 *
 * The invariant is now structural rather than guarded: only `notifyUser` and
 * `notifyUsers` dispatch, both of them create documents, and no update path
 * goes near them. There is no flag to check because there is no send inside the
 * model to suppress.
 *
 * These assertions were rewritten rather than deleted. The old ones tested a
 * mechanism that no longer exists, and leaving them would have blocked the
 * change while looking green; deleting the file would have lost the record of
 * why the invariant matters. The behavioural proof — create once, read K times,
 * count the emails — lives in tests/integration/notification-service.test.js,
 * which can observe real sends. What remains here is the structural half.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §16.2 F-N2.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';



const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
const read = (rel) => stripComments(readFileSync(new URL(rel, import.meta.url), 'utf8'));

const notificationModel = read('../models/Notification.js');
const notificationService = read('../services/notificationService.js');
const notificationController = read('../controllers/notificationController.js');

describe('the model cannot send, so an update cannot re-send', () => {
  test('the model registers no save hook of its own', () => {
    // Counting Notification.schema.s.hooks is not the check it looks like:
    // Mongoose registers five pre-save and three post-save hooks of its own for
    // validation and change tracking, so the count is never zero and says
    // nothing about this model. The source is what carries the answer.
    assert.doesNotMatch(
      notificationModel, /notificationSchema\.(pre|post)\(\s*["']save["']/,
      'a save hook is back on Notification; if it sends, marking read re-sends'
    );
  });

  test('the model registers no insertMany hook either', () => {
    assert.doesNotMatch(notificationModel, /notificationSchema\.post\(\s*["']insertMany["']/);
  });

  test('the model imports no mailer', () => {
    assert.doesNotMatch(notificationModel, /emailService|sendGeneralNotification/);
  });

  test('the model performs no recipient lookup', () => {
    assert.doesNotMatch(notificationModel, /User\.find/);
  });
});

describe('only the service dispatches, and only on create', () => {
  test('the service is the sole sender', () => {
    assert.match(notificationService, /sendGeneralNotification/);
  });

  test('both entry points create rather than update', () => {
    // If either ever dispatched from an update path, the duplicate-send bug
    // returns in a new place.
    assert.match(notificationService, /Notification\.create/);
    assert.match(notificationService, /Notification\.insertMany/);
    // Scoped to Notification specifically. The service legitimately updates
    // OTHER collections — since Phase 1 it stamps `lastMatchAt` on the saved
    // searches a listing matched, and writes an OutboundLog row per capped
    // send. Neither touches a notification, and neither can dispatch. A
    // blanket ban on the word `updateMany` was really a ban on Notification
    // updates wearing a wider costume.
    assert.doesNotMatch(notificationService, /Notification\.(findByIdAndUpdate|updateMany|updateOne)/);
    assert.doesNotMatch(notificationService, /\.save\(\)/);
  });

  test('bulk delivery goes through the batched path', () => {
    assert.match(notificationService, /\$in/, 'the batch lookup is what makes fan-out cheap');
  });
});

describe('the caller that caused the duplicates', () => {
  test('markNotificationRead still saves the document', () => {
    // It still calls .save(). That used to be the trigger for a second email;
    // now it is inert, which is the point.
    const fn = notificationController.slice(
      notificationController.indexOf('markNotificationRead')
    );
    assert.match(fn, /isRead\s*=\s*true/);
    assert.match(fn, /\.save\(\)/);
  });

  test('mark-all-read still uses updateMany', () => {
    // updateMany bypassed document middleware, so the two buttons used to
    // behave differently: one re-sent email per item, the other did not. With
    // delivery out of the model both are inert and the difference is gone.
    assert.match(notificationController, /updateMany/);
  });

  test('the notification controller sends no email of its own', () => {
    assert.doesNotMatch(notificationController, /sendGeneralNotification/);
  });
});
