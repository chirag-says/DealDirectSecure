/**
 * Buyer deal notifications (Phase 2.8)
 *
 * The buyer was named as counterparty to a transaction, had proof documents
 * bearing their name uploaded, and was told nothing — unless an admin later
 * approved it. On rejection they were never told at all.
 *
 * This adds the missing business event using the existing notification system.
 * No new delivery mechanism, no change to deal state transitions, no change to
 * the approval notifications that already worked.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §14.1 F-D11.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import TransactionVerification from '../models/TransactionVerification.js';
import Notification from '../models/Notification.js';

const stripComments = (src) =>
  src.replace(new RegExp('/\\*[\\s\\S]*?\\*/', 'g'), '').replace(new RegExp('//[^\\r\\n]*', 'g'), '');

const read = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');

const propertyCode = stripComments(read('../controllers/propertyController.js'));
const adminCode = stripComments(read('../controllers/adminController.js'));

const fnBody = (src, name) => {
  const start = src.indexOf(`export const ${name}`);
  assert.notEqual(start, -1, `${name} not found`);
  const next = src.indexOf('\nexport const ', start + 10);
  return src.slice(start, next === -1 ? src.length : next);
};

const closeDeal = fnBody(propertyCode, 'closeDeal');
const approve = fnBody(adminCode, 'approveDealVerification');
const reject = fnBody(adminCode, 'rejectDealVerification');

/** Every Notification.create in a block, with the recipient expression. */
const recipients = (block) =>
  [...block.matchAll(/Notification\.create\(\{\s*user:\s*([^,\n]+)/g)].map((m) => m[1].trim());

describe('deal submission notifies the buyer', () => {
  test('closeDeal creates a notification for the buyer', () => {
    assert.ok(
      recipients(closeDeal).includes('verification.buyer'),
      'the buyer is still not told a deal was submitted in their name'
    );
  });

  test('the recipient comes from the persisted record, not the request body', () => {
    // buyerId is validated against property.interestedUsers, so it cannot name
    // an arbitrary user — but reading the stored value means the notification
    // and the verification can never disagree about the counterparty.
    assert.doesNotMatch(
      closeDeal,
      /Notification\.create\(\{\s*user:\s*buyerId/,
      'the notification must not trust the client-supplied id directly'
    );
  });

  test('the buyer is still validated against the property before any of this', () => {
    const validateAt = closeDeal.indexOf('isBuyerInterested');
    const notifyAt = closeDeal.indexOf('user: verification.buyer');
    assert.ok(validateAt !== -1, 'the interestedUsers check was removed');
    assert.ok(validateAt < notifyAt, 'validation must precede notification');
  });

  test('an unknown buyer receives nothing', () => {
    // Guarded, so a verification without a buyer cannot produce a
    // Notification with user: undefined — which the schema requires.
    assert.match(closeDeal, /if \(verification\.buyer\)/);
    assert.equal(Notification.schema.path('user').isRequired, true);
  });

  test('the buyer notification does not block the submission', () => {
    // The verification exists and the property already moved to
    // pending_verification by this point.
    const block = closeDeal.slice(closeDeal.indexOf('if (verification.buyer)'));
    assert.match(block.slice(0, 900), /\}\)\.catch\(/);
    assert.doesNotMatch(block.slice(0, 200), /await Notification\.create/);
  });

  test('it carries no admin or document detail', () => {
    const block = closeDeal.slice(closeDeal.indexOf('if (verification.buyer)'), closeDeal.indexOf('[CloseDeal] Verification'));
    assert.doesNotMatch(block, /documentUrls|adminNotes/);
  });
});

describe('the owner notification is unchanged', () => {
  test('closeDeal still notifies the owner', () => {
    assert.ok(recipients(closeDeal).includes('userId'), 'the owner notification was disturbed');
  });

  test('the owner notification is still awaited', () => {
    assert.match(closeDeal, /await Notification\.create\(\{\s*user: userId/);
  });

  test('the owner is notified before the buyer', () => {
    const ownerAt = closeDeal.indexOf('user: userId');
    const buyerAt = closeDeal.indexOf('user: verification.buyer');
    assert.ok(ownerAt !== -1 && buyerAt !== -1);
    assert.ok(ownerAt < buyerAt);
  });

  test('the owner still gets the submission wording and their own action link', () => {
    assert.match(closeDeal, /Deal Closure Submitted/);
    assert.match(closeDeal, /View My Properties/);
  });
});

describe('rejection notifies the correct buyer', () => {
  test('reject creates a notification for the buyer', () => {
    assert.ok(
      recipients(reject).includes('verification.buyer'),
      'the buyer is left waiting on an outcome that already happened'
    );
  });

  test('it is guarded on the buyer existing', () => {
    assert.match(reject, /if \(verification\.buyer\)/);
  });

  test('the admin reason is NOT forwarded to the buyer', () => {
    // adminNotes is written about the owner's submission and their documents.
    const buyerBlock = reject.slice(reject.indexOf('if (verification.buyer)'));
    assert.doesNotMatch(
      buyerBlock.slice(0, 1200),
      /adminNotes/,
      'internal review detail about another party must not reach the buyer'
    );
  });

  test('the owner still receives the reason', () => {
    assert.match(reject, /Reason: \$\{adminNotes\.trim\(\)\}/);
  });

  test('the owner notification still comes first and is awaited', () => {
    const ownerAt = reject.indexOf('await Notification.create');
    const buyerAt = reject.indexOf('if (verification.buyer)');
    assert.ok(ownerAt !== -1 && ownerAt < buyerAt, 'a buyer-notification failure must not block the owner');
  });

  test('buyer is a real field on the verification, so the recipient resolves', () => {
    assert.ok(TransactionVerification.schema.path('buyer'));
    assert.equal(String(TransactionVerification.schema.path('buyer').options.ref), 'User');
  });

  test('no new rejection semantics were introduced', () => {
    // Same guard, same property reactivation, same status value.
    assert.match(reject, /status === 'pending'|status !== "pending"|status !== 'pending'/);
    assert.match(reject, /status: "active"/);
    assert.match(reject, /verification\.status = "rejected"/);
  });
});

describe('approval notifications are untouched', () => {
  test('approve still notifies both parties', () => {
    const to = recipients(approve);
    assert.ok(to.includes('verification.owner._id'), 'the owner approval notification changed');
    assert.ok(to.includes('verification.buyer._id'), 'the buyer approval notification changed');
  });

  test('approve still creates exactly two notifications', () => {
    assert.equal(recipients(approve).length, 2);
  });

  test('the reward-claim wording is unchanged', () => {
    assert.match(approve, /Claim Your Reward/);
    assert.match(approve, /type: "deal_reward"/);
  });

  test('approve still awards no points itself', () => {
    // Rewards stay pull-based via claimDealReward.
    assert.doesNotMatch(approve, /awardPoints\(/);
  });
});

describe('no duplicate notifications', () => {
  test('closeDeal creates exactly two — one per party', () => {
    const to = recipients(closeDeal);
    assert.equal(to.length, 2, `closeDeal creates ${to.length} notifications: ${to.join(', ')}`);
    assert.deepEqual([...new Set(to)].sort(), ['userId', 'verification.buyer'].sort());
  });

  test('reject creates exactly two — one per party', () => {
    const to = recipients(reject);
    assert.equal(to.length, 2, `reject creates ${to.length} notifications: ${to.join(', ')}`);
    assert.deepEqual([...new Set(to)].sort(), ['verification.buyer', 'verification.owner'].sort());
  });

  test('the same recipient is never notified twice in one flow', () => {
    for (const [name, block] of [['closeDeal', closeDeal], ['reject', reject], ['approve', approve]]) {
      const to = recipients(block);
      assert.equal(new Set(to).size, to.length, `${name} notifies the same user more than once`);
    }
  });

  test('no insertMany was introduced for these flows', () => {
    // insertMany bypasses the post-save hook that sends email; using it here
    // would change delivery behaviour, which is out of scope.
    for (const block of [closeDeal, reject]) {
      assert.doesNotMatch(block, /Notification\.insertMany/);
    }
  });
});

describe('notification infrastructure is unchanged', () => {
  test('delivery still goes through the model post-save hook', () => {
    const model = read('../models/Notification.js');
    assert.match(model, /notificationSchema\.post\("save"/);
    assert.match(model, /sendGeneralNotification/);
  });

  test('the duplicate-send guard from 2.5 is still in place', () => {
    const model = read('../models/Notification.js');
    assert.match(model, /if \(!doc\.\$locals\?\.wasNew\) return;/);
  });

  test('deal state transitions were not changed', () => {
    assert.match(closeDeal, /status: "pending_verification"/);
    assert.doesNotMatch(closeDeal, /status: "sold"|status: "rented"/);
  });
});
