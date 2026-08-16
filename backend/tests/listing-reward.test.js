/**
 * Listing reward — one per account, not one per property.
 *
 * INTENDED BEHAVIOUR (see the block comment in rewardService.awardPoints):
 * a user is rewarded once for becoming a lister. Deleting the listing and
 * creating another earns nothing further, and there is deliberately no
 * clawback on delete.
 *
 * These drive the real cap predicate against real Reward documents and the real
 * embedded transaction ledger. No database is needed — the check reads
 * wallet.transactions, which addTransaction maintains in memory.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §22.2 H5 / F-R1 (G1).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import Reward from '../models/Reward.js';

const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
const read = (rel) => stripComments(readFileSync(new URL(rel, import.meta.url), 'utf8'));
const rewardService = read('../services/rewardService.js');
const propertyController = read('../controllers/propertyController.js');

/** The cap predicate as awardPoints applies it. */
const alreadyClaimedListing = (wallet) =>
  wallet.transactions.some((t) => t.action === 'list_property');

const newWallet = () => new Reward({ user: '507f1f77bcf86cd799439011' });

/** Simulates one successful listing: award if the cap allows. */
function listProperty(wallet, points = 112) {
  if (alreadyClaimedListing(wallet)) return { pointsAwarded: 0, capped: true };
  wallet.addTransaction({
    type: 'earn',
    action: 'list_property',
    points,
    metadata: { propertyId: String(Math.random()).slice(2) },
  });
  return { pointsAwarded: points, capped: false };
}

/** deleteMyProperty deliberately does not touch the wallet. */
const deleteProperty = () => {};

describe('the legitimate first listing is still rewarded', () => {
  test('a new user is rewarded for their first listing', () => {
    const w = newWallet();
    const r = listProperty(w);
    assert.equal(r.capped, false);
    assert.equal(r.pointsAwarded, 112);
    assert.equal(w.totalPoints, 112);
    assert.equal(w.availablePoints, 112);
  });

  test('the reward is a real earn that counts toward tier', () => {
    const w = newWallet();
    listProperty(w, 1200);
    assert.equal(w.totalPoints, 1200);
    assert.equal(w.tier, 'silver', 'the first listing must still advance tier normally');
  });
});

describe('create → reward → delete → recreate earns nothing further', () => {
  test('the full cycle awards exactly once', () => {
    const w = newWallet();

    const first = listProperty(w);
    assert.equal(first.pointsAwarded, 112, 'first listing must be rewarded');

    deleteProperty();

    const second = listProperty(w);
    assert.equal(second.pointsAwarded, 0, 'recreating after delete must not pay again');
    assert.equal(second.capped, true);

    assert.equal(w.totalPoints, 112, 'balance drifted across a delete/recreate cycle');
    assert.equal(w.availablePoints, 112);
  });

  test('twenty delete/recreate cycles yield the first reward only', () => {
    // The farming loop: unbounded before this cap, worth ~₹5.61 expected per
    // iteration with nothing but the global rate limiter in the way.
    const w = newWallet();
    let paid = 0;

    for (let i = 0; i < 20; i++) {
      paid += listProperty(w).pointsAwarded;
      deleteProperty();
    }

    assert.equal(paid, 112, `farming loop paid out ${paid} points across 20 cycles`);
    assert.equal(w.totalPoints, 112);
    assert.equal(
      w.transactions.filter((t) => t.action === 'list_property').length,
      1,
      'only one listing reward transaction may exist per account'
    );
  });

  test('no clawback is applied on delete — the cap makes it unnecessary', () => {
    // Documented decision: forfeiting on delete punishes a legitimate delete,
    // cannot recover already-spent points, and interacts badly with the
    // negative-balance clamp. Recorded as a test so a future change is deliberate.
    const w = newWallet();
    listProperty(w);
    const afterListing = { total: w.totalPoints, available: w.availablePoints };

    deleteProperty();

    assert.equal(w.totalPoints, afterListing.total, 'delete must not forfeit points');
    assert.equal(w.availablePoints, afterListing.available);
    assert.equal(
      w.transactions.some((t) => t.type === 'forfeit'),
      false,
      'a forfeit appeared — if clawback is now intended, update the documented decision first'
    );
  });
});

describe('the cap is scoped to listing rewards only', () => {
  test('other earning actions are unaffected', () => {
    const w = newWallet();
    listProperty(w);

    // Enquiries, deal closure and reports keep their own rules.
    w.addTransaction({ type: 'earn', action: 'send_enquiry', points: 36 });
    w.addTransaction({ type: 'earn', action: 'complete_deal', points: 2728 });
    w.addTransaction({ type: 'earn', action: 'report_property', points: 100 });

    assert.equal(w.totalPoints, 112 + 36 + 2728 + 100);
  });

  test('a second account is rewarded independently', () => {
    const a = newWallet();
    const b = new Reward({ user: '507f1f77bcf86cd799439099' });
    listProperty(a);
    const r = listProperty(b);
    assert.equal(r.pointsAwarded, 112, 'the cap must be per account, not global');
  });

  test('the daily enquiry cap still exists alongside it', () => {
    assert.match(rewardService, /action === "send_enquiry"/);
    assert.match(rewardService, /todaysEnquiriesCount >= 5/);
  });
});

describe('the cap is wired into awardPoints', () => {
  test('awardPoints checks for a prior listing reward', () => {
    assert.match(
      rewardService,
      /action === "list_property"[\s\S]{0,400}t\.action === "list_property"/,
      'the one-time cap is missing from the service'
    );
  });

  test('a capped award reports success with zero points, not an error', () => {
    // The caller stores `reward` on the response; returning success:false would
    // surface as a failed listing.
    const block = rewardService.slice(rewardService.indexOf('action === "list_property"'));
    const capReturn = block.slice(0, block.indexOf('DAILY LIMIT CHECK'));
    assert.match(capReturn, /success: true/);
    assert.match(capReturn, /pointsAwarded: 0/);
  });

  test('the cap runs before any points are drawn', () => {
    const fn = rewardService.slice(rewardService.indexOf('export const awardPoints'));
    const capAt = fn.indexOf('action === "list_property"');
    const drawAt = fn.indexOf('getRandomReward(');
    assert.ok(capAt !== -1 && drawAt !== -1);
    assert.ok(capAt < drawAt, 'the cap must short-circuit before a reward is generated');
  });

  test('addProperty still awards on the create path', () => {
    assert.match(propertyController, /awardPoints\(req\.user\._id, "list_property"/);
  });

  test('deleteMyProperty still does not touch the wallet', () => {
    const fn = propertyController.slice(
      propertyController.indexOf('export const deleteMyProperty'),
      propertyController.indexOf('\nexport const ', propertyController.indexOf('export const deleteMyProperty') + 10)
    );
    assert.doesNotMatch(fn, /awardPoints|addTransaction|Reward\./);
  });
});
