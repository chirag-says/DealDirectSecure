/**
 * Reward ledger arithmetic — redemption reversal must not inflate lifetime points.
 *
 * These drive the real `addTransaction` method on real Reward documents. No
 * database is needed: addTransaction mutates the in-memory document, which is
 * exactly the arithmetic under test.
 *
 * INVARIANT: a debit followed by its reversal returns availablePoints to where
 * it started and leaves totalPoints (and therefore the tier) untouched.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §15.2 F-R2.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import Reward from '../models/Reward.js';

const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
const read = (rel) => stripComments(readFileSync(new URL(rel, import.meta.url), 'utf8'));
const hubbleController = read('../controllers/hubbleController.js');

const makeWallet = (earned = 0) => {
  const w = new Reward({ user: '507f1f77bcf86cd799439011' });
  if (earned) w.addTransaction({ type: 'earn', action: 'list_property', points: earned });
  return w;
};

const debit = (w, points, referenceId) =>
  w.addTransaction({
    type: 'redeem',
    action: 'hubble_debit',
    points: -Math.abs(points),
    metadata: { referenceId, source: 'hubble' },
  });

const reverse = (w, points, referenceId) =>
  w.addTransaction({
    type: 'refund',
    action: 'hubble_reversal',
    points: Math.abs(points),
    metadata: { referenceId, source: 'hubble' },
  });

describe('a debit reduces only the spendable balance', () => {
  test('redeem decrements availablePoints and leaves totalPoints alone', () => {
    const w = makeWallet(2000);
    assert.equal(w.totalPoints, 2000);
    assert.equal(w.availablePoints, 2000);

    debit(w, 500, 'ref-1');
    assert.equal(w.availablePoints, 1500);
    assert.equal(w.totalPoints, 2000, 'lifetime earnings are not reduced by spending');
  });
});

describe('a reversal restores the balance without inflating lifetime points', () => {
  test('debit then reverse returns both counters to their starting values', () => {
    const w = makeWallet(2000);
    const before = { total: w.totalPoints, available: w.availablePoints, tier: w.tier };

    debit(w, 500, 'ref-1');
    reverse(w, 500, 'ref-1');

    assert.equal(w.availablePoints, before.available, 'the refund must restore spendable points');
    assert.equal(w.totalPoints, before.total, 'the refund must NOT credit lifetime points');
    assert.equal(w.tier, before.tier);
  });

  test('a reversal alone does not create lifetime points', () => {
    const w = makeWallet(2000);
    debit(w, 1000, 'ref-1');
    const totalAfterDebit = w.totalPoints;
    reverse(w, 1000, 'ref-1');
    assert.equal(w.totalPoints, totalAfterDebit);
  });
});

describe('repeated debit/reverse cycles cannot inflate the tier', () => {
  test('fifteen cycles leave the wallet exactly where it started', () => {
    // The reported exploit: each cycle previously added the refund to
    // totalPoints, so a silver wallet reached gold after 3 cycles and diamond
    // after 13, without earning anything.
    //
    // Each debit stays within the balance, matching handleHubbleDebit's
    // `availablePoints < debitAmount → 400` guard. See the clamp test below for
    // why that guard is load-bearing.
    const w = makeWallet(2000);
    const start = { total: w.totalPoints, available: w.availablePoints, tier: w.tier };
    assert.equal(start.tier, 'silver');

    for (let i = 0; i < 15; i++) {
      debit(w, 1000, `ref-${i}`);
      reverse(w, 1000, `ref-${i}`);
    }

    assert.equal(w.totalPoints, start.total, `totalPoints drifted to ${w.totalPoints}`);
    assert.equal(w.availablePoints, start.available);
    assert.equal(w.tier, 'silver', 'tier was inflated by churn');
  });

  test('the tier multiplier is unchanged after churn', () => {
    const w = makeWallet(2000);
    const before = w.getTierMultiplier();
    for (let i = 0; i < 20; i++) {
      debit(w, 800, `r${i}`);
      reverse(w, 800, `r${i}`);
    }
    assert.equal(w.getTierMultiplier(), before, 'churn must not raise future earning rates');
  });

  test('KNOWN CONSTRAINT: the negative-balance clamp makes the debit guard load-bearing', () => {
    // addTransaction clamps availablePoints at 0. If a debit larger than the
    // balance ever reached the wallet, the clamp would absorb the overdraft and
    // the matching refund would create points from nothing.
    //
    // This is unreachable through the API: handleHubbleDebit rejects a debit
    // exceeding the balance before calling addTransaction. Pinned here so that
    // guard is not removed as redundant, and recorded in the audit as F-R17
    // (clamps hide ledger corruption instead of surfacing it).
    const w = makeWallet(500);
    debit(w, 1000, 'overdraft');
    assert.equal(w.availablePoints, 0, 'clamped, not negative');
    reverse(w, 1000, 'overdraft');
    assert.equal(w.availablePoints, 1000, 'the clamp turned a 500 balance into 1000');
    assert.equal(w.totalPoints, 500, 'lifetime points still correct — the refund fix holds');
  });

  test('the debit handler guards the balance before writing', () => {
    assert.match(
      hubbleController,
      /availablePoints\s*<\s*debitAmount/,
      'without this check the clamp above becomes reachable'
    );
  });

  test('a wallet that legitimately earns still advances tier', () => {
    // Guards against over-correcting into "tier never moves".
    const w = makeWallet(500);
    assert.equal(w.tier, 'bronze');
    w.addTransaction({ type: 'earn', action: 'complete_deal', points: 5000 });
    assert.equal(w.totalPoints, 5500);
    assert.equal(w.tier, 'gold');
  });

  test('churn on top of real earnings does not push the tier up', () => {
    const w = makeWallet(4900); // just under gold
    assert.equal(w.tier, 'silver');
    for (let i = 0; i < 10; i++) {
      debit(w, 500, `x${i}`);
      reverse(w, 500, `x${i}`);
    }
    assert.equal(w.tier, 'silver', 'churn crossed a tier threshold');
    assert.equal(w.totalPoints, 4900);
  });
});

describe('refund semantics are distinct from adjustment', () => {
  test('an adjustment still moves lifetime points (admin corrections must)', () => {
    const w = makeWallet(1000);
    w.addTransaction({ type: 'adjustment', action: 'admin_adjustment', points: 500 });
    assert.equal(w.totalPoints, 1500);
    assert.equal(w.availablePoints, 1500);
  });

  test('refund is an accepted transaction type', () => {
    const w = makeWallet(1000);
    debit(w, 100, 'r');
    reverse(w, 100, 'r');
    const last = w.transactions[w.transactions.length - 1];
    assert.equal(last.type, 'refund');
    const err = w.validateSync();
    assert.ok(!err, `refund rejected by schema validation: ${err?.message}`);
  });

  test('a refund cannot drive availablePoints above what was debited', () => {
    const w = makeWallet(1000);
    debit(w, 300, 'r');
    reverse(w, 300, 'r');
    assert.equal(w.availablePoints, 1000);
  });
});

describe('the reversal is wired and the debit lookups still work', () => {
  test('handleHubbleReverse books a refund, not an adjustment', () => {
    const fn = hubbleController.slice(hubbleController.indexOf('handleHubbleReverse'));
    assert.match(fn, /type:\s*["']refund["']/);
    assert.doesNotMatch(
      fn.slice(0, fn.indexOf('await reward.save()')),
      /type:\s*["']adjustment["']/,
      'reversal is booked as an adjustment again'
    );
  });

  test('the original debit is still located by type "redeem"', () => {
    // The reversal must not be findable as a debit — this is why "refund" is a
    // distinct type rather than a positive "redeem".
    const matches = hubbleController.match(/t\.type === "redeem"/g) || [];
    assert.equal(matches.length, 2, 'debit idempotency and reversal lookup both key on redeem');
  });

  test('duplicate reversals are still detected by action', () => {
    assert.match(hubbleController, /t\.action === "hubble_reversal"/);
  });

  test('a refund transaction can never satisfy the debit idempotency check', () => {
    const w = makeWallet(1000);
    debit(w, 200, 'dup-ref');
    reverse(w, 200, 'dup-ref');
    const debitsWithRef = w.transactions.filter(
      (t) => t.metadata?.referenceId === 'dup-ref' && t.type === 'redeem'
    );
    assert.equal(debitsWithRef.length, 1, 'the reversal would be mistaken for the debit');
  });
});
