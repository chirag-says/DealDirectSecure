/**
 * Deal races — duplicate verification and double reward claim.
 *
 * The concurrency tests run both the old check-then-act algorithm and the new
 * conditional-update algorithm against a small in-memory store whose update is
 * atomic in the same sense Mongo's findOneAndUpdate is. They assert the
 * observable difference — how many callers win — rather than the wording of the
 * implementation. Source assertions then pin that the controller uses the
 * winning algorithm.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §14.1 (F-D5 duplicate
 * verification), §14.3 (F-D3 double claim).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import TransactionVerification from '../models/TransactionVerification.js';

const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
const read = (rel) => stripComments(readFileSync(new URL(rel, import.meta.url), 'utf8'));
const propertyController = read('../controllers/propertyController.js');

/* ------------------------------------------------------------------ *
 * A document whose conditional update is atomic, like findOneAndUpdate.
 * ------------------------------------------------------------------ */
class Doc {
  constructor() {
    this.ownerClaimed = false;
    this.ownerReward = { points: 0 };
    this.awards = 0;
  }

  /** Atomic: flip field false → true, returning whether THIS caller won. */
  takeClaim(field) {
    if (this[field]) return false;
    this[field] = true;
    return true;
  }
}

/** Simulates an await boundary — lets every pending caller interleave. */
const yieldToOthers = () => new Promise((r) => setImmediate(r));

/** The old implementation: read, await, write. */
async function claimCheckThenAct(doc) {
  if (doc.ownerClaimed) return 'already';
  await yieldToOthers(); // awardPoints()
  doc.awards += 1;
  doc.ownerClaimed = true;
  return 'awarded';
}

/** The new implementation: take the claim atomically, then award. */
async function claimAtomic(doc) {
  const won = doc.takeClaim('ownerClaimed');
  if (!won) return 'already';
  await yieldToOthers(); // awardPoints()
  doc.awards += 1;
  return 'awarded';
}

describe('double reward claim — concurrency', () => {
  test('the old check-then-act awards twice on a double-click', async () => {
    // Establishes the bug the fix targets; if this ever stops reproducing, the
    // comparison below proves nothing.
    const doc = new Doc();
    const results = await Promise.all([claimCheckThenAct(doc), claimCheckThenAct(doc)]);
    assert.deepEqual(results, ['awarded', 'awarded']);
    assert.equal(doc.awards, 2, 'expected the old algorithm to double-award');
  });

  test('the atomic claim awards exactly once for two concurrent callers', async () => {
    const doc = new Doc();
    const results = await Promise.all([claimAtomic(doc), claimAtomic(doc)]);
    assert.equal(doc.awards, 1, 'points were awarded more than once');
    assert.equal(results.filter((r) => r === 'awarded').length, 1);
    assert.equal(results.filter((r) => r === 'already').length, 1);
  });

  test('the atomic claim awards exactly once for twenty concurrent callers', async () => {
    const doc = new Doc();
    const results = await Promise.all(Array.from({ length: 20 }, () => claimAtomic(doc)));
    assert.equal(doc.awards, 1);
    assert.equal(results.filter((r) => r === 'awarded').length, 1);
  });

  test('a later sequential claim still reports alreadyClaimed', async () => {
    const doc = new Doc();
    assert.equal(await claimAtomic(doc), 'awarded');
    assert.equal(await claimAtomic(doc), 'already');
    assert.equal(doc.awards, 1);
  });

  test('releasing the claim after a failed award lets the user retry', async () => {
    const doc = new Doc();
    assert.equal(doc.takeClaim('ownerClaimed'), true);
    doc.ownerClaimed = false; // compensating rollback
    assert.equal(doc.takeClaim('ownerClaimed'), true, 'user must not be locked out of an unpaid reward');
  });

  test('owner and buyer claims are independent', () => {
    const doc = new Doc();
    doc.buyerClaimed = false;
    assert.equal(doc.takeClaim('ownerClaimed'), true);
    assert.equal(doc.takeClaim('buyerClaimed'), true, 'the buyer must still be able to claim');
  });
});

describe('double reward claim — wired into the controller', () => {
  const fn = propertyController.slice(
    propertyController.indexOf('export const claimDealReward'),
    propertyController.indexOf('\nexport const ', propertyController.indexOf('export const claimDealReward') + 10)
  );

  test('the claim is taken with a conditional atomic update', () => {
    assert.match(
      fn,
      /findOneAndUpdate\(\s*\{\s*_id: verificationId,\s*\[claimField\]:\s*\{\s*\$ne:\s*true\s*\}\s*\}/,
      'the claim must be taken by a guarded update, not a read followed by a write'
    );
  });

  test('the claim is taken before points are awarded', () => {
    const claimAt = fn.indexOf('findOneAndUpdate');
    const awardAt = fn.indexOf('awardPoints(');
    assert.ok(claimAt !== -1 && awardAt !== -1);
    assert.ok(claimAt < awardAt, 'awarding before claiming reopens the race');
  });

  test('a losing caller returns alreadyClaimed instead of awarding', () => {
    assert.match(fn, /if \(!claimed\)/);
    assert.match(fn, /alreadyClaimed: true/);
  });

  test('a losing caller re-reads the stored amount', () => {
    // The document loaded at the top of the handler predates the winner's
    // write, so returning its reward field would report zero.
    const losing = fn.slice(fn.indexOf('if (!claimed)'), fn.indexOf('const action ='));
    assert.match(losing, /findById\(verificationId\)/);
  });

  test('the claim is released if awarding throws', () => {
    assert.match(fn, /\[claimField\]:\s*false/, 'a failed award must not permanently consume the claim');
  });

  test('the claim is released when awardPoints resolves unsuccessfully', () => {
    // awardPoints returns { success: false } rather than throwing for an
    // unmapped action or an exhausted concurrency retry.
    assert.match(fn, /!rewardResult\?\.success/);
  });

  test('the old in-memory mutate-and-save path is gone', () => {
    assert.doesNotMatch(fn, /verification\.ownerClaimed = true/);
    assert.doesNotMatch(fn, /verification\.buyerClaimed = true/);
    assert.doesNotMatch(fn, /await verification\.save\(\)/);
  });
});

describe('duplicate pending verification', () => {
  const partialUnique = () =>
    TransactionVerification.schema
      .indexes()
      .find(([fields, opts]) => fields.property === 1 && opts?.unique && opts?.partialFilterExpression);

  test('a partial unique index constrains pending rows only', () => {
    const partial = partialUnique();
    assert.ok(partial, 'no unique index enforcing one pending verification per property');
    assert.deepEqual(partial[1].partialFilterExpression, { status: 'pending' });
  });

  test('the index key differs from the existing plain property index', () => {
    // MongoDB will not build a second index with an identical key pattern: it
    // fails at boot and the constraint is declared but never enforced. Verified
    // against the live collection on 2026-08-16 — with key { property } alone
    // the index was absent; with { property, status } it builds.
    const partial = partialUnique();
    assert.deepEqual(partial[0], { property: 1, status: 1 });
    assert.ok(partial[1].name, 'give it an explicit name so it is identifiable in listIndexes');
  });

  test('the index does not constrain approved or rejected rows', () => {
    // A property legitimately accumulates verifications over its lifetime; only
    // one may be pending at a time.
    const partial = partialUnique();
    assert.notEqual(partial[1].partialFilterExpression.status, 'approved');
    assert.equal(Object.keys(partial[1].partialFilterExpression).length, 1);
  });

  test('the plain property index is retained for lookups', () => {
    const idx = TransactionVerification.schema.indexes();
    const plain = idx.find(([fields, opts]) => fields.property === 1 && !opts?.unique);
    assert.ok(plain, 'dropping the non-unique index would slow every property lookup');
  });

  test('closeDeal converts a duplicate-key collision into the same 400', () => {
    const fn = propertyController.slice(
      propertyController.indexOf('export const closeDeal'),
      propertyController.indexOf('\nexport const ', propertyController.indexOf('export const closeDeal') + 10)
    );
    assert.match(fn, /err\?\.code === 11000/, 'the race must not surface as a 500');
    assert.match(fn, /already pending/);
  });

  test('closeDeal keeps the fast-path check as well', () => {
    const fn = propertyController.slice(propertyController.indexOf('export const closeDeal'));
    assert.match(fn, /TransactionVerification\.findOne\(/);
    assert.match(fn, /status: "pending"/);
  });

  test('a non-duplicate error is not swallowed', () => {
    const fn = propertyController.slice(propertyController.indexOf('export const closeDeal'));
    assert.match(fn, /throw err;/, 'only 11000 may be converted; anything else must propagate');
  });
});
