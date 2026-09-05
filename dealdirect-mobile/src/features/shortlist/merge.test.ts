import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  MAX_TRACKED_ACCOUNTS,
  MERGE_CAP,
  decideMerge,
  readMergedFor,
  rememberMerged,
} from './merge.ts';

const A = 'account-a';
const B = 'account-b';

describe('decideMerge', () => {
  it('sends the local ids on the first authenticated launch', () => {
    const decision = decideMerge({ userId: A, localIds: ['p1', 'p2'], mergedFor: [] });

    assert.equal(decision.shouldMerge, true);
    assert.deepEqual(decision.propertyIds, ['p1', 'p2']);
    assert.equal(decision.truncated, false);
    assert.equal(decision.skipReason, undefined);
  });

  it('sends nothing for a guest, and says why', () => {
    for (const userId of [null, undefined, '']) {
      const decision = decideMerge({ userId, localIds: ['p1'], mergedFor: [] });
      assert.equal(decision.shouldMerge, false);
      assert.equal(decision.skipReason, 'no-session');
      assert.deepEqual(decision.propertyIds, []);
    }
  });

  it('skips an account that already had its handover on this install', () => {
    const decision = decideMerge({ userId: A, localIds: ['p1'], mergedFor: [A] });

    assert.equal(decision.shouldMerge, false);
    assert.equal(decision.skipReason, 'already-merged');
    assert.deepEqual(decision.propertyIds, []);
  });

  it('still merges for a second account on the same install', () => {
    const decision = decideMerge({ userId: B, localIds: ['p1'], mergedFor: [A] });

    assert.equal(decision.shouldMerge, true);
    assert.deepEqual(decision.propertyIds, ['p1']);
  });

  it('skips when there is nothing local, rather than posting an empty array', () => {
    const decision = decideMerge({ userId: A, localIds: [], mergedFor: [] });

    assert.equal(decision.shouldMerge, false);
    assert.equal(decision.skipReason, 'nothing-local');
  });

  it('reports no-session before already-merged', () => {
    // The guard must never make a guest read as "already handled": a guest has
    // no account for the guard to have recorded.
    const decision = decideMerge({ userId: null, localIds: ['p1'], mergedFor: [A] });
    assert.equal(decision.skipReason, 'no-session');
  });

  it('drops duplicates and blanks, keeping the first occurrence', () => {
    const decision = decideMerge({
      userId: A,
      localIds: ['p1', 'p2', 'p1', '   ', '', ' p3 '],
      mergedFor: [],
    });

    assert.deepEqual(decision.propertyIds, ['p1', 'p2', 'p3']);
  });

  it('truncates to the server cap and says it truncated', () => {
    const localIds = Array.from({ length: MERGE_CAP + 5 }, (_, i) => `p${i}`);
    const decision = decideMerge({ userId: A, localIds, mergedFor: [] });

    assert.equal(decision.propertyIds.length, MERGE_CAP);
    assert.equal(decision.truncated, true);
    // The newest are first in the store, so the oldest are what falls off.
    assert.equal(decision.propertyIds[0], 'p0');
    assert.equal(decision.propertyIds.at(-1), `p${MERGE_CAP - 1}`);
  });

  it('does not report truncation at exactly the cap', () => {
    const localIds = Array.from({ length: MERGE_CAP }, (_, i) => `p${i}`);
    const decision = decideMerge({ userId: A, localIds, mergedFor: [] });

    assert.equal(decision.propertyIds.length, MERGE_CAP);
    assert.equal(decision.truncated, false);
  });

  it('never returns ids alongside a false decision', () => {
    const cases = [
      { userId: null, localIds: ['p1'], mergedFor: [] },
      { userId: A, localIds: ['p1'], mergedFor: [A] },
      { userId: A, localIds: [], mergedFor: [] },
    ];

    for (const input of cases) {
      const decision = decideMerge(input);
      assert.equal(decision.shouldMerge, false);
      assert.deepEqual(decision.propertyIds, []);
    }
  });
});

describe('the once-per-account guard', () => {
  it('appends an account and is idempotent', () => {
    assert.deepEqual(rememberMerged([], A), [A]);
    assert.deepEqual(rememberMerged([A], B), [A, B]);
    assert.deepEqual(rememberMerged([A, B], A), [A, B]);
  });

  it('keeps the guard bounded, dropping the oldest account', () => {
    const many = Array.from({ length: MAX_TRACKED_ACCOUNTS }, (_, i) => `acc-${i}`);
    const next = rememberMerged(many, 'acc-new');

    assert.equal(next.length, MAX_TRACKED_ACCOUNTS);
    assert.equal(next.includes('acc-0'), false);
    assert.equal(next.at(-1), 'acc-new');
  });

  it('reads the stored guard, and treats junk as empty', () => {
    assert.deepEqual(readMergedFor(JSON.stringify([A, B])), [A, B]);
    assert.deepEqual(readMergedFor(undefined), []);
    assert.deepEqual(readMergedFor('not json'), []);
    assert.deepEqual(readMergedFor(JSON.stringify({ a: 1 })), []);
    assert.deepEqual(readMergedFor(JSON.stringify([A, 3, null, ''])), [A]);
  });

  it('an account not in a junk guard still merges', () => {
    const decision = decideMerge({ userId: A, localIds: ['p1'], mergedFor: readMergedFor('{{') });
    assert.equal(decision.shouldMerge, true);
  });
});
