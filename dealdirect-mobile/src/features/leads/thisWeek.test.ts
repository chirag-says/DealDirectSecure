import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import type { Lead } from '../../types/backend/lead';
import { isWaitingOnOwner, summariseWeek } from './thisWeek.ts';

const NOW = Date.parse('2026-09-05T12:00:00.000Z');
const HOUR = 60 * 60 * 1000;

function lead(overrides: Partial<Lead> & { ageHours: number }): Lead {
  const { ageHours, ...rest } = overrides;
  const createdAt = new Date(NOW - ageHours * HOUR).toISOString();
  return {
    _id: 'l',
    property: 'p',
    propertyOwner: 'o',
    user: 'u',
    userSnapshot: { name: 'Buyer', email: 'b@example.com' },
    status: 'new',
    createdAt,
    updatedAt: createdAt,
    ...rest,
  } as Lead;
}

describe('isWaitingOnOwner', () => {
  it('is false inside the first 24 hours', () => {
    assert.equal(isWaitingOnOwner(lead({ ageHours: 23, firstOwnerResponseAt: null }), NOW), false);
  });

  it('is true past 24 hours with no owner response', () => {
    assert.equal(isWaitingOnOwner(lead({ ageHours: 25, firstOwnerResponseAt: null }), NOW), true);
  });

  it('is false once the owner has responded', () => {
    assert.equal(
      isWaitingOnOwner(lead({ ageHours: 90, firstOwnerResponseAt: '2026-09-03T00:00:00.000Z' }), NOW),
      false
    );
  });

  it('falls back to isViewed when the Phase 2 field is absent', () => {
    assert.equal(isWaitingOnOwner(lead({ ageHours: 48, isViewed: false }), NOW), true);
    assert.equal(isWaitingOnOwner(lead({ ageHours: 48, isViewed: true }), NOW), false);
    // Neither field: the old backend defaulted `isViewed` to false only when it
    // sent it, so an absent flag is not read as unread.
    assert.equal(isWaitingOnOwner(lead({ ageHours: 48 }), NOW), false);
  });

  it('prefers firstOwnerResponseAt over isViewed when both are present', () => {
    assert.equal(
      isWaitingOnOwner(lead({ ageHours: 48, isViewed: true, firstOwnerResponseAt: null }), NOW),
      true
    );
  });

  it('never counts a closed lead', () => {
    assert.equal(
      isWaitingOnOwner(lead({ ageHours: 48, status: 'converted', firstOwnerResponseAt: null }), NOW),
      false
    );
    assert.equal(
      isWaitingOnOwner(lead({ ageHours: 48, status: 'lost', firstOwnerResponseAt: null }), NOW),
      false
    );
  });
});

describe('summariseWeek', () => {
  it('counts the last seven days and the waiting rows', () => {
    const summary = summariseWeek(
      [
        lead({ ageHours: 2, firstOwnerResponseAt: null }),
        lead({ ageHours: 30, firstOwnerResponseAt: null }),
        lead({ ageHours: 24 * 6, firstOwnerResponseAt: '2026-09-01T00:00:00.000Z' }),
        lead({ ageHours: 24 * 9, firstOwnerResponseAt: null }),
      ],
      false,
      NOW
    );
    assert.deepEqual(summary, { newLeads: 3, waiting: 2, lowerBound: false });
  });

  it('marks the counts as a lower bound when pages remain', () => {
    assert.equal(summariseWeek([], true, NOW).lowerBound, true);
  });

  it('ignores an unparseable createdAt', () => {
    const summary = summariseWeek([lead({ ageHours: 1, createdAt: 'nope' })], false, NOW);
    assert.deepEqual(summary, { newLeads: 0, waiting: 0, lowerBound: false });
  });
});
