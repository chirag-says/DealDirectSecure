import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  composeVisitDate,
  MAX_DAYS_AHEAD,
  validateVisitTime,
  visitTimeErrorCopy,
} from './visitTime.ts';

const NOW = new Date('2026-09-04T10:00:00.000Z');
const DAY_MS = 24 * 60 * 60 * 1000;

describe('validateVisitTime', () => {
  it('accepts a time in the near future', () => {
    assert.equal(validateVisitTime(new Date(NOW.getTime() + DAY_MS), NOW), null);
  });

  it('refuses the past, and refuses "now" as past (the server compares strictly)', () => {
    assert.equal(validateVisitTime(new Date(NOW.getTime() - 1), NOW), 'TIME_IN_PAST');
    assert.equal(validateVisitTime(NOW, NOW), 'TIME_IN_PAST');
    assert.equal(validateVisitTime(new Date(NOW.getTime() + 1), NOW), null);
  });

  it('refuses more than 60 days ahead, and accepts exactly 60', () => {
    assert.equal(MAX_DAYS_AHEAD, 60);
    const limit = new Date(NOW.getTime() + 60 * DAY_MS);
    assert.equal(validateVisitTime(limit, NOW), null);
    assert.equal(validateVisitTime(new Date(limit.getTime() + 1), NOW), 'TOO_FAR_AHEAD');
  });

  it('refuses an invalid date', () => {
    assert.equal(validateVisitTime(new Date('nope'), NOW), 'INVALID_TIME');
  });
});

describe('composeVisitDate', () => {
  it('builds a local date from the day string and an hour/minute', () => {
    const date = composeVisitDate('2026-09-10', 14, 30);
    assert.ok(date);
    assert.equal(date.getFullYear(), 2026);
    assert.equal(date.getMonth(), 8);
    assert.equal(date.getDate(), 10);
    assert.equal(date.getHours(), 14);
    assert.equal(date.getMinutes(), 30);
    assert.equal(date.getSeconds(), 0);
  });

  it('rejects a malformed day', () => {
    assert.equal(composeVisitDate('10/09/2026', 14, 30), null);
    assert.equal(composeVisitDate('', 14, 30), null);
  });

  it('rejects an out-of-range hour or minute', () => {
    assert.equal(composeVisitDate('2026-09-10', 24, 0), null);
    assert.equal(composeVisitDate('2026-09-10', -1, 0), null);
    assert.equal(composeVisitDate('2026-09-10', 10, 60), null);
    assert.equal(composeVisitDate('2026-09-10', 10.5, 0), null);
  });

  it('rejects a day that would roll into the next month', () => {
    assert.equal(composeVisitDate('2026-02-31', 10, 0), null);
    assert.equal(composeVisitDate('2026-13-01', 10, 0), null);
  });
});

describe('visitTimeErrorCopy', () => {
  it('has a line for every code and a fallback', () => {
    assert.ok(visitTimeErrorCopy('TIME_IN_PAST').length > 0);
    assert.ok(visitTimeErrorCopy('TOO_FAR_AHEAD').includes('60'));
    assert.ok(visitTimeErrorCopy('INVALID_TIME').length > 0);
    assert.ok(visitTimeErrorCopy('VISIT_ALREADY_OPEN').length > 0);
    assert.ok(visitTimeErrorCopy('DEAL_CLOSED').length > 0);
    assert.ok(visitTimeErrorCopy(undefined).length > 0);
    assert.ok(visitTimeErrorCopy('SOMETHING_ELSE').length > 0);
  });
});
