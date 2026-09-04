/**
 * The pure halves of the scheduled jobs (Phase 0 / Phase 2).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { isoWeek } from '../jobs/ownerWeeklyDigest.js';
import { istDay, istDayBounds } from '../jobs/eventsRollup.js';
import { JOBS } from '../jobs/registry.js';
import cron from 'node-cron';

describe('isoWeek', () => {
  test('Monday and the following Sunday share a week', () => {
    assert.equal(isoWeek(new Date('2026-08-31T00:00:00Z')), '2026-W36');
    assert.equal(isoWeek(new Date('2026-09-06T23:59:59Z')), '2026-W36');
    assert.equal(isoWeek(new Date('2026-09-07T00:00:00Z')), '2026-W37');
  });

  test('the first days of January belong to the previous year when ISO says so', () => {
    assert.equal(isoWeek(new Date('2027-01-01T12:00:00Z')), '2026-W53');
  });
});

describe('IST day helpers', () => {
  test('an instant late in the UTC evening is already the next day in IST', () => {
    assert.equal(istDay(new Date('2026-09-04T20:00:00Z')), '2026-09-05');
    assert.equal(istDay(new Date('2026-09-04T18:29:59Z')), '2026-09-04');
  });

  test('day bounds cover exactly 24 hours starting at IST midnight', () => {
    const { start, end } = istDayBounds('2026-09-05');
    assert.equal(start.toISOString(), '2026-09-04T18:30:00.000Z');
    assert.equal(end.getTime() - start.getTime(), 86400 * 1000);
  });
});

describe('job registry', () => {
  test('every job has a unique name, a valid cron expression and a handler', () => {
    const names = new Set();
    for (const job of JOBS) {
      assert.ok(job.name && !names.has(job.name), `duplicate or missing name: ${job.name}`);
      names.add(job.name);
      assert.ok(cron.validate(job.schedule), `${job.name}: invalid schedule ${job.schedule}`);
      assert.equal(typeof job.handler, 'function', `${job.name}: handler`);
    }
  });

  test('the digest runs once a week, on Monday morning IST', () => {
    const digest = JOBS.find((j) => j.name === 'owner-weekly-digest');
    assert.equal(digest.schedule, '0 8 * * 1');
  });
});
