/**
 * Deal stage derivation (Phase 2, engine E3).
 *
 * The stage is a pure function of facts on the lead. These tests pin the
 * precedence and the edge cases the deal page depends on: an expired
 * proposal is not a scheduled visit, a done visit outranks an open one, an
 * agreement outranks visits, and a converted lead is closed no matter what
 * else is on the record.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { deriveStage, progressFor, STAGES, stageIndex } from '../utils/dealStage.js';

const NOW = new Date('2026-09-04T10:00:00.000Z');
const hours = (n) => new Date(NOW.getTime() + n * 3600 * 1000);

const lead = (over = {}) => ({ status: 'new', visits: [], createdAt: hours(-48), ...over });

describe('deriveStage', () => {
  test('a fresh lead is contacted', () => {
    assert.equal(deriveStage(lead(), NOW), 'contacted');
    assert.equal(deriveStage(null, NOW), 'contacted');
    assert.equal(deriveStage({}, NOW), 'contacted');
  });

  test('an open future visit is visit_scheduled, proposed or confirmed', () => {
    assert.equal(deriveStage(lead({ visits: [{ status: 'proposed', scheduledAt: hours(5) }] }), NOW), 'visit_scheduled');
    assert.equal(deriveStage(lead({ visits: [{ status: 'confirmed', scheduledAt: hours(5) }] }), NOW), 'visit_scheduled');
  });

  test('an open visit whose time has passed does not count', () => {
    assert.equal(deriveStage(lead({ visits: [{ status: 'confirmed', scheduledAt: hours(-1) }] }), NOW), 'contacted');
  });

  test('cancelled and no-show visits do not advance the stage', () => {
    assert.equal(deriveStage(lead({ visits: [{ status: 'cancelled', scheduledAt: hours(5) }] }), NOW), 'contacted');
    assert.equal(deriveStage(lead({ visits: [{ status: 'no_show', scheduledAt: hours(-5) }] }), NOW), 'contacted');
  });

  test('a done visit is visited, even with a later open one', () => {
    const l = lead({
      visits: [
        { status: 'done', scheduledAt: hours(-30) },
        { status: 'proposed', scheduledAt: hours(30) },
      ],
    });
    assert.equal(deriveStage(l, NOW), 'visited');
  });

  test('an agreement outranks visits', () => {
    const l = lead({ agreement: 'abc', visits: [{ status: 'done', scheduledAt: hours(-30) }] });
    assert.equal(deriveStage(l, NOW), 'agreement');
  });

  test('converted is closed regardless of everything else', () => {
    assert.equal(deriveStage(lead({ status: 'converted' }), NOW), 'closed');
    assert.equal(deriveStage(lead({ status: 'converted', agreement: 'x', visits: [] }), NOW), 'closed');
  });

  test('scheduledAt strings are accepted (lean documents)', () => {
    assert.equal(deriveStage(lead({ visits: [{ status: 'confirmed', scheduledAt: hours(2).toISOString() }] }), NOW), 'visit_scheduled');
  });
});

describe('progressFor', () => {
  test('always pre-stamps the first row with the enquiry', () => {
    const rows = progressFor(lead(), NOW);
    assert.equal(rows.length, STAGES.length);
    assert.equal(rows[0].key, 'contacted');
    assert.equal(rows[0].done, true);
    assert.ok(rows[0].reason);
    assert.equal(rows.slice(1).every((r) => r.done === false), true);
  });

  test('done flags follow the stage index monotonically', () => {
    const l = lead({ visits: [{ status: 'done', scheduledAt: hours(-30), updatedAt: hours(-29), feedback: 'interested' }] });
    const rows = progressFor(l, NOW);
    assert.deepEqual(rows.map((r) => r.done), [true, true, true, false, false]);
    assert.match(rows[2].reason, /interested/);
  });

  test('closed marks every row and names the verification', () => {
    const rows = progressFor(lead({ status: 'converted', closedAt: hours(-1) }), NOW);
    assert.equal(rows.every((r) => r.done), true);
    assert.match(rows[4].reason, /verified/i);
  });

  test('stageIndex never returns a negative index', () => {
    assert.equal(stageIndex('not-a-stage'), 0);
    assert.equal(stageIndex('closed'), 4);
  });
});
