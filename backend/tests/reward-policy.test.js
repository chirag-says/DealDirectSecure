/**
 * Reward policy configuration (Phase 3, F15).
 *
 * The defaults must reproduce pre-Phase-3 behaviour exactly, because the
 * client has not approved any numbers yet. These tests pin that, and pin
 * the explainer the clients render.
 */

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import { getRewardPolicy, describeRewardPolicy } from '../config/rewardPolicy.js';

const KEYS = [
  'MILESTONE_REWARDS_ENABLED', 'MILESTONE_VISIT_POINTS', 'MILESTONE_AGREEMENT_POINTS',
  'CLOSE_PAYOUT_FIXED_POINTS', 'PAYOUT_HOLD_DAYS', 'PAYOUT_HOLD_DAYS_FLAGGED',
];
const saved = {};

beforeEach(() => { for (const k of KEYS) { saved[k] = process.env[k]; delete process.env[k]; } });
afterEach(() => { for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });

describe('defaults change nothing', () => {
  test('milestones off, draw-only close, no hold, flagged hold 60 days', () => {
    const p = getRewardPolicy();
    assert.equal(p.milestonesEnabled, false);
    assert.equal(p.closePayoutFixedPoints, 0);
    assert.equal(p.payoutHoldDays, 0);
    assert.equal(p.payoutHoldDaysFlagged, 60);
    assert.equal(p.milestoneVisitPoints, 100);
    assert.equal(p.milestoneAgreementPoints, 200);
  });

  test('the explainer advertises no milestones while they are off', () => {
    const d = describeRewardPolicy();
    assert.deepEqual(d.milestones, []);
    assert.equal(d.close.fixedPoints, 0);
    assert.equal(d.close.drawBonus, true);
    assert.equal(d.pointValueRupees, 0.05);
  });
});

describe('configuration', () => {
  test('values are read from the environment at call time', () => {
    process.env.MILESTONE_REWARDS_ENABLED = 'true';
    process.env.MILESTONE_VISIT_POINTS = '150';
    process.env.CLOSE_PAYOUT_FIXED_POINTS = '2000';
    process.env.PAYOUT_HOLD_DAYS = '30';
    const p = getRewardPolicy();
    assert.equal(p.milestonesEnabled, true);
    assert.equal(p.milestoneVisitPoints, 150);
    assert.equal(p.closePayoutFixedPoints, 2000);
    assert.equal(p.payoutHoldDays, 30);
    const d = describeRewardPolicy();
    assert.equal(d.milestones.length, 2);
    assert.equal(d.milestones[0].points, 150);
    assert.equal(d.milestones.every((m) => m.cashable === false), true);
  });

  test('garbage and negatives fall back to the default', () => {
    process.env.PAYOUT_HOLD_DAYS = 'soon';
    process.env.MILESTONE_VISIT_POINTS = '-5';
    process.env.MILESTONE_REWARDS_ENABLED = 'yes';
    const p = getRewardPolicy();
    assert.equal(p.payoutHoldDays, 0);
    assert.equal(p.milestoneVisitPoints, 100);
    assert.equal(p.milestonesEnabled, false, 'only the literal "true" enables');
  });

  test('the policy object is frozen', () => {
    assert.throws(() => { getRewardPolicy().payoutHoldDays = 99; }, TypeError);
  });
});
