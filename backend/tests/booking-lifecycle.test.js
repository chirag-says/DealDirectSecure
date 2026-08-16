/**
 * Booking lifecycle — amount consistency, legal transitions, inventory
 * restoration, and the approval race path.
 *
 * The transition table and the inventory-holding set are imported from the
 * controller, so these assert the real rules rather than a copy.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §15.1 (F-A1 token amount,
 * F-A3 status bypass, F-A9 race-path state).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  BOOKING_STATUS_TRANSITIONS,
  STATUSES_HOLDING_INVENTORY,
} from '../controllers/bookingController.js';
import ProjectBooking from '../models/ProjectBooking.js';

const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
const read = (rel) => stripComments(readFileSync(new URL(rel, import.meta.url), 'utf8'));

const bookingController = read('../controllers/bookingController.js');

const SCHEMA_STATUSES = ProjectBooking.schema.path('status').options.enum;

/* ------------------------------------------------------------------ *
 * Amount resolution — mirrors createBooking and the client's own order.
 * ------------------------------------------------------------------ */
const resolveTokenAmount = (unitType, project) =>
  unitType?.paymentTerms?.bookingAmount ?? project?.financials?.bookingAmount ?? 0;

describe('booking amount consistency', () => {
  test('uses the unit-level amount when present', () => {
    const amount = resolveTokenAmount(
      { paymentTerms: { bookingAmount: 250000 } },
      { financials: { bookingAmount: 99 } }
    );
    assert.equal(amount, 250000, 'unit-level must win — it is what the client quotes');
  });

  test('falls back to the legacy project amount for older records', () => {
    assert.equal(resolveTokenAmount({ paymentTerms: {} }, { financials: { bookingAmount: 100000 } }), 100000);
    assert.equal(resolveTokenAmount({}, { financials: { bookingAmount: 100000 } }), 100000);
  });

  test('a project created since the financials move no longer resolves to zero', () => {
    // createProject stopped writing project.financials; before the fix this
    // combination produced 0 while the client quoted 250000.
    const unitType = { paymentTerms: { bookingAmount: 250000 } };
    const project = {}; // no financials written
    assert.equal(resolveTokenAmount(unitType, project), 250000);
    assert.notEqual(resolveTokenAmount(unitType, project), 0);
  });

  test('resolves to zero only when neither source has a value', () => {
    assert.equal(resolveTokenAmount({}, {}), 0);
  });

  test('a legitimate zero unit amount is not overridden by the project fallback', () => {
    // ?? not || — a genuine 0 at unit level must stand.
    assert.equal(resolveTokenAmount({ paymentTerms: { bookingAmount: 0 } }, { financials: { bookingAmount: 5000 } }), 0);
  });

  test('createBooking selects paymentTerms from the unit type', () => {
    assert.match(
      bookingController,
      /UnitType\.findById\(unitTypeId\)\.select\([^)]*paymentTerms/,
      'paymentTerms must be selected or the amount is always undefined'
    );
  });

  test('createBooking no longer reads the project amount first', () => {
    assert.match(
      bookingController,
      /unitType\.paymentTerms\?\.bookingAmount\s*\?\?\s*project\.financials\?\.bookingAmount/
    );
  });
});

describe('booking transition table', () => {
  test('every key and target is a real schema status', () => {
    for (const [from, targets] of Object.entries(BOOKING_STATUS_TRANSITIONS)) {
      assert.ok(SCHEMA_STATUSES.includes(from), `"${from}" is not a booking status`);
      for (const to of targets) {
        assert.ok(SCHEMA_STATUSES.includes(to), `"${to}" is not a booking status`);
      }
    }
  });

  test('every schema status is covered by the table', () => {
    for (const s of SCHEMA_STATUSES) {
      assert.ok(s in BOOKING_STATUS_TRANSITIONS, `"${s}" has no transition rule`);
    }
  });

  test('confirmed is not reachable from any state via the manual endpoint', () => {
    for (const [from, targets] of Object.entries(BOOKING_STATUS_TRANSITIONS)) {
      assert.ok(
        !targets.includes('confirmed'),
        `${from} → confirmed bypasses payment verification and the inventory decrement`
      );
    }
  });

  test('enquiry → confirmed is rejected (the reported bypass)', () => {
    assert.ok(!BOOKING_STATUS_TRANSITIONS.enquiry.includes('confirmed'));
  });

  test('payment_submitted → confirmed is rejected', () => {
    assert.ok(!BOOKING_STATUS_TRANSITIONS.payment_submitted.includes('confirmed'));
  });

  test('the legitimate confirmed → completed path still works', () => {
    assert.ok(BOOKING_STATUS_TRANSITIONS.confirmed.includes('completed'));
  });

  test('a non-terminal booking can still be cancelled', () => {
    for (const s of ['enquiry', 'payment_submitted', 'confirmed']) {
      assert.ok(BOOKING_STATUS_TRANSITIONS[s].includes('cancelled'), `${s} can no longer be cancelled`);
    }
  });

  test('cancelled is terminal', () => {
    assert.deepEqual(BOOKING_STATUS_TRANSITIONS.cancelled, []);
  });

  test('completed cannot silently return to an active state', () => {
    assert.ok(!BOOKING_STATUS_TRANSITIONS.completed.includes('enquiry'));
    assert.ok(!BOOKING_STATUS_TRANSITIONS.completed.includes('payment_submitted'));
  });

  test('the handler rejects a status outside the allowed targets', () => {
    assert.match(bookingController, /const allowed = \["cancelled", "completed"\]/);
    assert.match(bookingController, /INVALID_STATUS/);
  });

  test('the handler consults the table before writing', () => {
    const fn = bookingController.slice(bookingController.indexOf('export const updateBookingStatus'));
    const checkAt = fn.indexOf('ILLEGAL_TRANSITION');
    const writeAt = fn.indexOf('booking.status = status');
    assert.ok(checkAt !== -1 && writeAt !== -1);
    assert.ok(checkAt < writeAt, 'the transition guard must run before the status is assigned');
  });
});

describe('inventory restoration on cancellation', () => {
  const releasesInventory = (from, to) =>
    to === 'cancelled' && STATUSES_HOLDING_INVENTORY.includes(from);

  test('cancelling a confirmed booking returns the unit', () => {
    assert.equal(releasesInventory('confirmed', 'cancelled'), true);
  });

  test('cancelling a completed booking returns the unit', () => {
    assert.equal(releasesInventory('completed', 'cancelled'), true);
  });

  test('cancelling an enquiry does not invent inventory', () => {
    // No decrement ever happened for these, so restoring would inflate stock.
    assert.equal(releasesInventory('enquiry', 'cancelled'), false);
    assert.equal(releasesInventory('payment_submitted', 'cancelled'), false);
  });

  test('completing a booking does not restore inventory', () => {
    assert.equal(releasesInventory('confirmed', 'completed'), false);
  });

  test('a second cancel cannot double-restore', () => {
    // The transition table makes cancelled terminal, so the handler returns
    // before reaching the restore.
    assert.deepEqual(BOOKING_STATUS_TRANSITIONS.cancelled, []);
    assert.equal(releasesInventory('cancelled', 'cancelled'), false);
  });

  test('the restore is guarded so bookedUnits cannot go negative', () => {
    const fn = bookingController.slice(bookingController.indexOf('export const updateBookingStatus'));
    assert.match(fn, /"inventory\.bookedUnits":\s*\{\s*\$gte:\s*1\s*\}/);
    assert.match(fn, /"inventory\.availableUnits":\s*1/);
    assert.match(fn, /"inventory\.bookedUnits":\s*-1/);
  });

  test('the inventory-holding set matches the states that decrement', () => {
    assert.deepEqual([...STATUSES_HOLDING_INVENTORY].sort(), ['completed', 'confirmed']);
  });
});

describe('approval path and the inventory race', () => {
  // Slice forward from the approve branch to ITS matching else — searching the
  // whole file for '} else {' finds an earlier one and yields an empty slice.
  const approveAt = bookingController.indexOf('if (action === "approve")');
  const approve = bookingController.slice(
    approveAt,
    bookingController.indexOf('} else {', approveAt)
  );

  test('the atomic $gte:1 decrement is preserved exactly', () => {
    assert.match(approve, /"inventory\.availableUnits":\s*\{\s*\$gte:\s*1\s*\}/);
    assert.match(approve, /"inventory\.availableUnits":\s*-1/);
    assert.match(approve, /"inventory\.bookedUnits":\s*1/);
  });

  test('inventory is secured before the confirmation is persisted', () => {
    const decrementAt = approve.indexOf('UnitType.findOneAndUpdate');
    const confirmAt = approve.indexOf('booking.status = "confirmed"');
    assert.ok(decrementAt !== -1 && confirmAt !== -1);
    assert.ok(
      decrementAt < confirmAt,
      'persisting confirmed before reserving a unit allows an oversell if the process dies between the two writes'
    );
  });

  test('the race path records the payment as verified, not rejected', () => {
    const race = approve.slice(approve.indexOf('if (!inventoryResult)'));
    assert.match(race, /booking\.payment\.status = "verified"/, 'the money was received; erasing that hides a refund');
    assert.doesNotMatch(race, /payment\.status = "rejected"/);
  });

  test('the race path states that a refund is due', () => {
    const race = approve.slice(approve.indexOf('if (!inventoryResult)'));
    assert.match(race, /REFUND DUE/i, 'verified payment + cancelled booking must be unambiguous');
  });

  test('the race path cancels the booking and returns 409', () => {
    const race = approve.slice(approve.indexOf('if (!inventoryResult)'));
    assert.match(race, /booking\.status = "cancelled"/);
    assert.match(race, /status\(409\)/);
  });

  test('the race path does not enrol a campaign member', () => {
    const race = approve.slice(approve.indexOf('if (!inventoryResult)'), approve.indexOf('return res.status(409)'));
    assert.doesNotMatch(race, /syncBookingToCampaign/);
  });

  test('campaign enrolment on the manual endpoint no longer fires for confirmed', () => {
    const fn = bookingController.slice(bookingController.indexOf('export const updateBookingStatus'));
    assert.doesNotMatch(
      fn,
      /status === "confirmed" \|\| status === "completed"/,
      'confirmed is unreachable here; enrolling on it auto-created PAID members without payment'
    );
    assert.match(fn, /status === "completed"/);
  });
});
