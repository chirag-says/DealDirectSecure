/**
 * Property field contract — regression tests
 *
 * Runs with the Node built-in test runner (no dependency):
 *   npm test
 *
 * These assert business invariants, not HTTP status codes. Every case here
 * corresponds to a defect found in the 2026-08-16 audit; if one starts failing,
 * the defect has been reintroduced.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §7.2 (owner mass assignment),
 * §9.1 (fields silently destroyed on create).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  sanitizePropertyData,
  PROPERTY_ALLOWED_FIELDS,
  ADMIN_ONLY_FIELDS,
} from '../controllers/propertyController.js';
import Property from '../models/Property.js';

const schemaTopLevel = new Set(
  Object.keys(Property.schema.paths).map((p) => p.split('.')[0])
);

/** Fields the owner must never be able to set on their own listing. */
const SYSTEM_OWNED = [
  'isApproved',
  'status',
  'builder',
  'views',
  'likes',
  'rejectionReason',
  'owner',
  'interestedUsers',
  'inquiries',
  'approvedBy',
  'disapprovedBy',
];

/**
 * Fields the create/edit forms actually send that must reach the database.
 * Sourced from client-next AddPropertyContent.jsx (top-level appends and the
 * `features` object, which the controller spreads to top level before saving).
 */
const FORM_SENDS_AND_MUST_PERSIST = [
  // taxonomy — null refs here are why category filtering returns nothing
  'category', 'subcategory', 'propertyType',
  // pricing / metadata — priceUnit stripped is why the price filter is 1e5 out
  'priceUnit', 'gstApplicable', 'bookingAmount', 'videoUrl', 'ageOfProperty',
  // residential
  'floorNo', 'propertyAge', 'allowedFor', 'petFriendly', 'maintenanceIncluded',
  // commercial
  'commercialSubType', 'loadingArea', 'dockAvailable', 'shutters',
  'floorHeight', 'powerLoad',
  // commercial per-subtype configuration
  'workstations', 'conferenceRooms', 'cabins', 'frontage', 'storage',
  'displayWindows', 'displayArea', 'seatingCapacity', 'kitchenArea', 'barArea',
  'outdoorSeating', 'privateCabins', 'phoneBooths', 'loungeArea', 'loadingDocks',
  'ceilingHeight', 'floorLoadCapacity', 'powerConnection', 'overheadCrane',
  'centralAC',
];

describe('sanitizePropertyData — system-owned fields', () => {
  for (const field of SYSTEM_OWNED) {
    test(`strips "${field}" from a request body`, () => {
      const out = sanitizePropertyData({ title: 'A flat', [field]: 'attacker-value' });
      assert.ok(
        !(field in out),
        `${field} survived sanitization — an owner could set it via PUT /properties/my-properties/:id`
      );
      assert.equal(out.title, 'A flat', 'legitimate fields must still pass through');
    });
  }

  test('an owner cannot self-approve a disapproved listing', () => {
    const out = sanitizePropertyData({
      title: 'Edited title',
      isApproved: true,
      rejectionReason: '',
    });
    assert.ok(!('isApproved' in out));
    assert.ok(!('rejectionReason' in out));
  });

  test('an owner cannot mark a property sold without admin verification', () => {
    const out = sanitizePropertyData({ title: 'Edited title', status: 'sold' });
    assert.ok(!('status' in out));
  });

  test('an owner cannot move a listing into the builder feed', () => {
    const out = sanitizePropertyData({
      title: 'Edited title',
      builder: '507f1f77bcf86cd799439011',
    });
    assert.ok(!('builder' in out));
  });

  test('an owner cannot forge engagement counters', () => {
    const out = sanitizePropertyData({ title: 'T', views: 99999, likes: 99999 });
    assert.ok(!('views' in out));
    assert.ok(!('likes' in out));
  });
});

describe('sanitizePropertyData — form fields must survive', () => {
  test('every field the forms send is whitelisted', () => {
    const dropped = FORM_SENDS_AND_MUST_PERSIST.filter(
      (f) => !PROPERTY_ALLOWED_FIELDS.includes(f)
    );
    assert.deepEqual(
      dropped,
      [],
      `these are sent by the form and would be silently discarded: ${dropped.join(', ')}`
    );
  });

  test('a realistic commercial payload survives sanitization intact', () => {
    const payload = Object.fromEntries(
      FORM_SENDS_AND_MUST_PERSIST.map((f) => [f, 'v'])
    );
    payload.title = 'Commercial unit';
    const out = sanitizePropertyData(payload);
    for (const f of FORM_SENDS_AND_MUST_PERSIST) {
      assert.ok(f in out, `${f} was stripped by the whitelist`);
    }
  });

  test('unknown fields are still rejected (mass assignment stays blocked)', () => {
    const out = sanitizePropertyData({ title: 'T', someInventedField: 'x', __proto__: 'y' });
    assert.ok(!('someInventedField' in out));
  });
});

describe('field contract integrity', () => {
  test('no whitelisted name is also admin-only', () => {
    const overlap = PROPERTY_ALLOWED_FIELDS.filter((f) => ADMIN_ONLY_FIELDS.includes(f));
    assert.deepEqual(overlap, [], `contradictory entries: ${overlap.join(', ')}`);
  });

  test('every system-owned field is listed in ADMIN_ONLY_FIELDS', () => {
    const missing = SYSTEM_OWNED.filter((f) => !ADMIN_ONLY_FIELDS.includes(f));
    assert.deepEqual(missing, [], `not blocked: ${missing.join(', ')}`);
  });

  test('newly contracted fields all exist on propertySchema', () => {
    // Guards against whitelisting a name Mongoose will silently drop.
    const ghosts = FORM_SENDS_AND_MUST_PERSIST.filter((f) => !schemaTopLevel.has(f));
    assert.deepEqual(ghosts, [], `whitelisted but absent from the schema: ${ghosts.join(', ')}`);
  });
});

describe('write paths are wired to the sanitizer', () => {
  // Source-level assertions. The controller writes need a live MongoDB (and a
  // replica set, since addProperty uses a transaction), so these pin the wiring
  // rather than the behaviour. Replace with integration tests once a test
  // database exists.
  const source = readFileSync(
    new URL('../controllers/propertyController.js', import.meta.url),
    'utf8'
  );

  const bodyOf = (fnName) => {
    const start = source.indexOf(`export const ${fnName} = async (req, res)`);
    assert.notEqual(start, -1, `${fnName} not found — was it renamed?`);
    const next = source.indexOf('\nexport const ', start + 10);
    return source.slice(start, next === -1 ? source.length : next);
  };

  for (const fn of ['addProperty', 'updateMyProperty', 'addPropertyForBuilder', 'updateProperty']) {
    test(`${fn} sanitizes the request body`, () => {
      assert.match(
        bodyOf(fn),
        /sanitizePropertyData\(/,
        `${fn} writes to Property without applying the field whitelist`
      );
    });
  }

  test('updateMyProperty enforces schema validators on write', () => {
    assert.match(
      bodyOf('updateMyProperty'),
      /runValidators:\s*true/,
      'findByIdAndUpdate skips enum validation unless runValidators is set'
    );
  });

  test('updateMyProperty scopes its lookup to the owner (IDOR guard)', () => {
    assert.match(
      bodyOf('updateMyProperty'),
      /findOne\(\{\s*_id:\s*propertyId,\s*owner:\s*userId\s*\}\)/,
      'ownership must be enforced by a scoped query, not a post-hoc comparison'
    );
  });
});
