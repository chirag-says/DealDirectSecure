/**
 * Disapproved property recovery (Phase 2.1)
 *
 * An owner whose listing is disapproved must be able to see that it happened,
 * see why, open it, and correct it — without gaining any ability to approve it
 * themselves.
 *
 * The authorization tests drive the real sanitizer exported from the
 * controller, so they run against the Phase 0 hardening rather than a copy.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §9.2 F-P8.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { sanitizePropertyData } from '../controllers/propertyController.js';
import Property from '../models/Property.js';

const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
const read = (rel) => stripComments(readFileSync(new URL(rel, import.meta.url), 'utf8'));

const propertyController = read('../controllers/propertyController.js');
const propertyRoutes = read('../routes/propertyRoutes.js');

const ownerGet = propertyController.slice(
  propertyController.indexOf('export const getMyPropertyById'),
  propertyController.indexOf('\nexport const ', propertyController.indexOf('export const getMyPropertyById') + 10)
);

describe('an owner can retrieve their own disapproved property', () => {
  test('an owner-scoped single-property endpoint exists', () => {
    assert.match(propertyController, /export const getMyPropertyById/);
    assert.match(
      propertyRoutes,
      /router\.get\(\s*\n?\s*["']\/my-properties\/:id["']/,
      'GET /my-properties/:id is not registered'
    );
  });

  test('it is declared before the /:id wildcard', () => {
    // Express matches in declaration order; after the wildcard it would be dead.
    const ownerAt = propertyRoutes.indexOf('"/my-properties/:id"');
    const wildcardAt = propertyRoutes.indexOf('router.get("/:id"');
    assert.ok(ownerAt !== -1 && wildcardAt !== -1);
    assert.ok(ownerAt < wildcardAt, 'the owner route is shadowed by /:id');
  });

  test('it does not filter on isApproved, so a disapproved listing loads', () => {
    assert.doesNotMatch(
      ownerGet,
      /isApproved/,
      'filtering on approval here would recreate the lockout this endpoint exists to fix'
    );
  });

  test('it returns the rejection reason the owner needs', () => {
    // The handler returns the owner's own document; rejectionReason is on the
    // schema and is not stripped.
    assert.ok(Property.schema.path('rejectionReason'), 'rejectionReason left the schema');
    assert.doesNotMatch(ownerGet, /select\(/, 'no field projection should hide the reason');
  });
});

describe('another user cannot retrieve it through the owner endpoint', () => {
  test('the lookup is scoped to the caller', () => {
    assert.match(
      ownerGet,
      /Property\.findOne\(\{\s*_id:\s*propertyId,\s*owner:\s*userId\s*\}\)/,
      'ownership must be enforced by a scoped query, not a post-hoc comparison'
    );
  });

  test('a miss returns 404, not 403', () => {
    // Same response for "does not exist" and "belongs to someone else", so the
    // endpoint cannot be used to enumerate property ids.
    assert.match(ownerGet, /status\(404\)/);
    assert.doesNotMatch(ownerGet, /status\(403\)/);
  });

  test('the route requires authentication and the owner role', () => {
    const block = propertyRoutes.slice(
      propertyRoutes.indexOf('router.get('),
      propertyRoutes.indexOf('router.put(\n  "/my-properties/:id"')
    );
    const ownerRoute = propertyRoutes.slice(
      propertyRoutes.lastIndexOf('router.get(', propertyRoutes.indexOf('"/my-properties/:id"')),
      propertyRoutes.indexOf('"/my-properties/:id"') + 200
    );
    assert.match(ownerRoute, /authMiddleware/);
    assert.match(ownerRoute, /ownerOnlyListingAccess/);
    assert.match(ownerRoute, /validateMongoId/);
  });

  test('it exposes no other user contact details', () => {
    // The Phase 1 owner-PII fix must not be undone by a new populate.
    assert.doesNotMatch(ownerGet, /populate\(\s*["']owner["']/);
    assert.doesNotMatch(ownerGet, /email|phone/);
  });
});

describe('the owner still cannot change moderation state', () => {
  // These are the Phase 0 guarantees; 2.1 must not weaken them.
  test('isApproved is stripped from an owner edit', () => {
    const out = sanitizePropertyData({ title: 'Fixed title', isApproved: true });
    assert.ok(!('isApproved' in out), 'an owner could self-approve after a disapproval');
    assert.equal(out.title, 'Fixed title', 'legitimate corrections must still save');
  });

  test('status is stripped from an owner edit', () => {
    const out = sanitizePropertyData({ title: 'T', status: 'active' });
    assert.ok(!('status' in out));
  });

  test('rejectionReason is stripped from an owner edit', () => {
    const out = sanitizePropertyData({ title: 'T', rejectionReason: '' });
    assert.ok(!('rejectionReason' in out), 'an owner could erase the reason they were given');
  });

  test('an owner correcting a disapproved listing saves content but not moderation', () => {
    const out = sanitizePropertyData({
      title: 'Corrected, no phone number in the title',
      description: 'Rewritten to meet the guidelines',
      price: 4500000,
      isApproved: true,
      status: 'active',
      rejectionReason: '',
    });
    assert.equal(out.title, 'Corrected, no phone number in the title');
    assert.equal(out.description, 'Rewritten to meet the guidelines');
    assert.equal(out.price, 4500000);
    assert.ok(!('isApproved' in out));
    assert.ok(!('status' in out));
    assert.ok(!('rejectionReason' in out));
  });

  test('the update path still applies the whitelist and validators', () => {
    const fn = propertyController.slice(
      propertyController.indexOf('export const updateMyProperty'),
      propertyController.indexOf('\nexport const ', propertyController.indexOf('export const updateMyProperty') + 10)
    );
    assert.match(fn, /sanitizePropertyData\(/);
    assert.match(fn, /runValidators:\s*true/);
  });
});

describe('approved listings are unaffected', () => {
  test('the public endpoint still gates on approval', () => {
    const publicGet = propertyController.slice(
      propertyController.indexOf('export const getPropertyById'),
      propertyController.indexOf('\nexport const ', propertyController.indexOf('export const getPropertyById') + 10)
    );
    assert.match(publicGet, /isApproved === true/, 'the public endpoint must still hide unapproved listings');
    assert.match(publicGet, /status\(404\)/);
  });

  test('the public endpoint still withholds owner contact', () => {
    const publicGet = propertyController.slice(
      propertyController.indexOf('export const getPropertyById'),
      propertyController.indexOf('\nexport const ', propertyController.indexOf('export const getPropertyById') + 10)
    );
    const populate = publicGet.match(/\.populate\(\s*["']owner["']\s*,\s*["']([^"']+)["']\s*\)/);
    assert.ok(populate);
    const fields = populate[1].split(/\s+/);
    assert.ok(!fields.includes('email') && !fields.includes('phone'));
  });

  test('the owner list endpoint is unchanged', () => {
    assert.match(propertyRoutes, /router\.get\("\/my-properties", authMiddleware, getMyProperties\)/);
  });
});
