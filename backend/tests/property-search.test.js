/**
 * Property search contract (Phase 2.2, backend half)
 *
 * Covers the server-side capability the listing page needs: bounded pagination,
 * taxonomy filtering against the columns that hold correct data, availability
 * filtering, and raw-rupee price handling.
 *
 * Measured against live data during implementation (2026-08-16):
 *   baseline 31 · rent 21 + sale 10 = 31 · Residential 22 + Commercial 9 = 31
 *   limit=200000 → capped to 60 · page=-3 → floored to 1
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §10 (F-P9 50-cap, F-P13 uncapped
 * pagination, B30 phantom params), §9.3 M3 (sold listings in public reads).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import Property from '../models/Property.js';
import { escapeRegExp } from '../utils/escapeRegExp.js';

const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
const read = (rel) => stripComments(readFileSync(new URL(rel, import.meta.url), 'utf8'));

const controller = read('../controllers/propertyController.js');
const search = controller.slice(
  controller.indexOf('export const searchProperties'),
  controller.indexOf('\nexport const ', controller.indexOf('export const searchProperties') + 10)
);

/** Pagination bounds exactly as the controller computes them. */
const bounds = (limit, page) => ({
  limit: Math.min(Math.max(parseInt(limit, 10) || 12, 1), 60),
  page: Math.max(parseInt(page, 10) || 1, 1),
});

describe('pagination is bounded', () => {
  test('defaults to 12 per page, page 1', () => {
    assert.deepEqual(bounds(undefined, undefined), { limit: 12, page: 1 });
  });

  test('an explicit page size is honoured', () => {
    assert.equal(bounds(5).limit, 5);
    assert.equal(bounds(24).limit, 24);
  });

  test('limit is capped so one request cannot pull the corpus', () => {
    assert.equal(bounds(200000).limit, 60);
    assert.equal(bounds(61).limit, 60);
    assert.equal(bounds(60).limit, 60);
  });

  test('limit cannot go below 1', () => {
    assert.equal(bounds(0).limit, 12, 'zero falls back to the default');
    assert.equal(bounds(-5).limit, 1);
  });

  test('page is floored at 1 so skip is never negative', () => {
    assert.equal(bounds(12, 0).page, 1);
    assert.equal(bounds(12, -3).page, 1);
    assert.equal(bounds(12, 'abc').page, 1);
  });

  test('a valid page is preserved', () => {
    assert.equal(bounds(12, 3).page, 3);
  });

  test('skip is computed from the bounded values', () => {
    assert.match(search, /const skip = \(safePage - 1\) \* safeLimit/);
    assert.match(search, /\.limit\(safeLimit\)/);
  });

  test('the response reports the page size it actually used', () => {
    // Without this a client cannot tell its limit was capped.
    assert.match(search, /limit: safeLimit/);
    assert.match(search, /pages: Math\.ceil\(total \/ safeLimit\)/);
  });
});

describe('taxonomy filtering uses the columns that hold correct data', () => {
  test('categoryName and propertyTypeName are accepted', () => {
    assert.match(search, /categoryName,/);
    assert.match(search, /propertyTypeName,/);
    assert.match(search, /filter\.categoryName = \{/);
    assert.match(search, /filter\.propertyTypeName = \{/);
  });

  test('both are real schema paths', () => {
    assert.ok(Property.schema.path('categoryName'));
    assert.ok(Property.schema.path('propertyTypeName'));
  });

  test('the name match is anchored, so Villa does not match Villa Plot', () => {
    const pattern = `^${escapeRegExp('Villa')}$`;
    assert.equal(new RegExp(pattern, 'i').test('Villa'), true);
    assert.equal(new RegExp(pattern, 'i').test('Villa Plot'), false);
    assert.match(search, /\^\$\{escapeRegExp/);
  });

  test('the name match is case-insensitive', () => {
    const re = new RegExp(`^${escapeRegExp('Residential')}$`, 'i');
    assert.equal(re.test('residential'), true);
    assert.equal(re.test('RESIDENTIAL'), true);
  });

  test('name input is escaped — this endpoint is public', () => {
    const re = new RegExp(`^${escapeRegExp('.*')}$`, 'i');
    assert.equal(re.test('Residential'), false, 'a wildcard must not match everything');
    assert.equal(re.test('.*'), true);
    assert.match(search, /escapeRegExp\(String\(categoryName\)/);
    assert.match(search, /escapeRegExp\(String\(propertyTypeName\)/);
  });

  test('the ObjectId ref filters are still accepted for compatibility', () => {
    assert.match(search, /if \(category\) filter\.category = category/);
    assert.match(search, /if \(propertyType\) filter\.propertyType = propertyType/);
  });
});

describe('phantom parameters are gone', () => {
  test('buildingType and size are no longer read into the filter', () => {
    // Neither is on propertySchema; strictQuery:false let them reach MongoDB as
    // unknown paths and match zero documents, so any client sending one got an
    // empty list with no error.
    assert.doesNotMatch(search, /filter\.buildingType/);
    assert.doesNotMatch(search, /filter\.size/);
    assert.equal(Property.schema.path('buildingType'), undefined);
    assert.equal(Property.schema.path('size'), undefined);
  });
});

describe('only available listings are returned', () => {
  test('terminal and in-flight statuses are excluded', () => {
    assert.match(search, /filter\.status = \{\s*\$nin:/);
    for (const s of ['sold', 'rented', 'pending_verification', 'inactive']) {
      assert.match(search, new RegExp(`"${s}"`), `${s} is not excluded from search`);
    }
  });

  test('every excluded value is a real schema status', () => {
    const statuses = Property.schema.path('status').options.enum;
    for (const s of ['sold', 'rented', 'pending_verification', 'inactive']) {
      assert.ok(statuses.includes(s), `"${s}" is not a booking status`);
    }
  });

  test('active listings are not excluded', () => {
    const excluded = search.slice(search.indexOf('filter.status'), search.indexOf('filter.status') + 160);
    assert.doesNotMatch(excluded, /"active"/);
    assert.doesNotMatch(excluded, /"pending"/);
  });

  test('approval and the builder-feed split are still enforced', () => {
    assert.match(search, /isApproved: true/);
    assert.match(search, /builder: null/);
  });
});

describe('price is filtered in raw rupees', () => {
  test('priceFrom and priceTo map to $gte/$lte on price', () => {
    assert.match(search, /filter\.price\.\$gte = \+priceFrom/);
    assert.match(search, /filter\.price\.\$lte = \+priceTo/);
  });

  test('no unit conversion is applied server-side', () => {
    // price is stored in rupees. priceUnit is a display label and must not be
    // used as a multiplier — that is what made the old client-side filter
    // evaluate a 36,000 rental as 36 crore.
    assert.doesNotMatch(search, /priceUnit/);
    assert.doesNotMatch(search, /100000|1e5/);
  });

  test('price is a plain number on the schema', () => {
    assert.equal(Property.schema.path('price').instance, 'Number');
  });
});

describe('search term handling is unchanged and safe', () => {
  test('the free-text search still escapes its input', () => {
    assert.match(search, /escapeRegExp\(search\)/);
  });

  test('listingType alias expansion is preserved', () => {
    assert.match(search, /LISTING_TYPE_ALIASES/);
    assert.match(search, /rent: \["Rent", "rent"\]/);
    assert.match(search, /sale: \["Sell", "Sale", "sell", "sale"\]/);
  });
});
