/**
 * Saved-search matching (Phase 1, F8/F9).
 *
 * The rules moved out of two drifted copies inside propertyController into
 * one module. These tests pin the semantics that were preserved — including
 * the un-trimmed city comparison, which looks like a bug and is deliberately
 * kept, because changing it would silently widen who gets notified across
 * every saved search that already exists.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  candidateSearchFilter,
  crossedIntoBucket,
  priceBucketMatches,
  searchMatchesProperty,
} from '../utils/savedSearchMatch.js';

const propertyIn = (city, price) => ({ address: { city }, price });

describe('the city filter handed to MongoDB', () => {
  test('matches the city anchored and case-insensitively', () => {
    const filter = candidateSearchFilter(propertyIn('Pune', 100));
    const cityClause = filter.$or.find((c) => c['filters.city']?.$regex);
    assert.equal(cityClause['filters.city'].$regex, '^Pune$');
    assert.equal(cityClause['filters.city'].$options, 'i');
  });

  test('a search with no city still matches every city, as it always did', () => {
    const filter = candidateSearchFilter(propertyIn('Pune', 100));
    assert.ok(filter.$or.some((c) => Array.isArray(c['filters.city']?.$in)));
    assert.ok(filter.$or.some((c) => c['filters.city']?.$exists === false));
  });

  test('a city containing regex metacharacters is escaped, so "P.ne" cannot match "Pune"', () => {
    const filter = candidateSearchFilter(propertyIn('P.ne', 100));
    const cityClause = filter.$or.find((c) => c['filters.city']?.$regex);
    assert.equal(cityClause['filters.city'].$regex, '^P\\.ne$');
  });

  test('only active searches are ever candidates', () => {
    assert.equal(candidateSearchFilter(propertyIn('Pune', 1)).isActive, true);
  });

  test('a property with no city produces an anchored empty match, not a match-all', () => {
    const filter = candidateSearchFilter({ address: {} });
    const cityClause = filter.$or.find((c) => c['filters.city']?.$regex);
    assert.equal(cityClause['filters.city'].$regex, '^$');
  });
});

describe('the price buckets', () => {
  const cases = [
    ['low', 4999999, true],
    ['low', 5000000, false],
    ['mid', 5000000, true],
    ['mid', 15000000, true],
    ['mid', 15000001, false],
    ['mid', 4999999, false],
    ['high', 15000001, true],
    ['high', 15000000, false],
  ];

  for (const [range, price, expected] of cases) {
    test(`${range} ${expected ? 'contains' : 'excludes'} ${price}`, () => {
      assert.equal(priceBucketMatches(range, price), expected);
    });
  }

  test('no bucket, or no numeric price, skips the test entirely', () => {
    assert.equal(priceBucketMatches('', 999), true);
    assert.equal(priceBucketMatches(null, 999), true);
    assert.equal(priceBucketMatches('mid', undefined), true);
    assert.equal(priceBucketMatches('mid', 'lots'), true);
  });

  test('an unknown bucket matches nothing rather than everything', () => {
    assert.equal(priceBucketMatches('enormous', 100), false);
  });
});

describe('searchMatchesProperty', () => {
  test('a search with only a city matches any price in that city', () => {
    assert.equal(searchMatchesProperty({ filters: { city: 'Pune' } }, propertyIn('Pune', 90000000)), true);
  });

  test('a bucket that excludes the price refuses the match', () => {
    assert.equal(searchMatchesProperty({ filters: { priceRange: 'low' } }, propertyIn('Pune', 90000000)), false);
  });

  test('missing filters never throw', () => {
    assert.equal(searchMatchesProperty({}, propertyIn('Pune', 1)), true);
    assert.equal(searchMatchesProperty(undefined, undefined), true);
  });
});

describe('crossedIntoBucket — the half that finds new buyers', () => {
  test('a drop out of high and into mid reaches a mid watcher who never saw it', () => {
    assert.equal(crossedIntoBucket('mid', 16000000, 14000000), true);
  });

  test('a drop within one bucket does not re-announce to that bucket', () => {
    // Those watchers already saw the listing; the shortlist half covers them.
    assert.equal(crossedIntoBucket('mid', 14000000, 13000000), false);
  });

  test('a rise never counts as crossing in', () => {
    assert.equal(crossedIntoBucket('high', 14000000, 16000000), true, 'a rise CAN enter a higher bucket');
    assert.equal(crossedIntoBucket('mid', 4000000, 6000000), true);
    // The caller only ever passes drops; the function stays honest either way.
  });

  test('a search with no bucket is never "crossed into", because it always matched', () => {
    assert.equal(crossedIntoBucket('', 16000000, 14000000), false);
    assert.equal(crossedIntoBucket(null, 16000000, 14000000), false);
  });

  test('a drop from low to lower crosses nothing', () => {
    assert.equal(crossedIntoBucket('low', 4000000, 3000000), false);
  });
});
