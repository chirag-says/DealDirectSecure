/**
 * Locality statistics arithmetic (Phase 4, engine E4).
 *
 * These are the numbers the public pages publish under DealDirect's name, so
 * every one of them is a definition a reader can recompute by hand. The
 * tests pin the definitions, the bucketing of free text an owner typed, and
 * the boundaries where the honest answer is null.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  bhkBucket,
  localitySlug,
  median,
  normalizeListingType,
  percentChange,
  percentile,
  previousQuarter,
  quarterOf,
} from '../utils/locality.js';

describe('median', () => {
  test('odd samples take the middle, even samples average the two', () => {
    assert.equal(median([3, 1, 2]), 2);
    assert.equal(median([4, 1, 3, 2]), 2.5);
  });

  test('one value is its own median; an empty sample has none', () => {
    assert.equal(median([7]), 7);
    assert.equal(median([]), null);
    assert.equal(median([NaN, undefined, null]), null);
  });

  test('the caller\'s array is not reordered', () => {
    const input = [5, 1, 3];
    median(input);
    assert.deepEqual(input, [5, 1, 3]);
  });
});

describe('percentile', () => {
  test('nearest rank always returns a price some listing actually asks', () => {
    const prices = [10, 20, 30, 40];
    for (const pct of [25, 50, 75, 90]) {
      assert.ok(prices.includes(percentile(prices, pct)), `p${pct} must be a real asking price`);
    }
  });

  test('the quartiles bracket the median', () => {
    const prices = [10, 20, 30, 40, 50, 60, 70, 80];
    assert.ok(percentile(prices, 25) <= median(prices));
    assert.ok(percentile(prices, 75) >= median(prices));
  });

  test('the extremes clamp instead of running off the array', () => {
    assert.equal(percentile([10, 20, 30], 0), 10);
    assert.equal(percentile([10, 20, 30], 100), 30);
    assert.equal(percentile([], 50), null);
  });
});

describe('percentChange', () => {
  test('reports one decimal, signed', () => {
    assert.equal(percentChange(100, 90), -10);
    assert.equal(percentChange(3000000, 2850000), -5);
    assert.equal(percentChange(100, 133), 33);
  });

  test('refuses a base it cannot divide by', () => {
    assert.equal(percentChange(0, 100), null);
    assert.equal(percentChange(-5, 100), null);
    assert.equal(percentChange(null, 100), null);
    assert.equal(percentChange(100, undefined), null);
  });
});

describe('bhkBucket, over the free text owners actually type', () => {
  test('reads the first integer out of any spelling', () => {
    for (const input of ['2', '2 BHK', '2bhk', ' 2 ', '2BHK + study']) {
      assert.equal(bhkBucket(input), '2', input);
    }
  });

  test('four and above collapse, where the sample is always thin', () => {
    assert.equal(bhkBucket('4'), '4+');
    assert.equal(bhkBucket('5 BHK'), '4+');
    assert.equal(bhkBucket('12'), '4+');
  });

  test('anything unreadable is not bucketed rather than guessed', () => {
    for (const input of ['', null, undefined, 'studio', 'penthouse', '0', '21', {}]) {
      assert.equal(bhkBucket(input), null, JSON.stringify(input));
    }
  });
});

describe('normalizeListingType', () => {
  test('all six spellings the Property enum allows collapse to two', () => {
    assert.equal(normalizeListingType('Rent'), 'rent');
    assert.equal(normalizeListingType('rent'), 'rent');
    assert.equal(normalizeListingType('Sell'), 'sale');
    assert.equal(normalizeListingType('sell'), 'sale');
    assert.equal(normalizeListingType('Sale'), 'sale');
    assert.equal(normalizeListingType('sale'), 'sale');
  });

  test('anything else is refused, so it lands in no bucket', () => {
    assert.equal(normalizeListingType(''), null);
    assert.equal(normalizeListingType('lease'), null);
    assert.equal(normalizeListingType(undefined), null);
  });
});

describe('localitySlug', () => {
  test('is stable, lowercase and url-safe', () => {
    assert.equal(localitySlug('Pune', 'Wakad'), 'pune-wakad');
    assert.equal(localitySlug('  Pune  ', 'Baner Road'), 'pune-baner-road');
    assert.equal(localitySlug('Navi Mumbai', 'Kharghar Sector-7'), 'navi-mumbai-kharghar-sector-7');
  });

  test('punctuation and repeats collapse rather than escaping into the url', () => {
    assert.equal(localitySlug('Pune', 'D.P. Road / Aundh'), 'pune-d-p-road-aundh');
    assert.equal(localitySlug('Pune', '  --Wakad--  '), 'pune-wakad');
  });

  test('a missing half still yields a usable slug', () => {
    assert.equal(localitySlug('Pune', ''), 'pune');
    assert.equal(localitySlug('', ''), '');
  });
});

describe('quarters, in IST because that is the market being described', () => {
  test('an instant late in the UTC evening belongs to the next IST day, and its quarter', () => {
    assert.equal(quarterOf(new Date('2026-03-31T19:00:00Z')), '2026-Q2', 'past IST midnight into April');
    assert.equal(quarterOf(new Date('2026-03-31T17:00:00Z')), '2026-Q1');
  });

  test('every month lands in the right quarter', () => {
    assert.equal(quarterOf(new Date('2026-01-15T06:00:00Z')), '2026-Q1');
    assert.equal(quarterOf(new Date('2026-04-15T06:00:00Z')), '2026-Q2');
    assert.equal(quarterOf(new Date('2026-07-15T06:00:00Z')), '2026-Q3');
    assert.equal(quarterOf(new Date('2026-12-31T06:00:00Z')), '2026-Q4');
  });

  test('the previous quarter crosses the year correctly', () => {
    assert.equal(previousQuarter('2026-Q1'), '2025-Q4');
    assert.equal(previousQuarter('2026-Q3'), '2026-Q2');
    assert.equal(previousQuarter('nonsense'), null);
  });
});
