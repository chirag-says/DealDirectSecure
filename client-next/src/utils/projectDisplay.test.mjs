/**
 * Builder project card display rules: price, the fact strip, RERA.
 *
 *   npm test
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { compactPrice, projectPriceLabel, projectFacts, projectRera } from './projectDisplay.js';

test('prices print in lakh and crore, and nothing for a missing amount', () => {
  assert.equal(compactPrice(3737000), '₹37 L');
  assert.equal(compactPrice(15600000), '₹1.56 Cr');
  assert.equal(compactPrice(20000000), '₹2 Cr');
  assert.equal(compactPrice(20800000), '₹2.08 Cr');
  assert.equal(compactPrice(95000), '₹95,000');
  for (const blank of [0, -5, null, undefined, NaN, '3737000']) {
    assert.equal(compactPrice(blank), null, String(blank));
  }
});

test('a range shows only when min and max differ once printed', () => {
  assert.equal(projectPriceLabel({ min: 3737000, max: 6570000 }), '₹37 L – ₹66 L');
  assert.equal(projectPriceLabel({ min: 13550000, max: 13550000 }), '₹1.36 Cr');
  // 37.37 L and 37.4 L both print as ₹37 L: no "₹37 L – ₹37 L".
  assert.equal(projectPriceLabel({ min: 3737000, max: 3740000 }), '₹37 L');
  assert.equal(projectPriceLabel({ min: 0, max: 5000000 }), '₹50 L');
  assert.equal(projectPriceLabel({}), null);
  assert.equal(projectPriceLabel(undefined), null);
});

test('the fact strip lists possession, units and type in that order', () => {
  const facts = projectFacts({
    overview: { possessionDate: '2028-12-31T00:00:00.000Z', totalUnits: 1206 },
    basics: { subType: 'Apartment', category: 'Residential' },
  });
  assert.deepEqual(facts, [['Possession', 'Dec 2028'], ['Units', '1,206'], ['Type', 'Apartment']]);
});

test('empty facts are left out, not shown blank', () => {
  assert.deepEqual(projectFacts({}), []);
  assert.deepEqual(
    projectFacts({
      overview: { possessionDate: 'not a date', totalUnits: 0 },
      basics: { subType: 'N/A', category: 'Commercial' },
    }),
    [['Type', 'Commercial']],
  );
  assert.deepEqual(projectFacts({ basics: { subType: '  ', category: 'NA' } }), []);
});

test('RERA is the number as entered, or nothing when blank', () => {
  assert.equal(projectRera({ basics: { reraNumber: ' P52000053782 ' } }), 'P52000053782');
  assert.equal(projectRera({ basics: { reraNumber: 'Coming Soon' } }), 'Coming Soon');
  assert.equal(projectRera({ basics: { reraNumber: 'N/A' } }), null);
  assert.equal(projectRera({ basics: {} }), null);
  assert.equal(projectRera(null), null);
});
