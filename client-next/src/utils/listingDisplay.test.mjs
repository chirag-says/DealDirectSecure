/**
 * Listing display rules: amenity cleanup and labels, hiding empty facts.
 *
 *   npm test
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAmenities, amenityLabel, isBlankValue } from './listingDisplay.js';

test('the legacy amenities string becomes clean names', () => {
  assert.deepEqual(
    normalizeAmenities(['[" Lift"," Gym"," Swimming Pool"," Parking Open"]']),
    ['Lift', 'Gym', 'Swimming Pool', 'Parking Open'],
  );
  assert.deepEqual(normalizeAmenities('["Lift"]'), ['Lift']);
  assert.deepEqual(normalizeAmenities([' Lift ', 'lift', '']), ['Lift']);
  assert.deepEqual(normalizeAmenities(null), []);
});

test('amenity labels split camelCase keys only', () => {
  assert.equal(amenityLabel('powerBackup'), 'Power Backup');
  assert.equal(amenityLabel('Swimming Pool'), 'Swimming Pool');
  assert.equal(amenityLabel('CCTV'), 'CCTV');
  assert.equal(amenityLabel('lift'), 'Lift');
});

test('N/A and empty facts are blank; real values are not', () => {
  for (const v of [null, undefined, '', '  ', 'N/A', 'NA', 'n/a', 'N/A sq.ft', NaN]) {
    assert.equal(isBlankValue(v), true, `${v} should be blank`);
  }
  for (const v of ['East', '0', 0, '1400 sq.ft', 'Navi Mumbai', 'Nashik']) {
    assert.equal(isBlankValue(v), false, `${v} should show`);
  }
});
