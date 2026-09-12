import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { resolveEntryRoute } from './entryRoute.ts';

/**
 * The cold-start table, pinned. Three inputs, four rows, and the one that
 * matters most is the last: a signed-out person who has been here before
 * goes straight in, never back to the tour.
 */
describe('resolveEntryRoute', () => {
  test('waits while the session is still being restored', () => {
    assert.equal(resolveEntryRoute('restoring', false), null);
    assert.equal(resolveEntryRoute('restoring', true), null);
  });

  test('a signed-in person goes straight to the app, tour or no tour', () => {
    assert.equal(resolveEntryRoute('authenticated', false), '/(tabs)');
    assert.equal(resolveEntryRoute('authenticated', true), '/(tabs)');
  });

  test('a first-time guest sees the welcome screen', () => {
    assert.equal(resolveEntryRoute('guest', false), '/welcome');
  });

  test('a returning guest goes straight to the app', () => {
    assert.equal(resolveEntryRoute('guest', true), '/(tabs)');
  });

  test('anyone past the welcome who has not seen the primer sees it once', () => {
    assert.equal(resolveEntryRoute('guest', true, false), '/setup');
    assert.equal(resolveEntryRoute('authenticated', true, false), '/setup');
    assert.equal(resolveEntryRoute('authenticated', false, false), '/setup');
  });

  test('a first-time guest goes to the welcome, which hands over to the primer', () => {
    assert.equal(resolveEntryRoute('guest', false, false), '/welcome');
  });

  test('the primer never shows again once dismissed', () => {
    assert.equal(resolveEntryRoute('guest', true, true), '/(tabs)');
    assert.equal(resolveEntryRoute('authenticated', true, true), '/(tabs)');
  });
});
