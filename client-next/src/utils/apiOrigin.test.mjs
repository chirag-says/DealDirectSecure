/**
 * apiOriginFromEnv turns the configured API URL into a bare origin for the
 * CSP connect-src and the preconnect hint, or null when nothing is set.
 *
 *   npm test
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { apiOriginFromEnv } from './apiOrigin.js';

test('returns the origin of NEXT_PUBLIC_API_URL, dropping any path', () => {
  assert.equal(apiOriginFromEnv({ NEXT_PUBLIC_API_URL: 'https://backend.dealdirect.in/api/' }), 'https://backend.dealdirect.in');
  assert.equal(apiOriginFromEnv({ NEXT_PUBLIC_API_URL: 'http://localhost:9000' }), 'http://localhost:9000');
});

test('falls back to NEXT_PUBLIC_API_BASE', () => {
  assert.equal(apiOriginFromEnv({ NEXT_PUBLIC_API_BASE: 'http://localhost:9000/' }), 'http://localhost:9000');
});

test('returns null when unset or not a URL', () => {
  assert.equal(apiOriginFromEnv({}), null);
  assert.equal(apiOriginFromEnv({ NEXT_PUBLIC_API_URL: 'backend' }), null);
});
