/**
 * DealDirect takes no money from users.
 *
 * Owner decision, 2026-10-19: builder flats are enquiry-only and group buy is
 * removed. The backend no longer serves the payment-config, payment-proof or
 * campaign routes, so any code that still calls them is broken, and any copy
 * that still offers a booking or a payment promises something the platform
 * will not do. This keeps both out.
 *
 * The Hubble rewards storefront is a separate product and is not covered here.
 *
 * Comments are ignored, so code can still explain why a flow is not there.
 *
 *   npm test
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..');

const FORBIDDEN = [
  // Removed API routes and the client code that called them.
  '/bookings/payment-config',
  'submitPayment',
  '/payment-proof',
  'campaignApi',
  '/api/campaigns',
  // The paid booking flow and its copy.
  'BookingModal',
  'Book Now',
  'Book This Unit',
  'Pay now to book',
  'Go back and pay',
];

function sourceFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.(jsx?|mjs)$/.test(name) && !name.endsWith('.test.mjs') ? [path] : [];
  });
}

/** Block comments, JSX comments and whole-line // comments removed. */
function withoutComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .filter((line) => !line.trim().startsWith('//'))
    .join('\n');
}

test('no page, component or API helper offers a payment, a booking or a group buy', () => {
  const found = [];
  for (const file of sourceFiles(SRC)) {
    const text = withoutComments(readFileSync(file, 'utf8'));
    for (const needle of FORBIDDEN) {
      if (text.includes(needle)) found.push(`${relative(SRC, file)}: "${needle}"`);
    }
  }
  assert.deepEqual(found, []);
});
