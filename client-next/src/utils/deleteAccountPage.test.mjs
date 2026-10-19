/**
 * The public /delete-account page: reachable without signing in, its links
 * lead somewhere, and it promises nothing the deletion code does not do.
 *
 * Source checks only. The rendered page and its links were also checked in a
 * browser against a local build (privacy phase 1 handover).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..');
const page = readFileSync(join(SRC, 'app', 'delete-account', 'page.js'), 'utf8');

/** Reader-facing text: JSX tags and comments stripped, whitespace collapsed. */
const text = page
  .replace(/\/\*[\s\S]*?\*\//g, ' ')
  .replace(/<[^>]+>/g, ' ')
  .replace(/&apos;/g, "'")
  .replace(/\{" "\}/g, ' ')
  .replace(/\s+/g, ' ');

test('the page is public: not behind the auth middleware and not hidden from crawlers', () => {
  const middleware = readFileSync(join(SRC, 'middleware.js'), 'utf8');
  const protectedList = middleware.split('const PROTECTED_ROUTES = [')[1].split('];')[0];
  assert.ok(!protectedList.includes("'/delete-account'"));
  const robots = readFileSync(join(SRC, 'app', 'robots.js'), 'utf8');
  assert.ok(!robots.includes("'/delete-account'"));
});

test('every internal link points at a route that exists', () => {
  const hrefs = [...page.matchAll(/href="(\/[^"?#]*)/g)].map((m) => m[1]);
  assert.ok(hrefs.length > 0);
  for (const href of hrefs) {
    assert.ok(existsSync(join(SRC, 'app', href, 'page.js')), `${href} has no page`);
  }
});

test('it promises no complete deletion and no period nobody has set', () => {
  for (const promise of [
    /all (of )?your data/i,
    /all data/i,
    /completely (deleted|erased|removed)/i,
    /permanently erased/i,
    /within \d+\s*(days?|hours?|weeks?|months?)/i,
    /\d+\s*(days?|months?|years?) after/i,
  ]) {
    assert.ok(!promise.test(text), `the page must not say ${promise}`);
  }
});

test('it names each kind of record the account cascade keeps (utils/aggregateDelete.js USER_CASCADE.retained)', () => {
  const retained = {
    Lead: /Enquiries you sent to property owners/,
    // Group-buy memberships (CampaignMember) left the cascade on 2026-10-19,
    // with group buy itself. ProjectBooking now holds enquiries only.
    ProjectBooking: /Enquiries you sent about builder projects/,
    TransactionVerification: /Deal closure requests/,
    Agreement: /agreements made on DealDirect/,
  };
  for (const [collection, phrase] of Object.entries(retained)) {
    assert.match(text, phrase, collection);
  }
  assert.match(text, /A listing tied to a pending or approved deal closure/);
  assert.doesNotMatch(text, /payment|UTR|screenshot|group-buy/i, 'DealDirect takes no money, so no payment record is kept');
});

test('it states that deletion cannot be undone, and gives a way in for someone who cannot sign in', () => {
  assert.match(text, /cannot be undone/);
  assert.match(text, /Forgot password\?/);
});

test('it names no legal entity, contact or retention period on its own authority', () => {
  // Those are marked for confirmation instead; see the handover.
  assert.ok(!/LLP|Pvt\.? Ltd|Private Limited/i.test(text));
  assert.ok(!/@[a-z0-9-]+\.[a-z]/i.test(text), 'no email address');
  assert.ok(!/\+?91[\s-]?\d{5}/.test(text), 'no phone number');
});
