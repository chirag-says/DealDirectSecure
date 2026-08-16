/**
 * Frontend error states (Phase 2.5)
 *
 * INVARIANT: a failed request is never rendered as a successful empty result.
 * Each screen must distinguish LOADING / EMPTY / ERROR / SUCCESS.
 *
 * No frontend test framework was introduced (per scope), so these assert the
 * rendering structure in the client source. Each test names the user-visible
 * failure it prevents.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §20.1 (F-FE3 home, F-FE4 rewards,
 * F-FE29 listing errors swallowed).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const CLIENT = new URL('../../client-next/src/', import.meta.url);
const readClient = (rel) => readFileSync(new URL(rel, CLIENT), 'utf8');

/** Source with comments removed — for assertions about code ordering. */
const stripComments = (src) =>
  src
    .replace(new RegExp('/\\*[\\s\\S]*?\\*/', 'g'), '')
    .replace(new RegExp('//[^\\r\\n]*', 'g'), '');

const homePage = readClient('app/page.js');
const homeContent = readClient('app/HomeContent.jsx');
const rewards = readClient('app/rewards/dashboard/RewardsDashboardContent.jsx');
const listing = readClient('app/properties/PropertyListContent.jsx');
const bookings = readClient('app/my-bookings/MyBookingsContent.jsx');
const ssrFetch = readClient('utils/ssrFetch.js');

describe('home: a failed SSR fetch is not an empty page', () => {
  test('ssrFetch still signals failure as null rather than throwing', () => {
    // The whole detection depends on this contract.
    assert.match(ssrFetch, /return null/);
  });

  test('page.js distinguishes a failed fetch from an empty result', () => {
    assert.match(
      homePage,
      /propertiesUnavailable:\s*propsData === null/,
      'both cases collapse to [] without this check'
    );
  });

  test('the flag reaches HomeContent', () => {
    assert.match(homePage, /propertiesUnavailable=\{propertiesUnavailable\}/);
    assert.match(homeContent, /propertiesUnavailable = false/);
  });

  test('the error branch is checked before the empty branch', () => {
    const errorAt = homeContent.indexOf('propertiesUnavailable ? (');
    const emptyAt = homeContent.indexOf('properties.length === 0 ? (');
    assert.ok(errorAt !== -1, 'no error branch on the home properties section');
    assert.ok(emptyAt !== -1, 'the empty state was removed');
    assert.ok(errorAt < emptyAt, 'a failed fetch would fall through to the empty message');
  });

  test('the two states say different things', () => {
    // "No popular properties available right now" is a claim about inventory.
    assert.match(homeContent, /No popular properties available right now/);
    assert.match(homeContent, /couldn&apos;t load properties/);
  });

  test('the error state offers a way forward', () => {
    const block = homeContent.slice(homeContent.indexOf('propertiesUnavailable ? ('));
    // Window spans the branch body; the explanatory comment above it is long.
    assert.match(block.slice(0, 2000), /href="\/properties"/);
  });
});

describe('rewards: a failed wallet fetch is not a zero balance', () => {
  test('a load error is recorded, not only logged', () => {
    assert.match(rewards, /const \[loadError, setLoadError\]/);
    assert.match(rewards, /setLoadError\(/);
  });

  test('the catch sets the error state', () => {
    const catchBlock = rewards.slice(rewards.indexOf('} catch (err) {'), rewards.indexOf('} finally {'));
    assert.match(catchBlock, /setLoadError\(/, 'the failure was swallowed into console.error');
  });

  test('an unsuccessful response is treated as a failure too', () => {
    // A 200 without a wallet is still "we could not load your wallet".
    assert.match(rewards, /if \(!walletRes\.success\)/);
  });

  test('the page never renders the wallet card without a wallet', () => {
    // wallet.availablePoints.toLocaleString() is an unguarded dereference; with
    // wallet null it throws into the error boundary and the user sees a crash.
    //
    // Compared on comment-stripped source: the explanatory comment in the catch
    // block names the same expression and would otherwise match first.
    const code = stripComments(rewards);
    const guardAt = code.indexOf('if (loadError || !wallet)');
    const derefAt = code.indexOf('wallet.availablePoints');
    assert.ok(guardAt !== -1, 'no guard before the wallet card');
    assert.ok(derefAt !== -1);
    assert.ok(guardAt < derefAt, 'the guard must precede every wallet dereference');
  });

  test('the guard runs after loading, so it is not shown mid-fetch', () => {
    const loadingAt = rewards.indexOf('if (authLoading || loading)');
    const guardAt = rewards.indexOf('if (loadError || !wallet)');
    assert.ok(loadingAt !== -1 && loadingAt < guardAt, 'LOADING must be distinct from ERROR');
  });

  test('the tier no longer silently defaults when the wallet is missing', () => {
    assert.doesNotMatch(
      rewards,
      /const tc = wallet \? TIER_CONFIG\[wallet\.tier\] \|\| TIER_CONFIG\.bronze : TIER_CONFIG\.bronze/,
      'falling back to bronze presents a failed load as a real bronze wallet'
    );
    assert.match(rewards, /const tc = TIER_CONFIG\[wallet\.tier\] \|\| TIER_CONFIG\.bronze/);
  });

  test('the error state offers a retry', () => {
    const block = rewards.slice(rewards.indexOf('if (loadError || !wallet)'));
    assert.match(block.slice(0, 1400), /onClick=\{\(\) => fetchData\(\)\}/);
  });
});

describe('property listing: a failed search is not an empty search', () => {
  test('load errors are held in their own state', () => {
    assert.match(listing, /const \[loadError, setLoadError\]/);
  });

  test('the error branch precedes the no-results branch', () => {
    const errorAt = listing.indexOf(') : loadError ? (');
    const emptyAt = listing.indexOf('filteredProperties.length === 0 && relatedProperties.length === 0 ? (');
    assert.ok(errorAt !== -1, 'no error branch on the listing page');
    assert.ok(errorAt < emptyAt, 'a failed search would read as "nothing matched your filters"');
  });

  test('LOADING is checked before ERROR', () => {
    const loadingAt = listing.indexOf('{loading ? (');
    const errorAt = listing.indexOf(') : loadError ? (');
    assert.ok(loadingAt !== -1 && loadingAt < errorAt);
  });

  test('a first-page failure clears stale results', () => {
    const catchBlock = listing.slice(listing.indexOf('setLoadError(err?.response'));
    assert.match(catchBlock.slice(0, 400), /if \(firstPage\)/);
  });

  test('a failure while appending keeps the results already shown', () => {
    assert.match(listing, /loadError && page > 1/, 'page 2 failure must not wipe page 1');
  });

  test('the error state offers a retry that actually re-fires', () => {
    // setPage(1) alone would not re-run the effect when already on page 1.
    assert.match(listing, /setRetryToken\(\(t\) => t \+ 1\)/);
    assert.match(listing, /\[filters, page, propertyTypes, retryToken\]/);
  });
});

describe('my-bookings: a failed authenticated request is not a sign-in problem', () => {
  test('the auth guard still gates the fetch (2.4 must not regress)', () => {
    assert.match(bookings, /if \(!isAuthenticated\)/);
    assert.match(bookings, /router\.push\('\/login\?from=\/my-bookings'\)/);
  });

  test('the error branch no longer sends the user to /login', () => {
    const errorBlock = bookings.slice(bookings.indexOf(') : error ? ('), bookings.indexOf(') : bookings.length === 0 ? ('));
    assert.doesNotMatch(
      errorBlock,
      /href="\/login"/,
      'only authenticated users reach the fetch; a login CTA implies their session broke'
    );
  });

  test('it offers a retry instead', () => {
    const errorBlock = bookings.slice(bookings.indexOf(') : error ? ('), bookings.indexOf(') : bookings.length === 0 ? ('));
    assert.match(errorBlock, /onClick=\{\(\) => fetch_\(\)\}/);
  });

  test('all four states are distinguishable', () => {
    assert.match(bookings, /\{loading \? \(/);
    assert.match(bookings, /\) : error \? \(/);
    assert.match(bookings, /\) : bookings\.length === 0 \? \(/);
  });

  test('the empty state still speaks about bookings, not failure', () => {
    assert.match(bookings, /No bookings yet/);
  });
});

describe('no screen fakes an empty state on failure', () => {
  const SCREENS = [
    ['home', homeContent, 'propertiesUnavailable'],
    ['rewards dashboard', rewards, 'loadError'],
    ['property listing', listing, 'loadError'],
    ['my bookings', bookings, 'error'],
  ];

  for (const [name, src, marker] of SCREENS) {
    test(`${name} carries an explicit error signal`, () => {
      assert.ok(src.includes(marker), `${name} has no way to represent a failed request`);
    });
  }
});
