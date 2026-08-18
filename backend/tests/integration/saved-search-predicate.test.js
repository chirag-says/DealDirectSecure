/**
 * Suite 23: saved-search matching (Phase 4.2).
 *
 * THE FLOW.
 *
 *   property created
 *     -> notifySavedSearchMatches(property)      propertyController:488 and :655
 *     -> candidate saved searches                  <- the change is here
 *     -> city filter
 *     -> price-range filter
 *     -> notifyUsers() fan-out
 *
 * WHAT CHANGED. The candidate query was `SavedSearch.find({ isActive: true })`,
 * which pulls EVERY active saved search into Node and then discards most of
 * them in a loop. The city comparison now happens in MongoDB, so only genuine
 * candidates cross the wire.
 *
 * WHAT DID NOT CHANGE. The price-range test stays in JavaScript. It compares
 * against three hard-coded buckets rather than a stored bound, so there is no
 * indexable predicate to push down — turning it into `$lt`/`$gte` clauses would
 * be more code expressing the same comparison, further from the buckets it
 * encodes, with no measured benefit.
 *
 * CASE SEMANTICS ARE PRESERVED EXACTLY, and that is the delicate part. The old
 * comparison was `lower(propertyCity) === lower(savedCity)` — case-insensitive,
 * and NOT whitespace-trimmed. The replacement is an anchored case-insensitive
 * regex, which reproduces both properties including the one that looks like a
 * bug: " Pune" still does not match "Pune". Changing that would be a behaviour
 * change dressed as an optimisation, so the whitespace cases below pin it.
 *
 * A saved search with no city ("" — the schema default) still matches every
 * city, as it always did.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';

import { request } from './setup/app.js';
import { stopTestDatabase, truncateAll } from './setup/db.js';
import { stopFakeProviders } from './setup/fakeProviders.js';
import { makeBuyer } from './setup/factories.js';
import { notifySavedSearchMatches } from '../../services/notificationService.js';

let api;

test.before(async () => { api = await request(); });
test.beforeEach(async () => { await truncateAll(); });
test.after(async () => { await stopFakeProviders(); await stopTestDatabase(); });

const M = (n) => mongoose.model(n);

/** A watcher with one saved search. */
async function watcher(filters, { isActive = true } = {}) {
  const user = await makeBuyer();
  const search = await M('SavedSearch').create({
    user: user._id, name: `Watch ${filters.city || 'anywhere'}`, isActive, filters,
  });
  return { user, search };
}

const propertyIn = (city, price) => ({
  _id: new mongoose.Types.ObjectId(),
  title: 'A property',
  address: { city },
  price,
});

const notifiedUsers = async () =>
  (await M('Notification').find({ type: 'saved-search-match' }).lean()).map((n) => String(n.user));

// ---------------------------------------------------------------------------

test('city matching, with the old semantics intact', async (t) => {
  await t.test('an exact match notifies', async () => {
    const { user } = await watcher({ city: 'Pune' });
    await notifySavedSearchMatches(propertyIn('Pune'));
    assert.deepEqual(await notifiedUsers(), [String(user._id)]);
  });

  await t.test('a different city does not', async () => {
    await watcher({ city: 'Pune' });
    await notifySavedSearchMatches(propertyIn('Mumbai'));
    assert.deepEqual(await notifiedUsers(), []);
  });

  for (const [saved, incoming] of [
    ['Pune', 'pune'],
    ['pune', 'Pune'],
    ['PUNE', 'pune'],
    ['PuNe', 'pUnE'],
  ]) {
    await t.test(`case is ignored: saved "${saved}" vs incoming "${incoming}"`, async () => {
      const { user } = await watcher({ city: saved });
      await notifySavedSearchMatches(propertyIn(incoming));
      assert.deepEqual(await notifiedUsers(), [String(user._id)]);
    });
  }

  for (const [saved, incoming] of [
    [' Pune', 'Pune'],
    ['Pune', 'Pune '],
    ['Pune ', ' Pune'],
  ]) {
    await t.test(`whitespace is NOT trimmed: "${saved}" vs "${incoming}" does not match`, async () => {
      // Preserved deliberately. The old JS comparison did not trim either, and
      // making it trim would silently widen who gets notified. If that is
      // wanted it is a product change, not a performance one.
      await watcher({ city: saved });
      await notifySavedSearchMatches(propertyIn(incoming));
      assert.deepEqual(await notifiedUsers(), []);
    });
  }

  await t.test('a substring does not match — the comparison is anchored', async () => {
    // "Pune" must not match a search for "Punexyz" or vice versa.
    await watcher({ city: 'Pun' });
    await notifySavedSearchMatches(propertyIn('Pune'));
    assert.deepEqual(await notifiedUsers(), []);
  });

  await t.test('a regex metacharacter in the PROPERTY city is treated literally', async () => {
    // It is the property's city that is interpolated into the regex, so that is
    // the side escaping protects. An earlier version of this test put the
    // metacharacter on the saved-search side, where it is only ever compared
    // against — and the "unescaped" mutant survived as a result.
    //
    // Unescaped, a property in "P.ne" would notify everyone watching "Pune".
    await watcher({ city: 'Pune' });
    await notifySavedSearchMatches(propertyIn('P.ne'));
    assert.deepEqual(await notifiedUsers(), [], 'an unescaped property city became a wildcard');
  });

  await t.test('a metacharacter still matches its own literal city', async () => {
    // Escaping must not break the legitimate case: a city that genuinely
    // contains a dot should still match itself.
    const { user } = await watcher({ city: 'St. Louis' });
    await notifySavedSearchMatches(propertyIn('St. Louis'));
    assert.deepEqual(await notifiedUsers(), [String(user._id)]);
  });

  await t.test('a saved city containing a metacharacter is not a wildcard either', async () => {
    await watcher({ city: 'P.ne' });
    await notifySavedSearchMatches(propertyIn('Pune'));
    assert.deepEqual(await notifiedUsers(), []);
  });
});

// ---------------------------------------------------------------------------

test('a saved search with no city matches everywhere', async (t) => {
  await t.test('an empty city string matches any city', async () => {
    // "" is the schema default, so this is the common case for a search the
    // user never narrowed.
    const { user } = await watcher({ city: '' });
    await notifySavedSearchMatches(propertyIn('Anywhere'));
    assert.deepEqual(await notifiedUsers(), [String(user._id)]);
  });

  await t.test('an absent city field matches any city', async () => {
    const user = await makeBuyer();
    await M('SavedSearch').collection.insertOne({
      user: user._id, name: 'No filters', isActive: true, filters: {}, createdAt: new Date(),
    });

    await notifySavedSearchMatches(propertyIn('Anywhere'));
    assert.deepEqual(await notifiedUsers(), [String(user._id)]);
  });

  await t.test('a null city matches any city', async () => {
    const user = await makeBuyer();
    await M('SavedSearch').collection.insertOne({
      user: user._id, name: 'Null city', isActive: true, filters: { city: null }, createdAt: new Date(),
    });

    await notifySavedSearchMatches(propertyIn('Anywhere'));
    assert.deepEqual(await notifiedUsers(), [String(user._id)]);
  });

  await t.test('a property with no city notifies only unfiltered searches', async () => {
    const open = await watcher({ city: '' });
    await watcher({ city: 'Pune' });

    await notifySavedSearchMatches(propertyIn(undefined));

    assert.deepEqual(await notifiedUsers(), [String(open.user._id)]);
  });
});

// ---------------------------------------------------------------------------

test('the price buckets are untouched', async (t) => {
  const CASES = [
    ['low', 4_999_999, true], ['low', 5_000_000, false],
    ['mid', 5_000_000, true], ['mid', 15_000_000, true],
    ['mid', 4_999_999, false], ['mid', 15_000_001, false],
    ['high', 15_000_001, true], ['high', 15_000_000, false],
  ];

  for (const [bucket, price, shouldMatch] of CASES) {
    await t.test(`${bucket} @ ${price.toLocaleString()} ${shouldMatch ? 'matches' : 'does not'}`, async () => {
      const { user } = await watcher({ city: 'Pune', priceRange: bucket });
      await notifySavedSearchMatches(propertyIn('Pune', price));
      assert.deepEqual(await notifiedUsers(), shouldMatch ? [String(user._id)] : []);
    });
  }

  await t.test('a property with no price skips the bucket test entirely', async () => {
    // The old code guarded on `typeof price === "number"`, so a priced bucket
    // did not exclude an unpriced property. Preserved.
    const { user } = await watcher({ city: 'Pune', priceRange: 'high' });
    await notifySavedSearchMatches(propertyIn('Pune', undefined));
    assert.deepEqual(await notifiedUsers(), [String(user._id)]);
  });

  await t.test('an unknown bucket matches nothing', async () => {
    await watcher({ city: 'Pune', priceRange: 'nonsense' });
    await notifySavedSearchMatches(propertyIn('Pune', 1_000_000));
    assert.deepEqual(await notifiedUsers(), []);
  });

  await t.test('city match with a failing price does not notify', async () => {
    await watcher({ city: 'Pune', priceRange: 'high' });
    await notifySavedSearchMatches(propertyIn('Pune', 1_000_000));
    assert.deepEqual(await notifiedUsers(), []);
  });

  await t.test('city match with a passing price does notify', async () => {
    const { user } = await watcher({ city: 'Pune', priceRange: 'high' });
    await notifySavedSearchMatches(propertyIn('Pune', 20_000_000));
    assert.deepEqual(await notifiedUsers(), [String(user._id)]);
  });
});

// ---------------------------------------------------------------------------

test('fan-out is unchanged', async (t) => {
  await t.test('inactive searches are excluded', async () => {
    await watcher({ city: 'Pune' }, { isActive: false });
    await notifySavedSearchMatches(propertyIn('Pune'));
    assert.deepEqual(await notifiedUsers(), []);
  });

  await t.test('several watchers on one city all get notified once each', async () => {
    const users = [];
    for (let i = 0; i < 3; i += 1) users.push((await watcher({ city: 'Pune' })).user);

    await notifySavedSearchMatches(propertyIn('Pune'));

    const notified = (await notifiedUsers()).sort();
    assert.deepEqual(notified, users.map((u) => String(u._id)).sort());
    assert.equal(new Set(notified).size, 3, 'a watcher was notified more than once');
  });

  await t.test('a 20-watcher fan-out still batches the recipient lookup', async () => {
    for (let i = 0; i < 20; i += 1) await watcher({ city: 'Pune' });

    const originalFind = M('User').find.bind(M('User'));
    let queries = 0;
    M('User').find = (...args) => { queries += 1; return originalFind(...args); };

    try {
      await notifySavedSearchMatches(propertyIn('Pune'));
      assert.equal((await notifiedUsers()).length, 20);
      assert.ok(queries <= 1, `recipient lookup went N+1 again: ${queries} queries`);
    } finally {
      M('User').find = originalFind;
    }
  });

  await t.test('only matching watchers are notified in a mixed set', async () => {
    const hit = await watcher({ city: 'Pune' });
    const open = await watcher({ city: '' });
    await watcher({ city: 'Mumbai' });
    await watcher({ city: 'Delhi' });

    await notifySavedSearchMatches(propertyIn('Pune'));

    assert.deepEqual(
      (await notifiedUsers()).sort(),
      [String(hit.user._id), String(open.user._id)].sort()
    );
  });
});

// ---------------------------------------------------------------------------

test('the database does the city filtering, not JavaScript', async (t) => {
  await t.test('the query carries a city predicate', async () => {
    // The regression guard. If the predicate moves back into the loop this
    // still passes behaviourally, so the check is on what the query asks for.
    let capturedFilter = null;
    const original = M('SavedSearch').find.bind(M('SavedSearch'));
    M('SavedSearch').find = (filter, ...rest) => {
      capturedFilter = filter;
      return original(filter, ...rest);
    };

    try {
      await watcher({ city: 'Pune' });
      await notifySavedSearchMatches(propertyIn('Pune'));

      assert.ok(capturedFilter, 'SavedSearch.find was never called');
      assert.equal(capturedFilter.isActive, true, 'the active filter was lost');
      assert.ok(
        JSON.stringify(capturedFilter).includes('filters.city'),
        `the city predicate is not in the query: ${JSON.stringify(capturedFilter)}`
      );
    } finally {
      M('SavedSearch').find = original;
    }
  });

  await t.test('non-matching searches never reach Node', async () => {
    // The actual win: candidates are filtered server-side, so a property in
    // Pune does not pull every Mumbai watcher across the wire.
    await watcher({ city: 'Mumbai' });
    await watcher({ city: 'Delhi' });
    const hit = await watcher({ city: 'Pune' });

    let returned = 0;
    const original = M('SavedSearch').find.bind(M('SavedSearch'));
    M('SavedSearch').find = (...args) => {
      const q = original(...args);
      const originalThen = q.then.bind(q);
      q.then = (res, rej) => originalThen((docs) => { returned = docs.length; return res(docs); }, rej);
      return q;
    };

    try {
      await notifySavedSearchMatches(propertyIn('Pune'));
      assert.equal(returned, 1, `${returned} candidates crossed the wire; only 1 could match`);
      assert.deepEqual(await notifiedUsers(), [String(hit.user._id)]);
    } finally {
      M('SavedSearch').find = original;
    }
  });
});
