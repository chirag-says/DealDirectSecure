/**
 * Related-property suggestions.
 *
 * The listings page offers a few other properties when a search returns fewer
 * than six. That feature broke when discovery moved to server-side search: the
 * scoring read from the array of search results and excluded the search results
 * from it, so the pool became empty and the section silently stopped rendering.
 *
 * Nothing caught it because the scoring lived inside a React component and
 * could not be imported. It is now a pure module, and this exercises it
 * directly rather than reading source.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  scoreRelated,
  shouldSuggestRelated,
  hasActiveFilters,
  relatedPoolParams,
  getTypeFlags,
  RELATED_THRESHOLD,
  RELATED_LIMIT,
  RELATED_POOL_SIZE,
  RELEVANCE_CUTOFF,
} from '../../client-next/src/utils/relatedProperties.js';

const readClient = (rel) =>
  readFileSync(new URL(`../../client-next/src/${rel}`, import.meta.url), 'utf8');

const stripComments = (src) =>
  src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');

/** A residential listing, shaped the way the search endpoint returns them. */
const prop = (over = {}) => ({
  _id: over._id || Math.random().toString(36).slice(2),
  title: '3 BHK Apartment / Flat for Rent in kivale',
  price: 36000,
  listingType: 'Rent',
  bedrooms: 3,
  city: 'Pune',
  address: { city: 'Pune' },
  category: { name: 'Residential' },
  propertyType: { name: 'Apartment / Flat' },
  ...over,
});

// ---------------------------------------------------------------------------
// when to suggest
// ---------------------------------------------------------------------------

test('the rule: suggest only on a narrowed search with fewer than six results', async (t) => {
  await t.test('fewer than six matches, with a filter → suggest', () => {
    assert.equal(shouldSuggestRelated({ search: '4 bhk' }, 3), true);
    assert.equal(shouldSuggestRelated({ city: 'Pune' }, 0), true);
    assert.equal(shouldSuggestRelated({ search: '4 bhk' }, 5), true);
  });

  await t.test('six or more matches → do not', () => {
    // The page already has enough to show, and a second request would be waste.
    assert.equal(shouldSuggestRelated({ search: '4 bhk' }, 6), false);
    assert.equal(shouldSuggestRelated({ search: '4 bhk' }, 40), false);
  });

  await t.test('no filters → do not, however few results', () => {
    // Nothing to be "related" to: the visitor is already browsing everything.
    assert.equal(shouldSuggestRelated({}, 0), false);
    assert.equal(shouldSuggestRelated({ page: 2 }, 1), false);
  });

  await t.test('the threshold is six, and it is the boundary that is tested', () => {
    assert.equal(RELATED_THRESHOLD, 6);
    assert.equal(shouldSuggestRelated({ search: 'x' }, RELATED_THRESHOLD - 1), true);
    assert.equal(shouldSuggestRelated({ search: 'x' }, RELATED_THRESHOLD), false);
  });

  await t.test('every filter counts as narrowing', () => {
    for (const f of ['search', 'city', 'propertyType', 'priceRange', 'availableFor']) {
      assert.equal(hasActiveFilters({ [f]: 'value' }), true, `${f} was not treated as a filter`);
    }
    assert.equal(hasActiveFilters({}), false);
  });
});

// ---------------------------------------------------------------------------
// the pool
// ---------------------------------------------------------------------------

test('the candidate pool', async (t) => {
  await t.test('is requested unfiltered', () => {
    // Reapplying the visitor's filters would return the same short list that
    // triggered the suggestion in the first place.
    const params = relatedPoolParams();
    assert.deepEqual(Object.keys(params).sort(), ['limit', 'page']);
    assert.equal(params.page, 1);
  });

  await t.test('is within the limit the search endpoint accepts', () => {
    // searchProperties clamps limit to 60. Asking for more would silently
    // return fewer than intended.
    assert.ok(RELATED_POOL_SIZE <= 60, `pool of ${RELATED_POOL_SIZE} exceeds the endpoint cap of 60`);
    assert.equal(relatedPoolParams().limit, RELATED_POOL_SIZE);
  });

  await t.test('is big enough to rank meaningfully', () => {
    assert.ok(RELATED_POOL_SIZE >= RELATED_LIMIT * 4);
  });
});

// ---------------------------------------------------------------------------
// ranking
// ---------------------------------------------------------------------------

test('ranking', async (t) => {
  await t.test('THE REGRESSION: a pool that is only the matches yields nothing', () => {
    // This is exactly what the broken version did — it passed the search
    // results in as the pool and excluded them from themselves.
    const matched = [prop({ _id: 'a' }), prop({ _id: 'b' })];
    assert.deepEqual(scoreRelated(matched, { matched, filters: { search: '4 bhk' } }), []);
  });

  await t.test('and a real pool yields suggestions', () => {
    const matched = [prop({ _id: 'a' })];
    const pool = [prop({ _id: 'a' }), prop({ _id: 'b' }), prop({ _id: 'c' })];
    const out = scoreRelated(pool, { matched, filters: { search: '4 bhk' } });

    assert.equal(out.length, 2, 'the pool minus the one already shown');
    assert.deepEqual(out.map((p) => p._id).sort(), ['b', 'c']);
  });

  await t.test('nothing already shown is suggested again', () => {
    const matched = [prop({ _id: 'a' }), prop({ _id: 'b' })];
    const pool = [prop({ _id: 'a' }), prop({ _id: 'b' }), prop({ _id: 'c' })];
    const out = scoreRelated(pool, { matched, filters: { search: '4 bhk' } });
    assert.deepEqual(out.map((p) => p._id), ['c']);
  });

  await t.test('exclusion works when ids are objects, not strings', () => {
    // Found against real dev data. Over the wire an _id is a string and
    // identity comparison happens to work; anything holding real ObjectId
    // instances gets a distinct object per document, so a Set of raw values
    // matches nothing and every property already on screen is offered again.
    const objectId = (hex) => ({ toString: () => hex });
    const same = objectId('507f1f77bcf86cd799439011');
    const other = objectId('507f1f77bcf86cd799439011'); // equal value, different object

    const out = scoreRelated([prop({ _id: other })], {
      matched: [prop({ _id: same })],
      filters: { search: '3 bhk' },
    });

    assert.deepEqual(out, [], 'a property already shown was suggested again');
  });

  await t.test('an exact BHK match outranks an adjacent one', () => {
    // Titles deliberately carry no "BHK" text, so the bedroom count is the ONLY
    // thing separating these two. With the query words in the title as well,
    // both candidates collect the same +30 for the text match and the exact-BHK
    // bonus stops being what decides the order — which let a mutation halving
    // that bonus survive.
    const pool = [
      prop({ _id: 'four', title: 'Spacious home', bedrooms: 4, bhk: undefined }),
      prop({ _id: 'three', title: 'Spacious home', bedrooms: 3, bhk: undefined }),
    ];
    const out = scoreRelated(pool, { matched: [], filters: { search: '4 bhk' } });

    assert.equal(out[0]._id, 'four', 'the exact BHK should rank first');
    assert.equal(
      out[0].relevanceScore - out[1].relevanceScore, 10,
      'the exact-match bonus is no longer worth twice the adjacent one'
    );
  });

  await t.test('a two-BHK gap scores below an adjacent one', () => {
    const pool = [
      prop({ _id: 'six', title: '6 BHK Villa', bedrooms: 6 }),
      prop({ _id: 'five', title: '5 BHK Villa', bedrooms: 5 }),
    ];
    const out = scoreRelated(pool, { matched: [], filters: { search: '4 bhk' } });
    assert.equal(out[0]._id, 'five');
  });

  await t.test('the matching city outranks another city', () => {
    const pool = [
      prop({ _id: 'other', city: 'Mumbai', address: { city: 'Mumbai' } }),
      prop({ _id: 'same', city: 'Pune', address: { city: 'Pune' } }),
    ];
    const out = scoreRelated(pool, { matched: [], filters: { city: 'Pune' } });
    assert.equal(out[0]._id, 'same');
  });

  await t.test('but another city is still offered, as it was before', () => {
    // Suggestions crossing cities is the intended behaviour, not a bug: the
    // live page shows Pune, Panvel and Mumbai results side by side.
    const pool = [prop({ _id: 'other', city: 'Mumbai', address: { city: 'Mumbai' } })];
    const out = scoreRelated(pool, { matched: [], filters: { city: 'Pune', search: '3 bhk' } });
    assert.equal(out.length, 1);
  });

  await t.test('the right rent-or-sale intent outranks the wrong one', () => {
    const pool = [
      prop({ _id: 'sell', listingType: 'Sell' }),
      prop({ _id: 'rent', listingType: 'Rent' }),
    ];
    const out = scoreRelated(pool, { matched: [], filters: { availableFor: 'Rent', search: '3 bhk' } });
    assert.equal(out[0]._id, 'rent');
  });

  await t.test('commercial is not offered for a residential search', () => {
    const pool = [
      prop({
        _id: 'shop', title: 'Shop for Rent', bedrooms: 0,
        category: { name: 'Commercial' }, propertyType: { name: 'Shop' },
        city: 'Nagpur', address: { city: 'Nagpur' },
      }),
    ];
    const out = scoreRelated(pool, { matched: [], filters: { search: '4 bhk apartment', city: 'Pune' } });
    assert.deepEqual(out, [], 'a shop was suggested to someone searching for a 4 BHK');
  });

  await t.test('at most six are returned', () => {
    const pool = Array.from({ length: 30 }, (_, i) => prop({ _id: `p${i}` }));
    const out = scoreRelated(pool, { matched: [], filters: { search: '3 bhk' } });
    assert.equal(out.length, RELATED_LIMIT);
  });

  await t.test('results are ordered by score, descending', () => {
    const pool = Array.from({ length: 12 }, (_, i) =>
      prop({ _id: `p${i}`, bedrooms: i, title: `${i} BHK Apartment` }));
    const out = scoreRelated(pool, { matched: [], filters: { search: '4 bhk' } });
    const scores = out.map((p) => p.relevanceScore);
    assert.deepEqual(scores, [...scores].sort((a, b) => b - a));
  });

  await t.test('a candidate matching nothing is dropped, not merely ranked last', () => {
    // The cutoff earns its keep here. This property has no type, no city, the
    // wrong intent and a title sharing no word with the query — it scores zero
    // and must not be offered just because there was room on the page.
    const pool = [{ _id: 'nothing', title: '', price: 1, listingType: 'Sell' }];
    const out = scoreRelated(pool, {
      matched: [],
      filters: { search: '4 bhk', availableFor: 'Rent', city: 'Pune' },
    });
    assert.deepEqual(out, [], 'an entirely irrelevant property was suggested');
  });

  await t.test('every result carries its score, and clears the cutoff', () => {
    const out = scoreRelated([prop({ _id: 'x' })], { matched: [], filters: { search: '3 bhk' } });
    assert.equal(typeof out[0].relevanceScore, 'number');
    assert.ok(out[0].relevanceScore >= RELEVANCE_CUTOFF);
  });

  await t.test('the original property fields survive scoring', () => {
    // The cards render title, price and images from these objects.
    const out = scoreRelated([prop({ _id: 'x', title: 'Keep me', price: 4200 })],
      { matched: [], filters: { search: '3 bhk' } });
    assert.equal(out[0].title, 'Keep me');
    assert.equal(out[0].price, 4200);
    assert.equal(out[0]._id, 'x');
  });
});

// ---------------------------------------------------------------------------
// robustness — this runs on whatever the API returns
// ---------------------------------------------------------------------------

test('bad input does not take the page down', async (t) => {
  for (const [label, value] of [['null', null], ['undefined', undefined], ['a string', 'nope'], ['an object', {}]]) {
    await t.test(`a pool that is ${label} yields []`, () => {
      assert.deepEqual(scoreRelated(value, { matched: [], filters: {} }), []);
    });
  }

  await t.test('no options at all yields []', () => {
    assert.deepEqual(scoreRelated([]), []);
  });

  await t.test('entries without an _id are skipped, not crashed on', () => {
    const out = scoreRelated([null, {}, prop({ _id: 'ok' })], { matched: [], filters: { search: '3 bhk' } });
    assert.deepEqual(out.map((p) => p._id), ['ok']);
  });

  await t.test('a matched list containing junk is tolerated', () => {
    const out = scoreRelated([prop({ _id: 'ok' })],
      { matched: [null, undefined, {}], filters: { search: '3 bhk' } });
    assert.equal(out.length, 1);
  });
});

test('getTypeFlags reads the several shapes the API has used', async (t) => {
  await t.test('a populated category object', () => {
    assert.equal(getTypeFlags({ category: { name: 'Residential' } }).isResidential, true);
  });

  await t.test('a bare category string', () => {
    assert.equal(getTypeFlags({ category: 'Commercial' }).isCommercial, true);
  });

  await t.test('inferred from the property type when the category is absent', () => {
    assert.equal(getTypeFlags({ propertyType: { name: 'Villa' } }).isResidential, true);
    assert.equal(getTypeFlags({ propertyType: 'Warehouse' }).isCommercial, true);
  });

  await t.test('an empty property is neither, and does not throw', () => {
    const flags = getTypeFlags({});
    assert.equal(flags.isResidential, false);
    assert.equal(flags.isCommercial, false);
  });
});

// ---------------------------------------------------------------------------
// the wiring — the part that actually regressed
// ---------------------------------------------------------------------------

test('the listings page fetches a pool instead of reusing the results', async (t) => {
  const page = () => stripComments(readClient('app/properties/PropertyListContent.jsx'));

  await t.test('it uses the shared module rather than a second copy of the scoring', () => {
    assert.match(page(), /from ['"][^'"]*relatedProperties['"]/,
      'the page does not import the module — the scoring has been duplicated');
  });

  await t.test('the scoring is no longer inline', () => {
    // If it comes back inline it will drift from the tested copy.
    assert.doesNotMatch(page(), /relevanceScore:\s*score/,
      'the inline scoring is back alongside the module');
  });

  await t.test('THE REGRESSION: it no longer ranks the search results against themselves', () => {
    assert.doesNotMatch(page(), /const related = properties\s*\n?\s*\.filter/,
      'the pool is once again the match set, so nothing will ever be suggested');
  });

  await t.test('a separate request supplies the candidates', () => {
    assert.match(page(), /relatedPoolParams\(\)/,
      'no pool request — the suggestions have no candidates to rank');
  });

  await t.test('and it is only issued when the rule says so', () => {
    // Pinned to the GUARD, not to the identifier appearing somewhere in the
    // file. The memo below also calls shouldSuggestRelated, so a loose match
    // passed even with the fetch guard replaced by `if (false)`.
    assert.match(
      page(),
      /if\s*\(\s*!\s*shouldSuggestRelated\(\s*filters\s*,\s*properties\.length\s*\)\s*\)\s*\{/,
      'the pool is fetched unconditionally, on every search'
    );
  });

  await t.test('and the pool is cleared when the rule stops applying', () => {
    // Otherwise a stale pool from a narrow search keeps rendering suggestions
    // underneath a later search that returned plenty.
    const src = page();
    const guardAt = src.search(/if\s*\(\s*!\s*shouldSuggestRelated\(/);
    assert.notEqual(guardAt, -1);
    assert.match(src.slice(guardAt, guardAt + 200), /setRelatedPool\(\[\]\)/);
  });

  await t.test('the render still gates on there being suggestions', () => {
    assert.match(page(), /relatedProperties\.length > 0/);
  });

  await t.test('the debug console.log is gone', () => {
    // It ran on every render, for every visitor, in production.
    assert.doesNotMatch(page(), /console\.log\('Related properties calculation/);
  });
});
