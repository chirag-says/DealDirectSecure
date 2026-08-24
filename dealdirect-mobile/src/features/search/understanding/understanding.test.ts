import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { extractBhk } from './bhk.ts';
import { normalizeQuery, stripStopWords } from './normalize.ts';
import { parseQuery } from './parse.ts';
import { CRORE, LAKH, extractPrice, formatRupees } from './price.ts';
import { extractPropertyType } from './propertyType.ts';
import { extractConstruction, extractSoftSignals } from './softIntent.ts';
import { extractTransaction } from './transaction.ts';
import type { ParseContext } from './types.ts';

/**
 * Runs on plain Node — `npm run test:parser` — because this module has no React
 * Native dependency. No test framework was added to the project for it.
 *
 * Every bug found while building this became a case here. They are marked
 * REGRESSION so nobody "simplifies" one away later.
 */

const CTX: ParseContext = {
  cities: [
    { id: 'mumbai', label: 'Mumbai', aliases: ['mumbai', 'navi mumbai', 'bombay'] },
    { id: 'bangalore', label: 'Bengaluru', aliases: ['bangalore', 'bengaluru'] },
    { id: 'pune', label: 'Pune', aliases: ['pune'] },
    { id: 'kolkata', label: 'Kolkata', aliases: ['kolkata', 'calcutta'] },
  ],
  localities: [
    'hsr layout',
    'koramangala',
    'yelahanka',
    'jayanagar',
    'indiranagar',
    'bandra',
    'borivali',
    'goregaon',
    'lake town',
    'richmond town',
    'wakad',
    'navi mumbai',
    'sg highway',
    'hebbal',
  ],
};

const parse = (q: string) => parseQuery(q, CTX);

/* ══ normalisation ═══════════════════════════════════════════════════════ */

describe('normalizeQuery', () => {
  it('lower-cases and collapses whitespace', () => {
    assert.equal(normalizeQuery('  3   BHK   Flat  '), '3 bhk flat');
  });

  it('splits digits glued to letters', () => {
    assert.equal(normalizeQuery('2bhk'), '2 bhk');
    assert.equal(normalizeQuery('3BHK'), '3 bhk');
    assert.equal(normalizeQuery('1.2cr'), '1.2 cr');
  });

  it('handles hyphenated forms', () => {
    assert.equal(normalizeQuery('3-bhk'), '3 bhk');
  });

  it('strips currency symbols and Indian digit grouping', () => {
    assert.equal(normalizeQuery('₹1,25,00,000'), '12500000');
    assert.equal(normalizeQuery('Rs. 50 lakh'), '50 lakh');
  });

  it('keeps decimal points inside numbers only', () => {
    assert.equal(normalizeQuery('1.5 crore.'), '1.5 crore');
  });

  it('survives punctuation and emoji', () => {
    assert.equal(normalizeQuery('flat, 2 bhk!! 🏠'), 'flat 2 bhk');
  });

  it('returns empty for empty-ish input', () => {
    assert.equal(normalizeQuery(''), '');
    assert.equal(normalizeQuery('   '), '');
    assert.equal(normalizeQuery('!!!'), '');
  });

  it('strips stop words from a residual only', () => {
    assert.equal(stripStopWords('i need a place in the'), '');
    assert.equal(stripStopWords('prestige lakeside'), 'prestige lakeside');
  });
});

/* ══ price ═══════════════════════════════════════════════════════════════ */

describe('extractPrice', () => {
  const price = (q: string) => extractPrice(normalizeQuery(q));

  it('parses every crore spelling', () => {
    for (const q of ['1 cr', '1 crore', '1crore', '1.0 cr']) {
      assert.equal(price(q).maxPrice, CRORE, q);
    }
  });

  it('parses fractional crore exactly', () => {
    assert.equal(price('0.8 cr').maxPrice, 8_000_000);
    assert.equal(price('1.2 crore').maxPrice, 12_000_000);
    assert.equal(price('1.5cr').maxPrice, 15_000_000);
  });

  it('parses every lakh spelling', () => {
    for (const q of ['80 lakh', '80 lakhs', '80L', '80 lac', '80 lacs']) {
      assert.equal(price(q).maxPrice, 80 * LAKH, q);
    }
  });

  it('always returns integer rupees', () => {
    for (const q of ['1.15 cr', '0.35 cr', '2.75 crore', '1.1 lakh']) {
      const v = price(q).maxPrice!;
      assert.ok(Number.isInteger(v), `${q} → ${v} is not an integer`);
    }
  });

  it('reads upper-bound phrasing as a ceiling', () => {
    for (const q of [
      'below 1 crore',
      'under 1 crore',
      'less than 1 crore',
      'upto 1 crore',
      'within 1 crore',
      'max 1 crore',
      'budget 1 crore',
    ]) {
      const r = price(q);
      assert.equal(r.maxPrice, CRORE, q);
      assert.equal(r.minPrice, undefined, q);
    }
  });

  it('reads lower-bound phrasing as a floor', () => {
    for (const q of ['above 1 crore', 'over 1 crore', 'more than 1 crore', 'minimum 1 crore']) {
      const r = price(q);
      assert.equal(r.minPrice, CRORE, q);
      assert.equal(r.maxPrice, undefined, q);
    }
  });

  it('reads a range', () => {
    const r = price('between 80 lakh and 1 crore');
    assert.equal(r.minPrice, 80 * LAKH);
    assert.equal(r.maxPrice, CRORE);
  });

  it('defaults a bare amount to a ceiling, not a floor', () => {
    // REGRESSION: reading a stated budget as a minimum shows the most
    // expensive inventory to someone naming their limit.
    const r = price('3 bhk 1 crore');
    assert.equal(r.maxPrice, CRORE);
    assert.equal(r.minPrice, undefined);
  });

  it('does NOT read a BHK digit as money', () => {
    // REGRESSION: "3 bhk" contains a 3.
    const bhk = extractBhk(normalizeQuery('3 bhk'));
    const r = extractPrice(normalizeQuery('3 bhk'), bhk.spans);
    assert.equal(r.maxPrice, undefined);
    assert.equal(r.minPrice, undefined);
  });

  it('ignores small bare numbers', () => {
    assert.equal(price('2 bathrooms').maxPrice, undefined);
    assert.equal(price('4 bedroom').maxPrice, undefined);
    assert.equal(price('floor 7').maxPrice, undefined);
  });

  it('accepts a large bare number as rupees', () => {
    assert.equal(price('under 5000000').maxPrice, 5_000_000);
  });

  it('parses thousands for rentals', () => {
    assert.equal(price('under 25k').maxPrice, 25_000);
  });

  it('formats money the Indian way', () => {
    assert.equal(formatRupees(CRORE), '₹1 Cr');
    assert.equal(formatRupees(12_000_000), '₹1.2 Cr');
    assert.equal(formatRupees(80 * LAKH), '₹80 L');
    assert.equal(formatRupees(25_000), '₹25,000');
  });
});

/* ══ bhk ═════════════════════════════════════════════════════════════════ */

describe('extractBhk', () => {
  const bhk = (q: string) => extractBhk(normalizeQuery(q)).bhk;

  it('parses every spacing and casing', () => {
    for (const q of ['1bhk', '1 bhk', '1 BHK', '1-bhk', '1  Bhk']) {
      assert.equal(bhk(q), 1, q);
    }
  });

  it('parses 2 to 5', () => {
    assert.equal(bhk('2bhk'), 2);
    assert.equal(bhk('3bhk'), 3);
    assert.equal(bhk('4 bhk'), 4);
    assert.equal(bhk('5 bhk'), 5);
  });

  it('parses bedroom phrasing', () => {
    assert.equal(bhk('1 bedroom'), 1);
    assert.equal(bhk('2 bedrooms'), 2);
    assert.equal(bhk('3 bed'), 3);
  });

  it('parses word numbers', () => {
    assert.equal(bhk('two bhk'), 2);
    assert.equal(bhk('three bedroom'), 3);
  });

  it('treats 1 RK as 0 bedrooms, not 1', () => {
    // REGRESSION: an RK has no separate bedroom; the digit is a trap.
    assert.equal(bhk('1 rk'), 0);
    assert.equal(bhk('1rk'), 0);
    assert.equal(bhk('rk'), 0);
  });

  it('does not invent a count from unrelated numbers', () => {
    assert.equal(bhk('under 1 crore'), undefined);
    assert.equal(bhk('floor 3'), undefined);
    assert.equal(bhk('apartment'), undefined);
  });

  it('claims a bare bhk span without a count', () => {
    const r = extractBhk(normalizeQuery('bhk in bandra'));
    assert.equal(r.bhk, undefined);
    assert.equal(r.spans.length, 1);
  });
});

/* ══ property type — the compound-word trap ══════════════════════════════ */

describe('extractPropertyType', () => {
  const type = (q: string) => extractPropertyType(normalizeQuery(q)).propertyType;
  const category = (q: string) => extractPropertyType(normalizeQuery(q)).category;

  it('WAREHOUSE is not a house', () => {
    // REGRESSION: /house/ matches "warehouse". This exact bug inflated an
    // earlier benchmark to a false 94%.
    assert.equal(type('warehouse'), 'warehouse');
    assert.equal(category('warehouse'), 'commercial');
    assert.equal(type('warehouse for rent'), 'warehouse');
  });

  it('PENTHOUSE is not a house', () => {
    // REGRESSION: same trap, opposite category.
    assert.equal(type('penthouse'), 'penthouse');
    assert.equal(category('penthouse'), 'residential');
    assert.equal(type('3 bhk penthouse'), 'penthouse');
  });

  it('godown resolves to warehouse', () => {
    assert.equal(type('godown'), 'warehouse');
  });

  it('house still resolves to house', () => {
    assert.equal(type('house'), 'house');
    assert.equal(type('independent house'), 'house');
    assert.equal(type('bungalow'), 'house');
  });

  it('flat and apartment are the same thing', () => {
    assert.equal(type('flat'), 'apartment');
    assert.equal(type('flats'), 'apartment');
    assert.equal(type('apartment'), 'apartment');
    assert.equal(type('apartments'), 'apartment');
  });

  it('prefers the longest alias', () => {
    // "independent house" must not be shortened to "house" by rule order.
    assert.equal(type('independent house in bandra'), 'house');
    assert.equal(type('office space'), 'office');
  });

  it('resolves the commercial vocabulary', () => {
    assert.equal(type('showroom'), 'showroom');
    assert.equal(type('shop'), 'shop');
    assert.equal(type('retail'), 'shop');
    assert.equal(type('office'), 'office');
    assert.equal(type('restaurant'), 'restaurant');
    assert.equal(type('cafe'), 'restaurant');
    assert.equal(type('villa'), 'villa');
    assert.equal(type('plot'), 'plot');
  });

  it('infers residential from "home" with no built form', () => {
    // "home" appears in no live listing title, which is why the current
    // search returns nothing for it.
    assert.equal(type('home'), undefined);
    assert.equal(category('home'), 'residential');
    assert.equal(category('family home'), 'residential');
  });

  it('resolves an explicitly named type even beside a soft word', () => {
    // "office for my family business" NAMES the type. "family" is a soft
    // signal and must not fight it. An earlier version of this test asserted
    // ambiguity here and was simply wrong about what the query says.
    assert.equal(type('office for my family business'), 'office');
    assert.equal(category('office for my family business'), 'commercial');
  });

  it('refuses to guess when only conflicting HINTS are present', () => {
    // No explicit type word, and both categories implied. Guessing removes
    // half the corpus, so neither is claimed.
    assert.equal(category('commercial family property'), undefined);
  });

  it('a type after "near" is a destination, not the subject', () => {
    // REGRESSION: "affordable home close to office" was returning commercial
    // inventory to someone asking for somewhere to live.
    assert.equal(type('home close to office'), undefined);
    assert.equal(category('home close to office'), 'residential');
    assert.equal(type('flat near a shop'), 'apartment');
  });

  it('does not match a type inside a larger word', () => {
    assert.equal(type('shopping district'), undefined);
    assert.equal(type('officer colony'), undefined);
  });
});

/* ══ transaction — the "rental income" inversion ═════════════════════════ */

describe('extractTransaction', () => {
  const txn = (q: string) => extractTransaction(normalizeQuery(q)).transaction;

  it('reads plain rent vocabulary', () => {
    for (const q of ['for rent', 'rent', 'rental', 'renting', 'lease', 'to let']) {
      assert.equal(txn(q), 'rent', q);
    }
  });

  it('reads plain buy vocabulary', () => {
    for (const q of ['buy', 'buying', 'purchase', 'for sale', 'sale', 'resale']) {
      assert.equal(txn(q), 'sale', q);
    }
  });

  it('RENTAL INCOME means buy, not rent', () => {
    // REGRESSION: the highest-consequence ambiguity in the domain — reading it
    // as "rent" inverts the entire result set for an investor.
    assert.equal(txn('rental income'), 'sale');
    assert.equal(txn('property for rental income'), 'sale');
    assert.equal(txn('property suitable for rental income'), 'sale');
    assert.equal(txn('good rental yield'), 'sale');
    assert.equal(txn('buy to let'), 'sale');
  });

  it('investment phrasing means buy', () => {
    assert.equal(txn('investment property'), 'sale');
    assert.equal(txn('for investment'), 'sale');
  });

  it('flags investment queries', () => {
    assert.equal(extractTransaction(normalizeQuery('rental income')).investment, true);
    assert.equal(extractTransaction(normalizeQuery('for rent')).investment, false);
  });

  it('leaves an ambiguous both-sided query unresolved', () => {
    assert.equal(txn('buy or rent a 2 bhk'), undefined);
  });

  it('does not default when nothing is stated', () => {
    // Two thirds of the corpus is rental; defaulting to sale would hide it.
    assert.equal(txn('3 bhk in bandra'), undefined);
  });

  it('does not match rent inside another word', () => {
    assert.equal(txn('current listings'), undefined);
    assert.equal(txn('parent friendly'), undefined);
  });
});

/* ══ construction and soft signals ══════════════════════════════════════ */

describe('extractConstruction', () => {
  const stage = (q: string) => extractConstruction(normalizeQuery(q)).construction;

  it('reads ready-to-move phrasing', () => {
    for (const q of ['ready to move', 'ready possession', 'ready-to-move', 'immediate possession']) {
      assert.equal(stage(q), 'ready', q);
    }
  });

  it('reads under-construction phrasing', () => {
    for (const q of ['under construction', 'new launch', 'upcoming']) {
      assert.equal(stage(q), 'construction', q);
    }
  });

  it('does not let a bare "ready" capture an under-construction query', () => {
    // REGRESSION: "under construction, ready in 2027" must not read as ready.
    assert.equal(stage('under construction ready in 2027'), 'construction');
  });

  it('claims nothing when unstated', () => {
    assert.equal(stage('3 bhk in bandra'), undefined);
  });
});

describe('extractSoftSignals', () => {
  const soft = (q: string) => extractSoftSignals(normalizeQuery(q)).soft;

  it('recognises the intent vocabulary', () => {
    assert.deepEqual(soft('family home'), ['family']);
    assert.ok(soft('luxury apartment').includes('luxury'));
    assert.ok(soft('affordable flat').includes('affordable'));
    assert.ok(soft('near metro').includes('metro'));
    assert.ok(soft('close to it park').includes('workplace'));
    assert.ok(soft('quiet area').includes('quiet'));
    assert.ok(soft('furnished flat').includes('furnished'));
    assert.ok(soft('with parking').includes('parking'));
    assert.ok(soft('near schools').includes('schools'));
  });

  it('collects several at once', () => {
    const s = soft('luxury family home near metro in a quiet area');
    for (const expected of ['luxury', 'family', 'metro', 'quiet']) {
      assert.ok(s.includes(expected as never), expected);
    }
  });

  it('returns nothing for a purely structural query', () => {
    assert.deepEqual(soft('3 bhk under 1 crore'), []);
  });
});

/* ══ the whole pipeline ═════════════════════════════════════════════════ */

describe('parseQuery — structured extraction', () => {
  it('handles the canonical mixed query', () => {
    const r = parse('3 bhk family home near metro under 1.2 crore in yelahanka');
    assert.equal(r.hard.bhk, 3);
    assert.equal(r.hard.maxPrice, 12_000_000);
    assert.equal(r.hard.locality, 'yelahanka');
    assert.equal(r.hard.category, 'residential');
    assert.ok(r.soft.includes('family'));
    assert.ok(r.soft.includes('metro'));
  });

  it('handles type + locality + budget', () => {
    const r = parse('2 bhk flat in bandra under 1 crore');
    assert.equal(r.hard.bhk, 2);
    assert.equal(r.hard.propertyType, 'apartment');
    assert.equal(r.hard.locality, 'bandra');
    assert.equal(r.hard.maxPrice, CRORE);
  });

  it('handles rent + type + locality', () => {
    const r = parse('office space for rent in hsr layout');
    assert.equal(r.hard.transaction, 'rent');
    assert.equal(r.hard.propertyType, 'office');
    assert.equal(r.hard.locality, 'hsr layout');
    assert.equal(r.hard.category, 'commercial');
  });

  it('resolves a city', () => {
    const r = parse('3 bhk apartment for rent in bangalore');
    assert.equal(r.hard.city, 'bangalore');
    assert.equal(r.hard.transaction, 'rent');
  });

  it('accepts a city alias', () => {
    assert.equal(parse('flat in bengaluru').hard.city, 'bangalore');
    assert.equal(parse('flat in bombay').hard.city, 'mumbai');
  });

  it('prefers a locality over the city hiding inside it', () => {
    // REGRESSION: "navi mumbai" is a locality AND contains the alias "mumbai".
    const r = parse('3 bhk in navi mumbai');
    assert.equal(r.hard.locality, 'navi mumbai');
  });

  it('does NOT structure an unknown locality', () => {
    // The corpus has no Whitefield. Inventing the filter empties the screen;
    // leaving it as text lets the server answer honestly.
    const r = parse('3 bhk in whitefield');
    assert.equal(r.hard.locality, undefined);
    assert.ok(r.residual.includes('whitefield'));
  });

  it('keeps unknown words as residual text', () => {
    const r = parse('prestige lakeside habitat 3 bhk');
    assert.equal(r.hard.bhk, 3);
    assert.ok(r.residual.includes('prestige'));
    assert.ok(r.residual.includes('lakeside'));
  });

  it('understands a plain natural sentence', () => {
    const r = parse('i need a home for my family near a metro station');
    assert.equal(r.hard.category, 'residential');
    assert.ok(r.soft.includes('family'));
    assert.ok(r.soft.includes('metro'));
  });

  it('reads an investment query as a purchase', () => {
    const r = parse('good investment property in bangalore');
    assert.equal(r.hard.transaction, 'sale');
    assert.equal(r.hard.city, 'bangalore');
    assert.ok(r.soft.includes('investment'));
  });

  it('reads a rental-income query as a purchase too', () => {
    const r = parse('property suitable for rental income');
    assert.equal(r.hard.transaction, 'sale');
    assert.ok(r.soft.includes('investment'));
  });

  it('never turns a soft signal into a hard constraint', () => {
    const r = parse('luxury family home in a quiet area');
    assert.equal(Object.keys(r.hard).length, 1); // category only
    assert.equal(r.hard.category, 'residential');
    assert.ok(r.soft.length >= 3);
  });

  it('survives malformed and adversarial input', () => {
    for (const q of ['', '   ', '!!!', '???', '....', '3', 'bhk bhk bhk', 'a'.repeat(500)]) {
      const r = parse(q);
      assert.ok(typeof r.residual === 'string', q);
      assert.ok(Array.isArray(r.soft), q);
    }
  });

  it('is case and punctuation insensitive', () => {
    const a = parse('3 BHK Flat in Bandra under ₹1 Crore');
    const b = parse('3bhk flat, bandra, under 1cr');
    assert.equal(a.hard.bhk, b.hard.bhk);
    assert.equal(a.hard.propertyType, b.hard.propertyType);
    assert.equal(a.hard.locality, b.hard.locality);
    assert.equal(a.hard.maxPrice, b.hard.maxPrice);
  });

  it('keeps the original text intact', () => {
    const r = parse('  3 BHK  ');
    assert.equal(r.original, '  3 BHK  ');
  });
});

/* ══ the benchmark's own failure cases ══════════════════════════════════ */

describe('parseQuery — cases the 59-query benchmark got wrong', () => {
  it('"flats" implies residential', () => {
    // REGRESSION: the plural was missing from the vocabulary.
    assert.equal(parse('flats').hard.category, 'residential');
  });

  it('"bungalow" implies residential', () => {
    assert.equal(parse('bungalow').hard.category, 'residential');
  });

  it('"quiet residential area" implies residential', () => {
    assert.equal(parse('quiet residential area').hard.category, 'residential');
  });

  it('"affordable home close to office" is residential, not commercial', () => {
    // REGRESSION: "office" as a destination, not as the thing being bought.
    const r = parse('affordable home close to office');
    assert.equal(r.hard.category, 'residential');
    assert.notEqual(r.hard.propertyType, 'office');
  });

  it('"starter home for a couple" is residential', () => {
    assert.equal(parse('starter home for a couple').hard.category, 'residential');
  });

  it('"space for my business" is commercial', () => {
    assert.equal(parse('space for my business').hard.category, 'commercial');
  });
});
