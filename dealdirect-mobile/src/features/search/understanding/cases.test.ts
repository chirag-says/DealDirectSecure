import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { parseQuery } from './parse.ts';
import { CRORE, LAKH } from './price.ts';
import type { HardConstraints, ParseContext, SoftSignal } from './types.ts';

/**
 * Table-driven cases, one test per row.
 *
 * The suite next door tests each stage in isolation; this one tests whole
 * queries a user might actually type, so a regression in how the stages
 * COMPOSE is caught even when every stage still passes on its own.
 *
 * `expect` is a partial: only the listed keys are asserted, and every other
 * constraint is required to be ABSENT. That second half is the important one —
 * it is what stops a parser quietly inventing a filter nobody asked for.
 */

const CTX: ParseContext = {
  cities: [
    { id: 'mumbai', label: 'Mumbai', aliases: ['mumbai', 'navi mumbai', 'bombay'] },
    { id: 'bangalore', label: 'Bengaluru', aliases: ['bangalore', 'bengaluru'] },
    { id: 'pune', label: 'Pune', aliases: ['pune'] },
    { id: 'kolkata', label: 'Kolkata', aliases: ['kolkata', 'calcutta'] },
    { id: 'ahmedabad', label: 'Ahmedabad', aliases: ['ahmedabad'] },
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
    'andheri west',
  ],
};

interface Case {
  q: string;
  hard?: Partial<HardConstraints>;
  soft?: SoftSignal[];
  /** Substrings that must survive into the residual for the server regex. */
  residual?: string[];
  note?: string;
}

const CASES: Case[] = [
  /* ── exact and literal ────────────────────────────────────────────────── */
  { q: '3 bhk', hard: { bhk: 3 } },
  { q: '2 BHK', hard: { bhk: 2 } },
  { q: '4bhk', hard: { bhk: 4 } },
  { q: '1 rk', hard: { bhk: 0 } },
  { q: 'hsr layout', hard: { locality: 'hsr layout' } },
  { q: 'koramangala', hard: { locality: 'koramangala' } },
  { q: 'bandra', hard: { locality: 'bandra' } },
  { q: 'villa', hard: { propertyType: 'villa', category: 'residential' } },
  { q: 'showroom', hard: { propertyType: 'showroom', category: 'commercial' } },
  { q: 'plot', hard: { propertyType: 'plot', category: 'residential' } },

  /* ── synonyms ─────────────────────────────────────────────────────────── */
  { q: 'flat', hard: { propertyType: 'apartment', category: 'residential' } },
  { q: 'flats', hard: { propertyType: 'apartment', category: 'residential' } },
  { q: 'apartment', hard: { propertyType: 'apartment', category: 'residential' } },
  { q: 'house', hard: { propertyType: 'house', category: 'residential' } },
  { q: 'bungalow', hard: { propertyType: 'house', category: 'residential' } },
  { q: 'kothi', hard: { propertyType: 'house', category: 'residential' } },
  { q: 'godown', hard: { propertyType: 'warehouse', category: 'commercial' } },
  { q: 'retail', hard: { propertyType: 'shop', category: 'commercial' } },
  { q: 'cafe', hard: { propertyType: 'restaurant', category: 'commercial' } },
  { q: 'workspace', hard: { propertyType: 'office', category: 'commercial' } },
  {
    q: 'home',
    hard: { category: 'residential' },
    note: 'returns zero results against the current search',
  },

  /* ── compound words that contain another type ─────────────────────────── */
  { q: 'warehouse', hard: { propertyType: 'warehouse', category: 'commercial' } },
  { q: 'penthouse', hard: { propertyType: 'penthouse', category: 'residential' } },
  { q: 'warehouse for rent', hard: { propertyType: 'warehouse', transaction: 'rent' } },
  { q: '3 bhk penthouse', hard: { propertyType: 'penthouse', bhk: 3 } },
  { q: 'independent house', hard: { propertyType: 'house' } },
  { q: 'houseboat', residual: ['houseboat'], note: 'not a type we stock; stays text' },

  /* ── Indian money notation ────────────────────────────────────────────── */
  { q: '1 cr', hard: { maxPrice: CRORE } },
  { q: '1 crore', hard: { maxPrice: CRORE } },
  { q: '1.2 crore', hard: { maxPrice: 12_000_000 } },
  { q: '1.2cr', hard: { maxPrice: 12_000_000 } },
  { q: '0.8 cr', hard: { maxPrice: 8_000_000 } },
  { q: '80 lakh', hard: { maxPrice: 80 * LAKH } },
  { q: '80 lakhs', hard: { maxPrice: 80 * LAKH } },
  { q: '80L', hard: { maxPrice: 80 * LAKH } },
  { q: 'under 1 crore', hard: { maxPrice: CRORE } },
  { q: 'below 1 crore', hard: { maxPrice: CRORE } },
  { q: 'less than 1 crore', hard: { maxPrice: CRORE } },
  { q: 'above 1 crore', hard: { minPrice: CRORE } },
  { q: 'between 80 lakh and 1 crore', hard: { minPrice: 80 * LAKH, maxPrice: CRORE } },
  { q: 'under 25k', hard: { maxPrice: 25_000 } },

  /* ── transaction intent ───────────────────────────────────────────────── */
  { q: 'for sale', hard: { transaction: 'sale' } },
  { q: 'for rent', hard: { transaction: 'rent' } },
  { q: 'to let', hard: { transaction: 'rent' } },
  { q: 'lease', hard: { transaction: 'rent' } },
  { q: 'resale', hard: { transaction: 'sale' } },

  /* ── the rental-income inversion ──────────────────────────────────────── */
  {
    q: 'rental income',
    hard: { transaction: 'sale' },
    soft: ['investment'],
    note: 'means BUY — reading it as rent inverts the whole result set',
  },
  { q: 'property for rental income', hard: { transaction: 'sale' }, soft: ['investment'] },
  { q: 'good rental yield', hard: { transaction: 'sale' }, soft: ['investment'] },
  { q: 'buy to let', hard: { transaction: 'sale' }, soft: ['investment'] },
  { q: 'investment property', hard: { transaction: 'sale' }, soft: ['investment'] },

  /* ── ready / under construction ───────────────────────────────────────── */
  { q: 'ready to move', hard: { construction: 'ready' } },
  { q: 'ready possession', hard: { construction: 'ready' } },
  { q: 'under construction', hard: { construction: 'construction' } },
  { q: 'new launch', hard: { construction: 'construction' } },

  /* ── mixed, the real shape of a typed query ───────────────────────────── */
  { q: '2 bhk flat in bandra under 1 crore', hard: { bhk: 2, propertyType: 'apartment', locality: 'bandra', maxPrice: CRORE } },
  { q: '3 bhk in yelahanka under 1.5 crore', hard: { bhk: 3, locality: 'yelahanka', maxPrice: 15_000_000 } },
  { q: 'office space for rent in hsr layout', hard: { propertyType: 'office', transaction: 'rent', locality: 'hsr layout' } },
  { q: 'villa under 2 crore', hard: { propertyType: 'villa', maxPrice: 20_000_000 } },
  { q: '3 bhk apartment for rent in bangalore', hard: { bhk: 3, propertyType: 'apartment', transaction: 'rent', city: 'bangalore' } },
  { q: 'independent house for rent in bandra', hard: { propertyType: 'house', transaction: 'rent', locality: 'bandra' } },
  { q: 'commercial property in kolkata', hard: { category: 'commercial', city: 'kolkata' } },
  { q: '4 bhk for sale above 1 crore', hard: { bhk: 4, transaction: 'sale', minPrice: CRORE } },
  { q: '2 bhk near metro for rent', hard: { bhk: 2, transaction: 'rent' }, soft: ['metro'] },
  { q: 'ready to move flat in wakad', hard: { construction: 'ready', propertyType: 'apartment', locality: 'wakad' } },

  /* ── natural language ─────────────────────────────────────────────────── */
  { q: 'home for family near metro', hard: { category: 'residential' }, soft: ['family', 'metro'] },
  {
    q: '3 bhk for my family near metro under 1.2 crore',
    hard: { bhk: 3, maxPrice: 12_000_000, category: 'residential' },
    soft: ['family', 'metro'],
  },
  { q: 'affordable home near schools and metro', hard: { category: 'residential' }, soft: ['affordable', 'schools', 'metro'] },
  { q: 'luxury home for a family in a quiet area', hard: { category: 'residential' }, soft: ['luxury', 'family', 'quiet'] },
  { q: 'ready to move apartment close to it park', hard: { construction: 'ready', propertyType: 'apartment' }, soft: ['workplace'] },
  {
    q: 'i need a place to live with my parents',
    hard: { category: 'residential' },
    soft: ['family'],
    note: 'describes the need, not the built form',
  },
  { q: 'somewhere to stay in pune', hard: { category: 'residential', city: 'pune' } },
  { q: 'furnished flat for a small family', hard: { propertyType: 'apartment' }, soft: ['furnished', 'family'] },
  { q: 'quiet residential area', hard: { category: 'residential' }, soft: ['quiet'] },
  { q: 'starter home for a couple', hard: { category: 'residential' }, soft: ['family'] },
  { q: 'space for my business', hard: { category: 'commercial' } },
  {
    q: 'affordable home close to office',
    hard: { category: 'residential' },
    soft: ['affordable', 'workplace'],
    note: 'office is a destination here, not the property type',
  },

  /* ── things that must NOT become filters ──────────────────────────────── */
  { q: '3 bhk in whitefield', hard: { bhk: 3 }, residual: ['whitefield'], note: 'unknown locality stays text' },
  { q: 'prestige lakeside habitat', residual: ['prestige', 'lakeside', 'habitat'] },
  { q: 'godrej properties', residual: ['godrej'] },
  { q: 'shopping district', residual: ['shopping', 'district'], note: 'shop must not match inside shopping' },
  { q: 'current listings', residual: ['current', 'listings'], note: 'rent must not match inside current' },
  { q: 'buy or rent a 2 bhk', hard: { bhk: 2 }, note: 'both stated, so neither is claimed' },

  /* ── capitalisation, punctuation, malformed ───────────────────────────── */
  { q: '3 BHK FLAT IN BANDRA', hard: { bhk: 3, propertyType: 'apartment', locality: 'bandra' } },
  { q: '  2   bhk  ', hard: { bhk: 2 } },
  { q: 'flat, 2 bhk!!', hard: { bhk: 2, propertyType: 'apartment' } },
  { q: '₹1 crore flat', hard: { maxPrice: CRORE, propertyType: 'apartment' } },
  { q: 'Rs. 50 lakh plot', hard: { maxPrice: 50 * LAKH, propertyType: 'plot' } },
  { q: '3-bhk', hard: { bhk: 3 } },
  { q: '', hard: {} },
  { q: '   ', hard: {} },
  { q: '!!!', hard: {} },
  { q: '???!!!...', hard: {} },
  { q: '3', hard: {} },
  { q: '0', hard: {} },
  { q: 'bhk bhk bhk', hard: {} },
  { q: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', residual: ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'] },
  { q: '🏠🏠🏠', hard: {} },
  {
    q: 'select * from properties',
    residual: ['select'],
    note: '"properties" is a stop word and is correctly dropped',
  },
  { q: '../../etc/passwd', residual: ['etc', 'passwd'] },
];

/**
 * Keys asserted absent unless a row states them.
 *
 * `category` is deliberately NOT in this list. It is DERIVED — "3 bhk" implies
 * residential, "showroom" implies commercial — so requiring every row to
 * restate it would be over-specification, and the rows would drift out of date
 * the first time an alias moves. It is asserted when a row cares, and its
 * consistency is guaranteed by the invariant suite below instead.
 */
const ASSERTED_ABSENT: (keyof HardConstraints)[] = [
  'transaction',
  'bhk',
  'minPrice',
  'maxPrice',
  'city',
  'locality',
  'propertyType',
  'construction',
];

describe('parseQuery — whole-query cases', () => {
  for (const testCase of CASES) {
    const title = testCase.note
      ? `"${testCase.q}" — ${testCase.note}`
      : `"${testCase.q}"`;

    it(title, () => {
      const parsed = parseQuery(testCase.q, CTX);
      const expected = testCase.hard ?? {};

      for (const key of ASSERTED_ABSENT) {
        const want = expected[key];
        const got = parsed.hard[key];
        if (want === undefined) {
          // Absent by default: the parser must not invent a constraint.
          assert.equal(got, undefined, `${key} should not be set (got ${String(got)})`);
        } else {
          assert.equal(got, want, `${key}`);
        }
      }

      if (expected.category !== undefined) {
        assert.equal(parsed.hard.category, expected.category, 'category');
      }

      for (const signal of testCase.soft ?? []) {
        assert.ok(parsed.soft.includes(signal), `expected soft signal "${signal}"`);
      }

      for (const fragment of testCase.residual ?? []) {
        assert.ok(
          parsed.residual.includes(fragment),
          `expected "${fragment}" to survive into residual, got "${parsed.residual}"`
        );
      }
    });
  }
});

describe('parseQuery — invariants that must hold for every case', () => {
  it('never throws', () => {
    for (const testCase of CASES) {
      assert.doesNotThrow(() => parseQuery(testCase.q, CTX), testCase.q);
    }
  });

  it('always returns integer rupee bounds', () => {
    for (const testCase of CASES) {
      const { minPrice, maxPrice } = parseQuery(testCase.q, CTX).hard;
      if (minPrice !== undefined) assert.ok(Number.isInteger(minPrice), testCase.q);
      if (maxPrice !== undefined) assert.ok(Number.isInteger(maxPrice), testCase.q);
    }
  });

  it('never sets minPrice above maxPrice', () => {
    for (const testCase of CASES) {
      const { minPrice, maxPrice } = parseQuery(testCase.q, CTX).hard;
      if (minPrice !== undefined && maxPrice !== undefined) {
        assert.ok(minPrice <= maxPrice, `${testCase.q}: ${minPrice} > ${maxPrice}`);
      }
    }
  });

  it('never sets a locality outside the known set', () => {
    for (const testCase of CASES) {
      const { locality } = parseQuery(testCase.q, CTX).hard;
      if (locality !== undefined) {
        assert.ok(CTX.localities.includes(locality), `${testCase.q}: "${locality}" is not real`);
      }
    }
  });

  it('never sets a city outside the known set', () => {
    const ids = CTX.cities.map((c) => c.id);
    for (const testCase of CASES) {
      const { city } = parseQuery(testCase.q, CTX).hard;
      if (city !== undefined) assert.ok(ids.includes(city), `${testCase.q}: "${city}"`);
    }
  });

  it('never emits a bhk outside 0..9', () => {
    for (const testCase of CASES) {
      const { bhk } = parseQuery(testCase.q, CTX).hard;
      if (bhk !== undefined) assert.ok(bhk >= 0 && bhk <= 9, `${testCase.q}: ${bhk}`);
    }
  });

  it('never contradicts itself: category always agrees with property type', () => {
    const RESIDENTIAL = ['apartment', 'house', 'villa', 'penthouse', 'plot'];
    for (const testCase of CASES) {
      const { propertyType, category } = parseQuery(testCase.q, CTX).hard;
      if (!propertyType || !category) continue;
      const expected = RESIDENTIAL.includes(propertyType) ? 'residential' : 'commercial';
      assert.equal(category, expected, `${testCase.q}: ${propertyType} is not ${category}`);
    }
  });

  it('a bhk query is never classified commercial', () => {
    for (const testCase of CASES) {
      const { bhk, category } = parseQuery(testCase.q, CTX).hard;
      if (bhk === undefined) continue;
      assert.notEqual(category, 'commercial', testCase.q);
    }
  });

  it('is idempotent — parsing the normalised form again agrees', () => {
    for (const testCase of CASES) {
      const once = parseQuery(testCase.q, CTX);
      const twice = parseQuery(once.normalized, CTX);
      assert.deepEqual(twice.hard, once.hard, testCase.q);
    }
  });
});
