import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  MARKET_DEAD_BAND_PCT,
  configurationLabel,
  describePriceIntelligence,
} from './priceIntelligence.ts';
import type { PriceIntelligence } from '../../types/backend/property.ts';

/** Stands in for `@/ui`'s formatPrice, which cannot be imported under node. */
const money = (rupees: number) => `RS${rupees}`;

const NOW = new Date('2026-09-05T10:00:00.000Z');

function intel(overrides: Partial<PriceIntelligence> = {}): PriceIntelligence {
  return {
    listedAt: null,
    daysListed: null,
    changes: [],
    lastDrop: null,
    market: null,
    ...overrides,
  };
}

function market(overrides: Partial<NonNullable<PriceIntelligence['market']>> = {}) {
  return {
    scope: 'configuration' as const,
    bhk: '2 BHK',
    city: 'Pune',
    locality: 'Wakad',
    slug: 'pune-wakad-sale',
    period: '2026-Q3',
    count: 24,
    medianAsking: 8_000_000,
    p25: null,
    p75: null,
    qoqPct: null,
    deltaPct: null,
    ...overrides,
  };
}

describe('nothing to say', () => {
  it('reports empty for a missing payload', () => {
    for (const value of [null, undefined]) {
      const lines = describePriceIntelligence(value, money, NOW);
      assert.equal(lines.isEmpty, true);
      assert.equal(lines.lastDrop, null);
      assert.equal(lines.daysListed, null);
      assert.equal(lines.market, null);
      assert.deepEqual(lines.history, []);
    }
  });

  it('reports empty when every field is null', () => {
    assert.equal(describePriceIntelligence(intel(), money, NOW).isEmpty, true);
  });

  it('is not empty as soon as one field says something', () => {
    assert.equal(describePriceIntelligence(intel({ daysListed: 4 }), money, NOW).isEmpty, false);
  });
});

describe('days listed', () => {
  it('names today and yesterday rather than counting to zero', () => {
    assert.equal(describePriceIntelligence(intel({ daysListed: 0 }), money, NOW).daysListed, 'Listed today');
    assert.equal(
      describePriceIntelligence(intel({ daysListed: 1 }), money, NOW).daysListed,
      'Listed yesterday'
    );
  });

  it('counts days after that', () => {
    assert.equal(
      describePriceIntelligence(intel({ daysListed: 40 }), money, NOW).daysListed,
      'Listed 40 days ago'
    );
  });

  it('says nothing for null, a negative, or a non-number', () => {
    for (const days of [null, undefined, -3, Number.NaN, '12' as unknown as number]) {
      assert.equal(
        describePriceIntelligence(intel({ daysListed: days as number | null }), money, NOW)
          .daysListed,
        null
      );
    }
  });
});

describe('the last drop', () => {
  it('states the amount and the day', () => {
    const lines = describePriceIntelligence(
      intel({
        lastDrop: { from: 5_200_000, to: 5_000_000, deltaPct: -3.8, at: '2026-09-03T00:00:00.000Z' },
      }),
      money,
      NOW
    );

    assert.equal(lines.lastDrop, 'Price dropped RS200000 on 3 Sep');
  });

  it('refuses to call a rise a drop', () => {
    const lines = describePriceIntelligence(
      intel({
        lastDrop: { from: 5_000_000, to: 5_200_000, deltaPct: 4, at: '2026-09-03T00:00:00.000Z' },
      }),
      money,
      NOW
    );

    assert.equal(lines.lastDrop, null);
  });

  it('refuses a drop of nothing', () => {
    const lines = describePriceIntelligence(
      intel({ lastDrop: { from: 5_000_000, to: 5_000_000, deltaPct: 0, at: '2026-09-03' } }),
      money,
      NOW
    );

    assert.equal(lines.lastDrop, null);
  });

  it('still states the drop when the date is unusable', () => {
    const lines = describePriceIntelligence(
      intel({ lastDrop: { from: 200, to: 100, deltaPct: -50, at: 'not a date' } }),
      money,
      NOW
    );

    assert.equal(lines.lastDrop, 'Price dropped RS100');
  });

  it('adds the year when the drop was not this year', () => {
    const lines = describePriceIntelligence(
      intel({ lastDrop: { from: 200, to: 100, deltaPct: -50, at: '2025-01-09T00:00:00.000Z' } }),
      money,
      NOW
    );

    assert.match(lines.lastDrop ?? '', /2025/);
  });
});

describe('the market line', () => {
  it('says below when the listing asks under the median', () => {
    const lines = describePriceIntelligence(intel({ market: market({ deltaPct: -8 }) }), money, NOW);

    assert.equal(lines.market?.verdict, 'below');
    assert.equal(lines.market?.text, 'Asks 8% below the Wakad median for 2 BHKs');
    assert.equal(lines.market?.slug, 'pune-wakad-sale');
    assert.equal(lines.market?.count, 24);
  });

  it('says above when it asks over', () => {
    const lines = describePriceIntelligence(intel({ market: market({ deltaPct: 12.4 }) }), money, NOW);

    assert.equal(lines.market?.verdict, 'above');
    assert.equal(lines.market?.text, 'Asks 12% above the Wakad median for 2 BHKs');
  });

  it('says in line inside the dead band, either side of zero', () => {
    for (const delta of [0, 0.4, -0.4, MARKET_DEAD_BAND_PCT - 0.01, -(MARKET_DEAD_BAND_PCT - 0.01)]) {
      const lines = describePriceIntelligence(intel({ market: market({ deltaPct: delta }) }), money, NOW);
      assert.equal(lines.market?.verdict, 'in-line', `delta ${delta}`);
      assert.equal(lines.market?.text, 'In line with the Wakad median for 2 BHKs');
    }
  });

  it('leaves the dead band exactly at the boundary', () => {
    const lines = describePriceIntelligence(
      intel({ market: market({ deltaPct: MARKET_DEAD_BAND_PCT }) }),
      money,
      NOW
    );

    assert.equal(lines.market?.verdict, 'above');
  });

  it('names the locality scope honestly when the comparison is not like for like', () => {
    const lines = describePriceIntelligence(
      intel({ market: market({ scope: 'locality', bhk: null, deltaPct: -10 }) }),
      money,
      NOW
    );

    assert.equal(lines.market?.text, 'Asks 10% below the Wakad median');
  });

  it('falls back to the locality wording when the scope claims a configuration but names none', () => {
    const lines = describePriceIntelligence(
      intel({ market: market({ scope: 'configuration', bhk: null, deltaPct: -10 }) }),
      money,
      NOW
    );

    assert.equal(lines.market?.text, 'Asks 10% below the Wakad median');
  });

  it('renders nothing when the comparison itself is null', () => {
    assert.equal(describePriceIntelligence(intel({ market: null }), money, NOW).market, null);
  });

  it('renders nothing when deltaPct is missing or not a number', () => {
    for (const delta of [null, undefined, Number.NaN, Infinity]) {
      const lines = describePriceIntelligence(
        intel({ market: market({ deltaPct: delta as number | null }) }),
        money,
        NOW
      );
      assert.equal(lines.market, null, `delta ${String(delta)}`);
    }
  });

  it('renders nothing without a slug to open', () => {
    const lines = describePriceIntelligence(
      intel({ market: market({ slug: '', deltaPct: -8 }) }),
      money,
      NOW
    );

    assert.equal(lines.market, null);
  });
});

describe('configurationLabel', () => {
  it('pluralises the shapes the schema actually holds', () => {
    assert.equal(configurationLabel('2'), '2 BHKs');
    assert.equal(configurationLabel('2 BHK'), '2 BHKs');
    assert.equal(configurationLabel('3.5'), '3.5 BHKs');
    assert.equal(configurationLabel('Studio'), 'Studios');
    assert.equal(configurationLabel('Studios'), 'Studios');
    assert.equal(configurationLabel('  '), 'homes');
  });
});

describe('price history', () => {
  it('is empty when nothing changed', () => {
    assert.deepEqual(describePriceIntelligence(intel(), money, NOW).history, []);
  });

  it('orders newest first regardless of what the server sent', () => {
    const changes = [
      { from: 100, to: 90, deltaPct: -10, at: '2026-01-01T00:00:00.000Z' },
      { from: 90, to: 80, deltaPct: -11, at: '2026-06-01T00:00:00.000Z' },
      { from: 80, to: 85, deltaPct: 6, at: '2026-03-01T00:00:00.000Z' },
    ];

    const lines = describePriceIntelligence(intel({ changes }), money, NOW);

    assert.deepEqual(
      lines.history.map((row) => row.from),
      ['RS90', 'RS80', 'RS100']
    );
    assert.deepEqual(
      lines.history.map((row) => row.isDrop),
      [true, false, true]
    );
  });

  it('drops rows that carry no usable prices', () => {
    const changes = [
      { from: 100, to: 90, deltaPct: -10, at: '2026-01-01T00:00:00.000Z' },
      { from: null, to: 90, deltaPct: -10, at: '2026-02-01T00:00:00.000Z' },
    ] as unknown as PriceIntelligence['changes'];

    assert.equal(describePriceIntelligence(intel({ changes }), money, NOW).history.length, 1);
  });

  it('survives an unparseable date without printing one', () => {
    const changes = [{ from: 100, to: 90, deltaPct: -10, at: 'garbage' }];
    const lines = describePriceIntelligence(intel({ changes }), money, NOW);

    assert.equal(lines.history.length, 1);
    assert.equal(lines.history[0]?.when, '');
    assert.equal(lines.history[0]?.isDrop, true);
  });

  it('tolerates a non-array from an older or wrong-shaped response', () => {
    const lines = describePriceIntelligence(
      intel({ changes: null as unknown as PriceIntelligence['changes'] }),
      money,
      NOW
    );

    assert.deepEqual(lines.history, []);
    assert.equal(lines.isEmpty, true);
  });
});
