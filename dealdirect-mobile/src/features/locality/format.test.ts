import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  QOQ_DEAD_BAND_PCT,
  configurationHeading,
  formatMedian,
  formatQoq,
  formatQuarter,
  formatRange,
  formatSampleLine,
  trendBars,
} from './format.ts';

const money = (rupees: number) => `RS${rupees}`;

describe('formatQuarter', () => {
  it('reads the quarter the server writes', () => {
    assert.equal(formatQuarter('2026-Q3'), 'Q3 2026');
    assert.equal(formatQuarter('2026Q1'), 'Q1 2026');
    assert.equal(formatQuarter('  2025-q4  '), 'Q4 2025');
  });

  it('passes an unrecognised label through rather than blanking the screen', () => {
    assert.equal(formatQuarter('H1 2026'), 'H1 2026');
    assert.equal(formatQuarter('2026-Q5'), '2026-Q5');
  });

  it('is null when there is nothing to read', () => {
    assert.equal(formatQuarter(null), null);
    assert.equal(formatQuarter(undefined), null);
    assert.equal(formatQuarter('   '), null);
  });
});

describe('formatQoq', () => {
  it('says up for a rise and down for a fall', () => {
    assert.deepEqual(formatQoq(2.4), { text: 'Up 2.4% on the previous quarter', direction: 'up' });
    assert.deepEqual(formatQoq(-1.1), {
      text: 'Down 1.1% on the previous quarter',
      direction: 'down',
    });
  });

  it('drops a trailing zero decimal', () => {
    assert.equal(formatQoq(3)?.text, 'Up 3% on the previous quarter');
    assert.equal(formatQoq(-12.0)?.text, 'Down 12% on the previous quarter');
  });

  it('reads a move inside the dead band as flat, either side of zero', () => {
    for (const value of [0, 0.2, -0.2, QOQ_DEAD_BAND_PCT - 0.01, -(QOQ_DEAD_BAND_PCT - 0.01)]) {
      assert.deepEqual(
        formatQoq(value),
        { text: 'Flat on the previous quarter', direction: 'flat' },
        `qoq ${value}`
      );
    }
  });

  it('leaves the dead band exactly at the boundary', () => {
    assert.equal(formatQoq(QOQ_DEAD_BAND_PCT)?.direction, 'up');
    assert.equal(formatQoq(-QOQ_DEAD_BAND_PCT)?.direction, 'down');
  });

  it('says nothing when there is no previous quarter', () => {
    assert.equal(formatQoq(null), null);
    assert.equal(formatQoq(undefined), null);
    assert.equal(formatQoq(Number.NaN), null);
    assert.equal(formatQoq(Infinity), null);
  });
});

describe('formatMedian', () => {
  it('formats a real figure', () => {
    assert.equal(formatMedian(8_000_000, money), 'RS8000000');
  });

  it('treats zero, a negative and a missing value as no data', () => {
    for (const value of [0, -1, null, undefined, Number.NaN]) {
      assert.equal(formatMedian(value as number | null, money), null, `median ${String(value)}`);
    }
  });
});

describe('formatRange', () => {
  it('needs both quartiles', () => {
    assert.equal(formatRange(2_800_000, 3_400_000, money), 'Most ask between RS2800000 and RS3400000');
    assert.equal(formatRange(null, 3_400_000, money), null);
    assert.equal(formatRange(2_800_000, null, money), null);
    assert.equal(formatRange(null, null, money), null);
  });

  it('refuses an inverted range rather than printing it backwards', () => {
    assert.equal(formatRange(3_400_000, 2_800_000, money), null);
  });
});

describe('formatSampleLine', () => {
  it('names the sample and the quarter', () => {
    assert.equal(formatSampleLine(24, '2026-Q3'), 'Median of 24 asking prices in Q3 2026');
  });

  it('is singular at one', () => {
    assert.equal(formatSampleLine(1, '2026-Q3'), 'Median of 1 asking price in Q3 2026');
  });

  it('drops the quarter when there is none to name', () => {
    assert.equal(formatSampleLine(9, null), 'Median of 9 asking prices');
  });
});

describe('trendBars', () => {
  it('is empty when there is nothing to draw', () => {
    assert.deepEqual(trendBars([]), []);
    assert.deepEqual(trendBars([{ period: '2026-Q1', medianAsking: 0, count: 4 }]), []);
  });

  it('draws a single quarter at full height', () => {
    const bars = trendBars([{ period: '2026-Q3', medianAsking: 5_000_000, count: 8 }]);
    assert.equal(bars.length, 1);
    assert.equal(bars[0]?.height, 1);
    assert.equal(bars[0]?.label, 'Q3 2026');
  });

  it('scales the tallest to one and keeps the shortest visible', () => {
    const bars = trendBars([
      { period: '2026-Q1', medianAsking: 100, count: 5 },
      { period: '2026-Q2', medianAsking: 110, count: 6 },
      { period: '2026-Q3', medianAsking: 105, count: 7 },
    ]);

    assert.equal(bars.length, 3);
    assert.equal(bars[1]?.height, 1);
    assert.ok((bars[0]?.height ?? 0) > 0, 'shortest bar is still a bar');
    assert.ok((bars[0]?.height ?? 1) < (bars[2]?.height ?? 0), 'order is preserved');
  });

  it('draws equal medians at equal height rather than dividing by zero', () => {
    const bars = trendBars([
      { period: '2026-Q1', medianAsking: 100, count: 5 },
      { period: '2026-Q2', medianAsking: 100, count: 5 },
    ]);

    assert.deepEqual(
      bars.map((bar) => bar.height),
      [1, 1]
    );
  });

  it('skips quarters with no usable median instead of drawing them at zero', () => {
    const bars = trendBars([
      { period: '2026-Q1', medianAsking: 100, count: 5 },
      { period: '2026-Q2', medianAsking: 0, count: 0 },
      { period: '2026-Q3', medianAsking: 120, count: 9 },
    ]);

    assert.deepEqual(
      bars.map((bar) => bar.period),
      ['2026-Q1', '2026-Q3']
    );
  });
});

describe('configurationHeading', () => {
  it('normalises the shapes the schema holds', () => {
    assert.equal(configurationHeading('2'), '2 BHK');
    assert.equal(configurationHeading('2 BHK'), '2 BHK');
    assert.equal(configurationHeading('Studio'), 'Studio');
    assert.equal(configurationHeading(null), 'All homes');
    assert.equal(configurationHeading('  '), 'All homes');
  });
});
