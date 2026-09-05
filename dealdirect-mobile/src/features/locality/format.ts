/**
 * Turning locality aggregates into the words and shapes the screen draws.
 *
 * Pure, and free of runtime imports so it runs under `node --test`. The money
 * formatter is passed in for the same reason it is in
 * `features/properties/priceIntelligence.ts`: `formatPrice` lives in `@/ui`,
 * which imports React Native.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS DATA IS, IN ONE SENTENCE
 *
 * Medians of what DealDirect owners ASK, per quarter, per locality, published
 * only where there are enough listings to be worth publishing. Not sale
 * prices, not valuations, not a market index. Every string produced here is
 * built to survive being read next to that disclosure.
 */

export type PriceFormatter = (rupees: number) => string;

/**
 * Quarter-on-quarter moves smaller than this read as flat.
 *
 * Half a percent on a median of a few dozen asking prices is one listing being
 * added or withdrawn. Calling that "up" would make the number look like a
 * market signal when it is sampling noise.
 */
export const QOQ_DEAD_BAND_PCT = 0.5;

export type QoqDirection = 'up' | 'down' | 'flat';

export interface QoqLine {
  text: string;
  direction: QoqDirection;
}

/** `2026-Q3` becomes `Q3 2026`. Anything else comes back unchanged, or null. */
export function formatQuarter(period: string | null | undefined): string | null {
  if (!period) return null;

  const match = /^(\d{4})-?Q([1-4])$/i.exec(period.trim());
  if (!match) return period.trim() || null;

  return `Q${match[2]} ${match[1]}`;
}

/**
 * "up 2.4% on the previous quarter".
 *
 * Null when there is no previous quarter to compare with, which is the common
 * case for a locality that has just cleared the sample floor. Saying "0%"
 * there would assert stability that has not been observed.
 */
export function formatQoq(qoqPct: number | null | undefined): QoqLine | null {
  if (typeof qoqPct !== 'number' || !Number.isFinite(qoqPct)) return null;

  if (Math.abs(qoqPct) < QOQ_DEAD_BAND_PCT) {
    return { text: 'Flat on the previous quarter', direction: 'flat' };
  }

  const direction: QoqDirection = qoqPct > 0 ? 'up' : 'down';
  // One decimal place: two implies a precision a median of forty asking prices
  // does not have, and none loses the difference between 1.4% and 2.4%.
  const magnitude = Math.abs(qoqPct).toFixed(1).replace(/\.0$/, '');

  return { text: `${direction === 'up' ? 'Up' : 'Down'} ${magnitude}% on the previous quarter`, direction };
}

/** Money, or null. A zero or a negative median is missing data, not a price. */
export function formatMedian(
  value: number | null | undefined,
  formatPrice: PriceFormatter
): string | null {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return null;
  return formatPrice(value);
}

/**
 * "Most ask between 28 Lakh and 34 Lakh".
 *
 * Null unless BOTH quartiles are present and ordered. A half-open range would
 * have to be written as "from" or "up to", which says something different and
 * weaker than the sentence this line exists to say.
 */
export function formatRange(
  p25: number | null | undefined,
  p75: number | null | undefined,
  formatPrice: PriceFormatter
): string | null {
  const low = formatMedian(p25, formatPrice);
  const high = formatMedian(p75, formatPrice);
  if (!low || !high) return null;
  if ((p25 as number) > (p75 as number)) return null;

  return `Most ask between ${low} and ${high}`;
}

/** "Median of 24 asking prices in Q3 2026". */
export function formatSampleLine(count: number, period: string | null | undefined): string {
  const quarter = formatQuarter(period);
  const listings = `${count} asking ${count === 1 ? 'price' : 'prices'}`;
  return quarter ? `Median of ${listings} in ${quarter}` : `Median of ${listings}`;
}

export interface TrendBar {
  period: string;
  /** Quarter label for the axis, e.g. `Q3 2026`. */
  label: string;
  /** 0 to 1, relative to the tallest bar in the set. */
  height: number;
  count: number;
  medianAsking: number;
}

/**
 * Bar heights for the trend, computed rather than charted.
 *
 * ---------------------------------------------------------------------------
 * WHY THE BASELINE IS NOT ZERO
 *
 * Four quarterly medians within a few percent of each other, drawn from zero,
 * are four identical bars: the chart says nothing and takes a third of the
 * screen to say it. Drawn from just below the minimum, the same four bars show
 * the shape of the move.
 *
 * That is also exactly how a chart lies, so the floor is a documented fraction
 * of the range rather than the minimum itself (which would always render one
 * bar at zero height and imply a value of nothing), and the screen prints the
 * median beside each bar. The numbers are the truth; the bars are the shape.
 *
 * A single quarter renders one full-height bar, because there is no shape to
 * show and scaling one value against itself is meaningless either way.
 */
export function trendBars(
  points: readonly { period: string; medianAsking: number; count: number }[]
): TrendBar[] {
  const usable = points.filter(
    (point) => typeof point?.medianAsking === 'number' && point.medianAsking > 0
  );

  if (usable.length === 0) return [];

  const values = usable.map((point) => point.medianAsking);
  const max = Math.max(...values);
  const min = Math.min(...values);
  // A tenth of the spread below the smallest value, so the shortest bar is
  // visibly a bar rather than a gap.
  const floor = max === min ? 0 : min - (max - min) * 0.1;

  return usable.map((point) => ({
    period: point.period,
    label: formatQuarter(point.period) ?? point.period,
    height: max === floor ? 1 : (point.medianAsking - floor) / (max - floor),
    count: point.count,
    medianAsking: point.medianAsking,
  }));
}

/** "2 BHK" and "2" both read as "2 BHK"; anything else is left alone. */
export function configurationHeading(bhk: string | null | undefined): string {
  const trimmed = (bhk ?? '').trim();
  if (!trimmed) return 'All homes';
  if (/^\d+(\.\d+)?$/.test(trimmed)) return `${trimmed} BHK`;
  return trimmed;
}
