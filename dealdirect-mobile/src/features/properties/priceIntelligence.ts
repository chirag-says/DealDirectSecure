/**
 * The price story of one listing, turned into the lines a screen renders.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A PURE FUNCTION WITH THE FORMATTER INJECTED
 *
 * Every field on `priceIntelligence` can be null, several of them mean the
 * opposite of what they look like, and one of them (`market.deltaPct`) is a
 * signed comparison whose sign decides whether the sentence says "below" or
 * "above". Getting that backwards prints a confident lie on the conversion
 * screen. So the interpretation lives in one tested place rather than in JSX.
 *
 * `formatPrice` is passed in rather than imported because it lives in `@/ui`,
 * which imports React Native, and this module has to run under `node --test`.
 * The screen passes the real one, so there is no second money formatter.
 *
 * ---------------------------------------------------------------------------
 * THE DEAD BAND
 *
 * A listing that asks 0.4% under the median is not "below the median" in any
 * sense a buyer can act on — it is the same price, and saying otherwise trains
 * people to distrust the line. Anything inside the band reads as in line.
 * Three percent is chosen to be wider than rounding and narrower than a
 * negotiating position.
 *
 * ---------------------------------------------------------------------------
 * NOTHING IS RENDERED FROM A ZERO
 *
 * `daysListed: 0` is "listed today", not "listed 0 days ago". A `lastDrop`
 * whose `to` is not lower than its `from` is not a drop and produces no line
 * at all, whatever the server called it. An absent field produces null, and
 * the caller renders nothing rather than a placeholder.
 */

import type { PriceIntelligence } from '@/types/backend/property';

/** Percentage points either side of the median that still read as "in line". */
export const MARKET_DEAD_BAND_PCT = 3;

export type MarketVerdict = 'below' | 'above' | 'in-line';

export interface MarketLine {
  text: string;
  verdict: MarketVerdict;
  /** The locality page this line opens. */
  slug: string;
  /** How many listings the median is drawn from, for the caller to disclose. */
  count: number;
}

export interface PriceHistoryRow {
  from: string;
  to: string;
  when: string;
  /** True when the price went down. Used for the arrow, not for the wording. */
  isDrop: boolean;
}

export interface PriceIntelligenceLines {
  /** "Price dropped 2 Lakh on 3 Sep". Null unless there was a real drop. */
  lastDrop: string | null;
  /** "Listed 40 days ago". Null when the server did not say. */
  daysListed: string | null;
  market: MarketLine | null;
  /** Newest first. Empty when the listing has never changed price. */
  history: PriceHistoryRow[];
  /** Nothing to render at all. Lets the caller unmount the whole section. */
  isEmpty: boolean;
}

export type PriceFormatter = (rupees: number) => string;

const EMPTY: PriceIntelligenceLines = {
  lastDrop: null,
  daysListed: null,
  market: null,
  history: [],
  isEmpty: true,
};

export function describePriceIntelligence(
  intel: PriceIntelligence | null | undefined,
  formatPrice: PriceFormatter,
  now: Date = new Date()
): PriceIntelligenceLines {
  if (!intel) return EMPTY;

  const lastDrop = describeLastDrop(intel, formatPrice, now);
  const daysListed = describeDaysListed(intel.daysListed);
  const market = describeMarket(intel);
  const history = describeHistory(intel.changes, formatPrice, now);

  return {
    lastDrop,
    daysListed,
    market,
    history,
    isEmpty: !lastDrop && !daysListed && !market && history.length === 0,
  };
}

function describeLastDrop(
  intel: PriceIntelligence,
  formatPrice: PriceFormatter,
  now: Date
): string | null {
  const drop = intel.lastDrop;
  if (!drop) return null;

  const amount = drop.from - drop.to;
  // Not a drop, whatever the field is called. A rise belongs in the history
  // list, where the direction is shown rather than asserted.
  if (!(amount > 0)) return null;

  const when = formatDay(drop.at, now);
  const money = formatPrice(amount);

  return when ? `Price dropped ${money} on ${when}` : `Price dropped ${money}`;
}

function describeDaysListed(days: number | null | undefined): string | null {
  if (typeof days !== 'number' || !Number.isFinite(days) || days < 0) return null;
  if (days === 0) return 'Listed today';
  if (days === 1) return 'Listed yesterday';
  return `Listed ${days} days ago`;
}

/**
 * "Asks 8% below the Wakad median for 2 BHKs".
 *
 * The scope is named honestly: `configuration` compares like for like and says
 * so, `locality` compares against everything in the area and must not pretend
 * otherwise, because a 1 BHK is cheap against a locality median for reasons
 * that have nothing to do with it being a bargain.
 */
function describeMarket(intel: PriceIntelligence): MarketLine | null {
  const market = intel.market;
  if (!market) return null;

  const delta = market.deltaPct;
  if (typeof delta !== 'number' || !Number.isFinite(delta)) return null;
  if (!market.slug || !market.locality) return null;

  const scope =
    market.scope === 'configuration' && market.bhk
      ? `the ${market.locality} median for ${configurationLabel(market.bhk)}`
      : `the ${market.locality} median`;

  if (Math.abs(delta) < MARKET_DEAD_BAND_PCT) {
    return { text: `In line with ${scope}`, verdict: 'in-line', slug: market.slug, count: market.count };
  }

  const magnitude = Math.round(Math.abs(delta));
  const direction = delta < 0 ? 'below' : 'above';

  return {
    text: `Asks ${magnitude}% ${direction} ${scope}`,
    verdict: direction,
    slug: market.slug,
    count: market.count,
  };
}

/** "2 BHK" and "2" both become "2 BHKs"; "Studio" becomes "Studios". */
export function configurationLabel(bhk: string): string {
  const trimmed = bhk.trim();
  if (!trimmed) return 'homes';
  if (/^\d+(\.\d+)?$/.test(trimmed)) return `${trimmed} BHKs`;
  if (/s$/i.test(trimmed)) return trimmed;
  return `${trimmed}s`;
}

function describeHistory(
  changes: PriceIntelligence['changes'],
  formatPrice: PriceFormatter,
  now: Date
): PriceHistoryRow[] {
  if (!Array.isArray(changes)) return [];

  return (
    changes
      .filter((change) => typeof change?.from === 'number' && typeof change?.to === 'number')
      // Newest first, sorted rather than reversed: a price history is read
      // backwards, and the contract does not promise an order, so assuming one
      // and flipping it would be right half the time. An unparseable date
      // sorts last instead of poisoning the comparison with NaN.
      .slice()
      .sort((a, b) => timeOf(b.at) - timeOf(a.at))
      .map((change) => ({
        from: formatPrice(change.from),
        to: formatPrice(change.to),
        when: formatDay(change.at, now) ?? '',
        isDrop: change.to < change.from,
      }))
  );
}

function timeOf(value: string | null | undefined): number {
  if (!value) return -Infinity;
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? -Infinity : time;
}

/**
 * Month names, written out rather than taken from `toLocaleDateString`.
 *
 * `Intl` with `month: 'short'` is not stable across the places this runs: Node
 * gives "Sept" for September under `en-IN`, and Hermes on an Android build
 * without full ICU gives something else again. A three-letter month is not
 * worth a per-platform surprise on the conversion screen, and it is not worth
 * a test that passes on a laptop and fails on a phone.
 */
const MONTHS = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'May',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec',
] as const;

/**
 * "3 Sep", or "3 Sep 2025" when it was not this year.
 *
 * Returns null for an unparseable date rather than "Invalid Date", which is
 * the string this kind of code prints on a production screen when nobody
 * checks.
 */
function formatDay(value: string | null | undefined, now: Date): string | null {
  if (!value) return null;

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;

  const day = `${date.getDate()} ${MONTHS[date.getMonth()]}`;
  return date.getFullYear() === now.getFullYear() ? day : `${day} ${date.getFullYear()}`;
}
