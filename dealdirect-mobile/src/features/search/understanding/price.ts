import type { EntityMatch, Rupees } from './types.ts';

/**
 * Stage — money.
 *
 * ---------------------------------------------------------------------------
 * INTEGER RUPEES, ALWAYS
 *
 * `0.8 cr` is 8,000,000 and must not be 7,999,999.99999999. Every conversion
 * multiplies by an integer scale and rounds once, at the end, so no
 * intermediate float survives into a comparison. The backend stores `price` as
 * rupees (verified against production; `priceUnit` is a mislabelled schema
 * default and is never a multiplier — see `features/search/filters.ts`), so
 * these values are directly comparable with it.
 *
 * ---------------------------------------------------------------------------
 * A BARE NUMBER IS USUALLY NOT MONEY
 *
 * "3 bhk" contains a 3. "2 bhk under 1 cr" contains a 2 and a 1. Treating any
 * digit as an amount is the single easiest way to produce a filter the user
 * never asked for, so a number with no unit only counts as money when it is
 * large enough that it cannot be anything else, and never when it is adjacent
 * to a BHK marker.
 */

export const LAKH = 100_000;
export const CRORE = 10_000_000;
export const THOUSAND = 1_000;

/**
 * Below this, a unitless number is not treated as a price.
 *
 * Rentals start around ₹5,000 a month in this corpus, so the floor sits just
 * under that. Anything smaller in a property query is a BHK, a floor number, a
 * bathroom count or a year.
 */
const BARE_NUMBER_FLOOR = 4_000;

interface Amount {
  value: Rupees;
  text: string;
  index: number;
}

const UNIT_SCALE: Record<string, number> = {
  cr: CRORE,
  crore: CRORE,
  crores: CRORE,
  cror: CRORE,
  l: LAKH,
  lac: LAKH,
  lacs: LAKH,
  lakh: LAKH,
  lakhs: LAKH,
  lak: LAKH,
  k: THOUSAND,
  thousand: THOUSAND,
};

/**
 * Matches `<number> <optional unit>`.
 *
 * The unit is optional so bare numbers are seen and can be rejected on the
 * floor rule rather than silently missed.
 */
const AMOUNT = new RegExp(
  String.raw`(\d+(?:\.\d+)?)\s*(${Object.keys(UNIT_SCALE).join('|')})?\b`,
  'g'
);

/** Phrases that make an amount a ceiling. */
const UPPER_BOUND =
  /\b(?:under|below|less\s+than|lesser\s+than|upto|up\s+to|within|max|maximum|budget|cheaper\s+than|not\s+more\s+than|at\s+most)\b/;

/** Phrases that make an amount a floor. */
const LOWER_BOUND =
  /\b(?:above|over|more\s+than|greater\s+than|minimum|min|starting\s+(?:at|from)|from|at\s+least|plus)\b/;

/** Phrases that make two amounts a range. */
const RANGE = /\b(?:between|range|from)\b|\bto\b|\band\b|-/;

export interface PriceResult {
  minPrice?: Rupees;
  maxPrice?: Rupees;
  matches: EntityMatch[];
}

/**
 * `bhkSpans` are character ranges already claimed by the BHK extractor. A
 * number inside one of them is a bedroom count and is never money, which is
 * what stops "3 bhk" contributing a ₹3 floor.
 */
export function extractPrice(text: string, bhkSpans: readonly [number, number][] = []): PriceResult {
  const amounts: Amount[] = [];

  AMOUNT.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = AMOUNT.exec(text)) !== null) {
    const raw = m[1];
    const unit = m[2];
    if (!raw) continue;

    const start = m.index;
    const end = start + m[0].length;
    if (bhkSpans.some(([s, e]) => start >= s && end <= e)) continue;

    const n = Number.parseFloat(raw);
    if (!Number.isFinite(n)) continue;

    if (unit) {
      const scale = UNIT_SCALE[unit];
      if (scale === undefined) continue;
      // One rounding, at the end. 0.8 * 10_000_000 is exact here, but 1.15 cr
      // is not, and rounding once is what keeps it an integer rupee value.
      amounts.push({ value: Math.round(n * scale), text: m[0].trim(), index: start });
      continue;
    }

    // Unitless. Only money if it could not plausibly be anything else, and
    // never if a BHK-ish word follows it.
    const following = text.slice(end, end + 12);
    if (/^\s*(?:bhk|rk|bed|bedroom|bathroom|bath|floor|bathrooms)\b/.test(following)) continue;
    if (n >= BARE_NUMBER_FLOOR) {
      amounts.push({ value: Math.round(n), text: m[0].trim(), index: start });
    }
  }

  if (amounts.length === 0) return { matches: [] };

  const hasUpper = UPPER_BOUND.test(text);
  const hasLower = LOWER_BOUND.test(text);
  const looksRanged = amounts.length >= 2 && RANGE.test(text);

  const asMatch = (a: Amount, label: string): EntityMatch => ({
    kind: 'price',
    text: a.text,
    label,
  });

  if (looksRanged && !hasUpper && !hasLower) {
    const sorted = [...amounts].sort((x, y) => x.value - y.value);
    const lo = sorted[0]!;
    const hi = sorted[sorted.length - 1]!;
    return {
      minPrice: lo.value,
      maxPrice: hi.value,
      matches: [asMatch(lo, `from ${formatRupees(lo.value)}`), asMatch(hi, `to ${formatRupees(hi.value)}`)],
    };
  }

  // "between 80 lakh and 1 crore" says both words; the range reading wins over
  // either single bound.
  if (amounts.length >= 2 && /\bbetween\b/.test(text)) {
    const sorted = [...amounts].sort((x, y) => x.value - y.value);
    const lo = sorted[0]!;
    const hi = sorted[sorted.length - 1]!;
    return {
      minPrice: lo.value,
      maxPrice: hi.value,
      matches: [asMatch(lo, `from ${formatRupees(lo.value)}`), asMatch(hi, `to ${formatRupees(hi.value)}`)],
    };
  }

  const first = amounts[0]!;

  if (hasLower && !hasUpper) {
    return { minPrice: first.value, matches: [asMatch(first, `above ${formatRupees(first.value)}`)] };
  }

  /*
    The default reading of a bare budget is a CEILING.

    "3 bhk 1 crore" is how people say "about a crore, not more" — nobody types a
    number meaning "at least this much" without saying so. Reading it as a floor
    would return the most expensive inventory to someone stating their limit,
    which is the worst possible failure for this field.
  */
  return { maxPrice: first.value, matches: [asMatch(first, `under ${formatRupees(first.value)}`)] };
}

/** Indian-format money, for the "searching for…" summary. */
export function formatRupees(value: Rupees): string {
  if (value >= CRORE) {
    const cr = value / CRORE;
    return `₹${trimZeros(cr)} Cr`;
  }
  if (value >= LAKH) {
    const l = value / LAKH;
    return `₹${trimZeros(l)} L`;
  }
  return `₹${value.toLocaleString('en-IN')}`;
}

function trimZeros(n: number): string {
  return n.toFixed(2).replace(/\.?0+$/, '');
}
