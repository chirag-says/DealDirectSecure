import type { EntityMatch } from './types.ts';

/**
 * Stage — bedroom count.
 *
 * Returns the matched character spans as well as the value, because `price.ts`
 * needs them: the `3` in "3 bhk" must never be read as three rupees.
 *
 * `0` is a real answer meaning 1 RK, not "unset". Callers must check for
 * `undefined`, never falsiness — `if (bhk)` silently drops every studio.
 */

const WORD_NUMBERS: Record<string, number> = {
  one: 1,
  two: 2,
  three: 3,
  four: 4,
  five: 5,
  six: 6,
  single: 1,
  double: 2,
};

export interface BhkResult {
  bhk?: number;
  spans: [number, number][];
  matches: EntityMatch[];
}

/**
 * 1 RK is checked FIRST and separately.
 *
 * "1 rk" contains a 1, and a bedroom pattern would read it as a 1 BHK — which
 * is a different product: an RK has no separate bedroom. The app's own
 * `bhkCount` in `filters.ts` documents the same ordering rule for the same
 * reason.
 */
const RK = /\b(\d)?\s*rk\b/;

/** `3 bhk`, `3 bedroom`, `3 bedrooms`, `3 bed`, `3 br`. */
const DIGIT_BHK = /\b(\d)\s*(bhk|bedrooms?|beds?|br)\b/;

/** `three bhk`, `two bedroom`. */
const WORD_BHK = new RegExp(
  String.raw`\b(${Object.keys(WORD_NUMBERS).join('|')})\s*(bhk|bedrooms?|beds?)\b`
);

/** A bare `bhk` with no number carries no count, but does mean "residential". */
const BARE_BHK = /\bbhk\b/;

export function extractBhk(text: string): BhkResult {
  const rk = RK.exec(text);
  if (rk) {
    return {
      bhk: 0,
      spans: [[rk.index, rk.index + rk[0].length]],
      matches: [{ kind: 'bhk', text: rk[0].trim(), label: '1 RK' }],
    };
  }

  const digit = DIGIT_BHK.exec(text);
  if (digit && digit[1]) {
    const value = Number.parseInt(digit[1], 10);
    return {
      bhk: value,
      spans: [[digit.index, digit.index + digit[0].length]],
      matches: [{ kind: 'bhk', text: digit[0].trim(), label: `${value} BHK` }],
    };
  }

  const word = WORD_BHK.exec(text);
  if (word && word[1]) {
    const value = WORD_NUMBERS[word[1]];
    if (value !== undefined) {
      return {
        bhk: value,
        spans: [[word.index, word.index + word[0].length]],
        matches: [{ kind: 'bhk', text: word[0].trim(), label: `${value} BHK` }],
      };
    }
  }

  const bare = BARE_BHK.exec(text);
  if (bare) {
    // No count to constrain on, but the word still tells us it is a home.
    // `category` is set by the property-type stage; this only claims the span.
    return { spans: [[bare.index, bare.index + bare[0].length]], matches: [] };
  }

  return { spans: [], matches: [] };
}
