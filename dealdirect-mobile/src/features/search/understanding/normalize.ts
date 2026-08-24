/**
 * Stage 1 — normalisation.
 *
 * Everything downstream reads the normalised string, so this is the only place
 * that knows about casing, punctuation or spacing. Extractors that had to cope
 * with "2BHK", "2 bhk" and "2-BHK" separately would each grow their own
 * variant handling and they would drift apart.
 */

/**
 * Currency symbols and separators seen in real Indian property queries.
 *
 * The rupee sign appears as ₹ (U+20B9) and occasionally as "Rs." or "INR". All
 * three are dropped: the amount is what matters and `price.ts` reads the unit
 * word, not the symbol.
 */
const CURRENCY = /[₹]|(?:\brs\.?\b)|(?:\binr\b)/g;

/**
 * Digit separators.
 *
 * Indian grouping is 1,25,00,000 rather than 12,500,000, so commas cannot be
 * parsed as thousands markers — they are simply removed and the digits read as
 * one number. This is also why `price.ts` refuses to treat a bare number as
 * money unless it is large enough to be money.
 */
const THOUSAND_SEPARATORS = /(\d),(?=\d)/g;

export function normalizeQuery(input: string): string {
  return (
    String(input ?? '')
      .toLowerCase()
      // Unicode dashes and quotes arrive from phone keyboards and would break
      // word-boundary matching in every extractor below.
      .replace(/[‐-―−]/g, '-')
      .replace(/[‘’‛]/g, "'")
      .replace(/[“”]/g, '"')
      .replace(CURRENCY, ' ')
      .replace(THOUSAND_SEPARATORS, '$1')
      // "2bhk" → "2 bhk", "3-bhk" → "3 bhk". Done here rather than in the BHK
      // extractor because the price extractor also benefits: "1.2cr" → "1.2 cr".
      .replace(/(\d)\s*-\s*(?=[a-z])/g, '$1 ')
      .replace(/(\d)(?=[a-z])/g, '$1 ')
      // Punctuation becomes space, so "flat, 2 bhk." tokenises cleanly. The
      // decimal point is preserved: "1.2 crore" must not become "1 2 crore".
      .replace(/[^\p{L}\p{N}.\s+]/gu, ' ')
      // A dot only survives between digits.
      .replace(/\.(?!\d)/g, ' ')
      .replace(/(?<!\d)\./g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
  );
}

/**
 * Removes a matched span from the residual text.
 *
 * Extractors report the substring they consumed; this deletes the first
 * occurrence so the same words cannot be claimed twice and so what remains is
 * genuinely unclaimed. Whole-word only: removing "rent" from "current" would
 * corrupt the residual, and the residual is what reaches the server's regex.
 */
export function consume(residual: string, matched: string): string {
  const trimmed = matched.trim();
  if (!trimmed) return residual;

  const pattern = new RegExp(
    `(?<![\\p{L}\\p{N}])${escapeRegExp(trimmed)}(?![\\p{L}\\p{N}])`,
    'u'
  );
  return residual.replace(pattern, ' ').replace(/\s+/g, ' ').trim();
}

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Words that carry no search meaning on their own.
 *
 * Stripped from the residual only — never from the text extractors read, since
 * "for rent" and "under 1 crore" depend on these words. A residual of "in for
 * my" would otherwise be sent to the server as a regex and match nothing.
 */
const STOP_WORDS = new Set([
  'a',
  'an',
  'the',
  'in',
  'at',
  'on',
  'for',
  'of',
  'to',
  'with',
  'near',
  'nearby',
  'close',
  'my',
  'me',
  'i',
  'we',
  'our',
  'need',
  'want',
  'looking',
  'look',
  'find',
  'searching',
  'search',
  'show',
  'get',
  'some',
  'any',
  'good',
  'nice',
  'please',
  'and',
  'or',
  'is',
  'are',
  'am',
  'be',
  'place',
  'property',
  'properties',
  'option',
  'options',

  /*
    Generic descriptors.

    These reach the residual after every extractor has had its turn, and the
    residual is AND-ed against listing titles by the server's regex. No title
    contains "starter" or "area", so leaving them in turns a query the corpus
    CAN answer into an empty screen — which is the exact failure this module
    exists to remove. The benchmark caught six of them: "quiet residential
    area", "starter home for a couple", "furnished flat for a small family",
    "i need a place to live with my parents" and two more.

    Every word here is one that cannot be part of a property, locality or
    builder name. Anything that could be — "lake", "park", "garden", "green" —
    stays out of this list on purpose, because dropping it would silently
    weaken a search for a real place.
  */
  'area',
  'areas',
  'small',
  'big',
  'large',
  'spacious',
  'starter',
  'live',
  'stay',
  'move',
  'buy',
  'rent',
  'best',
  'top',
  'great',
  'ideal',
  'ideally',
  'preferably',
  'prefer',
  'something',
  'somewhere',
  'anywhere',
  'available',
  'suitable',
  'requirement',
  'requirements',
]);

export function stripStopWords(residual: string): string {
  return residual
    .split(/\s+/)
    .filter((word) => word.length > 0 && !STOP_WORDS.has(word))
    .join(' ')
    .trim();
}
