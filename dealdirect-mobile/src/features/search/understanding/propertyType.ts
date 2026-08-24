import type { CanonicalPropertyType, EntityMatch, PropertyCategory } from './types.ts';

/**
 * Stage — what KIND of property.
 *
 * ---------------------------------------------------------------------------
 * THE COMPOUND-WORD TRAP
 *
 * "warehouse" contains "house". "penthouse" contains "house". "houseboat"
 * starts with it. An unanchored `/house/` therefore classifies a godown as a
 * home, and it does so silently — the benchmark that first measured this
 * reported a 94% score built partly on warehouses being counted as houses.
 *
 * Two defences, and the second is the one that actually holds:
 *
 *  1. Every pattern is `\b`-anchored. `\bhouse\b` does not match "warehouse",
 *     because there is no word boundary between "ware" and "house".
 *  2. Matching is LONGEST-ALIAS-FIRST across the whole vocabulary, not
 *     first-rule-wins. Ordering rules by hand is what breaks the day somebody
 *     inserts a rule above `house` without thinking about it; sorting by
 *     length makes the correct behaviour a property of the data.
 *
 * Both are asserted in `understanding.test.ts` and `cases.test.ts`, including
 * "warehouse", "penthouse" and "houseboat". Do not collapse this into one
 * regex.
 *
 * ---------------------------------------------------------------------------
 * THE CANONICAL SET COMES FROM THE LIVE TAXONOMY
 *
 * Read from `propertyTypeName` across the production corpus on 2026-08-24:
 *
 *   Showroom · Apartment / Flat · Warehouse / Godown · Villa · Office Space
 *   Independent House · Penthouse · Restaurant / Cafe · Shop / Retail
 *
 * `plot` is included because the listing form offers it even though no live
 * listing uses it yet. Nothing else is invented: a type the taxonomy does not
 * have would produce a filter that always returns nothing.
 */

interface TypeEntry {
  canonical: CanonicalPropertyType;
  category: PropertyCategory;
  label: string;
  aliases: readonly string[];
}

export const PROPERTY_TYPES: readonly TypeEntry[] = [
  {
    canonical: 'apartment',
    category: 'residential',
    label: 'Apartment',
    aliases: ['apartment', 'apartments', 'flat', 'flats', 'apartment / flat'],
  },
  {
    canonical: 'house',
    category: 'residential',
    label: 'House',
    aliases: ['house', 'houses', 'independent house', 'bungalow', 'bungalows', 'row house', 'kothi'],
  },
  { canonical: 'villa', category: 'residential', label: 'Villa', aliases: ['villa', 'villas'] },
  {
    canonical: 'penthouse',
    category: 'residential',
    label: 'Penthouse',
    aliases: ['penthouse', 'penthouses'],
  },
  {
    canonical: 'plot',
    category: 'residential',
    label: 'Plot',
    aliases: ['plot', 'plots', 'land', 'site'],
  },
  {
    canonical: 'office',
    category: 'commercial',
    label: 'Office space',
    aliases: ['office', 'offices', 'office space', 'workspace', 'coworking'],
  },
  {
    canonical: 'shop',
    category: 'commercial',
    label: 'Shop',
    aliases: ['shop', 'shops', 'retail', 'retail space', 'store'],
  },
  {
    canonical: 'showroom',
    category: 'commercial',
    label: 'Showroom',
    aliases: ['showroom', 'showrooms'],
  },
  {
    canonical: 'warehouse',
    category: 'commercial',
    label: 'Warehouse',
    aliases: ['warehouse', 'warehouses', 'godown', 'godowns', 'storage unit'],
  },
  {
    canonical: 'restaurant',
    category: 'commercial',
    label: 'Restaurant',
    aliases: ['restaurant', 'restaurants', 'cafe', 'cafes', 'cloud kitchen'],
  },
];

/**
 * Every alias, longest first. Built once.
 *
 * Longest-first is what makes "independent house" beat "house" and, combined
 * with word boundaries, what makes the vocabulary safe to extend without
 * re-reasoning about order.
 */
const ALIAS_INDEX: readonly { alias: string; entry: TypeEntry }[] = PROPERTY_TYPES.flatMap((entry) =>
  entry.aliases.map((alias) => ({ alias, entry }))
).sort((a, b) => b.alias.length - a.alias.length);

/**
 * Words that say "somewhere a person lives" without naming a built form.
 *
 * "home" is the important one: it is the single most common word users type
 * and NO live listing title contains it, which is why `"home"` returns zero
 * results against the current search today.
 */
const RESIDENTIAL_HINTS = [
  'home',
  'homes',
  'residential',
  'residence',
  'family',
  'living',
  'bhk',
  'rk',
  'studio',
  // "a place to live", "somewhere to stay" — people describe the NEED rather
  // than the built form far more often than a taxonomy expects. Without these,
  // "i need a place to live with my parents" produced no constraint at all and
  // returned commercial units to somebody looking for a home.
  'live',
  'stay',
  'reside',
  'shifting',
  'accommodation',
];

const COMMERCIAL_HINTS = ['commercial', 'business', 'industrial', 'warehousing'];

export interface PropertyTypeResult {
  propertyType?: CanonicalPropertyType;
  category?: PropertyCategory;
  matches: EntityMatch[];
  /** Spans consumed, so the caller can strip them from the residual. */
  consumed: string[];
}

/**
 * Phrases that turn the following noun into a DESTINATION, not the subject.
 *
 * "affordable home close to office" is a request for a HOME. The word "office"
 * describes where the buyer commutes, and reading it as the property type
 * inverts the query into a commercial search — the same class of inversion as
 * "rental income" meaning buy. Found by the benchmark, which had this query
 * returning commercial inventory to someone asking for somewhere to live.
 *
 * The noun still matters, so it is left for `softIntent.ts` to pick up as a
 * proximity signal; it simply stops being a hard filter.
 */
const PROXIMITY_PREFIX =
  /\b(?:near|nearby|close\s+to|next\s+to|beside|besides|around|adjacent\s+to|walking\s+distance\s+(?:to|from)|opposite|facing)\s+(?:the\s+|a\s+|an\s+)?$/;

export function extractPropertyType(text: string): PropertyTypeResult {
  for (const { alias, entry } of ALIAS_INDEX) {
    const at = indexOfWord(text, alias);
    if (at < 0) continue;

    // A type word introduced by "near"/"close to" names somewhere the user
    // wants to BE, not what they want to buy. See PROXIMITY_PREFIX.
    if (PROXIMITY_PREFIX.test(text.slice(0, at))) continue;

    return {
      propertyType: entry.canonical,
      category: entry.category,
      matches: [{ kind: 'propertyType', text: alias, label: entry.label }],
      consumed: [alias],
    };
  }

  // No built form named. Fall back to a category if the query implies one.
  const residential = RESIDENTIAL_HINTS.find((hint) => wordBoundaryTest(text, hint));
  const commercial = COMMERCIAL_HINTS.find((hint) => wordBoundaryTest(text, hint));

  /*
    Both present is genuinely ambiguous — "office space for my family business"
    — so neither is claimed. A category guessed wrong here removes the entire
    correct half of the corpus, which is worse than not filtering at all.
  */
  if (residential && commercial) return { matches: [], consumed: [] };

  /*
    The hint word is CONSUMED, and that is not a detail.

    "home" becomes `category: residential`. If the word also stayed in the
    residual it would be sent to the server's regex as well, and no listing
    title contains "home" — every title says "Apartment / Flat" or
    "Independent House". The query would then be filtered twice: correctly by
    category, and fatally by text, returning nothing for the 22 residential
    listings that match.

    Caught by the benchmark, where "home", "good family home", "affordable
    home" and five others were still returning empty after the parser was
    supposedly handling them.
  */
  if (residential) {
    return {
      category: 'residential',
      matches: [{ kind: 'category', text: residential, label: 'Residential' }],
      consumed: [residential],
    };
  }
  if (commercial) {
    return {
      category: 'commercial',
      matches: [{ kind: 'category', text: commercial, label: 'Commercial' }],
      consumed: [commercial],
    };
  }

  return { matches: [], consumed: [] };
}

/**
 * Whole-word containment.
 *
 * `\b` is not used directly because an alias can contain a space
 * ("independent house"), and the boundary has to apply to the phrase as a
 * whole. Unicode-aware so a Devanagari locality adjacent to an alias does not
 * count as a boundary.
 */
export function wordBoundaryTest(haystack: string, needle: string): boolean {
  return indexOfWord(haystack, needle) >= 0;
}

/**
 * Where a whole-word match starts, or -1.
 *
 * Shared with `wordBoundaryTest` so the two can never disagree about what
 * counts as a match — the proximity check reads this index to decide whether a
 * type word is the subject or a landmark, and an off-by-one there would be
 * invisible.
 */
export function indexOfWord(haystack: string, needle: string): number {
  const pattern = new RegExp(
    `(?<![\\p{L}\\p{N}])${needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\p{L}\\p{N}])`,
    'u'
  );
  const match = pattern.exec(haystack);
  return match ? match.index : -1;
}
