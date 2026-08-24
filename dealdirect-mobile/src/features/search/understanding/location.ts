import type { EntityMatch, ParseContext } from './types.ts';
import { wordBoundaryTest } from './propertyType.ts';

/**
 * Stage — where.
 *
 * ---------------------------------------------------------------------------
 * A LOCATION IS ONLY STRUCTURED IF WE CAN PROVE IT
 *
 * The rule that keeps this honest: a locality becomes a FILTER only when it
 * matches something the corpus actually contains. Anything else stays in the
 * residual and reaches the server's regex, which is the one component able to
 * say truthfully whether it matches.
 *
 * The failure this avoids is specific and bad. Turning an unrecognised word
 * into `locality = "whitefield"` produces a client-side filter that excludes
 * every listing, on a screen with no visible control explaining why — the user
 * sees an empty result for inventory that may well exist under a spelling we
 * did not anticipate. Leaving it unstructured degrades to today's behaviour,
 * which is a worse search but never a lying one.
 *
 * ---------------------------------------------------------------------------
 * CITIES ARE DIFFERENT FROM LOCALITIES
 *
 * Cities come from the app's own table with hand-maintained aliases, because
 * `address.city` holds both "Bangalore" and "Bengaluru" in production and an
 * exact match under-returns. Localities have no such table and no aliases —
 * they are whatever owners typed — so they are matched against the live set
 * and normalised only for case and spacing.
 */

export interface LocationResult {
  city?: string;
  locality?: string;
  matches: EntityMatch[];
  consumed: string[];
}

export function extractLocation(text: string, context: ParseContext): LocationResult {
  const matches: EntityMatch[] = [];
  const consumed: string[] = [];
  let city: string | undefined;
  let locality: string | undefined;

  /*
    Localities first, and longest-first within that.

    "Navi Mumbai" is a locality in this corpus AND contains the city alias
    "mumbai". Resolving the city first would consume the word and leave
    "navi", which matches nothing. Claiming the longest locality first keeps
    the more specific reading.
  */
  const localities = [...context.localities]
    .filter((value) => value.length >= 3)
    .sort((a, b) => b.length - a.length);

  for (const candidate of localities) {
    if (wordBoundaryTest(text, candidate)) {
      locality = candidate;
      matches.push({ kind: 'locality', text: candidate, label: titleCase(candidate) });
      consumed.push(candidate);
      break;
    }
  }

  const cityAliases = context.cities
    .flatMap((entry) => entry.aliases.map((alias) => ({ alias, entry })))
    .sort((a, b) => b.alias.length - a.alias.length);

  for (const { alias, entry } of cityAliases) {
    if (wordBoundaryTest(text, alias)) {
      // Skip an alias that sits inside the locality we already claimed, so
      // "Navi Mumbai" does not also assert the Mumbai city filter from the same
      // words. A city stated separately still resolves.
      if (locality && wordBoundaryTest(locality, alias)) continue;
      city = entry.id;
      matches.push({ kind: 'city', text: alias, label: entry.label });
      consumed.push(alias);
      break;
    }
  }

  return { city, locality, matches, consumed };
}

/**
 * Normalises a locality for comparison.
 *
 * Owners type "HSR Layout", "hsr layout" and "Hsr  Layout". Case and internal
 * spacing are the only variations that can be collapsed safely; anything more
 * aggressive (stripping spaces so "white field" matches "whitefield") is a
 * guess about a place name, and a wrong guess here filters the screen empty.
 */
export function normalizeLocality(value: string): string {
  return String(value ?? '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

function titleCase(value: string): string {
  return value.replace(/\b\p{L}/gu, (c) => c.toUpperCase());
}
