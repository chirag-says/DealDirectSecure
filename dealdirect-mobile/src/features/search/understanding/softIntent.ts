import type { ConstructionStage, EntityMatch, SoftSignal } from './types.ts';
import { wordBoundaryTest } from './propertyType.ts';

/**
 * Stage — what the user meant but did not state as a constraint.
 *
 * ---------------------------------------------------------------------------
 * NONE OF THIS FILTERS. THAT IS THE POINT.
 *
 * "family home" must not require a database field called `family`, because
 * there isn't one and never will be. If these became filters, the most natural
 * queries in the language would return empty screens — the precise failure this
 * whole project exists to remove.
 *
 * So soft signals are carried, not applied. Today they do two useful things:
 * they explain the search back to the user, and they keep the words out of the
 * residual so the server's regex is not handed "family" to match against titles
 * that will never contain it. Tomorrow they are where a semantic ranking stage
 * attaches, without any other file changing.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS DELIBERATELY NOT INFERRED
 *
 * "investment" does not set a price band. "luxury" does not set a floor.
 * "affordable" does not set a ceiling. The corpus records no rental yield, no
 * price history and no locality tier, so any number attached to these words
 * would be invented. A signal that carries no data is honest; a signal that
 * carries a fabricated threshold is worse than nothing.
 */

const SIGNAL_VOCABULARY: readonly { signal: SoftSignal; label: string; words: readonly string[] }[] =
  [
    {
      signal: 'family',
      label: 'family-friendly',
      words: ['family', 'families', 'kids', 'children', 'parents', 'couple'],
    },
    {
      signal: 'investment',
      label: 'investment',
      words: ['investment', 'invest', 'rental income', 'rental yield', 'returns', 'appreciation'],
    },
    {
      signal: 'luxury',
      label: 'luxury',
      words: ['luxury', 'luxurious', 'premium', 'posh', 'upscale', 'high end', 'lavish'],
    },
    {
      signal: 'affordable',
      label: 'affordable',
      words: ['affordable', 'cheap', 'budget', 'low cost', 'economical', 'inexpensive'],
    },
    {
      signal: 'metro',
      label: 'near metro',
      words: ['metro', 'metro station', 'station', 'railway'],
    },
    {
      signal: 'workplace',
      label: 'near work',
      words: [
        'it park',
        'itpl',
        'tech park',
        'it companies',
        'it company',
        'it professional',
        'office commute',
        'close to office',
        'near office',
        'workplace',
      ],
    },
    { signal: 'quiet', label: 'quiet', words: ['quiet', 'peaceful', 'calm', 'serene', 'silent'] },
    {
      signal: 'furnished',
      label: 'furnished',
      words: ['furnished', 'fully furnished', 'semi furnished', 'furniture'],
    },
    { signal: 'parking', label: 'parking', words: ['parking', 'car park', 'garage'] },
    { signal: 'schools', label: 'near schools', words: ['school', 'schools', 'college'] },
  ];

export interface SoftResult {
  soft: SoftSignal[];
  matches: EntityMatch[];
  consumed: string[];
}

export function extractSoftSignals(text: string): SoftResult {
  const soft: SoftSignal[] = [];
  const matches: EntityMatch[] = [];
  const consumed: string[] = [];

  for (const { signal, label, words } of SIGNAL_VOCABULARY) {
    // Longest first so "rental income" is consumed whole rather than leaving
    // "income" behind in the residual.
    const sorted = [...words].sort((a, b) => b.length - a.length);
    const hit = sorted.find((word) => wordBoundaryTest(text, word));
    if (!hit) continue;

    soft.push(signal);
    matches.push({ kind: 'soft', text: hit, label });
    consumed.push(hit);
  }

  return { soft, matches, consumed };
}

/**
 * Construction stage — a HARD constraint, unlike everything else in this file.
 *
 * It lives here because it is phrase-shaped like the soft signals, but "ready
 * to move" is a statement of fact about the property and the app already has a
 * filter for it (two buckets over the backend's free text, matching
 * `matchesConstructionStatus` in `filters.ts`).
 */
const CONSTRUCTION_VOCABULARY: readonly {
  stage: ConstructionStage;
  label: string;
  words: readonly string[];
}[] = [
  {
    stage: 'ready',
    label: 'Ready to move',
    words: ['ready to move', 'ready possession', 'ready-to-move', 'move in ready', 'immediate possession', 'ready'],
  },
  {
    stage: 'construction',
    label: 'Under construction',
    words: ['under construction', 'new launch', 'pre launch', 'prelaunch', 'upcoming'],
  },
];

export interface ConstructionResult {
  construction?: ConstructionStage;
  matches: EntityMatch[];
  consumed: string[];
}

export function extractConstruction(text: string): ConstructionResult {
  /*
    Under-construction phrases are checked FIRST.

    "ready" is a substring-free single word, but "not ready" and "ready in
    2026" are not what they appear; more importantly a query saying "under
    construction" must never be caught by a bare "ready" rule added later. The
    specific phrases are also longer, so they win on the same longest-first
    principle the rest of the module uses.
  */
  const ordered = [...CONSTRUCTION_VOCABULARY].reverse();

  for (const { stage, label, words } of ordered) {
    const sorted = [...words].sort((a, b) => b.length - a.length);
    const hit = sorted.find((word) => wordBoundaryTest(text, word));
    if (hit) {
      return {
        construction: stage,
        matches: [{ kind: 'construction', text: hit, label }],
        consumed: [hit],
      };
    }
  }

  return { matches: [], consumed: [] };
}
