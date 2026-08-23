import { useSyncExternalStore } from 'react';

import { PREF_KEYS, prefsStorage } from '@/storage';
import { DEFAULT_FILTERS, hasAnyCriteria, type SearchFilters } from './filters';

/**
 * The last search that had criteria, kept so the tab can offer it back.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NOT `recentSearches`
 *
 * `recent.ts` stores TERMS — the strings someone typed, shown as a history
 * list while the field has focus. This stores a SEARCH: the whole filter set,
 * including the four client-only facets that never appear in the query string,
 * plus how many results it produced.
 *
 * The difference matters on the second session. Someone who spent Tuesday
 * narrowing to 2 BHK rentals in Pune under a price band has built something,
 * and a history row reading "Pune" throws away everything except the word.
 * Restoring the filter set is the difference between resuming and starting
 * again, and it is the one piece of continuity a property app most obviously
 * owes a user, because the search runs over weeks.
 *
 * ---------------------------------------------------------------------------
 * ONE SLOT, NOT A LIST
 *
 * A list of saved filter sets already exists and is a server feature: saved
 * searches, with alerts, on Activity. This is the unsaved one — the search you
 * were in the middle of and did not think to save. Keeping more than the last
 * one would quietly become a second, worse saved-searches list with no alerts
 * and no sync, competing with the real one.
 *
 * ---------------------------------------------------------------------------
 * COSTS NOTHING TO SHOW
 *
 * Read from disk, synchronously, like `recentlyViewed`. The card it feeds
 * paints on a cold start with no request, which is what lets the idle state
 * carry content without spending from the 20-per-minute budget the results
 * feed underneath it is already using.
 *
 * Device preference, not account data, so it lives in `prefsStorage` and
 * survives logout — the same rule recent searches and recently-viewed follow.
 */

export interface ResumableSearch {
  filters: SearchFilters;
  /**
   * Result count at the time it was stored.
   *
   * Displayed as "about N", never as a live figure, because it is a snapshot:
   * inventory moves and the count is not re-verified until the search is
   * actually re-run. Stored at all because "24 homes" is what makes the card
   * worth tapping rather than a filter set the user has to decode.
   */
  resultCount: number;
  /** Epoch ms. Used to age the card out; see `MAX_AGE_MS`. */
  savedAt: number;
}

/**
 * A fortnight.
 *
 * Long enough to cover the gap between weekend property sessions, which is the
 * rhythm this card exists for. Past that the filter set is more likely to be
 * stale than useful — budgets change, someone has already rented the flat —
 * and offering it back reads as the app not having noticed the time passing.
 */
const MAX_AGE_MS = 14 * 24 * 60 * 60 * 1000;

function read(): ResumableSearch | null {
  const raw = prefsStorage.getString(PREF_KEYS.resumeSearch);
  if (!raw) return null;

  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return null;

    const entry = parsed as ResumableSearch;
    if (typeof entry.savedAt !== 'number' || typeof entry.filters !== 'object') return null;
    if (Date.now() - entry.savedAt > MAX_AGE_MS) return null;

    // Merged over the defaults rather than trusted whole: this record can
    // outlive the version of `SearchFilters` that wrote it, and a filter set
    // missing a field added since would otherwise restore as `undefined` and
    // read as a filter the user cannot see or clear.
    return {
      filters: { ...DEFAULT_FILTERS, ...entry.filters },
      resultCount: typeof entry.resultCount === 'number' ? entry.resultCount : 0,
      savedAt: entry.savedAt,
    };
  } catch {
    prefsStorage.remove(PREF_KEYS.resumeSearch);
    return null;
  }
}

/** See the note on the same pattern in `properties/recentlyViewed.ts`. */
const listeners = new Set<() => void>();
let snapshot: ResumableSearch | null | undefined;

function getSnapshot(): ResumableSearch | null {
  if (snapshot === undefined) snapshot = read();
  return snapshot;
}

function emit(next: ResumableSearch | null): void {
  snapshot = next;
  if (next === null) prefsStorage.remove(PREF_KEYS.resumeSearch);
  else prefsStorage.set(PREF_KEYS.resumeSearch, JSON.stringify(next));
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/**
 * Records a search worth resuming.
 *
 * Ignores filter sets with no criteria: "everything, newest first" is what the
 * tab already shows when it opens, so offering to resume it would be a card
 * that does nothing.
 *
 * Written when a result count is known rather than at the moment of the tap,
 * so the card can say how much was there. Repeated calls for the same criteria
 * simply overwrite, which is what makes the single slot track the search as the
 * user narrows it.
 */
export function recordResumableSearch(filters: SearchFilters, resultCount: number): void {
  if (!hasAnyCriteria(filters)) return;

  const current = getSnapshot();
  if (
    current &&
    current.resultCount === resultCount &&
    JSON.stringify(current.filters) === JSON.stringify(filters)
  ) {
    // Nothing changed. Returning early keeps `savedAt` at the moment the search
    // was actually built, so scrolling a list for ten minutes does not keep
    // renewing a fortnight-long clock.
    return;
  }

  emit({ filters, resultCount, savedAt: Date.now() });
}

/** Dismissal. The card offers this so a finished search can be put away. */
export function clearResumableSearch(): void {
  emit(null);
}

export function useResumableSearch(): ResumableSearch | null {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

/**
 * A one-shot read, for the screen that ACTS on the stored search rather than
 * displaying it.
 *
 * Home subscribes (`useResumableSearch`) because its card must appear and
 * disappear as the store changes. Search reads once inside its route effect,
 * because subscribing there would re-run the effect every time the user
 * narrowed their search and stamp the stored filters back over the ones they
 * were editing — the same fight the effect's `appliedRouteKey` guard exists to
 * prevent.
 */
export function readResumableSearch(): ResumableSearch | null {
  return getSnapshot();
}
