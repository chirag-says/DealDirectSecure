import { PREF_KEYS, prefsStorage } from '@/storage';

/**
 * Recent searches.
 *
 * Stored in MMKV, shown with no network call at all. This is the cheapest way
 * to keep the search screen useful while staying inside a 20-per-minute limiter
 * that is shared across everyone behind the same carrier NAT: the most common
 * search a user makes is one they have made before.
 *
 * Device preference, not account data, so it survives logout — the same reason
 * `clearUserScopedStorage` leaves `prefsStorage` alone.
 */

const MAX_RECENT = 8;
const MAX_TERM_LENGTH = 80;

export function readRecentSearches(): string[] {
  const raw = prefsStorage.getString(PREF_KEYS.recentSearches);
  if (!raw) return [];

  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is string => typeof item === 'string').slice(0, MAX_RECENT);
  } catch {
    // A corrupt entry is not worth surfacing. Drop it and carry on empty.
    // MMKV v4 renamed `delete` to `remove`.
    prefsStorage.remove(PREF_KEYS.recentSearches);
    return [];
  }
}

/** Most recent first, case-insensitively deduped, capped. */
export function addRecentSearch(term: string): string[] {
  const trimmed = term.trim().slice(0, MAX_TERM_LENGTH);
  if (trimmed.length < 2) return readRecentSearches();

  const existing = readRecentSearches().filter(
    (item) => item.toLowerCase() !== trimmed.toLowerCase()
  );
  const next = [trimmed, ...existing].slice(0, MAX_RECENT);

  prefsStorage.set(PREF_KEYS.recentSearches, JSON.stringify(next));
  return next;
}

export function removeRecentSearch(term: string): string[] {
  const next = readRecentSearches().filter((item) => item !== term);
  prefsStorage.set(PREF_KEYS.recentSearches, JSON.stringify(next));
  return next;
}

export function clearRecentSearches(): void {
  prefsStorage.remove(PREF_KEYS.recentSearches);
}
