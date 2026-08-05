import { createMMKV } from 'react-native-mmkv';

/**
 * Fast synchronous key-value storage.
 *
 * NOT encrypted. Credentials go to `secure.ts` instead.
 *
 * Three separate instances rather than one namespaced store, so that clearing
 * one category cannot take out another. Logging out must drop cached API data
 * without discarding the user's theme choice, and clearing a corrupt query
 * cache must not lose an in-progress listing draft.
 *
 * API note: react-native-mmkv v4 replaced the `new MMKV()` constructor with the
 * `createMMKV()` factory, and `MMKV` is now a type rather than a class. v4 is
 * built on Nitro modules, so `react-native-nitro-modules` is a required peer
 * and the New Architecture is mandatory. Both hold here.
 */

/** Persisted TanStack Query cache. Cleared on logout. */
export const cacheStorage = createMMKV({ id: 'dd.cache' });

/** User preferences: theme, recent searches. Survives logout. */
export const prefsStorage = createMMKV({ id: 'dd.prefs' });

/**
 * Long-form drafts, currently the add-property form.
 *
 * Kept apart because losing a half-finished listing is the single worst
 * offline outcome in the app, and this store must never be caught up in a
 * cache eviction. Written by M8.
 */
export const draftStorage = createMMKV({ id: 'dd.drafts' });

/** Keys used in `prefsStorage`. Centralised so they cannot drift. */
export const PREF_KEYS = {
  themePreference: 'theme.preference',
  recentSearches: 'search.recent',
  /** Listings opened, most recent first. Feeds Home's "Recently Viewed". */
  recentlyViewed: 'property.recentlyViewed',
} as const;

/**
 * Clears everything tied to the signed-in user.
 *
 * Deliberately leaves `prefsStorage` alone: theme and recent searches are
 * device preferences, not account data, and resetting them at logout would be
 * a surprise rather than a safeguard.
 */
export function clearUserScopedStorage(): void {
  cacheStorage.clearAll();
  draftStorage.clearAll();
}
