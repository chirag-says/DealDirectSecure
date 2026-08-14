import { optionalNativeModule } from '@/config/optionalNative';

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
 *
 * ---------------------------------------------------------------------------
 * EXPO GO FALLBACK
 *
 * Expo Go does not bundle react-native-mmkv, and a Nitro module that is not in
 * the binary throws when its JS is first evaluated — not when it is called. So
 * the import has to be a guarded `require`, not a static `import`, or the
 * whole app dies at startup before anything can degrade gracefully.
 *
 * When it is missing, storage becomes an in-memory Map. Everything keeps
 * working for the run; NOTHING survives a reload. Concretely, in Expo Go:
 * theme preference resets to system, recent searches and recently-viewed start
 * empty, the offline query cache does not persist, and a half-written listing
 * draft is lost on reload. That is the correct trade for a preview host — the
 * alternative is not running at all — but it is not a mode to ship in, which
 * is why the warning below is loud and unconditional.
 */

/**
 * The storage surface this app actually uses, and nothing more.
 *
 * Deliberately NOT MMKV's full interface. Four methods are called across the
 * ten modules that touch storage (`getString`, `set`, `remove`, `clearAll`),
 * so those four are the contract. Narrowing it here is what lets a Map satisfy
 * the same type honestly instead of a cast, and it documents the real
 * dependency: widening this is a deliberate act that immediately shows the
 * fallback needs the same method.
 */
export interface KeyValueStore {
  getString(key: string): string | undefined;
  set(key: string, value: string): void;
  remove(key: string): void;
  clearAll(): void;
}

type StoreFactory = (options: { id: string }) => KeyValueStore;

/** In-memory stand-in. Per-instance, so the three stores stay independent. */
function createMemoryStore(): KeyValueStore {
  const map = new Map<string, string>();

  return {
    getString: (key) => map.get(key),
    set: (key, value) => void map.set(key, value),
    remove: (key) => void map.delete(key),
    clearAll: () => map.clear(),
  };
}

const createStore =
  optionalNativeModule(
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    () => (require('react-native-mmkv') as { createMMKV: StoreFactory }).createMMKV,
    'react-native-mmkv',
    'Falling back to in-memory storage: theme, recent searches, the offline ' +
      'query cache and listing drafts will NOT survive a reload.'
  ) ?? createMemoryStore;

/** Persisted TanStack Query cache. Cleared on logout. */
export const cacheStorage = createStore({ id: 'dd.cache' });

/** User preferences: theme, recent searches. Survives logout. */
export const prefsStorage = createStore({ id: 'dd.prefs' });

/**
 * Long-form drafts, currently the add-property form.
 *
 * Kept apart because losing a half-finished listing is the single worst
 * offline outcome in the app, and this store must never be caught up in a
 * cache eviction. Written by M8.
 */
export const draftStorage = createStore({ id: 'dd.drafts' });

/** Keys used in `prefsStorage`. Centralised so they cannot drift. */
export const PREF_KEYS = {
  themePreference: 'theme.preference',
  recentSearches: 'search.recent',
  /** Listings opened, most recent first. Feeds Home's "Recently Viewed". */
  recentlyViewed: 'property.recentlyViewed',
  /** Whether the local-notification permission prompt has been shown once
   *  (M13). Asked at most once ever, not on every Messages tab visit. */
  notificationPermissionAsked: 'notifications.permissionAsked',
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
