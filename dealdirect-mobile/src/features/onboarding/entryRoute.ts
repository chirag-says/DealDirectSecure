/**
 * The pure half of `welcomeState.ts`, in its own module so `node --test` can
 * import it without pulling in the storage layer (which needs the native
 * MMKV module). Same table, same reasoning; see the sibling file.
 */

export type EntryStatus = 'restoring' | 'authenticated' | 'guest';
export type EntryRoute = '/(tabs)' | '/welcome' | '/setup';

/**
 * `setupSeen` (2026-09-06): the permissions primer. A first-time guest still
 * goes to the welcome screen, which hands over to the primer itself. Anyone
 * else who has not been through the primer, signed in or not, sees it once
 * before the app; that covers installs from before it existed.
 */
export function resolveEntryRoute(
  status: EntryStatus,
  welcomeSeen: boolean,
  setupSeen = true
): EntryRoute | null {
  if (status === 'restoring') return null;
  if (status === 'authenticated') return setupSeen ? '/(tabs)' : '/setup';
  if (!welcomeSeen) return '/welcome';
  return setupSeen ? '/(tabs)' : '/setup';
}
