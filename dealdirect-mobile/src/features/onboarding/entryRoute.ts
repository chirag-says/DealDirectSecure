/**
 * The pure half of `welcomeState.ts`, in its own module so `node --test` can
 * import it without pulling in the storage layer (which needs the native
 * MMKV module). Same table, same reasoning; see the sibling file.
 */

export type EntryStatus = 'restoring' | 'authenticated' | 'guest';
export type EntryRoute = '/(tabs)' | '/welcome';

export function resolveEntryRoute(status: EntryStatus, welcomeSeen: boolean): EntryRoute | null {
  if (status === 'restoring') return null;
  if (status === 'authenticated') return '/(tabs)';
  return welcomeSeen ? '/(tabs)' : '/welcome';
}
