import { createSyncStoragePersister } from '@tanstack/query-sync-storage-persister';
import type { Query } from '@tanstack/react-query';

import { cacheStorage } from '@/storage';

/**
 * MMKV-backed query cache persistence (M12).
 *
 * `createSyncStoragePersister` wants a Web Storage-shaped object
 * (`getItem`/`setItem`/`removeItem`); MMKV's own API is `getString`/`set`/
 * `remove`. This is that adapter, nothing else — `cacheStorage` already exists
 * (provisioned in M0, cleared on logout by `clearUserScopedStorage`), so
 * logout already drops this persisted cache along with everything else in it.
 */
const mmkvPersistStorage = {
  getItem: (key: string) => cacheStorage.getString(key) ?? null,
  setItem: (key: string, value: string) => cacheStorage.set(key, value),
  removeItem: (key: string) => cacheStorage.remove(key),
};

export const queryPersister = createSyncStoragePersister({
  storage: mmkvPersistStorage,
  key: 'dd.query.persisted',
  // Large socket-driven or paginated caches (chat messages, infinite feeds)
  // serialise fine; MMKV has no practical size ceiling for this.
});

/** A day. Data older than this on a cold start is discarded rather than shown
 *  as if current — stale-but-displayed is fine for a background refetch, not
 *  for a listing a user has not opened the app to see in 24 hours. */
export const PERSIST_MAX_AGE = 24 * 60 * 60_000;

/**
 * What gets written to disk.
 *
 * Excludes anything derived from a socket event rather than a fetch (chat
 * messages, online-status queries) — persisting those would show a "live"
 * conversation as current after the socket has been disconnected for hours,
 * which is a worse read than an empty state. Everything else — properties,
 * projects, leads, rewards, profile — is a plain REST read and is safe to
 * resurrect as "possibly stale" on a cold start.
 */
export function shouldPersistQuery(query: Query): boolean {
  const domain = query.queryKey[0];
  if (domain === 'chat') return false;
  return query.state.status === 'success';
}
