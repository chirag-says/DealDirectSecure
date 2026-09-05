import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useEffect, useMemo, useRef } from 'react';

import { ApiError, qk } from '@/api';
import { useAuth } from '@/auth';
import type { RailProperty } from '@/features/properties';
import { PREF_KEYS, prefsStorage } from '@/storage';
import type { ObjectId } from '@/types/backend/common';
import { itemToStoredEntry } from './adapters';
import {
  addToShortlist,
  createShortlistShare,
  fetchSharedShortlist,
  fetchShortlistIds,
  fetchShortlistPage,
  mergeShortlist,
  removeFromShortlistOnServer,
  revokeShortlistShare,
  setShortlistNoteOnServer,
  type ShortlistPage,
} from './api';
import { decideMerge, readMergedFor, rememberMerged } from './merge';
import {
  clearLocalShortlist,
  findLocalShortlistEntry,
  isLocallyShortlisted,
  localEntryToItem,
  localShortlistIds,
  removeLocalShortlist,
  restoreLocalShortlist,
  setLocalShortlist,
  setLocalShortlistNote,
  toggleLocalShortlist,
  useLocalShortlist,
} from './store';
import type { ShortlistItem } from './types';

/**
 * The shortlist, server-backed, without losing the guest.
 *
 * ---------------------------------------------------------------------------
 * WHO OWNS THE TRUTH, AND WHO OWNS THE PAINT
 *
 * TanStack Query owns the truth for a signed-in user: `GET /shortlist` and
 * `GET /shortlist/ids` are the only things that can tell this device what is
 * actually saved. The MMKV store owns the paint: it is synchronous, it works
 * offline, it works signed out, and every save button reads it without
 * awaiting anything.
 *
 * They are kept in one direction. A successful list fetch WRITES the store; a
 * mutation writes the store first and reconciles after. Nothing ever reads the
 * store to decide what to send the server, except the one-time merge.
 *
 * ---------------------------------------------------------------------------
 * NOTHING HERE FETCHES UNLESS A SCREEN ASKED IT TO
 *
 * `useShortlist()` is read by Home (`shortlist.length`) and Home must not
 * issue a request — HANDOFF 5.2. So `useShortlist()` observes the list query
 * with `enabled: false`: it reads whatever is cached (including the persisted
 * cache from a previous launch) and falls back to the store, and it never
 * triggers a fetch. The screen that actually renders the list calls
 * `useShortlistList()`, which is the same key with `enabled` on.
 */

// --- Membership ------------------------------------------------------------

/**
 * The ids that are saved, from whichever source is authoritative right now.
 *
 * A signed-in user's set is the server's, once it has arrived; before that,
 * and for a guest, it is the device's. The union is deliberately NOT taken:
 * after the handover the local list is empty, so a union would only ever add
 * rows the server has already refused or the user has already deleted.
 */
function useShortlistIdSet(): ReadonlySet<string> {
  const { status } = useAuth();
  const local = useLocalShortlist();

  const serverIds = useQuery({
    queryKey: qk.shortlistIds(),
    queryFn: ({ signal }) => fetchShortlistIds(signal),
    enabled: status === 'authenticated',
    // Membership changes only when this device changes it (mutations
    // invalidate) or when another device does. Five minutes is short enough
    // that a second phone's save shows up within a session and long enough
    // that opening six listings costs one request, not six.
    staleTime: 5 * 60_000,
  });

  return useMemo(() => {
    if (status === 'authenticated' && serverIds.data) return new Set(serverIds.data);
    return new Set(local.map((entry) => entry.property.id));
  }, [status, serverIds.data, local]);
}

/**
 * Is this listing saved?
 *
 * Reads the set above, so a signed-in user gets the server's answer and a
 * guest gets the device's, with no branch at the call site.
 */
export function useIsShortlisted(id: string | undefined): boolean {
  const ids = useShortlistIdSet();
  if (!id) return false;
  return ids.has(id);
}

// --- The list --------------------------------------------------------------

function pageToItems(page: ShortlistPage | undefined, fallback: ShortlistItem[]): ShortlistItem[] {
  return page ? page.items : fallback;
}

/**
 * The list, read-only and request-free.
 *
 * Home's activity tile counts this. It must stay an ARRAY: that call site is
 * frozen and does `shortlist.length`.
 */
export function useShortlist(): ShortlistItem[] {
  const { status } = useAuth();
  const local = useLocalShortlist();

  // `enabled: false` observes the cache without ever fetching. This is what
  // lets Home read the real list when it happens to be cached and pay nothing
  // when it is not.
  const cached = useQuery({
    queryKey: qk.shortlistList(),
    queryFn: ({ signal }) => fetchShortlistPage(1, signal),
    enabled: false,
    // Same staleness as the fetching observer below, so the two views of one
    // cache entry cannot disagree about whether it needs refreshing. `enabled`
    // is the only thing that differs, and it is per-observer by design.
    staleTime: 60_000,
  });

  const localItems = useMemo(() => local.map(localEntryToItem), [local]);

  return useMemo(
    () => (status === 'authenticated' ? pageToItems(cached.data, localItems) : localItems),
    [status, cached.data, localItems]
  );
}

export interface ShortlistListState {
  items: ShortlistItem[];
  isLoading: boolean;
  isRefreshing: boolean;
  error: unknown;
  refresh: () => void;
  /** True when the rows on screen came from disk rather than from the server. */
  isOfflineCopy: boolean;
  signedIn: boolean;
  total: number;
}

/**
 * The list, fetched. Only the Activity segment and the share sheet call this.
 *
 * On success the store is replaced with what came back, which is what makes
 * the next cold start work offline and what keeps Home's count honest.
 */
export function useShortlistList(): ShortlistListState {
  const { status } = useAuth();
  const signedIn = status === 'authenticated';
  const local = useLocalShortlist();

  const query = useQuery({
    queryKey: qk.shortlistList(),
    queryFn: ({ signal }) => fetchShortlistPage(1, signal),
    enabled: signedIn,
    staleTime: 60_000,
  });

  // Write-through to the offline cache. In an effect rather than in the query
  // function because a query function must stay a pure fetch — TanStack calls
  // it for retries and refetches, and writing storage from inside it would
  // make the cache a function of how many times a request was attempted.
  useEffect(() => {
    if (!signedIn || !query.data) return;
    setLocalShortlist(query.data.items.map(itemToStoredEntry));
  }, [signedIn, query.data]);

  const localItems = useMemo(() => local.map(localEntryToItem), [local]);

  return {
    items: signedIn ? pageToItems(query.data, localItems) : localItems,
    isLoading: signedIn && query.isPending && localItems.length === 0,
    isRefreshing: query.isRefetching,
    // An error with rows on screen is not an error state: the offline copy is
    // real data, and blanking it to say "could not load" is the worse answer.
    error: query.error && localItems.length === 0 ? query.error : null,
    refresh: () => void query.refetch(),
    isOfflineCopy: signedIn && !query.data && localItems.length > 0,
    signedIn,
    total: query.data?.total ?? localItems.length,
  };
}

// --- Writing ---------------------------------------------------------------

export interface ToggleShortlistResult {
  /** Whether the listing ended up saved. Synchronous; the request follows. */
  toggle: (property: RailProperty) => boolean;
  isPending: boolean;
}

/**
 * Save or unsave, optimistically, with rollback.
 *
 * The store write happens first and synchronously — that is the whole reason
 * the store still exists — and the request follows. A failure puts the row
 * back exactly as it was, including its original timestamp, so a failed unsave
 * does not silently reorder the list.
 *
 * A guest's toggle is the same call with the request skipped. There is no
 * second code path for the signed-out case, which is what stops it rotting.
 */
export function useToggleShortlist(): ToggleShortlistResult {
  const { status } = useAuth();
  const queryClient = useQueryClient();
  const signedIn = status === 'authenticated';

  const mutation = useMutation({
    mutationFn: ({ id, saved, note }: { id: ObjectId; saved: boolean; note?: string }) =>
      saved ? addToShortlist(id, note) : removeFromShortlistOnServer(id),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: qk.shortlist });
    },
  });

  const { mutate } = mutation;

  const toggle = useCallback(
    (property: RailProperty) => {
      const previous = findLocalShortlistEntry(property.id);
      const saved = toggleLocalShortlist(property);

      if (!signedIn) return saved;

      mutate(
        { id: property.id, saved, note: previous?.note },
        {
          onError: () => {
            // Put the device back where it was. `restoreLocalShortlist` keeps
            // the original `shortlistedAt`, so the row returns to its place in
            // the list rather than jumping to the top.
            if (previous) restoreLocalShortlist(previous);
            else removeLocalShortlist(property.id);
          },
        }
      );

      return saved;
    },
    [signedIn, mutate]
  );

  return { toggle, isPending: mutation.isPending };
}

export interface ShortlistNoteResult {
  setNote: (propertyId: ObjectId, note: string) => Promise<void>;
  isPending: boolean;
  error: unknown;
}

/**
 * The private note on a shortlisted listing.
 *
 * Awaited rather than optimistic: a note is typed and confirmed in a sheet,
 * so there is a button to keep spinning, and a note that appeared and then
 * vanished would read as lost work rather than as a failed request. 404
 * NOT_SHORTLISTED means the row went away on another device; the message says
 * that rather than "something went wrong".
 */
export function useShortlistNote(): ShortlistNoteResult {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: ({ propertyId, note }: { propertyId: ObjectId; note: string }) =>
      setShortlistNoteOnServer(propertyId, note),
    onSuccess: (note, { propertyId }) => {
      setLocalShortlistNote(propertyId, note);
      void queryClient.invalidateQueries({ queryKey: qk.shortlistList() });
    },
  });

  const { mutateAsync } = mutation;

  return {
    setNote: useCallback(
      async (propertyId: ObjectId, note: string) => {
        await mutateAsync({ propertyId, note });
      },
      [mutateAsync]
    ),
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

// --- Sharing ---------------------------------------------------------------

export interface ShortlistShareState {
  create: () => Promise<{ token: string; expiresAt: string; count: number }>;
  revoke: () => Promise<void>;
  isCreating: boolean;
  isRevoking: boolean;
  /** 409 EMPTY_SHORTLIST, surfaced as its own state rather than as an error. */
  isEmpty: boolean;
  error: unknown;
}

/**
 * Create or revoke the public link.
 *
 * `POST /shortlist/share` ROTATES: a new link kills the previous one. The
 * sheet says so, because a user who has already sent the old link to three
 * people needs to know that pressing this again breaks it for them.
 */
export function useShortlistShare(): ShortlistShareState {
  const create = useMutation({ mutationFn: createShortlistShare });
  const revoke = useMutation({ mutationFn: revokeShortlistShare });

  const createError = create.error;
  const isEmpty = createError instanceof ApiError && createError.code === 'EMPTY_SHORTLIST';

  const { mutateAsync: runCreate } = create;
  const { mutateAsync: runRevoke } = revoke;

  return {
    create: useCallback(() => runCreate(), [runCreate]),
    revoke: useCallback(async () => {
      await runRevoke();
    }, [runRevoke]),
    isCreating: create.isPending,
    isRevoking: revoke.isPending,
    isEmpty,
    error: isEmpty ? null : (createError ?? revoke.error),
  };
}

/** Someone else's shortlist, by token. Public: no session, no store writes. */
export function useSharedShortlist(token: string | undefined) {
  const query = useQuery({
    queryKey: qk.shortlistShared(token ?? ''),
    queryFn: ({ signal }) => fetchSharedShortlist(token as string, signal),
    enabled: !!token,
    staleTime: 5 * 60_000,
    retry: false,
  });

  const error = query.error;

  return {
    shortlist: query.data,
    isLoading: query.isPending && !!token,
    /** Expired, revoked, or never existed. All three are 404 and read alike. */
    isMissing: error instanceof ApiError && error.kind === 'notFound',
    error,
    refresh: () => void query.refetch(),
  };
}

// --- The one-time handover -------------------------------------------------

/**
 * Hands this device's list to the server, once per account.
 *
 * Mounted by the surfaces that already care about the shortlist — the save
 * button and the Activity segment — rather than at the root, so a user who
 * never touches the feature never pays for it and the app's launch path gains
 * no request.
 *
 * The decision is `decideMerge`'s (pure, tested). This hook is only the
 * effect: post, clear the local list, record the account, and refetch so the
 * store is immediately repopulated from the server rather than left empty
 * until the next time the list screen is opened.
 *
 * Failure is silent and leaves the guard unset, so the next launch tries
 * again. A merge that never happens costs the user their guest-era saves; a
 * merge that reports an error they cannot act on costs them a dialog. The
 * first is worse but recoverable, the second is just noise.
 */
export function useShortlistSync(): void {
  const { status, user } = useAuth();
  const queryClient = useQueryClient();
  const attempted = useRef<string | null>(null);

  useEffect(() => {
    const userId = status === 'authenticated' ? user?._id : null;
    if (!userId || attempted.current === userId) return;

    const mergedFor = readMergedFor(prefsStorage.getString(PREF_KEYS.shortlistMergedFor));
    const decision = decideMerge({ userId, localIds: localShortlistIds(), mergedFor });
    if (!decision.shouldMerge) return;

    // Guarded in memory as well as in storage: the effect can re-run before
    // the request resolves (a refocus, a re-render with a new object identity
    // for `user`), and two merges in flight would double-count nothing useful.
    attempted.current = userId;

    void mergeShortlist(decision.propertyIds)
      .then(() => {
        clearLocalShortlist();
        prefsStorage.set(
          PREF_KEYS.shortlistMergedFor,
          JSON.stringify(rememberMerged(mergedFor, userId))
        );
        // Repopulates the store from the server, so the local list being empty
        // is a fact for milliseconds rather than until the next list open.
        void queryClient.invalidateQueries({ queryKey: qk.shortlist });
      })
      .catch(() => {
        // Left unguarded on purpose: the next launch retries.
        attempted.current = null;
      });
  }, [status, user?._id, queryClient]);
}

/** Synchronous membership for code that cannot use a hook. Device-only. */
export { isLocallyShortlisted };
