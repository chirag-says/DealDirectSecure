import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback } from 'react';

import { call, qk, savedSearchesEndpoints } from '@/api';
import { useAuth } from '@/auth';
import type { ObjectId } from '@/types/backend/common';
import type { CreateSavedSearchRequest } from '@/types/backend/savedSearch';
import { adaptSavedSearch } from './adapters';
import type { SavedSearchSummary } from './types';

/**
 * Saved searches.
 *
 * ---------------------------------------------------------------------------
 * THERE IS NO REVERSIBLE ON/OFF SWITCH, SO NONE IS EXPOSED
 *
 * `PATCH /saved-searches/:id/toggle` flips `isActive`, and
 * `GET /saved-searches/mine` filters to `isActive: true`. Turning a search off
 * therefore removes it from the only endpoint that can list it: the client can
 * never see it again, and so can never turn it back on. It is a delete that
 * leaves a row behind.
 *
 * Offering that as a switch would be a trap — every user who flipped it would
 * lose the search and be unable to explain where it went. So the toggle is not
 * wired to any control. What IS offered is `PUT /saved-searches/:id` with
 * `notifyEmail` / `notifyInApp`, which is genuinely reversible and is what a
 * user means by "stop alerting me", plus an explicit delete.
 *
 * Reinstating the toggle needs one backend change: have `mine` return every
 * search and let the client filter. Until then this is the honest surface.
 */

export interface SavedSearchListState {
  items: SavedSearchSummary[];
  isLoading: boolean;
  isRefreshing: boolean;
  error: unknown;
  refresh: () => void;
  requiresAuth: boolean;
}

export function useSavedSearches(): SavedSearchListState {
  const { status } = useAuth();
  const signedIn = status === 'authenticated';

  const query = useQuery({
    queryKey: qk.savedSearchList(),
    queryFn: async ({ signal }) => {
      const response = await call(savedSearchesEndpoints.mine, { signal });
      return (response.searches ?? []).map(adaptSavedSearch);
    },
    enabled: signedIn,
    staleTime: 60_000,
  });

  return {
    items: query.data ?? [],
    isLoading: signedIn && query.isPending,
    isRefreshing: query.isRefetching,
    error: query.error,
    refresh: () => void query.refetch(),
    requiresAuth: !signedIn,
  };
}

/**
 * Creates a saved search.
 *
 * Not optimistic. The server assigns the id, and creating one also generates a
 * notification, so guessing the row and reconciling it buys nothing over a
 * spinner on a button the user pressed once.
 */
export function useCreateSavedSearch() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (payload: CreateSavedSearchRequest) =>
      call(savedSearchesEndpoints.create, { data: payload }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.savedSearches });
      // Creating a search writes a "Search saved" notification server-side, so
      // the badge is wrong until this refetches.
      void queryClient.invalidateQueries({ queryKey: qk.notifications });
    },
  });

  return {
    create: useCallback(
      (payload: CreateSavedSearchRequest) => mutation.mutateAsync(payload),
      [mutation]
    ),
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

/** Alert preferences. The reversible half of what `toggle` pretends to be. */
export function useUpdateSavedSearchAlerts() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: ({
      id,
      notifyEmail,
      notifyInApp,
    }: {
      id: ObjectId;
      notifyEmail?: boolean;
      notifyInApp?: boolean;
    }) =>
      call(savedSearchesEndpoints.update, {
        params: { id },
        data: { notifyEmail, notifyInApp },
      }),

    onMutate: async ({ id, notifyEmail, notifyInApp }) => {
      await queryClient.cancelQueries({ queryKey: qk.savedSearchList() });
      const previous = queryClient.getQueryData<SavedSearchSummary[]>(qk.savedSearchList());

      queryClient.setQueryData<SavedSearchSummary[]>(qk.savedSearchList(), (current) =>
        (current ?? []).map((item) =>
          item.id === id
            ? {
                ...item,
                notifyEmail: notifyEmail ?? item.notifyEmail,
                notifyInApp: notifyInApp ?? item.notifyInApp,
              }
            : item
        )
      );

      return { previous };
    },

    onError: (_error, _vars, context) => {
      queryClient.setQueryData(qk.savedSearchList(), context?.previous);
    },

    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: qk.savedSearchList() });
    },
  });

  return {
    setAlerts: useCallback(
      (id: ObjectId, next: { notifyEmail?: boolean; notifyInApp?: boolean }) =>
        mutation.mutate({ id, ...next }),
      [mutation]
    ),
    isPending: mutation.isPending,
  };
}

export function useDeleteSavedSearch() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (id: ObjectId) => call(savedSearchesEndpoints.remove, { params: { id } }),

    onMutate: async (id: ObjectId) => {
      await queryClient.cancelQueries({ queryKey: qk.savedSearchList() });
      const previous = queryClient.getQueryData<SavedSearchSummary[]>(qk.savedSearchList());

      queryClient.setQueryData<SavedSearchSummary[]>(qk.savedSearchList(), (current) =>
        (current ?? []).filter((item) => item.id !== id)
      );

      return { previous };
    },

    onError: (_error, _id, context) => {
      queryClient.setQueryData(qk.savedSearchList(), context?.previous);
    },

    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: qk.savedSearchList() });
    },
  });

  return {
    remove: useCallback((id: ObjectId) => mutation.mutate(id), [mutation]),
    isPending: mutation.isPending,
  };
}
