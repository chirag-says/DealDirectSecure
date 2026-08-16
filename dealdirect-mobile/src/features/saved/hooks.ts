/**
 * The user's interest list — what the backend calls "saved".
 *
 * ---------------------------------------------------------------------------
 * THIS IS NOT A BOOKMARK LIST, AND THE SCREEN MUST NOT IMPLY IT IS
 *
 * `GET /properties/saved` queries `{ "interestedUsers.user": userId }`, the
 * same array `POST /properties/interested/:id` writes to. There is exactly one
 * list on this backend and two names for it. Everything in here was an
 * announcement to an owner: a lead exists for each row, and each owner has the
 * user's name, email and phone.
 *
 * Two consequences the UI has to carry:
 *
 * 1. It holds at most FIVE rows. The backend refuses a sixth anywhere in the
 *    app, so this screen is also where a user goes to make room. That makes
 *    the count a functional part of the screen, not decoration.
 *
 * 2. Removing a row stops the user appearing in the owner's interested list,
 *    but does NOT delete the lead already created or unsend the email. The
 *    copy must not promise otherwise.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback } from 'react';

import { call, propertiesEndpoints, qk } from '@/api';
import { useAuth } from '@/auth';
import { adaptProperty, type PropertySummary } from '@/features/properties';
import type { ObjectId } from '@/types/backend/common';

/** The backend's own cap, mirrored here only for display. It is enforced server-side. */
export const INTEREST_LIMIT = 5;

export interface SavedListState {
  items: PropertySummary[];
  isLoading: boolean;
  isRefreshing: boolean;
  error: unknown;
  refresh: () => void;
  /** Rows used out of the cap, for the "3 of 5" line. */
  used: number;
  remaining: number;
  requiresAuth: boolean;
}

export function useSavedProperties(): SavedListState {
  const { status } = useAuth();
  const signedIn = status === 'authenticated';

  const query = useQuery({
    queryKey: qk.savedProperties(),
    queryFn: async ({ signal }) => {
      const response = await call(propertiesEndpoints.saved, { signal });
      return (response.data ?? []).map(adaptProperty);
    },
    enabled: signedIn,
    // Short, because the cap makes staleness actionable: a user who removed a
    // listing on another device needs to see the freed slot.
    staleTime: 30_000,
  });

  const items = query.data ?? [];

  return {
    items,
    isLoading: signedIn && query.isPending,
    isRefreshing: query.isRefetching,
    error: query.error,
    refresh: () => void query.refetch(),
    used: items.length,
    remaining: Math.max(0, INTEREST_LIMIT - items.length),
    requiresAuth: !signedIn,
  };
}

/**
 * Removes a listing from the interest list.
 *
 * Uses `DELETE /properties/interested/:id` rather than the `/saved/:id` path.
 * They are the same controller behaviour, but the interest path names what is
 * actually happening, and a future backend that splits the two will keep this
 * one meaning what it says.
 *
 * Both the list and the per-listing flag are invalidated, because they are two
 * views of one fact and a stale detail screen would offer to add something
 * already present.
 */
export function useRemoveInterest() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (id: ObjectId) =>
      call(propertiesEndpoints.removeInterest, { params: { id } }),

    onMutate: async (id: ObjectId) => {
      await queryClient.cancelQueries({ queryKey: qk.savedProperties() });

      const previous = queryClient.getQueryData<PropertySummary[]>(qk.savedProperties());
      queryClient.setQueryData<PropertySummary[]>(qk.savedProperties(), (current) =>
        (current ?? []).filter((item) => item.id !== id)
      );

      // The detail screen's flag, flipped in the same breath so returning to a
      // listing just removed does not show it as still marked.
      queryClient.setQueryData(qk.propertyInterest(id), false);

      return { previous };
    },

    onError: (_error, id, context) => {
      queryClient.setQueryData(qk.savedProperties(), context?.previous);
      void queryClient.invalidateQueries({ queryKey: qk.propertyInterest(id) });
    },

    onSettled: (_data, _error, id) => {
      void queryClient.invalidateQueries({ queryKey: qk.savedProperties() });
      void queryClient.invalidateQueries({ queryKey: qk.propertyInterest(id) });
    },
  });

  return {
    remove: useCallback((id: ObjectId) => mutation.mutate(id), [mutation]),
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

