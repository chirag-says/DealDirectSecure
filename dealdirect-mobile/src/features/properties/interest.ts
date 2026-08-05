/**
 * The interest action.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS ACTUALLY DOES, AND WHY THERE IS NO HEART ICON
 *
 * `POST /properties/interested/:id` is not a bookmark. It pushes the user into
 * the listing's `interestedUsers`, creates a `Lead` for the owner, and
 * notifies them by email. `GET /properties/saved` then reads back that same
 * array — saved and interested are one list on this backend under two names,
 * and `DELETE /saved/:id` and `DELETE /interested/:id` are the same operation
 * written twice.
 *
 * So a heart icon would be a lie. A heart means "remember this for me", it is
 * private, and it is free. This is none of those: it hands the user's name,
 * email and phone to a stranger and is capped at five. The control has to say
 * what it does, which is why the button is labelled and carries a consequence
 * line instead.
 *
 * ---------------------------------------------------------------------------
 * THE CAP IS SERVER-SIDE AND CANNOT BE PREDICTED HERE
 *
 * The backend counts the user's interests across ALL listings and rejects the
 * sixth with a 400. This client cannot know that count without fetching the
 * whole saved list, so it does not try to pre-empt the rejection. The optimistic
 * flip rolls back and the server's own message is shown, which is both accurate
 * and always current if the limit ever changes.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useState } from 'react';

import { ApiError, call, propertiesEndpoints, qk } from '@/api';
import { useAuth } from '@/auth';
import type { ObjectId } from '@/types/backend/common';

export interface InterestState {
  /** True once the check has confirmed it. Optimistically true mid-flight. */
  isInterested: boolean;
  /** The check is still running; the button should not claim a state yet. */
  isLoading: boolean;
  /** A mark or remove is in flight. */
  isPending: boolean;
  /** Signed out. The action is offered but routes to login instead. */
  requiresAuth: boolean;
  toggle: () => void;
  /** Server's explanation of the last rejection, cleared on the next attempt. */
  error: string | null;
  clearError: () => void;
}

export function useInterest(
  propertyId: ObjectId | undefined,
  options: { onRequiresAuth?: () => void } = {}
): InterestState {
  const queryClient = useQueryClient();
  const { status } = useAuth();
  const signedIn = status === 'authenticated';

  const key = qk.propertyInterest(propertyId ?? '');

  const check = useQuery({
    queryKey: key,
    queryFn: async ({ signal }) => {
      const response = await call(propertiesEndpoints.checkInterested, {
        params: { id: propertyId as ObjectId },
        signal,
      });
      return response.isInterested === true;
    },
    // Signed-out users have no interest state to fetch. The endpoint would 401
    // and the session handler would treat it as a dead session.
    enabled: signedIn && !!propertyId,
    staleTime: 60_000,
  });

  // Component state, not cache. A rejection message belongs to this screen's
  // last attempt: it must not survive a remount, and nothing else invalidates
  // or reads it.
  const [error, setError] = useState<string | null>(null);

  const mutate = useMutation({
    mutationFn: (next: boolean) =>
      call(next ? propertiesEndpoints.markInterested : propertiesEndpoints.removeInterest, {
        params: { id: propertyId as ObjectId },
      }),

    onMutate: async (next: boolean) => {
      setError(null);

      // An in-flight check would land after the optimistic write and undo it.
      await queryClient.cancelQueries({ queryKey: key });

      const previous = queryClient.getQueryData<boolean>(key);
      queryClient.setQueryData(key, next);
      return { previous };
    },

    onError: (error, _next, context) => {
      // Rollback. `previous` is undefined when nothing was cached, which is a
      // meaningful state — it puts the button back into "unknown" rather than
      // asserting false.
      queryClient.setQueryData(key, context?.previous);

      // 400s here are real answers, not faults: the five-listing cap, your own
      // listing, one already marked. The server's wording is better than
      // anything this layer could invent and stays correct if the rule changes.
      if (error instanceof ApiError && error.status === 400) setError(error.message);
      else setError('Could not update. Please try again.');
    },

    onSettled: () => {
      // Confirm against the server. The optimistic value is a guess until this
      // lands, and the cap means a success is not guaranteed by a valid press.
      void queryClient.invalidateQueries({ queryKey: key });
    },
  });

  // Depends on the callback itself rather than on `options`, which callers
  // build as an object literal and would therefore change every render.
  const { onRequiresAuth } = options;

  const toggle = useCallback(() => {
    if (!propertyId) return;

    if (!signedIn) {
      onRequiresAuth?.();
      return;
    }

    mutate.mutate(!(check.data ?? false));
  }, [propertyId, signedIn, onRequiresAuth, mutate, check.data]);

  return {
    isInterested: check.data ?? false,
    isLoading: signedIn && check.isPending && !!propertyId,
    isPending: mutate.isPending,
    requiresAuth: !signedIn,
    toggle,
    error,
    clearError: useCallback(() => setError(null), []),
  };
}
