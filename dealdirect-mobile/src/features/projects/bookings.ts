import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { call, bookingsEndpoints, qk } from '@/api';
import { useAuth } from '@/auth';
import type { ObjectId } from '@/types/backend/common';
import type { CreateBookingRequest } from '@/types/backend/project';

export function useMyBookings() {
  const { status } = useAuth();
  const signedIn = status === 'authenticated';
  // Cold start has not decided yet. Treated as loading rather than as
  // signed-out, or the screens flash a sign-in prompt at a user who is about to
  // turn out to be signed in.
  const restoring = status === 'restoring';

  const query = useQuery({
    queryKey: qk.myBookings(),
    queryFn: async ({ signal }) => {
      const response = await call(bookingsEndpoints.mine, { signal });
      return response.data;
    },
    // Without this a guest fired the request anyway and met a 401, which the
    // screen rendered as "Could not load your bookings" — an error, for the
    // ordinary state of not being signed in. The screens show a sign-in prompt
    // instead; this is what lets them.
    enabled: signedIn,
    staleTime: 15_000,
  });

  return {
    bookings: query.data ?? [],
    // `isPending` stays true forever on a disabled query, so a signed-out user
    // would sit under a skeleton that never resolves. Screens must check this
    // BEFORE `signedIn`, so that the undecided cold-start moment reads as
    // loading rather than as a refusal.
    isLoading: restoring || (signedIn && query.isPending),
    isRefreshing: query.isRefetching,
    error: query.error,
    refresh: () => void query.refetch(),
    signedIn,
  };
}

export function useCreateBooking() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (request: CreateBookingRequest) => call(bookingsEndpoints.create, { data: request }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: qk.myBookings() }),
  });

  return {
    createBooking: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
    reset: mutation.reset,
  };
}

/**
 * Withdraw your own booking.
 *
 * Deliberately does not touch the payment cache or claim a refund: the server
 * leaves the UTR and screenshot exactly as submitted, and `refundMayBeDue` in
 * the response is the signal that a person has to arrange one.
 */
export function useCancelBooking(id: ObjectId) {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (reason?: string) => {
      const trimmed = reason?.trim();
      return call(bookingsEndpoints.cancel, {
        params: { id },
        data: trimmed ? { reason: trimmed } : {},
      });
    },
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: qk.myBookings() }),
  });

  return {
    cancelBooking: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

export function usePaymentConfig() {
  const query = useQuery({
    queryKey: qk.paymentConfig,
    queryFn: async () => {
      const response = await call(bookingsEndpoints.paymentConfig);
      return response.data;
    },
    staleTime: 10 * 60_000,
  });

  return {
    config: query.data ?? null,
    isLoading: query.isPending,
    error: query.error,
  };
}

/**
 * Submit proof of the token payment.
 *
 * Two corrections, 2026-08-13:
 *
 * - The text field is `utrNumber`, not `utr` (defect F5). The controller
 *   destructures `{ utrNumber }` (`bookingController.js:161`) and the model
 *   stores `payment.utrNumber`, so everything typed into the old field was
 *   discarded server-side — the request still succeeded on the strength of
 *   the screenshot alone, and the admin reconciling the payment got
 *   "UTR submitted: screenshot only" with no reference to match on.
 * - Either input suffices (defect F8). The backend rejects only when BOTH are
 *   missing (`bookingController.js:164-166`), and the website accepts either.
 *   Each field is appended only when present, so a screenshot-only or
 *   reference-only submission both go through.
 */
export function useSubmitBookingPayment(id: ObjectId) {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: ({ screenshotUri, utr }: { screenshotUri?: string; utr?: string }) => {
      const form = new FormData();

      if (screenshotUri) {
        const name = screenshotUri.split('/').pop() ?? 'payment-screenshot.jpg';
        form.append('screenshot', {
          uri: screenshotUri,
          name,
          type: 'image/jpeg',
        } as unknown as Blob);
      }

      const reference = utr?.trim();
      if (reference) form.append('utrNumber', reference);

      return call(bookingsEndpoints.submitPayment, { params: { id }, data: form });
    },
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: qk.myBookings() }),
  });

  return {
    submitPayment: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
  };
}
