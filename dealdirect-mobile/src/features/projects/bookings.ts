import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { call, bookingsEndpoints, qk } from '@/api';
import type { ObjectId } from '@/types/backend/common';
import type { CreateBookingRequest } from '@/types/backend/project';

export function useMyBookings() {
  const query = useQuery({
    queryKey: qk.myBookings(),
    queryFn: async ({ signal }) => {
      const response = await call(bookingsEndpoints.mine, { signal });
      return response.data;
    },
    staleTime: 15_000,
  });

  return {
    bookings: query.data ?? [],
    isLoading: query.isPending,
    isRefreshing: query.isRefetching,
    error: query.error,
    refresh: () => void query.refetch(),
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
