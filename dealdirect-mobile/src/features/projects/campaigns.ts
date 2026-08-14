import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { call, campaignsEndpoints, qk } from '@/api';
import type { ObjectId } from '@/types/backend/common';

export function useCampaignsForUnitType(unitTypeId: ObjectId) {
  const query = useQuery({
    queryKey: qk.campaignsByUnitType(unitTypeId),
    queryFn: async ({ signal }) => {
      const response = await call(campaignsEndpoints.byUnitType, {
        params: { unitTypeId },
        signal,
      });
      return response.data;
    },
    enabled: Boolean(unitTypeId),
    staleTime: 60_000,
  });

  return {
    campaigns: query.data ?? [],
    isLoading: query.isPending,
    error: query.error,
  };
}

export function useCampaignDetail(id: ObjectId) {
  const query = useQuery({
    queryKey: qk.campaignDetail(id),
    queryFn: async ({ signal }) => {
      const response = await call(campaignsEndpoints.detail, { params: { id }, signal });
      return response.data;
    },
    enabled: Boolean(id),
    staleTime: 30_000,
  });

  return {
    campaign: query.data ?? null,
    isLoading: query.isPending,
    error: query.error,
    refresh: () => void query.refetch(),
  };
}

/**
 * Join/exit share a 10-per-15-minute limiter with each other
 * (`rateLimit: 'groupBuy'`), so a user mashing the button sees a 429 quickly —
 * `ApiError.retryAfterSeconds` carries how long to wait, surfaced by the
 * screen rather than silently retried.
 */
export function useJoinCampaign(id: ObjectId) {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () => call(campaignsEndpoints.join, { params: { id } }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: qk.campaignDetail(id) }),
  });

  return {
    join: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

export function useExitCampaign(id: ObjectId) {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () => call(campaignsEndpoints.exit, { params: { id } }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: qk.campaignDetail(id) }),
  });

  return {
    exit: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

export function useUploadPaymentProof(id: ObjectId) {
  const mutation = useMutation({
    mutationFn: (uri: string) => {
      const form = new FormData();
      const name = uri.split('/').pop() ?? 'payment-proof.jpg';
      form.append('paymentProof', { uri, name, type: 'image/jpeg' } as unknown as Blob);
      return call(campaignsEndpoints.uploadPaymentProof, { params: { id }, data: form });
    },
  });

  return {
    upload: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
  };
}
