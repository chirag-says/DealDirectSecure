/**
 * Owner listing CRUD.
 *
 * An owner account is capped at ONE property server-side (the atomic
 * check-and-create in `addProperty`), so "my properties" is really "my
 * property" in practice for this role. The hook still returns a list because
 * `GET /properties/my-properties` does, and a future relaxation of that cap
 * should not require touching this file.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { call, propertiesEndpoints, qk } from '@/api';
import type { ObjectId } from '@/types/backend/common';
import type { Property } from '@/types/backend/property';
import { clearListingDraft } from './draft';
import { buildAddFormData, buildEditFormData } from './formData';
import type { CategorizedPhoto, ListingFormValues } from './types';

export function useMyProperties() {
  const query = useQuery({
    queryKey: qk.myProperties(),
    queryFn: async () => {
      const response = await call(propertiesEndpoints.myProperties);
      return response.data;
    },
    staleTime: 30_000,
  });

  return {
    properties: query.data ?? ([] as Property[]),
    isLoading: query.isPending,
    isRefreshing: query.isRefetching,
    error: query.error,
    refresh: () => void query.refetch(),
  };
}

export function useAddListing() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: ({
      values,
      newPhotos,
    }: {
      values: ListingFormValues;
      newPhotos: CategorizedPhoto[];
    }) => call(propertiesEndpoints.add, { data: buildAddFormData(values, newPhotos) }),
    onSuccess: (response) => {
      clearListingDraft();
      void queryClient.invalidateQueries({ queryKey: qk.myProperties() });

      // Listing a property earns points. The wallet is now stale by that much;
      // the caller decides whether to reveal the award (see `RewardReveal`).
      if (response.reward && response.reward.pointsAwarded > 0) {
        void queryClient.invalidateQueries({ queryKey: qk.rewardsWallet() });
        void queryClient.invalidateQueries({ queryKey: qk.rewardsTransactions() });
      }
    },
  });

  return {
    add: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

export function useUpdateListing(id: ObjectId) {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: ({
      values,
      newPhotos,
      existingPhotos,
    }: {
      values: ListingFormValues;
      newPhotos: CategorizedPhoto[];
      existingPhotos: CategorizedPhoto[];
    }) =>
      call(propertiesEndpoints.updateMine, {
        params: { id },
        data: buildEditFormData(values, newPhotos, existingPhotos),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.myProperties() });
      void queryClient.invalidateQueries({ queryKey: qk.propertyDetail(id) });
    },
  });

  return {
    update: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

export function useDeleteListing() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (id: ObjectId) => call(propertiesEndpoints.deleteMine, { params: { id } }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: qk.myProperties() }),
  });

  return {
    remove: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

// --- Close deal --------------------------------------------------------

export interface CloseDealValues {
  buyerId: ObjectId;
  closingType: 'sold' | 'rented';
  /** Local file URIs, not yet uploaded. At least one required by the backend. */
  documentUris: string[];
}

function buildCloseDealFormData(values: CloseDealValues): FormData {
  const form = new FormData();
  form.append('buyerId', values.buyerId);
  form.append('closingType', values.closingType);

  values.documentUris.forEach((uri, index) => {
    const filename = uri.split('/').pop() ?? `document-${index}.jpg`;
    const ext = filename.split('.').pop()?.toLowerCase();
    const mime = ext === 'pdf' ? 'application/pdf' : ext === 'png' ? 'image/png' : 'image/jpeg';
    form.append('documents', { uri, name: filename, type: mime } as unknown as Blob);
  });

  return form;
}

/**
 * Owner submits proof to close a deal — see `CloseDealSheet`. Sets the
 * property to `pending_verification` server-side; the reward is claimed
 * separately, later, once admin approves (`useClaimDealReward` in
 * `features/rewards`).
 */
export function useCloseDeal(propertyId: ObjectId) {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (values: CloseDealValues) =>
      call(propertiesEndpoints.closeDeal, {
        params: { id: propertyId },
        data: buildCloseDealFormData(values),
      }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: qk.myProperties() }),
  });

  return {
    submit: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
    reset: mutation.reset,
  };
}
