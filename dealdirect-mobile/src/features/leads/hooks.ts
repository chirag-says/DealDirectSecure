/**
 * Owner's inbound pipeline: leads and analytics.
 *
 * Every route here sits behind `authMiddleware` only — there is no
 * owner-role gate at the route layer, so a signed-in buyer hitting these
 * screens would get an empty list rather than a 403. Screens still only link
 * here from the owner surface (`app/(tabs)/profile.tsx`'s `OwnerCard`), which
 * is itself gated on `user.role === 'owner'`.
 */

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useState } from 'react';

import { call, leadsEndpoints, qk } from '@/api';
import type { ObjectId } from '@/types/backend/common';
import type {
  AddContactHistoryRequest,
  Lead,
  LeadStatus,
  UpdateLeadStatusRequest,
} from '@/types/backend/lead';

const PAGE_SIZE = 20;

/**
 * The owner's leads, optionally filtered by status.
 *
 * `enabled` defaults to true for the owner screens, which are all behind
 * `OwnerOnly`. Home passes the role check in, because it renders for buyers and
 * guests and must not request leads on their behalf. See the same note on
 * `useMyProperties`.
 */
export function useLeads(status?: LeadStatus, options?: { enabled?: boolean }) {
  const enabled = options?.enabled ?? true;
  const params = status ? { status, limit: PAGE_SIZE } : { limit: PAGE_SIZE };

  const query = useInfiniteQuery({
    queryKey: qk.leadList(params),
    queryFn: async ({ pageParam }) => {
      const response = await call(leadsEndpoints.list, { data: { ...params, page: pageParam } });
      return response;
    },
    initialPageParam: 1,
    getNextPageParam: (lastPage) =>
      lastPage.pagination.page < lastPage.pagination.pages ? lastPage.pagination.page + 1 : undefined,
    enabled,
    staleTime: 15_000,
  });

  const leads = query.data?.pages.flatMap((page) => page.data) ?? [];
  const stats = query.data?.pages[0]?.stats;
  /**
   * The server's count for this filter, not `leads.length`.
   *
   * `leads` holds however many pages have been fetched, so counting it reports
   * "20" for an owner with sixty. `pagination.total` is the figure the server
   * computed for the same query, and it is the only honest one to display.
   *
   * `stats` is typed `unknown` deliberately — the endpoint's shape for it is
   * not pinned down — so anything wanting a number should read this instead of
   * reaching into it.
   */
  const total = query.data?.pages[0]?.pagination.total ?? null;

  return {
    leads,
    stats,
    total,
    isLoading: enabled && query.isPending,
    isRefreshing: query.isRefetching && !query.isFetchingNextPage,
    isFetchingMore: query.isFetchingNextPage,
    hasMore: query.hasNextPage,
    error: query.error,
    refresh: () => void query.refetch(),
    loadMore: () => {
      if (query.hasNextPage && !query.isFetchingNextPage) void query.fetchNextPage();
    },
  };
}

export function useLeadAnalytics(days = 30) {
  const query = useQuery({
    queryKey: qk.leadAnalytics(days),
    queryFn: async () => {
      const response = await call(leadsEndpoints.analytics, { data: { days } });
      return response.data;
    },
    staleTime: 60_000,
  });

  return {
    analytics: query.data ?? null,
    isLoading: query.isPending,
    error: query.error,
    refresh: () => void query.refetch(),
  };
}

/** Invalidates every lead list, regardless of which status filter it was built with. */
function invalidateLeadLists(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: qk.leads });
}

export function useUpdateLeadStatus() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: ({ id, ...body }: UpdateLeadStatusRequest & { id: ObjectId }) =>
      call(leadsEndpoints.updateStatus, { params: { id }, data: body }),
    onSuccess: () => invalidateLeadLists(queryClient),
  });

  return {
    updateStatus: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

export function useMarkLeadViewed() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (id: ObjectId) => call(leadsEndpoints.markViewed, { params: { id } }),
    onSuccess: () => invalidateLeadLists(queryClient),
  });

  return {
    markViewed: useCallback((id: ObjectId) => mutation.mutate(id), [mutation]),
  };
}

export function useAddContactHistory() {
  const queryClient = useQueryClient();
  const [lastLeadId, setLastLeadId] = useState<ObjectId | null>(null);

  const mutation = useMutation({
    mutationFn: ({ id, ...body }: AddContactHistoryRequest & { id: ObjectId }) => {
      setLastLeadId(id);
      return call(leadsEndpoints.addContactHistory, { params: { id }, data: body });
    },
    onSuccess: (response) => {
      invalidateLeadLists(queryClient);
      return response;
    },
  });

  return {
    addContact: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
    lastLeadId,
  };
}

export type { Lead, LeadStatus };
