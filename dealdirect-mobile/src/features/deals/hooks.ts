/**
 * Deals: the lead seen from either side, with its visits, conversation,
 * agreement and close.
 *
 * Every write here returns the new `stage` (and the visit it touched), and
 * every write invalidates BOTH the deal detail and the deal list: the list
 * rows carry `stage`, `nextVisit` and `unread`, so a visit confirmed on the
 * detail screen has to move the row behind it too.
 */

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback } from 'react';

import { ApiError, call, dealsEndpoints, qk } from '@/api';
import { useAuth } from '@/auth';
import type { ObjectId } from '@/types/backend/common';
import type {
  AttestRequest,
  DealDetail,
  DealListRow,
  DealRole,
  ProposeVisitRequest,
  VisitAction,
  VisitFeedback,
} from '@/types/backend/deal';

const PAGE_SIZE = 20;

export interface DealListState {
  deals: DealListRow[];
  total: number | null;
  isLoading: boolean;
  isRefreshing: boolean;
  isFetchingMore: boolean;
  hasMore: boolean;
  error: unknown;
  refresh: () => void;
  loadMore: () => void;
  requiresAuth: boolean;
}

/**
 * The caller's deals, both roles unless narrowed. Sorted by `updatedAt`
 * desc server-side; sorted again here across pages so a row that moved
 * while paging does not sit out of order.
 */
export function useMyDeals(role?: DealRole): DealListState {
  const { status } = useAuth();
  const signedIn = status === 'authenticated';
  const params = role ? { role, limit: PAGE_SIZE } : { limit: PAGE_SIZE };

  const query = useInfiniteQuery({
    queryKey: qk.dealList(params),
    queryFn: ({ pageParam, signal }) =>
      call(dealsEndpoints.list, { data: { ...params, page: pageParam }, signal }),
    initialPageParam: 1,
    getNextPageParam: (last) =>
      last.pagination.page < last.pagination.pages ? last.pagination.page + 1 : undefined,
    enabled: signedIn,
    staleTime: 15_000,
  });

  const deals = (query.data?.pages.flatMap((page) => page.data) ?? []).sort(
    (a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
  );

  return {
    deals,
    total: query.data?.pages[0]?.pagination.total ?? null,
    isLoading: signedIn && query.isPending,
    isRefreshing: query.isRefetching && !query.isFetchingNextPage,
    isFetchingMore: query.isFetchingNextPage,
    hasMore: !!query.hasNextPage,
    error: query.error,
    refresh: () => void query.refetch(),
    loadMore: () => {
      if (query.hasNextPage && !query.isFetchingNextPage) void query.fetchNextPage();
    },
    requiresAuth: !signedIn,
  };
}

export interface DealState {
  deal: DealDetail | null;
  isLoading: boolean;
  isRefreshing: boolean;
  error: unknown;
  /** 403 NOT_A_PARTY: the deal exists and belongs to two other people. */
  isNotAParty: boolean;
  /** 404, or a malformed id. */
  isMissing: boolean;
  refresh: () => void;
}

export function useDeal(leadId: ObjectId | undefined): DealState {
  const { status } = useAuth();
  const signedIn = status === 'authenticated';

  const query = useQuery({
    queryKey: qk.dealDetail(leadId ?? ''),
    queryFn: async ({ signal }) => {
      const response = await call(dealsEndpoints.detail, { params: { leadId: leadId! }, signal });
      return response.data;
    },
    enabled: signedIn && !!leadId,
    staleTime: 15_000,
    retry: (count, error) =>
      // A 403 or 404 will not change on retry; a network blip might.
      count < 2 && !(error instanceof ApiError && (error.status === 403 || error.status === 404)),
  });

  const error = query.error;
  const apiError = error instanceof ApiError ? error : null;

  return {
    deal: query.data ?? null,
    isLoading: signedIn && !!leadId && query.isPending,
    isRefreshing: query.isRefetching,
    error,
    isNotAParty: apiError?.code === 'NOT_A_PARTY' || apiError?.status === 403,
    isMissing:
      !leadId ||
      apiError?.kind === 'notFound' ||
      apiError?.code === 'INVALID_ID' ||
      (apiError?.status === 400 && apiError.code === undefined),
    refresh: () => void query.refetch(),
  };
}

/**
 * Every deal write moves both the detail and the list rows, so the whole
 * `deals` domain is dropped: the detail is one key under it, and the lists
 * are keyed by their params, which a mutation has no business enumerating.
 * The owner's CRM list (`leads`) is dropped too, since a visit or a reply
 * changes `stage` and `firstOwnerResponseAt` on the same document.
 */
function useInvalidateDeal() {
  const queryClient = useQueryClient();
  return useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: qk.deals });
    void queryClient.invalidateQueries({ queryKey: qk.leads });
  }, [queryClient]);
}

export function useProposeVisit(leadId: ObjectId) {
  const invalidate = useInvalidateDeal();

  const mutation = useMutation({
    mutationFn: (body: ProposeVisitRequest) =>
      call(dealsEndpoints.proposeVisit, { params: { leadId }, data: body }),
    onSuccess: invalidate,
  });

  return {
    propose: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
    reset: mutation.reset,
  };
}

export function useUpdateVisit(leadId: ObjectId) {
  const invalidate = useInvalidateDeal();

  const mutation = useMutation({
    mutationFn: ({ visitId, action }: { visitId: ObjectId; action: VisitAction }) =>
      call(dealsEndpoints.updateVisit, { params: { leadId, visitId }, data: { action } }),
    onSuccess: invalidate,
  });

  return {
    update: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
    /** Which visit and action are in flight, so one button spins, not four. */
    pending: mutation.isPending ? mutation.variables : null,
  };
}

export function useVisitFeedback(leadId: ObjectId) {
  const invalidate = useInvalidateDeal();

  const mutation = useMutation({
    mutationFn: ({ visitId, feedback }: { visitId: ObjectId; feedback: VisitFeedback }) =>
      call(dealsEndpoints.visitFeedback, { params: { leadId, visitId }, data: { feedback } }),
    onSuccess: invalidate,
  });

  return {
    give: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
    pending: mutation.isPending ? mutation.variables : null,
  };
}

/**
 * Opens (or finds) the deal's conversation. 503 `CHAT_DISABLED` is a quiet
 * state the deal already reports as `chatEnabled: false`; the caller renders
 * the "not available" line rather than an error.
 */
export function useOpenConversation(leadId: ObjectId) {
  const invalidate = useInvalidateDeal();

  const mutation = useMutation({
    mutationFn: () => call(dealsEndpoints.openConversation, { params: { leadId } }),
    onSuccess: invalidate,
  });

  const error = mutation.error;

  return {
    open: mutation.mutateAsync,
    isPending: mutation.isPending,
    error,
    isDisabled: error instanceof ApiError && error.code === 'CHAT_DISABLED',
  };
}

export function useAttestClose(leadId: ObjectId) {
  const invalidate = useInvalidateDeal();

  const mutation = useMutation({
    mutationFn: (body: AttestRequest) =>
      call(dealsEndpoints.attest, { params: { leadId }, data: body }),
    onSuccess: invalidate,
  });

  return {
    attest: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
    pending: mutation.isPending ? mutation.variables : null,
  };
}
