/**
 * Reviews: written by the two parties to a verified close, read by anyone.
 *
 * Eligibility is per verification and per user, and it flips to "submitted"
 * the moment a review is written, so the mutation invalidates that one key
 * and the deal (whose `verification.review` block mirrors it) rather than
 * the public list, which does not change until the review PUBLISHES.
 */

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { call, qk, reviewsEndpoints } from '@/api';
import { useAuth } from '@/auth';
import type { ObjectId } from '@/types/backend/common';
import type { Review, ReviewSummary, SubmitReviewRequest } from '@/types/backend/review';

export function useReviewEligibility(verificationId: ObjectId | undefined) {
  const { status } = useAuth();
  const signedIn = status === 'authenticated';

  const query = useQuery({
    queryKey: qk.reviewEligibility(verificationId ?? ''),
    queryFn: async ({ signal }) => {
      const response = await call(reviewsEndpoints.eligibility, {
        params: { verificationId: verificationId! },
        signal,
      });
      return response.data;
    },
    enabled: signedIn && !!verificationId,
    staleTime: 15_000,
  });

  return {
    eligibility: query.data ?? null,
    isLoading: signedIn && !!verificationId && query.isPending,
    error: query.error,
    refresh: () => void query.refetch(),
  };
}

export function useSubmitReview() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (body: SubmitReviewRequest) => call(reviewsEndpoints.submit, { data: body }),
    onSuccess: (_response, body) => {
      void queryClient.invalidateQueries({ queryKey: qk.reviewEligibility(body.verificationId) });
      void queryClient.invalidateQueries({ queryKey: qk.deals });
    },
  });

  return {
    submit: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
  };
}

const USER_PAGE_SIZE = 10;

export interface UserReviewsState {
  reviews: Review[];
  summary: ReviewSummary | null;
  isLoading: boolean;
  isFetchingMore: boolean;
  hasMore: boolean;
  error: unknown;
  refresh: () => void;
  loadMore: () => void;
}

/** Public. Ten at a time, oldest pages kept, for the owner's reviews sheet. */
export function useUserReviews(userId: ObjectId | undefined, enabled = true): UserReviewsState {
  const query = useInfiniteQuery({
    queryKey: qk.reviewsForUser(userId ?? ''),
    queryFn: ({ pageParam, signal }) =>
      call(reviewsEndpoints.forUser, {
        params: { userId: userId! },
        data: { page: pageParam, limit: USER_PAGE_SIZE },
        signal,
      }),
    initialPageParam: 1,
    getNextPageParam: (last) =>
      last.pagination.page < last.pagination.pages ? last.pagination.page + 1 : undefined,
    enabled: enabled && !!userId,
    staleTime: 5 * 60_000,
  });

  return {
    reviews: query.data?.pages.flatMap((page) => page.data) ?? [],
    summary: query.data?.pages[0]?.summary ?? null,
    isLoading: enabled && !!userId && query.isPending,
    isFetchingMore: query.isFetchingNextPage,
    hasMore: !!query.hasNextPage,
    error: query.error,
    refresh: () => void query.refetch(),
    loadMore: () => {
      if (query.hasNextPage && !query.isFetchingNextPage) void query.fetchNextPage();
    },
  };
}
