/**
 * Blog reads.
 *
 * The one content surface with a real data source behind it — everything else
 * under `features/content` is static copy or a link out (see `pages.ts`).
 *
 * Two contract traps this layer absorbs, both from `docs/API_CONTRACT.md`:
 *
 *   - The free-text param is `q`, NOT `search` as in property search, and it
 *     runs a Mongo `$text` query, so it matches WHOLE WORDS. "apart" finds
 *     nothing that "apartment" would.
 *   - Posts are addressed by SLUG, not by id, and the detail response carries
 *     a `related` array alongside `data`.
 *
 * `/blogs` is not on the 20-per-minute search limiter (that covers
 * `/properties/search`, `/suggestions` and `/filter` only), so this is under no
 * pressure to defer or dedupe beyond ordinary caching.
 */

import { useInfiniteQuery, useQuery } from '@tanstack/react-query';

import { blogsEndpoints, call, qk } from '@/api';
import type { Blog } from '@/types/backend/misc';

const PAGE_SIZE = 10;

export function useBlogFeed(category?: string) {
  const query = useInfiniteQuery({
    queryKey: qk.blogList(category ?? ''),
    initialPageParam: 1,
    queryFn: ({ pageParam, signal }) =>
      call(blogsEndpoints.list, {
        data: { page: pageParam, limit: PAGE_SIZE, category: category || undefined },
        signal,
      }),
    getNextPageParam: (lastPage, allPages) => {
      const pages = lastPage.pagination?.pages ?? 0;
      const next = allPages.length + 1;
      return next <= pages ? next : undefined;
    },
    staleTime: 5 * 60_000,
  });

  // Deduped by id: a post published between two page fetches shifts the offset
  // and would otherwise appear twice, which React would then warn about.
  const seen = new Set<string>();
  const posts: Blog[] = [];
  for (const page of query.data?.pages ?? []) {
    for (const post of page.data ?? []) {
      if (seen.has(post._id)) continue;
      seen.add(post._id);
      posts.push(post);
    }
  }

  return {
    posts,
    total: query.data?.pages[0]?.pagination?.total ?? 0,
    isLoading: query.isPending,
    isRefreshing: query.isRefetching && !query.isFetchingNextPage,
    isLoadingMore: query.isFetchingNextPage,
    hasMore: query.hasNextPage,
    loadMore: () => {
      if (query.hasNextPage && !query.isFetchingNextPage) void query.fetchNextPage();
    },
    error: query.error,
    refresh: () => void query.refetch(),
  };
}

export function useBlogPost(slug: string | undefined) {
  const query = useQuery({
    queryKey: qk.blogPost(slug ?? ''),
    queryFn: ({ signal }) => call(blogsEndpoints.bySlug, { params: { slug: slug as string }, signal }),
    enabled: !!slug,
    staleTime: 10 * 60_000,
  });

  return {
    post: query.data?.data ?? null,
    related: query.data?.related ?? [],
    isLoading: !!slug && query.isPending,
    error: query.error,
    refresh: () => void query.refetch(),
  };
}
