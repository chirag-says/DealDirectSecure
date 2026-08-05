import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { qk } from '@/api';
import { fetchPropertyPage, type PropertySummary } from '@/features/properties';
import type { Collection } from './collections';

/**
 * Runs one collection and decides whether it is worth showing.
 *
 * The engine every discovery rail on Home shares. A collection describes what
 * it wants; this resolves it to rows and to a single `visible` boolean that the
 * caller uses to render or to disappear.
 */

/** Cards per rail. Beyond this the row is a feed, which is the browse screen. */
export const RAIL_LENGTH = 10;

/**
 * Ten minutes.
 *
 * Long, on purpose. Collections are editorial rather than live — "Luxury
 * Collection" does not change between one glance at Home and the next, and a
 * user who scrolls to the bottom and back must not re-spend the 20-per-minute
 * search budget to see the same nine rows. Pull-to-refresh remains the explicit
 * way to force fresh data, which is the right place for that decision.
 */
const COLLECTION_STALE_MS = 10 * 60_000;

export interface CollectionResult {
  items: PropertySummary[];
  /** True once there is enough to render. False means: render nothing at all. */
  visible: boolean;
  isLoading: boolean;
  /** Total matching on the server, before the client intent guard. */
  total: number;
}

export function useCollection(collection: Collection): CollectionResult {
  const query = useQuery({
    queryKey: qk.collection(collection.id, collection.params),
    queryFn: ({ signal }) => fetchPropertyPage(collection.params, signal),
    staleTime: COLLECTION_STALE_MS,
    // A failed rail should vanish, not retry three times into a rate limiter
    // that is already the binding constraint on this screen.
    retry: 1,
  });

  const items = useMemo(() => {
    const rows = query.data?.items ?? [];

    // The client-side intent guard. See the `intent` field on `Collection` for
    // why this duplicates a server filter: that filter is written but not yet
    // deployed, so today this is the only thing keeping a ₹20,000-a-month
    // rental out of "Luxury Collection".
    const scoped = collection.intent
      ? rows.filter((row) => row.intent === collection.intent)
      : rows;

    return scoped.slice(0, RAIL_LENGTH);
  }, [query.data, collection.intent]);

  /**
   * The gate reads the CLIENT-FILTERED length, never the envelope's `total`.
   *
   * `total` counts what the server matched, and the server is currently not
   * applying `listingType` at all, so for an intent-scoped collection it
   * reports the whole corpus. Gating on it would show a "Luxury Collection"
   * that survives the check and then renders one card.
   *
   * Counting what will actually be drawn is also the more conservative rule in
   * general: it cannot pass a collection whose rows were filtered away for any
   * reason, including reasons added later.
   */
  const visible = !query.isPending && items.length >= collection.minResults;

  return {
    items,
    visible,
    isLoading: query.isPending,
    total: query.data?.total ?? 0,
  };
}
