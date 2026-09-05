import { useQuery } from '@tanstack/react-query';

import { ApiError, call, localitiesEndpoints, qk } from '@/api';
import type {
  LocalityDetail,
  LocalityListingType,
  LocalitySummary,
  PriceGuidance,
} from '@/types/backend/locality';

/**
 * Locality price data.
 *
 * ---------------------------------------------------------------------------
 * BELOW THE SAMPLE FLOOR IS AN ANSWER, NOT A FAILURE
 *
 * The server publishes nothing for a locality with fewer than five listings,
 * and says so with a 404 on the detail route and a null body on guidance.
 * Both mean the same thing: there is not enough here to say anything honest.
 * These hooks separate that from a real failure (`isMissing` versus `error`)
 * so the screens can render an empty state for one and a retry for the other.
 *
 * ---------------------------------------------------------------------------
 * IT IS A QUARTERLY AGGREGATE, SO IT IS CACHED LIKE ONE
 *
 * The numbers move four times a year. An hour of `staleTime` is still two
 * thousand times more often than the data changes, and it means switching
 * between sale and rent, or coming back from a listing, costs nothing.
 */

const QUARTERLY_STALE_TIME = 60 * 60_000;

export interface LocalityDetailQuery {
  locality: LocalityDetail | undefined;
  isLoading: boolean;
  /** Below the sample floor. Render an empty state, never an error. */
  isMissing: boolean;
  error: unknown;
  refresh: () => void;
}

export function useLocality(
  slug: string | undefined,
  listingType: LocalityListingType
): LocalityDetailQuery {
  const query = useQuery({
    queryKey: qk.locality(slug ?? '', listingType),
    queryFn: async ({ signal }) => {
      const response = await call(localitiesEndpoints.detail, {
        params: { slug: slug as string },
        data: { listingType },
        signal,
      });
      return response.data;
    },
    enabled: !!slug,
    staleTime: QUARTERLY_STALE_TIME,
    // A 404 here is a verdict, not a hiccup. Retrying it three times just
    // makes the empty state take a second and a half longer to appear.
    retry: (failureCount, error) =>
      error instanceof ApiError && error.kind === 'notFound' ? false : failureCount < 2,
  });

  const error = query.error;
  const isMissing = error instanceof ApiError && error.kind === 'notFound';

  return {
    locality: query.data,
    isLoading: query.isPending && !!slug,
    isMissing,
    error: isMissing ? null : error,
    refresh: () => void query.refetch(),
  };
}

export interface LocalityListQuery {
  items: LocalitySummary[];
  sampleFloor: number;
  isLoading: boolean;
  error: unknown;
}

/**
 * Localities with published data, optionally narrowed to a city.
 *
 * Not currently rendered by any screen — the locality page is reached from a
 * listing, which is where the question comes up. Kept because it is the whole
 * of the list endpoint and a browse-by-locality surface is one component away.
 */
export function useLocalities(params: {
  city?: string;
  listingType?: LocalityListingType;
  limit?: number;
  enabled?: boolean;
}): LocalityListQuery {
  const { enabled = true, ...request } = params;

  const query = useQuery({
    queryKey: qk.localities(request),
    queryFn: ({ signal }) => call(localitiesEndpoints.list, { data: request, signal }),
    enabled,
    staleTime: QUARTERLY_STALE_TIME,
  });

  return {
    items: query.data?.data ?? [],
    sampleFloor: query.data?.sampleFloor ?? 0,
    isLoading: query.isPending && enabled,
    error: query.error,
  };
}

export interface PriceGuidanceQuery {
  guidance: PriceGuidance | null;
  isLoading: boolean;
}

/**
 * The one comparison line the listing form shows while an owner types a price.
 *
 * Disabled until both city and locality are present, because without them the
 * server answers 400 LOCATION_REQUIRED and the request is pure waste. The
 * CALLER debounces the inputs — this hook only decides whether there is
 * anything to ask.
 *
 * A null body is a successful answer meaning "nothing to compare against", and
 * it is cached like any other, so a locality with no data is asked about once.
 * There is no error surface at all: a guidance line that fails to load simply
 * does not appear, and the form never mentions it.
 */
export function usePriceGuidance(params: {
  city?: string;
  locality?: string;
  listingType?: LocalityListingType;
  bhk?: string;
}): PriceGuidanceQuery {
  const city = params.city?.trim();
  const locality = params.locality?.trim();
  const enabled = !!city && !!locality;

  const request = {
    city,
    locality,
    listingType: params.listingType,
    bhk: params.bhk?.trim() || undefined,
  };

  const query = useQuery({
    queryKey: qk.priceGuidance(request),
    queryFn: async ({ signal }) => {
      const response = await call(localitiesEndpoints.guidance, { data: request, signal });
      return response.data ?? null;
    },
    enabled,
    staleTime: QUARTERLY_STALE_TIME,
    retry: false,
  });

  return {
    guidance: query.data ?? null,
    isLoading: enabled && query.isPending,
  };
}
