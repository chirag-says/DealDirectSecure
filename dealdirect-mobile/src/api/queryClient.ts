import { QueryClient } from '@tanstack/react-query';

import { ApiError, isSessionFatal } from './errors';

/**
 * TanStack Query configuration.
 *
 * The retry policy is shaped by the backend's rate limits rather than by
 * generic defaults. Limits are keyed on IP, and on Indian carrier NAT many
 * subscribers share one address, so a client that retries eagerly spends a
 * budget it shares with strangers. Global is 500 per 15 minutes and search is
 * 20 per minute.
 *
 * Cache persistence to MMKV is NOT wired here — that lives at the provider
 * level (`app/_layout.tsx`'s `PersistQueryClientProvider`, `src/api/
 * persistence.ts`), M12. This factory stays persistence-agnostic so a test or
 * a future non-persisted context can still construct a plain client.
 */

const MAX_RETRIES = 2;

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 60_000,
        gcTime: 15 * 60_000,
        retry: (failureCount, error) => {
          if (failureCount >= MAX_RETRIES) return false;
          if (!(error instanceof ApiError)) return false;

          // A dead session never recovers by asking again.
          if (isSessionFatal(error)) return false;

          // Neither does a 403, a 404, or a body the server rejected.
          if (['forbidden', 'notFound', 'validation'].includes(error.kind)) return false;

          // Retrying a rate limit is what caused it. Back off and let the user
          // decide, honouring the reset the server sent.
          if (error.kind === 'rateLimited') return false;

          return true;
        },
        retryDelay: (attempt) => Math.min(1000 * 2 ** attempt, 8000),
        refetchOnWindowFocus: false,
        refetchOnReconnect: true,
      },
      mutations: {
        // Mutations are never retried automatically. Nothing on this backend
        // implements idempotency keys except agreement generation, so a
        // duplicated POST can create a second property, lead or booking.
        retry: false,
      },
    },
  });
}
