import { useCallback, useEffect, useState } from 'react';

import { ApiError, call, rewardsEndpoints } from '@/api';

/**
 * A one-shot Hubble SDK session: the config plus a fresh SSO token, combined
 * into the URL the WebView loads.
 *
 * ---------------------------------------------------------------------------
 * DELIBERATELY NOT A TANSTACK QUERY, AND THAT IS THE WHOLE POINT
 *
 * Every other read in this app goes through the query cache. These two must
 * not, for two independent reasons:
 *
 * 1. The token is SINGLE-USE and lives five minutes in an in-process Map on the
 *    server. A cached one is either already spent or already expired, and both
 *    fail the same way — the SDK loads, fails SSO, and emits `error` with
 *    nothing on screen explaining why. It has to be minted per open.
 *
 * 2. The config carries `appSecret`. This app persists successful queries to
 *    MMKV for offline reads (`api/persistence.ts`), so caching it would write a
 *    credential to disk, where it would outlive the session and survive a
 *    logout that never knew to clear it.
 *
 * Holding both in component state instead means they exist for exactly as long
 * as the screen does.
 */

export interface HubbleSession {
  /** The full SDK URL, ready to hand to a WebView. */
  url: string | null;
  isLoading: boolean;
  /** True when the backend has no Hubble credentials configured (503). */
  unavailable: boolean;
  error: ApiError | null;
  retry: () => void;
}

export function useHubbleSession(): HubbleSession {
  const [url, setUrl] = useState<string | null>(null);
  const [isLoading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [attempt, setAttempt] = useState(0);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  useEffect(() => {
    let cancelled = false;

    const open = async () => {
      setLoading(true);
      setError(null);
      setUnavailable(false);

      try {
        /*
          Sequential, not parallel, and on purpose. The token is the perishable
          half: minting it first and then discovering the config is missing
          would burn a five-minute credential on a screen that cannot open.
        */
        const configResponse = await call(rewardsEndpoints.hubbleConfig);
        if (cancelled) return;

        const tokenResponse = await call(rewardsEndpoints.hubbleToken);
        if (cancelled) return;

        const { clientId, appSecret, sdkBaseUrl, theme } = configResponse.config;

        // `wrap-plt=rn` is what tells the SDK it is inside a React Native
        // WebView rather than a browser; it changes how the SDK hands off to
        // UPI apps. Without it the payment step fails on device.
        const params = new URLSearchParams({
          clientId,
          appSecret,
          token: tokenResponse.token,
          'wrap-plt': 'rn',
        });
        if (theme) params.append('theme', theme);

        // `sdkBaseUrl` is documented with a trailing slash; tolerate either.
        const base = sdkBaseUrl.endsWith('/') ? sdkBaseUrl : `${sdkBaseUrl}/`;
        setUrl(`${base}?${params.toString()}`);
      } catch (caught) {
        if (cancelled) return;
        const apiError = caught instanceof ApiError ? caught : null;

        // 503 is "this deployment has no Hubble credentials", which is the
        // normal state in development. It is a different message from a
        // failure, because there is nothing for the user to retry.
        if (apiError?.status === 503) setUnavailable(true);
        else setError(apiError);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    void open();
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  return { url, isLoading, unavailable, error, retry };
}

/**
 * Hosts that stay INSIDE the WebView.
 *
 * Hubble's own domains and Razorpay's. Matching only the SDK base URL is the
 * documented mistake: it sends the payment gateway to the system browser, so
 * the user pays outside the WebView and the SDK never learns the result.
 *
 * A regex rather than `new URL()`, whose behaviour is unreliable under Hermes.
 */
export const HUBBLE_INTERNAL_URL =
  /^https:\/\/([a-z0-9-]+\.)*(myhubble\.money|razorpay\.com)(\/|$)/i;
