import axios, { type AxiosInstance, type InternalAxiosRequestConfig } from 'axios';

import { API_URL } from '@/config/env';
import { normalizeError } from './errors';
import { sessionHeaders } from './userAgent';

/**
 * The DealDirect API client.
 *
 * Two instances, because one timeout cannot serve both cases: JSON calls should
 * fail fast, while a 10 MB image upload over Indian cellular legitimately takes
 * minutes and a 30-second ceiling would break listing creation.
 *
 * ---------------------------------------------------------------------------
 * NOTABLY ABSENT: CSRF. And the reason matters — corrected 2026-08-13.
 *
 * This used to say "no route enforces it", which was true of the deployed
 * backend and is no longer true of the source. `validateCsrfToken` is indeed
 * commented out, but `requireCsrf` (`middleware/csrfProtection.js`) is applied
 * to twelve named write routes, including `POST /properties/add`,
 * `POST /properties/interested/:id` and `PUT /properties/my-properties/:id`.
 *
 * This client still builds no CSRF plumbing, and that is still correct — but
 * because it is EXEMPT, not because nothing enforces it. `requireCsrf` returns
 * `next()` immediately for a request carrying no `Origin` header, on the
 * grounds that CSRF is a browser-only attack and a native client has no
 * ambient credentials to forge. React Native's networking sends no `Origin`.
 *
 * THE CONSTRAINT THAT FOLLOWS: no DealDirect API call may ever originate from
 * a WebView, from `react-native-web`, or from anything else that attaches an
 * `Origin` header — those twelve writes would 403 with
 * `CSRF_ORIGIN_REJECTED`. This binds the pending map work
 * (`react-native-webview`) and any future Hubble rewards WebView: map tiles
 * and Nominatim are fine, being different hosts carrying no cookie, but a
 * WebView must not call THIS API. Fetch in the app, pass the result in.
 */

/** Correlates a client-side report with a backend log line. */
function requestId(): string {
  return `m-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * Called when a response comes back that may carry a Set-Cookie. Wired up by
 * the auth layer to avoid a circular import between transport and session.
 */
let onResponse: (() => void) | null = null;

export function setResponseObserver(observer: (() => void) | null): void {
  onResponse = observer;
}

function attachInterceptors(instance: AxiosInstance): AxiosInstance {
  instance.interceptors.request.use((config: InternalAxiosRequestConfig) => {
    // The User-Agent here is load-bearing for session integrity: the backend
    // fingerprints the session from it and revokes on drift. See userAgent.ts.
    const headers = sessionHeaders();
    for (const [key, value] of Object.entries(headers)) {
      config.headers.set(key, value);
    }
    config.headers.set('X-Request-ID', requestId());
    return config;
  });

  instance.interceptors.response.use(
    (response) => {
      onResponse?.();
      return response;
    },
    (error) => {
      // A 401 may still have cleared cookies server-side, so the observer runs
      // on failures too.
      onResponse?.();
      return Promise.reject(normalizeError(error));
    }
  );

  return instance;
}

/** JSON calls. */
export const apiClient = attachInterceptors(
  axios.create({
    baseURL: API_URL,
    withCredentials: true,
    timeout: 30_000,
    headers: { 'Content-Type': 'application/json' },
  })
);

/**
 * Multipart uploads.
 *
 * `Content-Type` is intentionally unset: axios must derive it so the multipart
 * boundary is generated. Setting it by hand produces a body multer cannot parse.
 */
export const uploadClient = attachInterceptors(
  axios.create({
    baseURL: API_URL,
    withCredentials: true,
    timeout: 120_000,
  })
);
