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
 * Notably absent: CSRF. `validateCsrfToken` is commented out at
 * backend/server.js:763 and no route enforces it. Building that plumbing would
 * be dead code that a later reader mistakes for load-bearing.
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
