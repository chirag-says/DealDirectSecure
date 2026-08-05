/**
 * Environment configuration.
 *
 * Everything here is PUBLIC. `EXPO_PUBLIC_*` values are inlined into the
 * JavaScript bundle at build time and are readable by anyone who unzips the
 * app, so only non-secret values belong in this file. API keys that must stay
 * private are restricted by bundle identifier at the provider, never hidden in
 * the bundle.
 *
 * Values are validated once at module load and fail loudly rather than
 * producing a request to `undefined/api/...` at runtime.
 */

import Constants from 'expo-constants';

const readRequired = (key: string, value: string | undefined): string => {
  if (!value || value.trim().length === 0) {
    throw new Error(
      `[config] Missing required environment variable ${key}. ` +
        `Copy .env.example to .env and fill it in before starting the app.`
    );
  }
  return value.replace(/\/+$/, '');
};

/**
 * Base URL including the `/api` prefix, e.g. `https://api.dealdirect.in/api`.
 *
 * The backend mounts every route under `/api` (see backend/server.js), except
 * `/health` and `/ping`. Endpoint paths in src/api/endpoints are declared
 * WITHOUT the `/api` prefix and are resolved against this base.
 */
export const API_URL = readRequired('EXPO_PUBLIC_API_URL', process.env.EXPO_PUBLIC_API_URL);

/**
 * Socket.IO origin WITHOUT the `/api` suffix, e.g. `https://api.dealdirect.in`.
 *
 * Socket.IO attaches at the server root, not under `/api`, which is why this is
 * a separate value rather than being derived by trimming API_URL.
 */
export const SOCKET_URL = readRequired(
  'EXPO_PUBLIC_SOCKET_URL',
  process.env.EXPO_PUBLIC_SOCKET_URL
);

/**
 * App version, surfaced to the backend as the `X-App-Version` header.
 *
 * This value must NEVER be interpolated into the User-Agent string. The backend
 * derives a session fingerprint from the User-Agent, and a fingerprint change
 * revokes the session, so a version bump in that header would log out every
 * user on release day. Version belongs in its own header, which the fingerprint
 * ignores.
 */
/**
 * Public website origin, e.g. `https://dealdirect.in`. OPTIONAL.
 *
 * Used only to build shareable links (`/properties/:id` on the website). It is
 * optional and has NO fallback on purpose: a guessed domain produces a link
 * that looks right and 404s, which is worse than sharing the listing's details
 * with no link at all. Every caller must handle `undefined`.
 */
export const WEB_URL: string | undefined = process.env.EXPO_PUBLIC_WEB_URL?.trim()
  ? process.env.EXPO_PUBLIC_WEB_URL.trim().replace(/\/+$/, '')
  : undefined;

export const APP_VERSION = Constants.expoConfig?.version ?? '0.0.0';

export const IS_DEV = __DEV__;

export const config = {
  API_URL,
  SOCKET_URL,
  WEB_URL,
  APP_VERSION,
  IS_DEV,
} as const;
