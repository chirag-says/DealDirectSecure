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
 * Public website origin. Overridable, but no longer optional.
 *
 * Used for shareable listing links and for the Privacy policy and Terms links
 * on the Support screen.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS NOW HAS A DEFAULT — fixed 2026-08-24
 *
 * It was `undefined` unless `EXPO_PUBLIC_WEB_URL` was set, on the reasoning
 * that a guessed domain yields a link that looks right and 404s. Sound, except
 * that the variable is set in NO environment — not in `.env`, and not in any
 * of the three `eas.json` profiles — so the consequence was that `LEGAL_LINKS`
 * returned `[]` and the Support screen silently dropped the section containing
 * the Privacy policy and Terms. Every build shipped with no legal links at all,
 * which both app stores reject.
 *
 * The domain was never actually a guess: the backend's own config uses
 * `CLIENT_URL=https://dealdirect.in`, and it issues the session cookie scoped
 * to `.dealdirect.in`, so the apex is already load-bearing in this app. Naming
 * it here is recording a fact the system depends on, not inventing one. The env
 * override survives for staging.
 */
const DEFAULT_WEB_URL = 'https://dealdirect.in';

export const WEB_URL: string = process.env.EXPO_PUBLIC_WEB_URL?.trim()
  ? process.env.EXPO_PUBLIC_WEB_URL.trim().replace(/\/+$/, '')
  : DEFAULT_WEB_URL;

/**
 * Google OAuth client IDs.
 *
 * OPTIONAL, and optional on purpose: unset, `isGoogleSignInConfigured()` is
 * false, the Google buttons are not rendered, and email + password continues to
 * work exactly as before. A build without these is a usable build, not a broken
 * one — which is what lets the backend and the app ship on separate days.
 *
 * WEB is the one that must always be set, on every platform including Android.
 * The Android SDK uses it as `webClientId` to mint a token audienced to our
 * backend; without it `idToken` comes back null and the failure presents as a
 * server problem rather than a configuration one.
 *
 * A client ID is public by construction — it identifies the app to Google and
 * authorises nothing on its own — so it belongs with the other EXPO_PUBLIC_
 * values rather than in a secret store.
 */
export const GOOGLE_WEB_CLIENT_ID: string =
  process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID?.trim() ?? '';

export const GOOGLE_IOS_CLIENT_ID: string =
  process.env.EXPO_PUBLIC_GOOGLE_IOS_CLIENT_ID?.trim() ?? '';

export const APP_VERSION = Constants.expoConfig?.version ?? '0.0.0';

export const IS_DEV = __DEV__;

export const config = {
  API_URL,
  SOCKET_URL,
  WEB_URL,
  GOOGLE_WEB_CLIENT_ID,
  GOOGLE_IOS_CLIENT_ID,
  APP_VERSION,
  IS_DEV,
} as const;
