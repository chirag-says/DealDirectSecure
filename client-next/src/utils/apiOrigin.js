/**
 * Origin of the backend API for this build, or null when none is configured.
 *
 * NEXT_PUBLIC_API_URL is the bare origin and NEXT_PUBLIC_API_BASE the older
 * name (both are read by utils/config.js). This is the one place that turns
 * them into an origin, so next.config.mjs (CSP connect-src) and app/layout.js
 * (preconnect) cannot drift apart.
 */
export function apiOriginFromEnv(env = process.env) {
  const raw = env.NEXT_PUBLIC_API_URL || env.NEXT_PUBLIC_API_BASE;
  if (!raw) return null;
  try {
    return new URL(raw).origin;
  } catch {
    return null;
  }
}
