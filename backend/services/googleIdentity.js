/**
 * Google ID token verification.
 *
 * The clients (Expo app, Next.js site) run the Google sign-in UI and receive an
 * ID token — a JWT signed by Google. This module is the only thing that decides
 * whether such a token is real. Nothing else in the codebase may read an email
 * out of a request body and believe it.
 *
 * Required ENV variables:
 *   GOOGLE_CLIENT_ID_WEB      - Web client ID. Used by client-next, and as the
 *                               Android `serverClientId`, so tokens minted on
 *                               Android carry THIS as their audience.
 *   GOOGLE_CLIENT_ID_ANDROID  - Android client ID (optional; see note below)
 *   GOOGLE_CLIENT_ID_IOS      - iOS client ID
 *
 * All configured IDs are passed as the accepted audience set. A token minted
 * for someone else's app is rejected, which is what stops an attacker replaying
 * a token they obtained from an unrelated Google integration.
 */
import { OAuth2Client } from "google-auth-library";

let client = null;

const getClient = () => {
  if (!client) client = new OAuth2Client();
  return client;
};

/**
 * Every client ID we are willing to accept a token for.
 *
 * Read at call time, not import time, so dotenv has loaded — the same pattern
 * smsService.js uses for the Equence credentials.
 */
const getAudience = () =>
  [
    process.env.GOOGLE_CLIENT_ID_WEB,
    process.env.GOOGLE_CLIENT_ID_ANDROID,
    process.env.GOOGLE_CLIENT_ID_IOS,
  ].filter(Boolean);

export const isGoogleAuthConfigured = () => getAudience().length > 0;

/**
 * Verify a Google ID token and return the identity it asserts.
 *
 * Resolves to `{ ok: true, identity }` or `{ ok: false, reason }`. It does not
 * throw on a bad token: an invalid token is an expected, routine outcome of a
 * public auth endpoint, not an exceptional condition, and making callers wrap
 * every call in try/catch to handle the normal case reads badly.
 */
export const verifyGoogleIdToken = async (idToken) => {
  if (!idToken || typeof idToken !== "string") {
    return { ok: false, reason: "MISSING_TOKEN" };
  }

  const audience = getAudience();
  if (audience.length === 0) {
    console.error("[GoogleAuth] No GOOGLE_CLIENT_ID_* configured; refusing to verify");
    return { ok: false, reason: "NOT_CONFIGURED" };
  }

  let payload;
  try {
    // Checks the signature against Google's rotating public keys, the issuer,
    // the expiry, and that `aud` is one of ours. Any failure throws.
    const ticket = await getClient().verifyIdToken({ idToken, audience });
    payload = ticket.getPayload();
  } catch (err) {
    console.warn("[GoogleAuth] Token verification failed:", err.message);
    return { ok: false, reason: "INVALID_TOKEN" };
  }

  if (!payload?.sub) {
    return { ok: false, reason: "INVALID_TOKEN" };
  }

  // Google can assert an identity whose email it has NOT confirmed, and in that
  // case it is not vouching for the inbox. Since the link decision in
  // authGoogleController leans entirely on Google having checked, an
  // unconfirmed email cannot be allowed through.
  if (payload.email_verified !== true || !payload.email) {
    return { ok: false, reason: "EMAIL_NOT_VERIFIED" };
  }

  return {
    ok: true,
    identity: {
      googleId: payload.sub,
      email: payload.email.toLowerCase().trim(),
      name: payload.name?.trim() || null,
      picture: payload.picture || null,
    },
  };
};
