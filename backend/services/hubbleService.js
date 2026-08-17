/**
 * Hubble SDK Service — DealDirect Rewards
 * Handles SSO token generation for Hubble gift card integration.
 *
 * Flow (Classic SSO):
 *  1. Frontend calls GET /api/rewards/hubble/token to get a short-lived token
 *  2. Frontend passes this token in the Hubble SDK iframe URL
 *  3. Hubble calls POST /api/rewards/hubble/sso with { token }
 *  4. We validate the token and return user details to Hubble
 */

import crypto from "crypto";

// In-memory token store (token → { userId, expiresAt })
// In production, consider Redis for multi-instance deployments
const tokenStore = new Map();

// Cleanup expired tokens every 5 minutes.
//
// unref() so this timer alone does not hold the event loop open. In the running
// server the listening socket keeps the process alive, so the sweep still fires
// exactly as before; the difference only shows in a process with no server
// handle, such as the integration test runner, which would otherwise never
// exit and every suite would fail on timeout rather than on its assertions.
const tokenCleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [token, data] of tokenStore.entries()) {
    if (now > data.expiresAt) {
      tokenStore.delete(token);
    }
  }
}, 5 * 60 * 1000);
tokenCleanupTimer.unref?.();

/**
 * Generate a short-lived, single-use SSO token for a user.
 * Token expires in 5 minutes and can only be used once.
 *
 * @param {Object} user - The authenticated DealDirect user
 * @returns {string} The generated token
 */
export const generateHubbleToken = (user) => {
  // Generate a cryptographically secure random token
  const token = crypto.randomBytes(32).toString("hex");

  // Store with user data and 5-minute expiry
  tokenStore.set(token, {
    userId: user._id.toString(),
    name: user.name || "",
    email: user.email || "",
    phone: user.phone || "",
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
  });

  return token;
};

/**
 * Validate and consume an SSO token.
 * Returns user data if valid, null if invalid/expired/already used.
 * Token is deleted after validation (single-use).
 *
 * @param {string} token - The token to validate
 * @returns {Object|null} User data or null
 */
export const validateHubbleToken = (token) => {
  if (!token || typeof token !== "string") return null;

  const data = tokenStore.get(token);
  if (!data) return null;

  // Check expiry
  if (Date.now() > data.expiresAt) {
    tokenStore.delete(token);
    return null;
  }

  // Single-use: delete after validation
  tokenStore.delete(token);

  return {
    userId: data.userId,
    firstName: data.name?.split(" ")[0] || "",
    lastName: data.name?.split(" ").slice(1).join(" ") || "",
    email: data.email,
    phoneNumber: data.phone,
  };
};

/**
 * Check if Hubble is configured (env vars present)
 */
export const isHubbleConfigured = () => {
  return !!(
    process.env.HUBBLE_CLIENT_ID &&
    process.env.HUBBLE_APP_SECRET
  );
};
