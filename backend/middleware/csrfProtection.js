/**
 * CSRF Protection Middleware
 * 
 * Implements Double Submit Cookie pattern for CSRF protection:
 * 1. Backend generates a random CSRF token and sends it as a non-httpOnly cookie
 * 2. Frontend reads this cookie and includes it in X-CSRF-Token header
 * 3. Backend validates that the header matches the cookie
 * 
 * This works alongside HttpOnly session cookies for complete security.
 */

import crypto from 'crypto';

// ============================================
// CONFIGURATION
// ============================================

const CSRF_COOKIE_NAME = 'csrf_token';
const CSRF_HEADER_NAME = 'x-csrf-token';
const TOKEN_LENGTH = 32; // 256 bits
const TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

const isProduction = process.env.NODE_ENV === 'production';

// ============================================
// TOKEN GENERATION
// ============================================

/**
 * Generate a cryptographically secure CSRF token
 */
const generateToken = () => {
    return crypto.randomBytes(TOKEN_LENGTH).toString('hex');
};

// ============================================
// CSRF COOKIE SETTINGS
// ============================================

const getCookieOptions = () => ({
    httpOnly: false, // MUST be false so frontend JavaScript can read it
    secure: isProduction, // HTTPS only in production
    // IMPORTANT: For cross-origin deployments (frontend and backend on different domains),
    // we need 'none' with secure:true to allow cookies to be sent cross-origin
    sameSite: isProduction ? 'none' : 'lax',
    path: '/',
    maxAge: TOKEN_EXPIRY_MS,
    domain: process.env.COOKIE_DOMAIN || undefined,
});

// ============================================
// SET CSRF TOKEN
// ============================================

/**
 * Middleware to set CSRF token cookie on every request
 * This ensures the frontend always has a valid CSRF token
 */
export const setCsrfToken = (req, res, next) => {
    // Check if CSRF token already exists in cookies
    let token = req.cookies?.[CSRF_COOKIE_NAME];

    // Generate new token if none exists
    if (!token) {
        token = generateToken();
    }

    // Set/refresh the CSRF cookie
    res.cookie(CSRF_COOKIE_NAME, token, getCookieOptions());

    // Attach token to request for use in API responses
    req.csrfToken = token;

    next();
};

// ============================================
// CSRF TOKEN ENDPOINT
// ============================================

/**
 * Endpoint handler to get a fresh CSRF token
 * GET /api/csrf-token
 * 
 * SECURITY FIX: Token is NO LONGER returned in the JSON response body.
 * The token is ONLY sent via the non-HttpOnly cookie.
 * 
 * This properly implements the Double Submit Cookie pattern:
 * 1. Backend sets token in non-HttpOnly cookie (accessible to JavaScript)
 * 2. Frontend reads cookie and sends token in X-CSRF-Token header
 * 3. Backend validates that header matches cookie
 * 
 * Returning the token in the response body defeats the purpose of the pattern
 * as it could be captured by malicious scripts in certain attack scenarios.
 */
export const getCsrfTokenHandler = (req, res) => {
    // Generate fresh token
    const token = generateToken();

    // Set the cookie (non-HttpOnly so JavaScript can read it)
    res.cookie(CSRF_COOKIE_NAME, token, getCookieOptions());

    // ============================================
    // SECURITY FIX: Do NOT return token in response body
    // The frontend must read it from the cookie instead
    // ============================================
    res.status(200).json({
        success: true,
        message: 'CSRF token refreshed. Read the token from the csrf_token cookie.',
        // SECURITY: Token intentionally omitted from response body
        // csrfToken: token,  // <-- REMOVED for security
    });
};

// ============================================
// VALIDATE CSRF TOKEN
// ============================================

/**
 * Middleware to validate CSRF token on state-changing requests
 * Only applies to POST, PUT, PATCH, DELETE methods
 */
export const validateCsrfToken = (req, res, next) => {
    // Skip validation for safe methods
    const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
    if (safeMethods.includes(req.method)) {
        return next();
    }

    // Skip validation for webhook endpoints (they use their own authentication)
    if (req.path.includes('/webhook')) {
        return next();
    }

    // ============================================
    // CROSS-ORIGIN DEPLOYMENT: Skip CSRF for API requests
    // When frontend and backend are on different domains,
    // third-party cookies are blocked by browsers.
    // Security is maintained via:
    // 1. CORS whitelist (only allowed origins can make requests)
    // 2. HttpOnly session cookies with SameSite=None
    // 3. Preflight checks on all state-changing requests
    // ============================================
    if (req.path.startsWith('/api/')) {
        return next();
    }

    // ============================================
    // SECURITY FIX: Removed multipart/form-data exemption
    // 
    // VULNERABILITY FIXED: Previously, CSRF validation was skipped for all
    // multipart/form-data requests. This allowed attackers to craft malicious
    // forms that bypass CSRF protection on file upload endpoints.
    //
    // The frontend MUST include the CSRF token in the X-CSRF-Token header
    // for ALL state-changing requests, including file uploads.
    //
    // REMOVED CODE:
    // const contentType = req.headers['content-type'] || '';
    // if (contentType.includes('multipart/form-data')) {
    //     return next();
    // }
    // ============================================

    // Get token from cookie
    const cookieToken = req.cookies?.[CSRF_COOKIE_NAME];

    // Get token from header
    const headerToken = req.headers[CSRF_HEADER_NAME];

    // Validate: both must exist and match
    if (!cookieToken) {
        console.warn('[CSRF] No CSRF cookie found', { path: req.path, ip: req.ip });
        return res.status(403).json({
            success: false,
            message: 'CSRF validation failed. Please refresh the page and try again.',
            code: 'CSRF_MISSING_COOKIE',
        });
    }

    if (!headerToken) {
        console.warn('[CSRF] No CSRF header found', { path: req.path, ip: req.ip });
        return res.status(403).json({
            success: false,
            message: 'CSRF validation failed. Please refresh the page and try again.',
            code: 'CSRF_MISSING_HEADER',
        });
    }

    // Constant-time comparison to prevent timing attacks
    if (!crypto.timingSafeEqual(Buffer.from(cookieToken), Buffer.from(headerToken))) {
        console.warn('[CSRF] Token mismatch', { path: req.path, ip: req.ip });
        return res.status(403).json({
            success: false,
            message: 'CSRF validation failed. Please refresh the page and try again.',
            code: 'CSRF_TOKEN_MISMATCH',
        });
    }

    // Token is valid
    next();
};

// ============================================
// PHASE 1 CSRF GUARD — per-route enforcement
//
// WHY A SECOND VALIDATOR RATHER THAN FIXING validateCsrfToken
//
// validateCsrfToken above early-returns for every path starting with `/api/`,
// which is the entire API. It is left untouched so nothing that currently
// depends on its behaviour changes. This guard is applied deliberately, to a
// named list of routes (see server.js), which is what "document exactly which
// routes are protected" requires.
//
// TWO INDEPENDENT CHECKS
//
// 1. ORIGIN — browsers attach `Origin` to every cross-origin POST, including
//    plain <form> submissions, and page JavaScript cannot forge or strip it.
//    A mismatched Origin is therefore conclusive evidence of a cross-site
//    request and is rejected outright.
//
// 2. DOUBLE-SUBMIT TOKEN — the non-HttpOnly `csrf_token` cookie must equal the
//    `X-CSRF-Token` header. An attacker's page cannot read the cookie
//    (different origin) and cannot set custom headers on a form submission,
//    so it cannot satisfy this.
//
// WHY REQUESTS WITHOUT AN `Origin` HEADER ARE ALLOWED THROUGH
//
// CSRF is a browser-only attack: it depends on the browser automatically
// attaching cookies to a request the user did not intend. A client with no
// `Origin` (the Expo mobile app, Next.js SSR, curl, a webhook) is not a
// browser carrying ambient credentials, so there is nothing to forge. Adding
// a token requirement there would break the mobile app — whose api/client.ts
// deliberately omits CSRF plumbing — while defending against nothing.
//
// EMERGENCY OFF-SWITCH
//
// Set CSRF_ENFORCE=false in the environment to disable this instantly, without
// a redeploy, if it turns out to block a legitimate flow in production.
// ============================================

/**
 * Build the Phase 1 CSRF guard.
 * @param {string[]} allowedOrigins - the CORS whitelist from server.js
 */
export const requireCsrf = (allowedOrigins = []) => {
    const allowed = new Set(allowedOrigins.filter(Boolean));

    return (req, res, next) => {
        // Emergency kill switch.
        if (process.env.CSRF_ENFORCE === 'false') return next();

        // Safe methods never mutate state.
        if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

        const origin = req.headers.origin;

        // No Origin → not a browser request → CSRF does not apply. See above.
        if (!origin) return next();

        // ── Check 1: Origin must be on the whitelist ──────────────────────
        if (!allowed.has(origin)) {
            console.warn(`[CSRF] Blocked ${req.method} ${req.path} — untrusted origin: ${origin}`);
            return res.status(403).json({
                success: false,
                message: 'Request blocked for security reasons.',
                code: 'CSRF_ORIGIN_REJECTED',
            });
        }

        // ── Check 2: double-submit token ──────────────────────────────────
        const cookieToken = req.cookies?.[CSRF_COOKIE_NAME];
        const headerToken = req.headers[CSRF_HEADER_NAME];

        if (!cookieToken || !headerToken) {
            console.warn(
                `[CSRF] Blocked ${req.method} ${req.path} — missing ${!cookieToken ? 'cookie' : 'header'} (origin: ${origin})`
            );
            return res.status(403).json({
                success: false,
                message: 'Security token missing. Please refresh the page and try again.',
                code: !cookieToken ? 'CSRF_MISSING_COOKIE' : 'CSRF_MISSING_HEADER',
            });
        }

        // timingSafeEqual throws on length mismatch, so compare lengths first.
        const a = Buffer.from(String(cookieToken));
        const b = Buffer.from(String(headerToken));
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
            console.warn(`[CSRF] Blocked ${req.method} ${req.path} — token mismatch (origin: ${origin})`);
            return res.status(403).json({
                success: false,
                message: 'Security token invalid. Please refresh the page and try again.',
                code: 'CSRF_TOKEN_MISMATCH',
            });
        }

        return next();
    };
};

// ============================================
// COMBINED MIDDLEWARE
// ============================================

/**
 * Combined middleware that:
 * 1. Sets CSRF token cookie on all requests
 * 2. Validates CSRF token on state-changing requests
 */
export const csrfProtection = (req, res, next) => {
    // First, ensure CSRF cookie is set
    setCsrfToken(req, res, () => {
        // Then validate on state-changing requests
        validateCsrfToken(req, res, next);
    });
};

// Default export
export default {
    setCsrfToken,
    getCsrfTokenHandler,
    validateCsrfToken,
    csrfProtection,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
};
