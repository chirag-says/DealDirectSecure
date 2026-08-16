import { NextResponse } from 'next/server';

/**
 * Next.js Middleware — Layer 1: Session Validation
 * 
 * Reads the `session_exists` companion cookie (non-HttpOnly, set by backend)
 * to determine authentication state at the edge — BEFORE any page renders.
 * 
 * - Sets `x-auth-hint` header so server/client components know auth state
 * - Redirects unauthenticated users away from protected routes
 * - Does NOT validate the actual session (that's the backend's job via checkAuth)
 */

// Routes that require authentication.
//
// Matching is `pathname === route || pathname.startsWith(route + '/')`, so each
// entry must be the exact private prefix. Two consequences worth keeping in
// mind when editing this list:
//
//   - '/rewards/dashboard' is listed, NOT '/rewards'. The rewards marketing
//     page at /rewards is public and must stay reachable by logged-out
//     visitors; protecting the parent would hide it.
//   - '/edit-property' covers '/edit-property/<id>' via the prefix rule.
//
// Three private routes were missing from this list and relied on their own
// in-content redirect alone, so a guest reached the page, rendered it, fired an
// authenticated request and got a 401 before being bounced. /my-bookings had no
// in-content guard either, so the 401 was all the user saw.
const PROTECTED_ROUTES = [
    '/profile',
    '/my-properties',
    '/add-property',
    '/edit-property',
    '/notifications',
    '/settings',
    '/saved-properties',
    '/my-bookings',
    '/rewards/dashboard',
];

// Routes that should redirect TO dashboard if already authenticated
const AUTH_ONLY_ROUTES = [
    // None for now — login page should still be accessible even when logged in
];

export function middleware(request) {
    const { pathname } = request.nextUrl;
    const sessionExists = request.cookies.get('session_exists')?.value === '1';

    const response = NextResponse.next();

    // Set auth hint header for downstream components
    response.headers.set('x-auth-hint', sessionExists ? '1' : '0');

    // Also set a cookie that client-side JS can read immediately on hydration
    // This survives across navigations (unlike headers)
    response.cookies.set('auth_hint', sessionExists ? '1' : '0', {
        httpOnly: false,
        secure: false,
        sameSite: 'lax',
        path: '/',
        maxAge: 60, // Short-lived — just for the initial render
    });

    // Redirect unauthenticated users from protected routes
    // Note: In cross-origin setups, session_exists may not be visible to middleware.
    // Only redirect if we're SURE there's no session (no session cookie AND no auth hint).
    if (!sessionExists) {
        const authHint = request.cookies.get('auth_hint')?.value;
        const definitelyNoSession = !authHint || authHint === '0';

        const isProtected = PROTECTED_ROUTES.some(route =>
            pathname === route || pathname.startsWith(route + '/')
        );

        if (isProtected && definitelyNoSession) {
            const loginUrl = new URL('/login', request.url);
            loginUrl.searchParams.set('from', pathname);
            loginUrl.searchParams.set('message', 'Please log in to access this page.');
            return NextResponse.redirect(loginUrl);
        }
    }

    return response;
}

export const config = {
    matcher: [
        /*
         * Match all request paths except:
         * - api routes (handled by backend)
         * - _next/static (static files)
         * - _next/image (image optimization)
         * - favicon.ico, icons, etc.
         */
        '/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)',
    ],
};
