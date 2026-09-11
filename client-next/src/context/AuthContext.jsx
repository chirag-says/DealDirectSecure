'use client';

/**
 * Auth Context - Cookie-Based Session Management (Next.js)
 * 
 * Provides authentication state management with:
 * - Automatic session validation on app load (fetches /api/users/me)
 * - Role-based access control helpers
 * - Graceful logout on 401 errors
 *
 * NO MFA HERE (removed in Phase 5.3). MFA is an admin feature, implemented in
 * the separate Admin app against /api/admin/mfa/*. The user API has never had
 * an MFA field, an MFA response code, or a /users/verify-mfa route, so the
 * flow this context used to carry could not run. The same was true of the
 * forced-password-change flow it sat beside.
 *
 * NEXT.JS MIGRATION NOTES:
 * - Added 'use client' directive (context uses hooks)
 * - Replaced useNavigate -> useRouter (from next/navigation)
 * - Replaced useLocation -> usePathname (from next/navigation)
 * - Replaced navigate('/path', { state: {...} }) -> router.push('/path?param=value')
 *
 * NOTE: Uses HttpOnly cookies for authentication - no tokens in localStorage
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import api, { authApi, setAuthErrorHandler } from '../utils/api';
import { setSentryUser } from '../utils/sentryUser';



// ============================================
// AUTH CONTEXT
// ============================================

const AuthContext = createContext(null);

// ============================================
// AUTH PROVIDER
// ============================================

export const AuthProvider = ({ children }) => {
    // User state - populated from /api/users/me on mount
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    // Owner property tracking - to hide "Register Property" button after posting
    const [ownerHasProperty, setOwnerHasProperty] = useState(false);

    const router = useRouter();
    const pathname = usePathname();

    // ============================================
    // CHECK AUTH STATUS ON MOUNT (Page Refresh)
    // ============================================

    /**
     * Check if owner already has a property posted
     * Used to hide "Register Property" button for owners who already listed
     */
    const checkOwnerProperty = useCallback(async (userData) => {
        if (userData?.role === 'owner') {
            try {
                const res = await api.get('/properties/my-properties');
                const count = typeof res.data?.count === 'number'
                    ? res.data.count
                    : Array.isArray(res.data?.data)
                        ? res.data.data.length
                        : 0;
                setOwnerHasProperty(count >= 1);
            } catch (err) {
                console.warn('Could not check owner properties:', err.message);
                setOwnerHasProperty(false);
            }
        } else {
            setOwnerHasProperty(false);
        }
    }, []);

    /**
     * Check if session cookie hint exists (non-HttpOnly companion cookie)
     * This allows instant detection of auth state without an API call.
     */
    const hasSessionHint = useCallback(() => {
        if (typeof document === 'undefined') return false;
        return document.cookie.split(';').some(c => c.trim().startsWith('session_exists='));
    }, []);

    /**
     * Fetches current user profile from /api/users/me on every page load.
     * HttpOnly cookies are sent automatically via withCredentials: true.
     * No localStorage token management needed.
     */
    const checkAuth = useCallback(async () => {
        try {
            // Layer 2: If no session cookie exists, skip the API call entirely.
            // This eliminates the "flash of unauthenticated content" for guests.
            if (!hasSessionHint()) {
                setUser(null);
                setOwnerHasProperty(false);
                setLoading(false);
                return;
            }

            setLoading(true);
            setError(null);

            const result = await authApi.checkAuth();

            if (result.authenticated && result.user) {
                setUser(result.user);
                // Check if owner has property
                await checkOwnerProperty(result.user);
            } else {
                setUser(null);
                setOwnerHasProperty(false);
            }
        } catch (err) {
            console.warn('Auth check failed:', err.message);
            setUser(null);
            setOwnerHasProperty(false);
        } finally {
            setLoading(false);
        }
    }, [checkOwnerProperty, hasSessionHint]);

    // Run auth check on mount (every page refresh)
    useEffect(() => {
        checkAuth();
    }, [checkAuth]);

    // Keep Sentry's user context in step with auth state.
    //
    // Keying off `user` rather than calling this from login() and logout()
    // covers every path that changes it — the mount-time checkAuth, a normal
    // login, a logout, and the 401 handler below that clears the session on
    // expiry. There is no route that can set a user and skip this.
    useEffect(() => {
        setSentryUser(user);
    }, [user]);

    // ============================================
    // HANDLE AUTH ERRORS (401/403)
    // ============================================

    useEffect(() => {
        setAuthErrorHandler((errorInfo) => {
            if (errorInfo.type === 'UNAUTHORIZED') {
                // Only redirect to login if user was previously authenticated (session expired)
                // Do NOT redirect if user was never logged in (e.g., visiting public pages)
                if (user) {
                    // Session expired - clear state and redirect
                    setUser(null);

                    // Redirect to login with message via query params (Next.js doesn't have navigation state)
                    const currentPath = typeof window !== 'undefined' ? window.location.pathname : '/';
                    router.replace(`/login?message=${encodeURIComponent(errorInfo.message || 'Your session has expired. Please log in again.')}&from=${encodeURIComponent(currentPath)}`);
                }
            } else if (errorInfo.type === 'FORBIDDEN') {
                // User doesn't have permission
                setError(errorInfo.message);
            }
        });

        return () => {
            setAuthErrorHandler(null);
        };
    }, [router, user]);

    // ============================================
    // AUTH ACTIONS
    // ============================================

    /**
     * Login handler. No localStorage token storage - uses HttpOnly cookies.
     */
    const login = async (email, password) => {
        try {
            setLoading(true);
            setError(null);

            const response = await authApi.login(email, password);

            if (response.success && response.user) {
                setUser(response.user);
                // Check if owner has property after login
                await checkOwnerProperty(response.user);
                return { success: true, user: response.user, reward: response.reward || null };
            }

            return { success: false, message: response.message || 'Login failed' };
        } catch (err) {
            const errorData = err.response?.data;

            const message = errorData?.message || 'Login failed. Please try again.';
            setError(message);
            return { success: false, message, errorData };
        } finally {
            setLoading(false);
        }
    };

    // `verifyMfa`, `changePasswordOnLogin` and `cancelPendingAuth` were removed
    // here (Phase 5.3). The first posted to /users/verify-mfa and the second to
    // /users/change-password-required. Neither route exists — userRoutes.js
    // registers no such path — so both calls would have 404ed, and nothing
    // could set the state that made them reachable in the first place.
    //
    // Users who need to change a password use the ordinary flows:
    // PUT /users/change-password when signed in, or the OTP reset when not.

    /**
     * Register handler - no localStorage token storage.
     */
    const register = async (userData) => {
        try {
            setLoading(true);
            setError(null);

            const response = await authApi.register(userData);

            if (response.success) {
                // Registration successful - may need OTP verification
                return { success: true, ...response };
            }

            return { success: false, message: response.message || 'Registration failed' };
        } catch (err) {
            const errorData = err.response?.data;

            const message = errorData?.message || 'Registration failed. Please try again.';
            setError(message);
            return { success: false, message, errorData };
        } finally {
            setLoading(false);
        }
    };

    /**
     * Google sign-in.
     *
     * `idToken` is the credential Google's button hands back. Returns
     * `{ linkRequired: true }` when the email already has a password account:
     * no session was issued and the caller must collect that password and call
     * `linkGoogle` with the same token. That refusal is a step in the flow, not
     * an error — see the note on `authApi.googleSignIn`.
     */
    const signInWithGoogle = async (idToken, referralCode) => {
        try {
            setLoading(true);
            setError(null);

            const response = await authApi.googleSignIn(idToken, referralCode);
            if (response.success && response.user) {
                setUser(response.user);
                await checkOwnerProperty(response.user);
                return { success: true, user: response.user };
            }
            return { success: false, message: response.message || 'Google sign-in failed' };
        } catch (err) {
            const errorData = err.response?.data;

            if (errorData?.code === 'GOOGLE_LINK_REQUIRED') {
                return { success: false, linkRequired: true, email: errorData.email };
            }

            const message = errorData?.message || 'Google sign-in failed. Please try again.';
            setError(message);
            return { success: false, message, errorData };
        } finally {
            setLoading(false);
        }
    };

    const linkGoogle = async (idToken, password) => {
        try {
            setLoading(true);
            setError(null);

            const response = await authApi.googleLink(idToken, password);
            if (response.success && response.user) {
                setUser(response.user);
                await checkOwnerProperty(response.user);
                return { success: true, user: response.user };
            }
            return { success: false, message: response.message || 'Could not connect Google' };
        } catch (err) {
            const errorData = err.response?.data;
            const message = errorData?.message || 'Could not connect Google. Please try again.';
            return { success: false, message, errorData };
        } finally {
            setLoading(false);
        }
    };

    // --- Just-in-time phone verification ---------------------------------

    const sendPhoneOtp = (phone) => authApi.sendPhoneOtp(phone);

    /**
     * Verifies the code and folds the updated user straight into state, so the
     * page behind the modal reflects the new `phoneVerified` without a refetch.
     */
    const verifyPhoneOtp = async (otp) => {
        const response = await authApi.verifyPhoneOtp(otp);
        if (response?.user) setUser(response.user);
        return response;
    };

    /**
     * Logout handler - clears session on server.
     * No localStorage cleanup needed for tokens - only user cache.
     */
    const logout = async () => {
        try {
            setLoading(true);
            await authApi.logout();
        } catch (err) {
            console.warn('Logout error:', err.message);
        } finally {
            // Always clear local state regardless of server response
            setUser(null);
            setLoading(false);

            // Redirect logic: 
            // If on a protected route, go to Home.
            // If on a public route, stay there.
            const protectedRoutes = [
                '/profile',
                '/saved-properties',
                '/notifications',
                '/agreements',
                '/add-property',
                '/edit-property',
                '/my-properties'
            ];

            const isProtected = protectedRoutes.some(route => pathname.startsWith(route));

            if (isProtected) {
                router.replace('/');
            }
            // Else stay on the same page
        }
    };

    /**
     * Update user state - for profile updates etc.
     * No localStorage storage needed.
     */
    const updateUser = (updatedUser) => {
        setUser(updatedUser);
    };

    // ============================================
    // ROLE HELPERS
    // ============================================

    const isAuthenticated = !!user;

    const isOwner = user?.role === 'owner';

    // 'user' and 'buyer' are equivalent roles (buyers/property seekers)
    const isBuyer = user?.role === 'user' || user?.role === 'buyer';

    /**
     * "This account is usable" — not proof of anything, despite the name.
     *
     * `registerUser` sets it after a PHONE OTP and `registerUserDirect` sets it
     * at creation with no proof at all, so it has never meant a verified email.
     * Kept because `loginUser` still answers 400 EMAIL_NOT_VERIFIED against it.
     * Use `phoneVerified` for any real decision.
     */
    const isVerified = user?.isVerified === true;

    /** Proved by entering an OTP sent to that number. What the gate reads. */
    const phoneVerified = user?.phoneVerified === true;

    const hasRole = (role) => {
        if (!user) return false;
        if (Array.isArray(role)) {
            // Handle 'buyer' and 'user' as equivalent
            const normalizedRoles = role.map(r => r === 'buyer' ? 'user' : r);
            const userRole = user.role === 'buyer' ? 'user' : user.role;
            return normalizedRoles.includes(userRole) || role.includes(user.role);
        }
        // Handle 'buyer' and 'user' as equivalent
        if (role === 'buyer' || role === 'user') {
            return user.role === 'buyer' || user.role === 'user';
        }
        return user.role === role;
    };

    const canAccessOwnerFeatures = isAuthenticated && (isOwner || user?.role === 'owner');

    /**
     * Who may reach the "post a listing" form.
     *
     * The `isOwner && isVerified` half is gone, deliberately. Posting a listing
     * is now what MAKES an account an owner — `ensureOwnerRole` grants the role
     * server-side at that moment, behind the phone check — so requiring the
     * role first would hide the button from exactly the people the new flow
     * exists to let through, and there would be no other way to get it.
     *
     * The one-listing cap is untouched. That is a separate product rule and it
     * stays until someone decides otherwise.
     *
     * The server is still the authority: `POST /properties/add` runs
     * `requirePhoneVerified` and `ensureOwnerRole` whatever this says.
     */
    const canAddProperty = isAuthenticated && !ownerHasProperty;

    // ============================================
    // CONTEXT VALUE
    // ============================================

    const value = {
        // State
        user,
        loading,
        error,

        // Auth status
        isAuthenticated,
        isOwner,
        isBuyer,
        isVerified,
        phoneVerified,
        ownerHasProperty,

        // Role helpers
        hasRole,
        canAccessOwnerFeatures,
        canAddProperty,

        // Actions
        login,
        register,
        signInWithGoogle,
        linkGoogle,
        sendPhoneOtp,
        verifyPhoneOtp,
        logout,
        checkAuth,
        updateUser,
        clearError: () => setError(null),
        refreshOwnerPropertyStatus: () => checkOwnerProperty(user),
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
};

// ============================================
// AUTH HOOK
// ============================================

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

// ProtectedRoute was removed here (Phase 5.3).
//
// It had zero call sites and was documented as deliberately not adopted:
// private routes are already guarded twice, by src/middleware.js at the edge
// and by each private *Content.jsx. Three of its five redirect targets
// (/verify-mfa, /change-password-required, /verify-email) are not routes, and
// two of its five branches depended on requiresMfa / requiresPasswordChange,
// which no user response has ever set.

export default AuthContext;
