'use client';

/**
 * Auth Context - Cookie-Based Session Management (Next.js)
 * 
 * Provides authentication state management with:
 * - Automatic session validation on app load (fetches /api/users/me)
 * - Role-based access control helpers
 * - Graceful logout on 401 errors
 * - MFA and password change requirement handling
 * 
 * NEXT.JS MIGRATION NOTES:
 * - Added 'use client' directive (context uses hooks)
 * - Replaced useNavigate -> useRouter (from next/navigation)
 * - Replaced useLocation -> usePathname (from next/navigation)
 * - Replaced navigate('/path', { state: {...} }) -> router.push('/path?param=value')
 * - ProtectedRoute rewritten to use useRouter for redirects
 * 
 * NOTE: Uses HttpOnly cookies for authentication - no tokens in localStorage
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import api, { authApi, setAuthErrorHandler } from '../utils/api';



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

    // Special auth states for MFA and password requirements
    const [requiresMfa, setRequiresMfa] = useState(false);
    const [requiresPasswordChange, setRequiresPasswordChange] = useState(false);
    const [pendingAuthData, setPendingAuthData] = useState(null);

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
                // Check if user needs to change password
                if (result.user.requiresPasswordChange) {
                    setRequiresPasswordChange(true);
                }
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
                    setRequiresMfa(false);
                    setRequiresPasswordChange(false);
                    setPendingAuthData(null);

                    // Redirect to login with message via query params (Next.js doesn't have navigation state)
                    const currentPath = typeof window !== 'undefined' ? window.location.pathname : '/';
                    router.replace(`/login?message=${encodeURIComponent(errorInfo.message || 'Your session has expired. Please log in again.')}&from=${encodeURIComponent(currentPath)}`);
                } else {
                    // User was never logged in - just clear any stale state, don't redirect
                    setRequiresMfa(false);
                    setRequiresPasswordChange(false);
                    setPendingAuthData(null);
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
     * Login handler with MFA and password change requirement support.
     * No localStorage token storage - uses HttpOnly cookies.
     */
    const login = async (email, password) => {
        try {
            setLoading(true);
            setError(null);
            setRequiresMfa(false);
            setRequiresPasswordChange(false);

            const response = await authApi.login(email, password);

            // Handle MFA requirement
            if (response.requiresMfa || response.code === 'REQUIRES_MFA') {
                setRequiresMfa(true);
                setPendingAuthData({ email, mfaToken: response.mfaToken });
                return {
                    success: false,
                    requiresMfa: true,
                    message: response.message || 'Please complete MFA verification'
                };
            }

            // Handle password change requirement
            if (response.passwordChangeRequired || response.code === 'PASSWORD_CHANGE_REQUIRED') {
                setRequiresPasswordChange(true);
                setPendingAuthData({ email, tempToken: response.tempToken });
                return {
                    success: false,
                    passwordChangeRequired: true,
                    message: response.message || 'You must change your password before continuing'
                };
            }

            if (response.success && response.user) {
                setUser(response.user);
                // Check if owner has property after login
                await checkOwnerProperty(response.user);
                return { success: true, user: response.user, reward: response.reward || null };
            }

            return { success: false, message: response.message || 'Login failed' };
        } catch (err) {
            const errorData = err.response?.data;

            // Handle MFA requirement from error response
            if (errorData?.requiresMfa || errorData?.code === 'REQUIRES_MFA') {
                setRequiresMfa(true);
                setPendingAuthData({ email, mfaToken: errorData.mfaToken });
                return {
                    success: false,
                    requiresMfa: true,
                    message: errorData.message || 'Please complete MFA verification'
                };
            }

            // Handle password change requirement from error response
            if (errorData?.passwordChangeRequired || errorData?.code === 'PASSWORD_CHANGE_REQUIRED') {
                setRequiresPasswordChange(true);
                setPendingAuthData({ email, tempToken: errorData.tempToken });
                return {
                    success: false,
                    passwordChangeRequired: true,
                    message: errorData.message || 'You must change your password before continuing'
                };
            }

            const message = errorData?.message || 'Login failed. Please try again.';
            setError(message);
            return { success: false, message, errorData };
        } finally {
            setLoading(false);
        }
    };

    /**
     * Verify MFA code after login
     */
    const verifyMfa = async (code) => {
        try {
            setLoading(true);
            setError(null);

            const response = await api.post('/users/verify-mfa', {
                email: pendingAuthData?.email,
                code,
                mfaToken: pendingAuthData?.mfaToken
            });

            if (response.data.success && response.data.user) {
                setUser(response.data.user);
                setRequiresMfa(false);
                setPendingAuthData(null);
                return { success: true, user: response.data.user };
            }

            return { success: false, message: response.data.message || 'MFA verification failed' };
        } catch (err) {
            const message = err.response?.data?.message || 'MFA verification failed. Please try again.';
            setError(message);
            return { success: false, message };
        } finally {
            setLoading(false);
        }
    };

    /**
     * Change password when required before login
     */
    const changePasswordOnLogin = async (newPassword) => {
        try {
            setLoading(true);
            setError(null);

            const response = await api.post('/users/change-password-required', {
                email: pendingAuthData?.email,
                newPassword,
                tempToken: pendingAuthData?.tempToken
            });

            if (response.data.success && response.data.user) {
                setUser(response.data.user);
                setRequiresPasswordChange(false);
                setPendingAuthData(null);
                return { success: true, user: response.data.user };
            }

            return { success: false, message: response.data.message || 'Password change failed' };
        } catch (err) {
            const message = err.response?.data?.message || 'Password change failed. Please try again.';
            setError(message);
            return { success: false, message };
        } finally {
            setLoading(false);
        }
    };

    /**
     * Cancel MFA or password change flow
     */
    const cancelPendingAuth = () => {
        setRequiresMfa(false);
        setRequiresPasswordChange(false);
        setPendingAuthData(null);
    };

    /**
     * Register handler - no localStorage token storage.
     */
    const register = async (userData) => {
        try {
            setLoading(true);
            setError(null);

            const response = await authApi.register(userData);

            // Handle MFA requirement for registration
            if (response.requiresMfa || response.code === 'REQUIRES_MFA') {
                setRequiresMfa(true);
                setPendingAuthData({ email: userData.email, mfaToken: response.mfaToken });
                return {
                    success: false,
                    requiresMfa: true,
                    message: response.message || 'Please complete MFA verification'
                };
            }

            // Handle password change requirement for registration
            if (response.passwordChangeRequired || response.code === 'PASSWORD_CHANGE_REQUIRED') {
                setRequiresPasswordChange(true);
                setPendingAuthData({ email: userData.email, tempToken: response.tempToken });
                return {
                    success: false,
                    passwordChangeRequired: true,
                    message: response.message || 'You must set a new password'
                };
            }

            if (response.success) {
                // Registration successful - may need OTP verification
                return { success: true, ...response };
            }

            return { success: false, message: response.message || 'Registration failed' };
        } catch (err) {
            const errorData = err.response?.data;

            // Handle MFA requirement from error response
            if (errorData?.requiresMfa || errorData?.code === 'REQUIRES_MFA') {
                setRequiresMfa(true);
                setPendingAuthData({ email: userData.email, mfaToken: errorData.mfaToken });
                return {
                    success: false,
                    requiresMfa: true,
                    message: errorData.message || 'Please complete MFA verification'
                };
            }

            // Handle password change requirement from error response
            if (errorData?.passwordChangeRequired || errorData?.code === 'PASSWORD_CHANGE_REQUIRED') {
                setRequiresPasswordChange(true);
                setPendingAuthData({ email: userData.email, tempToken: errorData.tempToken });
                return {
                    success: false,
                    passwordChangeRequired: true,
                    message: errorData.message || 'You must set a new password'
                };
            }

            const message = errorData?.message || 'Registration failed. Please try again.';
            setError(message);
            return { success: false, message, errorData };
        } finally {
            setLoading(false);
        }
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
            setRequiresMfa(false);
            setRequiresPasswordChange(false);
            setPendingAuthData(null);
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

    const isVerified = user?.isVerified === true;

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

    // Owner can add property only if verified AND hasn't posted yet
    const canAddProperty = isAuthenticated && isOwner && isVerified && !ownerHasProperty;

    // ============================================
    // CONTEXT VALUE
    // ============================================

    const value = {
        // State
        user,
        loading,
        error,

        // Special auth states
        requiresMfa,
        requiresPasswordChange,
        pendingAuthData,

        // Auth status
        isAuthenticated,
        isOwner,
        isBuyer,
        isVerified,
        ownerHasProperty,

        // Role helpers
        hasRole,
        canAccessOwnerFeatures,
        canAddProperty,

        // Actions
        login,
        register,
        logout,
        checkAuth,
        updateUser,
        clearError: () => setError(null),
        refreshOwnerPropertyStatus: () => checkOwnerProperty(user),

        // MFA & Password change handlers
        verifyMfa,
        changePasswordOnLogin,
        cancelPendingAuth,
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

// ============================================
// PROTECTED ROUTE COMPONENT
// ============================================

export const ProtectedRoute = ({ children, requiredRole = null, requireVerified = false }) => {
    const { isAuthenticated, loading, hasRole, isVerified, requiresMfa, requiresPasswordChange } = useAuth();
    const router = useRouter();
    const pathname = usePathname();

    useEffect(() => {
        if (!loading) {
            // Handle MFA requirement
            if (requiresMfa) {
                router.replace('/verify-mfa');
                return;
            }

            // Handle password change requirement
            if (requiresPasswordChange) {
                router.replace('/change-password-required');
                return;
            }

            if (!isAuthenticated) {
                router.replace(`/login?from=${encodeURIComponent(pathname)}`);
            } else if (requiredRole && !hasRole(requiredRole)) {
                router.replace('/');
            } else if (requireVerified && !isVerified) {
                router.replace('/verify-email');
            }
        }
    }, [loading, isAuthenticated, hasRole, isVerified, requiredRole, requireVerified, requiresMfa, requiresPasswordChange, router, pathname]);

    if (loading) {
        return (
            <div className="flex items-center justify-center min-h-screen">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-red-600"></div>
            </div>
        );
    }

    if (!isAuthenticated || requiresMfa || requiresPasswordChange) {
        return null;
    }

    if (requiredRole && !hasRole(requiredRole)) {
        return null;
    }

    if (requireVerified && !isVerified) {
        return null;
    }

    return children;
};

export default AuthContext;
