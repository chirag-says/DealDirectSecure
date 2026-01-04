/**
 * Auth Context - Cookie-Based Session Management
 * 
 * Provides authentication state management with:
 * - Automatic session validation on app load
 * - Role-based access control helpers
 * - Graceful logout on 401 errors
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import api, { authApi, setAuthErrorHandler } from '../utils/api';

// ============================================
// AUTH CONTEXT
// ============================================

const AuthContext = createContext(null);

// ============================================
// AUTH PROVIDER
// ============================================

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(() => {
        try {
            const savedUser = localStorage.getItem('user');
            return savedUser ? JSON.parse(savedUser) : null;
        } catch (error) {
            return null;
        }
    });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const navigate = useNavigate();

    // ============================================
    // CHECK AUTH STATUS ON MOUNT
    // ============================================

    const checkAuth = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);

            const result = await authApi.checkAuth();

            if (result.authenticated && result.user) {
                setUser(result.user);
                // Also store user in localStorage for quick access (non-sensitive data only)
                localStorage.setItem('user', JSON.stringify(result.user));
            } else {
                setUser(null);
                localStorage.removeItem('user');
            }
        } catch (err) {
            console.warn('Auth check failed:', err.message);
            setUser(null);
            localStorage.removeItem('user');
        } finally {
            setLoading(false);
        }
    }, []);

    // Run auth check on mount
    useEffect(() => {
        checkAuth();
    }, [checkAuth]);

    // ============================================
    // HANDLE AUTH ERRORS (401/403)
    // ============================================

    useEffect(() => {
        setAuthErrorHandler((errorInfo) => {
            if (errorInfo.type === 'UNAUTHORIZED') {
                // Session expired - clear state and redirect
                setUser(null);
                localStorage.removeItem('user');

                // Redirect to login with message
                navigate('/login', {
                    state: {
                        message: errorInfo.message,
                        from: window.location.pathname,
                    },
                    replace: true
                });
            } else if (errorInfo.type === 'FORBIDDEN') {
                // User doesn't have permission
                setError(errorInfo.message);
            }
        });

        return () => {
            setAuthErrorHandler(null);
        };
    }, [navigate]);

    // ============================================
    // AUTH ACTIONS
    // ============================================

    const login = async (email, password) => {
        try {
            setLoading(true);
            setError(null);

            const response = await authApi.login(email, password);

            if (response.success && response.user) {
                setUser(response.user);
                localStorage.setItem('user', JSON.stringify(response.user));
                return { success: true, user: response.user };
            }

            return { success: false, message: response.message || 'Login failed' };
        } catch (err) {
            const message = err.response?.data?.message || 'Login failed. Please try again.';
            setError(message);
            return { success: false, message };
        } finally {
            setLoading(false);
        }
    };

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
            const message = err.response?.data?.message || 'Registration failed. Please try again.';
            setError(message);
            return { success: false, message };
        } finally {
            setLoading(false);
        }
    };

    const logout = async () => {
        try {
            setLoading(true);
            await authApi.logout();
        } catch (err) {
            console.warn('Logout error:', err.message);
        } finally {
            setUser(null);
            localStorage.removeItem('user');
            setLoading(false);
            navigate('/login', { replace: true });
        }
    };

    const updateUser = (updatedUser) => {
        setUser(updatedUser);
        localStorage.setItem('user', JSON.stringify(updatedUser));
    };

    // ============================================
    // ROLE HELPERS
    // ============================================

    const isAuthenticated = !!user;

    const isOwner = user?.role === 'owner';

    const isBuyer = user?.role === 'user';

    const isVerified = user?.isVerified === true;

    const hasRole = (role) => {
        if (!user) return false;
        if (Array.isArray(role)) {
            return role.includes(user.role);
        }
        return user.role === role;
    };

    const canAccessOwnerFeatures = isAuthenticated && (isOwner || user?.role === 'owner');

    const canAddProperty = isAuthenticated && isOwner && isVerified;

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
    const { isAuthenticated, loading, hasRole, isVerified } = useAuth();
    const navigate = useNavigate();

    useEffect(() => {
        if (!loading) {
            if (!isAuthenticated) {
                navigate('/login', {
                    state: { from: window.location.pathname },
                    replace: true
                });
            } else if (requiredRole && !hasRole(requiredRole)) {
                navigate('/', { replace: true });
            } else if (requireVerified && !isVerified) {
                navigate('/verify-email', { replace: true });
            }
        }
    }, [loading, isAuthenticated, hasRole, isVerified, requiredRole, requireVerified, navigate]);

    if (loading) {
        return (
            <div className="flex items-center justify-center min-h-screen">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-red-600"></div>
            </div>
        );
    }

    if (!isAuthenticated) {
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
