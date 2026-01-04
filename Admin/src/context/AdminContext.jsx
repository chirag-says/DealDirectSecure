/**
 * AdminContext - Cookie-First Authentication State Management
 * 
 * This context manages the admin authentication state by verifying
 * the session cookie with the server on app mount, rather than
 * relying on localStorage tokens.
 */
import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import { adminAuthApi, setAdminAuthErrorHandler } from "../api/adminApi";
import { toast } from "react-toastify";

// ============================================
// CONTEXT CREATION
// ============================================

const AdminContext = createContext(null);

// ============================================
// AUTH STATES
// ============================================

export const AUTH_STATUS = {
    LOADING: "loading",
    AUTHENTICATED: "authenticated",
    UNAUTHENTICATED: "unauthenticated",
};

// ============================================
// PROVIDER COMPONENT
// ============================================

export const AdminProvider = ({ children }) => {
    const [authStatus, setAuthStatus] = useState(AUTH_STATUS.LOADING);
    const [admin, setAdmin] = useState(null);

    /**
     * Verify session with the server by calling /api/admin/profile
     * This is the source of truth for authentication state
     */
    const checkAuth = useCallback(async () => {
        setAuthStatus(AUTH_STATUS.LOADING);

        try {
            const result = await adminAuthApi.checkAuth();

            if (result.authenticated && result.admin) {
                setAdmin(result.admin);
                setAuthStatus(AUTH_STATUS.AUTHENTICATED);
                return true;
            } else {
                setAdmin(null);
                setAuthStatus(AUTH_STATUS.UNAUTHENTICATED);
                return false;
            }
        } catch (error) {
            console.error("Auth check failed:", error);
            setAdmin(null);
            setAuthStatus(AUTH_STATUS.UNAUTHENTICATED);
            return false;
        }
    }, []);

    /**
     * Login handler - after successful server login, verify session
     */
    const login = useCallback(async (adminData) => {
        if (adminData) {
            setAdmin(adminData);
            setAuthStatus(AUTH_STATUS.AUTHENTICATED);
        } else {
            // If no data passed, verify with server
            await checkAuth();
        }
    }, [checkAuth]);

    /**
     * Logout handler - calls server logout and clears state
     */
    const logout = useCallback(async () => {
        try {
            await adminAuthApi.logout();
        } catch (error) {
            console.warn("Logout request failed:", error);
        }

        // Clear state regardless of server response
        setAdmin(null);
        setAuthStatus(AUTH_STATUS.UNAUTHENTICATED);
    }, []);

    /**
     * Handle auth errors from API interceptor
     */
    useEffect(() => {
        setAdminAuthErrorHandler((error) => {
            if (error.type === "UNAUTHORIZED") {
                setAdmin(null);
                setAuthStatus(AUTH_STATUS.UNAUTHENTICATED);
                toast.error(error.message || "Session expired. Please log in again.");
            } else if (error.type === "FORBIDDEN") {
                toast.error(error.message || "Access denied.");
            }
        });

        return () => setAdminAuthErrorHandler(null);
    }, []);

    /**
     * Check authentication on app mount
     */
    useEffect(() => {
        checkAuth();
    }, [checkAuth]);

    // ============================================
    // DERIVED STATE
    // ============================================

    const isLoading = authStatus === AUTH_STATUS.LOADING;
    const isAuthenticated = authStatus === AUTH_STATUS.AUTHENTICATED;

    // Role and permissions
    const role = admin?.role || null;
    const roleName = role?.name || null;
    const roleLevel = role?.level || 0;
    const permissions = admin?.additionalPermissions || [];

    // ============================================
    // CONTEXT VALUE
    // ============================================

    const value = {
        // Auth state
        authStatus,
        isLoading,
        isAuthenticated,
        admin,

        // Role & permissions
        role,
        roleName,
        roleLevel,
        permissions,

        // Actions
        login,
        logout,
        checkAuth,
    };

    return (
        <AdminContext.Provider value={value}>
            {children}
        </AdminContext.Provider>
    );
};

// ============================================
// HOOK
// ============================================

export const useAdmin = () => {
    const context = useContext(AdminContext);

    if (!context) {
        throw new Error("useAdmin must be used within an AdminProvider");
    }

    return context;
};

export default AdminContext;
