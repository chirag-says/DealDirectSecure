/**
 * API Client - Cookie-Based Authentication
 * 
 * This module provides a pre-configured axios instance that:
 * - Automatically includes credentials (cookies) with every request
 * - Handles 401/403 errors gracefully
 * - Provides an auth context hook
 * 
 * NEXT.JS MIGRATION NOTES:
 * - Replaced import.meta.env.VITE_* with process.env.NEXT_PUBLIC_*
 * - Wrapped browser-only APIs (document.cookie, window.location) in typeof window checks
 * - This file should only be imported in client components ('use client')
 */

import axios from 'axios';

// ============================================
// API CLIENT CONFIGURATION
// ============================================

// Helper to remove trailing slashes
const removeTrailingSlash = (url) => {
    if (!url) return url;
    return url.endsWith('/') ? url.slice(0, -1) : url;
};

// ============================================
// SESSION HINT — reads the non-HttpOnly companion cookie
// set by the backend alongside the HttpOnly session token.
// If the cookie exists, we have (or recently had) a session.
// No localStorage needed — fully cookie-based.
// ============================================
const hasSessionCookie = () => {
    if (typeof document === 'undefined') return false;
    return document.cookie.split(';').some(c => c.trim().startsWith('session_exists='));
};

// Get base URL from environment or derive from NEXT_PUBLIC_API_BASE
const getApiBaseUrl = () => {
    // First, check if NEXT_PUBLIC_API_URL is set (includes /api)
    if (process.env.NEXT_PUBLIC_API_URL) {
        return removeTrailingSlash(process.env.NEXT_PUBLIC_API_URL);
    }
    // Second, check if NEXT_PUBLIC_API_BASE is set (without /api)
    if (process.env.NEXT_PUBLIC_API_BASE) {
        return `${removeTrailingSlash(process.env.NEXT_PUBLIC_API_BASE)}/api`;
    }
    // Fallback for development
    if (typeof window !== 'undefined') {
        return `${window.location.protocol}//${window.location.hostname}:9000/api`;
    }
    return 'http://localhost:9000/api';
};

const API_BASE_URL = getApiBaseUrl();

// Create axios instance with default config
const api = axios.create({
    baseURL: API_BASE_URL,
    withCredentials: true, // CRITICAL: Include cookies in every request
    headers: {
        'Content-Type': 'application/json',
    },
    timeout: 90000, // 90 second timeout for image uploads
});

// ============================================
// CSRF TOKEN HANDLING
// ============================================

const CSRF_COOKIE_NAME = 'csrf_token';
const CSRF_HEADER_NAME = 'X-CSRF-Token';

/**
 * Read a cookie value by name
 */
const getCookie = (name) => {
    if (typeof document === 'undefined') return null;
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        return parts.pop().split(';').shift();
    }
    return null;
};

/**
 * Fetch a fresh CSRF token from the server
 * Call this on app initialization
 */
export const fetchCsrfToken = async () => {
    try {
        const response = await api.get('/csrf-token');
        return response.data.csrfToken;
    } catch (error) {
        console.warn('Failed to fetch CSRF token:', error.message);
        return null;
    }
};

// ============================================
// REQUEST INTERCEPTOR
// ============================================

api.interceptors.request.use(
    (config) => {
        // For state-changing requests (POST, PUT, PATCH, DELETE),
        // include the CSRF token from the cookie in the header
        const method = (config.method || '').toUpperCase();
        const stateChangingMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];

        if (stateChangingMethods.includes(method)) {
            const csrfToken = getCookie(CSRF_COOKIE_NAME);
            if (csrfToken) {
                config.headers[CSRF_HEADER_NAME] = csrfToken;
            }
        }

        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// ============================================
// RESPONSE INTERCEPTOR - Handle Auth Errors
// ============================================

// Global auth state management
let onAuthError = null;

export const setAuthErrorHandler = (handler) => {
    onAuthError = handler;
};

api.interceptors.response.use(
    (response) => {
        // Success - return the response
        return response;
    },
    (error) => {
        const { response } = error;

        // ============================================
        // SECURITY FIX: Sanitize error responses
        // Never expose stack traces, internal paths, or DB details to the UI
        // ============================================
        const sanitizeErrorMessage = (message) => {
            if (!message || typeof message !== 'string') return 'An error occurred';

            // Patterns that indicate internal/sensitive information
            const sensitivePatterns = [
                /at\s+\w+\s+\([^)]+\:\d+:\d+\)/gi, // Stack trace: "at function (file:line:col)"
                /at\s+[^\n]+\n/gi, // Stack trace continuation
                /Error:\s*$/gi, // Empty error prefix
                /\/[a-z]:\//gi, // Windows paths
                /\/home\/|\/var\/|\/usr\//gi, // Linux paths
                /node_modules/gi, // Node modules path
                /__dirname|__filename/gi, // Node internals
                /MongoError|MongoServerError/gi, // MongoDB
                /CastError|ValidationError/gi, // Mongoose
                /ECONNREFUSED|ETIMEDOUT/gi, // Network errors
                /errno|syscall|code:\s*'[A-Z_]+'/gi, // System errors
            ];

            let sanitized = message;
            for (const pattern of sensitivePatterns) {
                sanitized = sanitized.replace(pattern, '');
            }

            // Trim and clean up
            sanitized = sanitized.replace(/\s+/g, ' ').trim();
            return sanitized || 'An error occurred';
        };

        if (response) {
            const { status, data } = response;

            // Sanitize error message before exposing
            if (data?.message) {
                data.message = sanitizeErrorMessage(data.message);
            }

            // Remove any stack traces
            if (data?.stack) {
                delete data.stack;
            }

            // Remove internal error details
            if (data?.error?.stack) {
                delete data.error.stack;
            }

            // Handle authentication errors
            if (status === 401) {
                // /users/me returning 401 just means the user is not logged in — this is
                // expected on every page load for guest users. Skip the warning entirely.
                const isAuthCheck = response.config?.url?.includes('/users/me');

                if (!isAuthCheck) {
                    console.warn('🔒 Session expired or unauthorized');

                    // Call the auth error handler if set (AuthContext handles clearing state)
                    if (onAuthError) {
                        onAuthError({
                            type: 'UNAUTHORIZED',
                            message: data?.message || 'Your session has expired. Please log in again.',
                            requestId: data?.requestId,
                        });
                    }
                }
            }

            // Handle forbidden errors
            if (status === 403) {
                console.warn('🚫 Access forbidden');

                if (onAuthError) {
                    onAuthError({
                        type: 'FORBIDDEN',
                        message: data?.message || 'You do not have permission to access this resource.',
                        requestId: data?.requestId,
                    });
                }
            }

            // Handle rate limiting
            if (status === 429) {
                console.warn('⏳ Rate limited');
            }
        }

        return Promise.reject(error);
    }
);

// ============================================
// AUTH API METHODS
// ============================================

export const authApi = {
    // Check current authentication status by fetching user profile.
    // Only called if the backend-set `session_exists` cookie is present,
    // eliminating the noisy 401 for guests who have never logged in.
    checkAuth: async () => {
        if (!hasSessionCookie()) {
            return { authenticated: false, user: null };
        }
        try {
            const response = await api.get('/users/me');
            return { authenticated: true, user: response.data.user || response.data };
        } catch {
            // Session cookie expired/invalid — companion cookie will be cleared by server
            return { authenticated: false, user: null };
        }
    },

    // Login
    login: async (email, password) => {
        const response = await api.post('/users/login', { email, password });
        return response.data;
    },

    // Register
    register: async (userData) => {
        const response = await api.post('/users/register', userData);
        return response.data;
    },

    // Logout - clears session cookie on server
    // NOTE: localStorage cleanup should be handled by AuthContext, not here
    logout: async () => {
        try {
            await api.post('/users/logout');
            return { success: true };
        } catch (error) {
            console.warn('Logout API call failed:', error.message);
            return { success: false, error: error.message };
        }
    },

    // Get profile
    getProfile: async () => {
        const response = await api.get('/users/profile');
        return response.data;
    },

    // Update profile
    updateProfile: async (formData) => {
        const response = await api.put('/users/profile', formData, {
            headers: { 'Content-Type': 'multipart/form-data' },
        });
        return response.data;
    },

    // Change password
    changePassword: async (currentPassword, newPassword) => {
        const response = await api.put('/users/change-password', {
            currentPassword,
            newPassword
        });
        return response.data;
    },

    // Verify OTP
    verifyOTP: async (email, otp) => {
        const response = await api.post('/users/verify-otp', { email, otp });
        return response.data;
    },

    // Resend OTP
    resendOTP: async (email) => {
        const response = await api.post('/users/resend-otp', { email });
        return response.data;
    },

    // Forgot password
    forgotPassword: async (email) => {
        const response = await api.post('/users/forgot-password', { email });
        return response.data;
    },

    // Reset password
    resetPassword: async (token, password) => {
        const response = await api.post('/users/reset-password', { token, password });
        return response.data;
    },
};

// ============================================
// PROPERTY API METHODS
// ============================================

export const propertyApi = {
    // Get all properties (public)
    getAll: async (params = {}) => {
        const response = await api.get('/properties/list', { params });
        return response.data;
    },

    // Search properties
    search: async (query) => {
        const response = await api.get('/properties/search', { params: { q: query } });
        return response.data;
    },

    // Get single property
    getById: async (id) => {
        const response = await api.get(`/properties/${id}`);
        return response.data;
    },

    // Get my properties (authenticated)
    getMyProperties: async () => {
        const response = await api.get('/properties/my-properties');
        return response.data;
    },

    // Add property (authenticated)
    add: async (formData) => {
        const response = await api.post('/properties/add', formData, {
            headers: { 'Content-Type': 'multipart/form-data' },
        });
        return response.data;
    },

    // Update my property
    update: async (id, formData) => {
        const response = await api.put(`/properties/my-properties/${id}`, formData, {
            headers: { 'Content-Type': 'multipart/form-data' },
        });
        return response.data;
    },

    // Delete my property
    delete: async (id) => {
        const response = await api.delete(`/properties/${id}`);
        return response.data;
    },

    // Mark interested
    markInterested: async (id) => {
        const response = await api.post(`/properties/interested/${id}`);
        return response.data;
    },

    // Check interested
    checkInterested: async (id) => {
        const response = await api.get(`/properties/interested/${id}/check`);
        return response.data;
    },

    // Remove interest
    removeInterest: async (id) => {
        const response = await api.delete(`/properties/interested/${id}`);
        return response.data;
    },

    // Get saved properties
    getSaved: async () => {
        const response = await api.get('/properties/saved');
        return response.data;
    },

    // Remove saved property
    removeSaved: async (id) => {
        const response = await api.delete(`/properties/saved/${id}`);
        return response.data;
    },
};

// ============================================
// NOTIFICATION API METHODS
// ============================================

export const notificationApi = {
    getAll: async () => {
        const response = await api.get('/notifications');
        return response.data;
    },

    markRead: async (id) => {
        const response = await api.put(`/notifications/${id}/read`);
        return response.data;
    },

    markAllRead: async () => {
        const response = await api.put('/notifications/read-all');
        return response.data;
    },
};

// ============================================
// LEAD API METHODS
// ============================================

export const leadApi = {
    getMyLeads: async () => {
        const response = await api.get('/leads');
        return response.data;
    },

    getAnalytics: async () => {
        const response = await api.get('/leads/analytics');
        return response.data;
    },

    updateStatus: async (id, status, notes) => {
        const response = await api.put(`/leads/${id}/status`, { status, notes });
        return response.data;
    },

    markViewed: async (id) => {
        const response = await api.put(`/leads/${id}/viewed`);
        return response.data;
    },
};

// ============================================
// AGREEMENT API METHODS
// ============================================

export const agreementApi = {
    generate: async (data) => {
        const response = await api.post('/agreements/generate', data);
        return response.data;
    },

    getMyAgreements: async () => {
        const response = await api.get('/agreements/my-agreements');
        return response.data;
    },

    getById: async (id) => {
        const response = await api.get(`/agreements/${id}`);
        return response.data;
    },

    sign: async (id) => {
        const response = await api.post(`/agreements/${id}/sign`);
        return response.data;
    },

    getTemplates: async () => {
        const response = await api.get('/agreements/templates');
        return response.data;
    },

    getStates: async () => {
        const response = await api.get('/agreements/states');
        return response.data;
    },
};

// ============================================
// CONTACT API METHODS
// ============================================

export const contactApi = {
    submit: async (data) => {
        const response = await api.post('/contact', data);
        return response.data;
    },
};

// ============================================
// SAVED SEARCH API METHODS
// ============================================

export const savedSearchApi = {
    create: async (data) => {
        const response = await api.post('/saved-searches', data);
        return response.data;
    },

    getMine: async () => {
        const response = await api.get('/saved-searches/mine');
        return response.data;
    },

    toggle: async (id) => {
        const response = await api.patch(`/saved-searches/${id}/toggle`);
        return response.data;
    },

    delete: async (id) => {
        const response = await api.delete(`/saved-searches/${id}`);
        return response.data;
    },
};

// ============================================
// REWARDS API METHODS
// ============================================

export const rewardsApi = {
    getWallet: async () => {
        const response = await api.get('/rewards/wallet');
        return response.data;
    },

    getTransactions: async (params = {}) => {
        const response = await api.get('/rewards/transactions', { params });
        return response.data;
    },

    getReferralCode: async () => {
        const response = await api.get('/rewards/referral-code');
        return response.data;
    },

    getReferrals: async () => {
        const response = await api.get('/rewards/referrals');
        return response.data;
    },

    getStore: async () => {
        const response = await api.get('/rewards/store');
        return response.data;
    },

    redeem: async (data) => {
        const response = await api.post('/rewards/redeem', data);
        return response.data;
    },

    // RewardPort Catalogue APIs (Legacy — kept for backward compatibility)
    getCatalogueCategories: async () => {
        const response = await api.get('/rewards/catalogue/categories');
        return response.data;
    },
    getCatalogueSubCategories: async (categoryId) => {
        const response = await api.get(`/rewards/catalogue/subcategories/${categoryId}`);
        return response.data;
    },
    getCatalogueProducts: async () => {
        const response = await api.get('/rewards/catalogue/products');
        return response.data;
    },
    filterCatalogueProducts: async (data) => {
        const response = await api.post('/rewards/catalogue/products/filter', data);
        return response.data;
    },
    getCatalogueProductDetails: async (productId) => {
        const response = await api.post('/rewards/catalogue/products/details', { productId });
        return response.data;
    },

    // Hubble Gift Card SDK
    getHubbleConfig: async () => {
        const response = await api.get('/rewards/hubble/config');
        return response.data;
    },
    getHubbleToken: async () => {
        const response = await api.get('/rewards/hubble/token');
        return response.data;
    },
};

// ============================================
// PROJECT API METHODS
// Mounted at: /api/projects
// ============================================

export const projectApi = {
    /**
     * List all active projects (public).
     * @param {object} params — e.g. { isActive: true, limit: 50, city: 'Mumbai' }
     */
    getAll: async (params = {}) => {
        const response = await api.get('/projects', { params });
        return response.data;
    },

    /**
     * Get a single project by ID (public).
     */
    getById: async (id) => {
        const response = await api.get(`/projects/${id}`);
        return response.data;
    },

    /**
     * Get all projects belonging to a specific builder (public).
     * Used on the builder profile page.
     */
    getByBuilder: async (builderId, params = {}) => {
        const response = await api.get(`/projects/builder/${builderId}`, { params });
        return response.data;
    },
};

// ============================================
// UNIT TYPE API METHODS
// Mounted at: /api/unit-types
// ============================================

export const unitTypeApi = {
    /**
     * Get all unit types for a project (public).
     * This is the primary call on the project detail page.
     */
    getByProject: async (projectId) => {
        const response = await api.get(`/unit-types/project/${projectId}`);
        return response.data;
    },

    /**
     * Get a single unit type by ID (public).
     * Used on the unit detail / booking page.
     */
    getById: async (id) => {
        const response = await api.get(`/unit-types/${id}`);
        return response.data;
    },
};

// ============================================
// CAMPAIGN API METHODS
// Mounted at: /api/campaigns
// ============================================

export const campaignApi = {
    /**
     * Get all campaigns for a specific unit type (public).
     * Displayed on the unit detail page as active group-buy offers.
     */
    getByUnitType: async (unitTypeId) => {
        const response = await api.get(`/campaigns/unit-type/${unitTypeId}`);
        return response.data;
    },

    /**
     * Get all campaigns for a project (public).
     */
    getByProject: async (projectId) => {
        const response = await api.get(`/campaigns/project/${projectId}`);
        return response.data;
    },

    /**
     * Get a single campaign by ID (public).
     */
    getById: async (id) => {
        const response = await api.get(`/campaigns/${id}`);
        return response.data;
    },

    /**
     * Join a campaign (authenticated buyer).
     * Adds the current user to the campaign member list.
     */
    join: async (campaignId) => {
        const response = await api.post(`/campaigns/${campaignId}/join`);
        return response.data;
    },

    /**
     * Exit / withdraw from a campaign (authenticated buyer).
     */
    exit: async (campaignId) => {
        const response = await api.post(`/campaigns/${campaignId}/exit`);
        return response.data;
    },

    /**
     * Upload payment proof for a campaign slot (authenticated buyer).
     * @param {string} campaignId
     * @param {FormData} formData — must contain `paymentProof` file field
     */
    uploadPaymentProof: async (campaignId, formData) => {
        const response = await api.post(`/campaigns/${campaignId}/payment-proof`, formData, {
            headers: { 'Content-Type': 'multipart/form-data' },
        });
        return response.data;
    },
};

// ============================================
// BOOKING API METHODS
// Mounted at: /api/bookings
// ============================================

export const bookingApi = {
    /**
     * Create a new booking for a unit type (optionally authenticated).
     * If the user is logged in, the booking is auto-linked to their account.
     * @param {object} data — { unitTypeId, projectId, name, phone, email, ... }
     */
    create: async (data) => {
        const response = await api.post('/bookings', data);
        return response.data;
    },

    /**
     * Submit payment proof (UTR + screenshot) for an existing booking.
     * @param {string} bookingId
     * @param {FormData} formData — must contain `screenshot` file field + UTR fields
     */
    submitPayment: async (bookingId, formData) => {
        const response = await api.post(`/bookings/${bookingId}/payment`, formData, {
            headers: { 'Content-Type': 'multipart/form-data' },
        });
        return response.data;
    },

    /**
     * Get all bookings for the currently authenticated user.
     */
    getMyBookings: async () => {
        const response = await api.get('/bookings/my');
        return response.data;
    },
};

// Export the base api instance for custom requests
export default api;
