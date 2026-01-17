/**
 * API Client - Cookie-Based Authentication
 * 
 * This module provides a pre-configured axios instance that:
 * - Automatically includes credentials (cookies) with every request
 * - Handles 401/403 errors gracefully
 * - Provides an auth context hook
 */

import axios from 'axios';

// ============================================
// API CLIENT CONFIGURATION
// ============================================

// Get base URL from environment or derive from VITE_API_BASE
const getApiBaseUrl = () => {
    // First, check if VITE_API_URL is set (includes /api)
    if (import.meta.env.VITE_API_URL) {
        return import.meta.env.VITE_API_URL;
    }
    // Second, check if VITE_API_BASE is set (without /api)
    if (import.meta.env.VITE_API_BASE) {
        return `${import.meta.env.VITE_API_BASE}/api`;
    }
    // Fallback for development
    return `${window.location.protocol}//${window.location.hostname}:9000/api`;
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
    // Check current authentication status by fetching user profile
    // Uses /users/me endpoint - HttpOnly cookies sent automatically
    checkAuth: async () => {
        try {
            const response = await api.get('/users/me');
            return { authenticated: true, user: response.data.user || response.data };
        } catch {
            // Session invalid or expired - don't log error, this is expected on first load
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

// Export the base api instance for custom requests
export default api;
