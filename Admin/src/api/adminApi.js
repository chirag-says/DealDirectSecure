/**
 * Admin API Client - Cookie-Based Authentication
 * 
 * Pre-configured axios instance with:
 * - Automatic cookie handling (withCredentials: true)
 * - 401/403 error handling with redirect
 * - Organized API methods for all admin endpoints
 */
import axios from "axios";

// Base URL should NOT include /api - endpoints add their own prefixes
const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:9000';

// ============================================
// AXIOS INSTANCE
// ============================================

const adminApi = axios.create({
    baseURL: API_URL,
    withCredentials: true, // CRITICAL: Send cookies with every request
    headers: {
        "Content-Type": "application/json",
    },
    timeout: 30000,
});

// ============================================
// AUTH ERROR HANDLER
// ============================================

let onAuthError = null;

export const setAdminAuthErrorHandler = (handler) => {
    onAuthError = handler;
};

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
 */
export const fetchAdminCsrfToken = async () => {
    try {
        const response = await adminApi.get('/csrf-token');
        return response.data.csrfToken;
    } catch (error) {
        console.warn('Failed to fetch CSRF token:', error.message);
        return null;
    }
};

// ============================================
// REQUEST INTERCEPTOR
// ============================================

adminApi.interceptors.request.use(
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
// RESPONSE INTERCEPTOR
// ============================================

adminApi.interceptors.response.use(
    (response) => response,
    (error) => {
        const { response } = error;

        if (response) {
            const { status, data } = response;

            if (status === 401) {
                console.warn("🔒 Admin session expired");
                // Auth state cleanup is handled by AdminContext via onAuthError callback

                if (onAuthError) {
                    onAuthError({
                        type: 'UNAUTHORIZED',
                        message: data?.message || 'Session expired. Please log in again.',
                    });
                }
            }

            if (status === 403) {
                console.warn("🚫 Admin access forbidden");

                if (onAuthError) {
                    onAuthError({
                        type: 'FORBIDDEN',
                        message: data?.message || 'You do not have permission to access this resource.',
                    });
                }
            }
        }

        return Promise.reject(error);
    }
);

// ============================================
// AUTH API
// ============================================

export const adminAuthApi = {
    login: async (email, password) => {
        const response = await adminApi.post('/api/admin/login', { email, password });
        return response.data;
    },

    changePassword: async (currentPassword, newPassword) => {
        const response = await adminApi.post('/api/admin/change-password', { currentPassword, newPassword });
        return response.data;
    },

    logout: async () => {
        try {
            await adminApi.post('/api/admin/logout');
        } catch (error) {
            console.warn('Logout error:', error.message);
        }
        // State cleanup is handled by AdminContext
    },

    getProfile: async () => {
        const response = await adminApi.get('/api/admin/profile');
        return response.data;
    },

    checkAuth: async () => {
        try {
            const response = await adminApi.get('/api/admin/profile');
            return { authenticated: true, admin: response.data.admin || response.data };
        } catch (error) {
            return { authenticated: false, admin: null };
        }
    },
};

// ============================================
// USER MANAGEMENT API
// ============================================

export const userManagementApi = {
    getAll: async (params = {}) => {
        const response = await adminApi.get('/api/users/list', { params });
        return response.data;
    },

    toggleBlock: async (userId) => {
        const response = await adminApi.put(`/api/users/block/${userId}`);
        return response.data;
    },

    getOwnersWithProjects: async () => {
        const response = await adminApi.get('/api/users/owners-projects');
        return response.data;
    },

    exportCSV: async () => {
        const response = await adminApi.get('/api/users/export-csv', { responseType: 'blob' });
        return response.data;
    },

    exportPDF: async () => {
        const response = await adminApi.get('/api/users/export-pdf', { responseType: 'blob' });
        return response.data;
    },
};

// ============================================
// PROPERTY MANAGEMENT API
// ============================================

export const propertyManagementApi = {
    getAll: async (params = {}) => {
        const response = await adminApi.get('/api/properties/admin/all', { params });
        return response.data;
    },

    approve: async (propertyId) => {
        const response = await adminApi.put(`/api/properties/approve/${propertyId}`);
        return response.data;
    },

    disapprove: async (propertyId, reason) => {
        const response = await adminApi.put(`/api/properties/disapprove/${propertyId}`, { reason });
        return response.data;
    },

    update: async (propertyId, formData) => {
        const response = await adminApi.put(`/api/properties/edit/${propertyId}`, formData, {
            headers: { 'Content-Type': 'multipart/form-data' },
        });
        return response.data;
    },

    delete: async (propertyId) => {
        const response = await adminApi.delete(`/api/properties/delete/${propertyId}`);
        return response.data;
    },
};

// ============================================
// LEAD MANAGEMENT API
// ============================================

export const leadManagementApi = {
    getAll: async (params = {}) => {
        const response = await adminApi.get('/api/admin/leads', { params });
        return response.data;
    },

    export: async (format = 'excel') => {
        const response = await adminApi.get(`/api/admin/leads/export`, {
            params: { format },
            responseType: 'blob'
        });
        return response.data;
    },
};

// ============================================
// CATEGORY MANAGEMENT API
// ============================================

export const categoryApi = {
    getAll: async () => {
        const response = await adminApi.get('/api/categories');
        return response.data;
    },

    create: async (data) => {
        const response = await adminApi.post('/api/categories', data);
        return response.data;
    },

    update: async (id, data) => {
        const response = await adminApi.put(`/api/categories/${id}`, data);
        return response.data;
    },

    delete: async (id) => {
        const response = await adminApi.delete(`/api/categories/${id}`);
        return response.data;
    },
};

// ============================================
// PROPERTY TYPE API
// ============================================

export const propertyTypeApi = {
    getAll: async () => {
        const response = await adminApi.get('/api/propertyTypes');
        return response.data;
    },

    create: async (data) => {
        const response = await adminApi.post('/api/propertyTypes', data);
        return response.data;
    },

    update: async (id, data) => {
        const response = await adminApi.put(`/api/propertyTypes/${id}`, data);
        return response.data;
    },

    delete: async (id) => {
        const response = await adminApi.delete(`/api/propertyTypes/${id}`);
        return response.data;
    },
};

// ============================================
// REPORTS API
// ============================================

export const reportsApi = {
    getPropertyReports: async (params = {}) => {
        const response = await adminApi.get('/api/admin/reports/properties', { params });
        return response.data;
    },

    getMessageReports: async (params = {}) => {
        const response = await adminApi.get('/api/admin/reports/messages', { params });
        return response.data;
    },

    resolveReport: async (reportId, resolution) => {
        const response = await adminApi.put(`/api/admin/reports/${reportId}/resolve`, resolution);
        return response.data;
    },
};

// ============================================
// MFA API
// ============================================

export const mfaApi = {
    setup: async () => {
        const response = await adminApi.post('/api/admin/mfa/setup');
        return response.data;
    },

    confirm: async (code) => {
        const response = await adminApi.post('/api/admin/mfa/confirm', { code });
        return response.data;
    },

    disable: async (password, code) => {
        const response = await adminApi.post('/api/admin/mfa/disable', { password, code });
        return response.data;
    },

    verify: async (code) => {
        const response = await adminApi.post('/api/admin/mfa/verify', { code });
        return response.data;
    },
};

// ============================================
// DASHBOARD API
// ============================================

export const dashboardApi = {
    getStats: async () => {
        const response = await adminApi.get('/api/admin/dashboard/stats');
        return response.data;
    },

    getRecentActivity: async () => {
        const response = await adminApi.get('/api/admin/dashboard/activity');
        return response.data;
    },
};

export default adminApi;
