/**
 * Admin API Client
 * Pre-configured axios instance with credentials for cookie-based authentication
 */
import axios from "axios";

const API_URL = import.meta.env.VITE_API_BASE_URL;

// Create axios instance with default config
const adminApi = axios.create({
    baseURL: API_URL,
    withCredentials: true, // CRITICAL: Send cookies with every request
    headers: {
        "Content-Type": "application/json",
    },
});

// Request interceptor - add token from localStorage as fallback (for legacy compatibility)
adminApi.interceptors.request.use(
    (config) => {
        // Cookies are sent automatically with withCredentials: true
        // This is just a fallback for any edge cases
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// Response interceptor - log errors but don't auto-redirect
adminApi.interceptors.response.use(
    (response) => response,
    (error) => {
        // Log auth errors for debugging
        if (error.response?.status === 401) {
            console.warn("Admin API auth error:", error.response?.data?.message);
        }
        return Promise.reject(error);
    }
);

export default adminApi;
