/**
 * Configuration utilities for API and environment settings
 * Provides consistent URL handling across the application
 */

// Get the API Base URL (without /api suffix)
export const getApiBase = () => {
    if (import.meta.env.VITE_API_BASE) {
        return import.meta.env.VITE_API_BASE;
    }
    // Fallback for development
    return `${window.location.protocol}//${window.location.hostname}:9000`;
};

// Get the API URL (with /api suffix)
export const getApiUrl = () => {
    if (import.meta.env.VITE_API_URL) {
        return import.meta.env.VITE_API_URL;
    }
    return `${getApiBase()}/api`;
};

// Resolve image source URL
export const resolveImageUrl = (img) => {
    if (!img) return "";
    const lower = img.toLowerCase();
    
    // Already a data URL or full URL
    if (lower.startsWith("data:")) return img;
    if (lower.startsWith("http://") || lower.startsWith("https://")) return img;
    
    const baseUrl = getApiBase();
    
    // Handle relative paths
    if (img.startsWith("/uploads")) return `${baseUrl}${img}`;
    if (img.startsWith("/")) return `${baseUrl}${img}`;
    return `${baseUrl}/uploads/${img}`;
};

// Export API_BASE for backward compatibility
export const API_BASE = getApiBase();
