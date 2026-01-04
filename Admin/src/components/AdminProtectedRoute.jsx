import React from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAdmin, AUTH_STATUS } from "../context/AdminContext";

/**
 * AdminProtectedRoute - Cookie-First Protected Route
 * 
 * Waits for the server-side session verification before deciding
 * whether to render children or redirect to login.
 * 
 * Features:
 * - Shows loading state while verifying session with server
 * - Redirects to login if session is invalid
 * - Preserves intended destination for post-login redirect
 */
const AdminProtectedRoute = ({ children }) => {
  const { authStatus, isAuthenticated } = useAdmin();
  const location = useLocation();

  // ✅ Show loading state while checking auth with server
  if (authStatus === AUTH_STATUS.LOADING) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
          <p className="text-gray-600 font-medium">Verifying session...</p>
        </div>
      </div>
    );
  }

  // ✅ Redirect to login if not authenticated
  if (!isAuthenticated) {
    // Save the intended destination for redirect after login
    return (
      <Navigate
        to="/admin/login"
        replace
        state={{ from: location.pathname }}
      />
    );
  }

  // ✅ Session verified - render protected content
  return children;
};

export default AdminProtectedRoute;
