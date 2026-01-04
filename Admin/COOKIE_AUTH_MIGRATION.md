# Cookie-First Authentication Migration Guide

## Overview
This document describes the migration from localStorage-based token authentication to cookie-first (HttpOnly session cookie) authentication for the Admin panel.

## Changes Made

### 1. New Context Created: `AdminContext.jsx`
**Location:** `Admin/src/context/AdminContext.jsx`

The AdminContext provides:
- **Auth state management** via server-side verification
- **`checkAuth()`** - Calls `/api/admin/profile` on app mount to verify session
- **`login(adminData)`** - Updates context after successful login
- **`logout()`** - Calls server logout endpoint and clears state
- **Role & permissions** - Stores `role`, `roleName`, `roleLevel`, `permissions` from server

Usage:
```jsx
import { useAdmin } from '../context/AdminContext';

const { admin, isAuthenticated, isLoading, role, logout } = useAdmin();
```

### 2. Updated: `AdminProtectedRoute.jsx`
- Now waits for server auth check before redirecting
- Shows loading spinner while verifying session
- Uses `useAdmin()` hook instead of `localStorage.getItem("adminToken")`

### 3. Updated: `App.jsx`
- Wrapped with `<AdminProvider>`
- Removed duplicate `ProtectedRoute` component
- Removed `getStoredAdminInfo()` function

### 4. Updated: `AdminLogin.jsx`
- Uses `adminAuthApi.login()` instead of direct axios
- Uses `useAdmin()` context for login
- Removed all `localStorage.setItem()` calls
- Redirects to intended destination after login

### 5. Updated: `Sidebar.jsx`
- Uses `useAdmin()` for admin info (name, email, role)
- Logout calls `logout()` from context
- Removed all localStorage operations

### 6. Updated: `Header.jsx`
- Uses `useAdmin()` for admin info
- Logout calls context `logout()`
- Removed localStorage reading

### 7. Updated: `adminApi.js`
- Removed localStorage cleanup (now handled by context)
- Auth error handler triggers context state cleanup

### 8. Updated: `AllProperty.jsx`
- Uses `adminApi` instead of direct axios
- Removed `localStorage.getItem("adminToken")`
- Removed `Authorization` header (cookies sent automatically)

---

## Migration Status: ✅ COMPLETE

All admin pages have been successfully migrated from localStorage-based token authentication to cookie-based authentication using `adminApi`.

### Files Updated:
1. ✅ **`AddProperty.jsx`** - Migrated
2. ✅ **`LeadMonitoring.jsx`** - Migrated
3. ✅ **`BuilderProjects.jsx`** - Migrated
4. ✅ **`BuilderVerification.jsx`** - Migrated
5. ✅ **`AllClients.jsx`** - Migrated
6. ✅ **`ContactInquiries.jsx`** - Migrated
7. ✅ **`PropertyReports.jsx`** - Migrated
8. ✅ **`ReportedMessages.jsx`** - Migrated
9. ✅ **`AllCategory.jsx`** - Migrated
10. ✅ **`AddSubCategory.jsx`** - Migrated
11. ✅ **`AddCategory.jsx`** - Migrated
12. ✅ **`PopularProperties.jsx`** - Migrated
13. ✅ **`SiteVisitManagement.jsx`** - Migrated
14. ✅ **`AllProperty.jsx`** - Migrated
15. ✅ **`Dashboard.jsx`** - Already using adminApi

---

## Migration Pattern

For each file, follow this pattern:

### Before (Token-based):
```jsx
import axios from "axios";

const token = localStorage.getItem("adminToken");

const res = await axios.get(`${API_URL}/api/endpoint`, {
    headers: { Authorization: `Bearer ${token}` }
});
```

### After (Cookie-based):
```jsx
import adminApi from "../api/adminApi";

// No token needed - cookies sent automatically
const res = await adminApi.get(`/api/endpoint`);
```

### Key Changes:
1. Replace `import axios from "axios"` with `import adminApi from "../api/adminApi"`
2. Remove `const token = localStorage.getItem("adminToken")`
3. Replace `axios.get/post/put/delete` with `adminApi.get/post/put/delete`
4. Remove `headers: { Authorization: ... }` - cookies are automatic
5. Change base URL from `${API_URL}/api/...` to `/api/...` (adminApi has baseURL set)

---

## How It Works

### Session Verification Flow:
1. App mounts → `AdminProvider` initializes
2. `checkAuth()` called → GET `/api/admin/profile` with cookies
3. Server validates HttpOnly session cookie
4. If valid → Returns admin data → Context stores it
5. If invalid → Returns 401 → Context sets unauthenticated

### Login Flow:
1. User submits credentials
2. `adminAuthApi.login()` → POST `/api/admin/login`
3. Server sets HttpOnly session cookie
4. Context updated with admin data
5. User redirected to dashboard

### Logout Flow:
1. User clicks logout
2. `logout()` → POST `/api/admin/logout`
3. Server clears session cookie
4. Context cleared
5. AdminProtectedRoute redirects to login

---

## Benefits of Cookie-First Auth

1. **Security**: HttpOnly cookies cannot be accessed by JavaScript (XSS-proof)
2. **No token exposure**: Token never in localStorage or memory
3. **Automatic handling**: Browser sends cookies with every request
4. **Server-controlled**: Session can be revoked server-side
5. **Simpler code**: No manual token management

---

## Testing

After migration, verify:
1. ✅ Login works and redirects to dashboard
2. ✅ Refresh page maintains session
3. ✅ Protected routes require authentication
4. ✅ Logout clears session
5. ✅ 401 errors redirect to login
6. ✅ Admin info displays correctly in Header/Sidebar
