# Frontend Cookie Migration Guide

This document provides instructions for migrating the DealDirect frontend from localStorage token-based authentication to HttpOnly cookie-based authentication.

## Overview

The backend has been updated to use HttpOnly cookies for authentication. The frontend needs to:
1. Use `withCredentials: true` for all API calls
2. Stop reading tokens from localStorage
3. Use the new AuthContext for authentication state
4. Handle 401/403 errors gracefully

## Files Created

1. **`client/src/utils/api.js`** - Centralized API client with `withCredentials: true`
2. **`client/src/context/AuthContext.jsx`** - Auth context with cookie-based session management
3. **`Admin/src/api/adminApi.js`** - Enhanced admin API client

## Migration Progress

### ✅ Completed Components

| Component | Status | Notes |
|-----------|--------|-------|
| `App.jsx` | ✅ Done | Wrapped with AuthProvider, ProtectedRoute |
| `Login.jsx` | ✅ Done | Uses withCredentials API |
| `Profile.jsx` | ✅ Done | Uses api.js and AuthContext |
| `Notifications.jsx` | ✅ Done | Uses api.js and AuthContext |
| `SavedProperties.jsx` | ✅ Done | Uses api.js and AuthContext |
| `ChatContext.jsx` | ✅ Done | Uses api.js and AuthContext |
| `Navbar.jsx` | ✅ Done | Uses AuthContext logout |
| `PropertyDetails.jsx` | ✅ Done | Uses api.js for interest check |
| `AddProperty.jsx` | ✅ Done | Uses api.js and AuthContext |
| `EditProperty.jsx` | ✅ Done | Uses api.js and AuthContext |
| `MyProperties.jsx` | ✅ Done | Uses api.js and AuthContext |
| `EmailVerificationModal.jsx` | ✅ Done | Uses api.js and AuthContext |
| `AuthModal.jsx` | ✅ Done | Uses api.js and AuthContext |

### 🔄 Remaining Components (Low Priority)

| Component | Status | Notes |
|-----------|--------|-------|
| `PropertyList.jsx` | 🔄 Pending | Public endpoints, lower priority |
| `Contact.jsx` | 🔄 Pending | Public contact form |
| `AgreementGenerator.jsx` | 🔄 Pending | Authenticated feature |

## Migration Steps

### Step 1: Update App.jsx ✅
The App.jsx has been updated to wrap the app with `AuthProvider` and use `ProtectedRoute` for protected routes.

### Step 2: Update Components to Use AuthContext

Replace localStorage token checks with useAuth hook:

**Before:**
```jsx
const token = localStorage.getItem("token");
const user = JSON.parse(localStorage.getItem("user") || "{}");

if (!token) {
  navigate("/login");
  return;
}

const res = await axios.get(`${API_BASE}/api/notifications`, {
  headers: { Authorization: `Bearer ${token}` },
});
```

**After:**
```jsx
import { useAuth } from '../context/AuthContext';
import api from '../utils/api';

const { user, isAuthenticated, logout } = useAuth();

if (!isAuthenticated) {
  navigate("/login");
  return;
}

const res = await api.get('/notifications');
```

### Step 3: Update Login/Register Pages

**Login.jsx - After:**
```jsx
import { useAuth } from '../../context/AuthContext';

function Login() {
  const { login, isAuthenticated, loading } = useAuth();
  const navigate = useNavigate();
  
  // Redirect if already logged in
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/');
    }
  }, [isAuthenticated, navigate]);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    const result = await login(email, password);
    if (result.success) {
      navigate('/');
    } else {
      setError(result.message);
    }
  };
  
  // ...
}
```

### Step 4: Update Logout Logic

**Before:**
```jsx
const handleLogout = () => {
  localStorage.removeItem("user");
  localStorage.removeItem("token");
  setUser(null);
  navigate("/login");
};
```

**After:**
```jsx
import { useAuth } from '../context/AuthContext';

const { logout } = useAuth();

const handleLogout = async () => {
  await logout();
  // logout() handles navigation
};
```

### Step 5: Handle Auth Errors in Components

The api.js client already handles 401/403 errors globally. Components don't need individual error handling for auth - they just need to check `isAuthenticated` before rendering protected content.

## API Client Usage

### Basic GET Request
```jsx
import api from '../utils/api';

const fetchData = async () => {
  try {
    const response = await api.get('/properties/my-properties');
    setProperties(response.data.data);
  } catch (error) {
    console.error('Error:', error.response?.data?.message);
  }
};
```

### POST with Form Data
```jsx
const formData = new FormData();
formData.append('title', title);
formData.append('images', file);

const response = await api.post('/properties/add', formData, {
  headers: { 'Content-Type': 'multipart/form-data' },
});
```

### Using API Helpers
```jsx
import { propertyApi, notificationApi } from '../utils/api';

// Get my properties
const properties = await propertyApi.getMyProperties();

// Mark notification read
await notificationApi.markRead(notificationId);
```

## Backend Migration Script

Run the legacy user migration script to ensure all users have proper RBAC fields:

```bash
cd backend
node scripts/migrateLegacyUsers.js
```

## Testing Checklist

- [x] User can register
- [x] User can login
- [x] Session persists across page refresh
- [x] Logout clears session
- [x] Protected routes redirect to login when not authenticated
- [x] Owner routes are inaccessible to buyers
- [ ] 401 errors redirect to login with message
- [ ] 403 errors show access denied message
- [x] All API calls work without Authorization header

## Environment Variables

Ensure the frontend has the correct API URL:

**client/.env**
```env
VITE_API_URL=http://localhost:9000/api
VITE_API_BASE=http://localhost:9000
```

**Admin/.env**
```env
VITE_API_BASE_URL=http://localhost:9000/api
```

## Production Considerations

1. **CORS:** Ensure backend CORS is configured to allow cookies from frontend domain
2. **SameSite:** Cookie SameSite attribute must match your deployment (Lax for same-site, None for cross-site with Secure)
3. **Secure:** In production, Secure cookie flag must be enabled (HTTPS only)
4. **Domain:** Cookie domain should be set appropriately for subdomains
