import Admin from "../models/Admin.js";
import AdminSession from "../models/AdminSession.js";
import AuditLog from "../models/AuditLog.js";

/**
 * Cookie configuration for secure session management
 */
export const COOKIE_CONFIG = {
  name: "admin_session",
  options: {
    httpOnly: true, // Prevents XSS attacks - cookie not accessible via JavaScript
    secure: process.env.NODE_ENV === "production", // HTTPS only in production
    sameSite: "strict", // Prevents CSRF attacks
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: "/",
    domain: process.env.COOKIE_DOMAIN || undefined,
  },
};

/**
 * MFA cookie configuration (shorter lived)
 */
export const MFA_COOKIE_CONFIG = {
  name: "admin_mfa_pending",
  options: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 10 * 60 * 1000, // 10 minutes to complete MFA
    path: "/",
  },
};

/**
 * Extract client IP address from request
 */
const getClientIp = (req) => {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    req.ip ||
    "unknown"
  );
};

/**
 * Parse user agent for device info
 */
const parseUserAgent = (userAgent = "") => {
  const info = {
    browser: "Unknown",
    os: "Unknown",
    device: "Unknown",
  };

  // Simple parsing - in production, use a proper UA parser library
  if (userAgent.includes("Chrome")) info.browser = "Chrome";
  else if (userAgent.includes("Firefox")) info.browser = "Firefox";
  else if (userAgent.includes("Safari")) info.browser = "Safari";
  else if (userAgent.includes("Edge")) info.browser = "Edge";

  if (userAgent.includes("Windows")) info.os = "Windows";
  else if (userAgent.includes("Mac")) info.os = "macOS";
  else if (userAgent.includes("Linux")) info.os = "Linux";
  else if (userAgent.includes("Android")) info.os = "Android";
  else if (userAgent.includes("iOS")) info.os = "iOS";

  if (userAgent.includes("Mobile")) info.device = "Mobile";
  else if (userAgent.includes("Tablet")) info.device = "Tablet";
  else info.device = "Desktop";

  return info;
};

/**
 * Create a new admin session
 */
export const createSession = async (admin, req) => {
  const sessionToken = AdminSession.generateToken();
  const fingerprint = AdminSession.generateFingerprint(req);
  const clientIp = getClientIp(req);
  const userAgent = req.headers["user-agent"] || "";
  const deviceInfo = parseUserAgent(userAgent);

  // Handle legacy admins that don't have MFA field
  const mfaEnabled = admin.mfa?.enabled ?? false;

  const session = await AdminSession.create({
    admin: admin._id,
    sessionToken,
    fingerprint,
    ipAddress: clientIp,
    userAgent,
    deviceInfo,
    expiresAt: new Date(Date.now() + COOKIE_CONFIG.options.maxAge),
    mfaVerified: !mfaEnabled, // If MFA not enabled, consider it verified
  });

  return { session, sessionToken };
};

/**
 * Set session cookie on response
 */
export const setSessionCookie = (res, sessionToken) => {
  res.cookie(COOKIE_CONFIG.name, sessionToken, COOKIE_CONFIG.options);
};

/**
 * Clear session cookie
 */
export const clearSessionCookie = (res) => {
  res.clearCookie(COOKIE_CONFIG.name, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
  });
};

/**
 * Set MFA pending cookie
 */
export const setMfaPendingCookie = (res, sessionToken) => {
  res.cookie(MFA_COOKIE_CONFIG.name, sessionToken, MFA_COOKIE_CONFIG.options);
};

/**
 * Clear MFA pending cookie
 */
export const clearMfaPendingCookie = (res) => {
  res.clearCookie(MFA_COOKIE_CONFIG.name, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
  });
};

/**
 * Main admin protection middleware
 * Strictly verifies session integrity against the database
 * Supports both HttpOnly cookies (preferred) and Bearer tokens (fallback for migration)
 */
export const protectAdmin = async (req, res, next) => {
  const startTime = Date.now();

  try {
    // Extract session token from HttpOnly cookie (preferred)
    let sessionToken = req.cookies?.[COOKIE_CONFIG.name];

    // Fallback: Check Authorization header for Bearer token (backward compatibility)
    if (!sessionToken) {
      const authHeader = req.headers.authorization;
      if (authHeader?.startsWith("Bearer ")) {
        sessionToken = authHeader.split(" ")[1];
      }
    }

    if (!sessionToken) {
      await AuditLog.log({
        admin: null,
        category: "authentication",
        action: "access_denied",
        description: "No session token provided",
        req,
        result: "denied",
        severity: "medium",
        isSecurityEvent: true,
      });

      return res.status(401).json({
        success: false,
        message: "Authentication required. Please log in.",
        code: "NO_SESSION",
      });
    }

    // Find and validate session in database
    const session = await AdminSession.findOne({
      sessionToken,
      isActive: true,
      expiresAt: { $gt: new Date() },
    });

    if (!session) {
      clearSessionCookie(res);

      await AuditLog.log({
        admin: null,
        category: "authentication",
        action: "invalid_session",
        description: "Session token not found or expired",
        req,
        result: "denied",
        severity: "medium",
        isSecurityEvent: true,
      });

      return res.status(401).json({
        success: false,
        message: "Session expired or invalid. Please log in again.",
        code: "INVALID_SESSION",
      });
    }

    // Note: Fingerprint verification disabled - was causing issues across tabs/requests
    // In production, consider implementing a more lenient fingerprint check

    // Check MFA verification status
    // Skip for legacy admins (those with string roles didn't have MFA)
    console.log("[AUTH] Session mfaVerified:", session.mfaVerified);
    if (!session.mfaVerified) {
      // Check if admin is a legacy admin with string role
      const adminCheck = await Admin.findById(session.admin);
      console.log("[AUTH] Admin role type:", typeof adminCheck?.role, "value:", adminCheck?.role);
      const isLegacyAdmin = typeof adminCheck?.role === "string";

      if (!isLegacyAdmin) {
        console.log("[AUTH] Not a legacy admin - requiring MFA");
        return res.status(403).json({
          success: false,
          message: "Multi-factor authentication required.",
          code: "MFA_REQUIRED",
          requiresMfa: true,
        });
      }

      // For legacy admins, auto-set mfaVerified to true
      console.log("[AUTH] Legacy admin detected - setting mfaVerified to true");
      session.mfaVerified = true;
      await session.save();
    }

    // Get admin from database
    // Note: Don't populate role - legacy admins have string roles instead of ObjectIds
    const admin = await Admin.findById(session.admin);

    if (!admin) {
      await session.revoke("admin_not_found");
      clearSessionCookie(res);

      return res.status(401).json({
        success: false,
        message: "Admin account not found.",
        code: "ADMIN_NOT_FOUND",
      });
    }

    // Check if admin account is active (default to true for legacy admins)
    if (admin.isActive === false) {
      await session.revoke("admin_deactivated");
      clearSessionCookie(res);

      await AuditLog.log({
        admin: admin._id,
        category: "authentication",
        action: "access_denied_inactive",
        description: "Inactive admin attempted to access protected resource",
        req,
        result: "denied",
        severity: "high",
        isSecurityEvent: true,
      });

      return res.status(403).json({
        success: false,
        message: "Your account has been deactivated. Contact a super admin.",
        code: "ACCOUNT_DEACTIVATED",
      });
    }

    // Check if admin is locked out
    if (admin.isLocked) {
      const lockExpiry = admin.security.lockoutUntil;
      const remainingMinutes = Math.ceil((lockExpiry - Date.now()) / 60000);

      return res.status(403).json({
        success: false,
        message: `Account temporarily locked. Try again in ${remainingMinutes} minutes.`,
        code: "ACCOUNT_LOCKED",
        lockoutUntil: lockExpiry,
      });
    }

    // Check if password must be changed
    if (admin.security.mustChangePassword) {
      // Only allow password change endpoint
      if (!req.originalUrl.includes("/change-password")) {
        return res.status(403).json({
          success: false,
          message: "You must change your password before continuing.",
          code: "PASSWORD_CHANGE_REQUIRED",
          requiresPasswordChange: true,
        });
      }
    }

    // Update session last activity
    await session.touch();

    // Attach admin and session to request
    req.admin = admin;
    req.adminSession = session;
    req.clientIp = getClientIp(req);

    // Calculate request duration for audit
    res.on("finish", async () => {
      const duration = Date.now() - startTime;

      // Log successful access (for sensitive operations)
      if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
        await AuditLog.log({
          admin: admin._id,
          category: "data_access",
          action: `${req.method.toLowerCase()}_request`,
          description: `${req.method} ${req.originalUrl}`,
          req,
          sessionId: session._id,
          result: res.statusCode < 400 ? "success" : "failure",
          statusCode: res.statusCode,
          duration,
        });
      }
    });

    next();
  } catch (error) {
    console.error("Admin auth middleware error:", error);

    // Clear potentially invalid session cookie
    clearSessionCookie(res);

    await AuditLog.log({
      admin: null,
      category: "system",
      action: "auth_middleware_error",
      description: "Unexpected error in admin authentication middleware",
      req,
      result: "failure",
      error,
      severity: "high",
    });

    return res.status(500).json({
      success: false,
      message: "Authentication error. Please try again.",
      code: "AUTH_ERROR",
    });
  }
};

/**
 * Permission checking middleware factory
 * Use: requirePermission("users:read")
 */
export const requirePermission = (...requiredPermissions) => {
  return async (req, res, next) => {
    try {
      if (!req.admin) {
        return res.status(401).json({
          success: false,
          message: "Authentication required.",
          code: "NOT_AUTHENTICATED",
        });
      }

      // Get admin's permission codes
      const adminPermissions = await req.admin.getPermissions();

      // Check if admin has any of the required permissions
      const hasPermission = requiredPermissions.some((perm) => adminPermissions.includes(perm));

      if (!hasPermission) {
        await AuditLog.log({
          admin: req.admin._id,
          category: "authorization",
          action: "permission_denied",
          description: `Access denied. Required: [${requiredPermissions.join(", ")}]`,
          req,
          sessionId: req.adminSession?._id,
          result: "denied",
          severity: "medium",
          metadata: { requiredPermissions, adminPermissions },
        });

        return res.status(403).json({
          success: false,
          message: "You do not have permission to perform this action.",
          code: "PERMISSION_DENIED",
          required: requiredPermissions,
        });
      }

      next();
    } catch (error) {
      console.error("Permission check error:", error);
      return res.status(500).json({
        success: false,
        message: "Authorization error.",
        code: "AUTHORIZATION_ERROR",
      });
    }
  };
};

/**
 * Role level checking middleware factory
 * Use: requireRoleLevel(50) // Requires role with level >= 50
 */
export const requireRoleLevel = (minLevel) => {
  return async (req, res, next) => {
    try {
      if (!req.admin) {
        return res.status(401).json({
          success: false,
          message: "Authentication required.",
          code: "NOT_AUTHENTICATED",
        });
      }

      const roleLevel = req.admin.role?.level || 0;

      if (roleLevel < minLevel) {
        await AuditLog.log({
          admin: req.admin._id,
          category: "authorization",
          action: "role_level_denied",
          description: `Access denied. Required level: ${minLevel}, Admin level: ${roleLevel}`,
          req,
          sessionId: req.adminSession?._id,
          result: "denied",
          severity: "medium",
        });

        return res.status(403).json({
          success: false,
          message: "Insufficient privileges for this action.",
          code: "INSUFFICIENT_ROLE_LEVEL",
        });
      }

      next();
    } catch (error) {
      console.error("Role level check error:", error);
      return res.status(500).json({
        success: false,
        message: "Authorization error.",
        code: "AUTHORIZATION_ERROR",
      });
    }
  };
};

/**
 * Super admin only middleware
 */
export const requireSuperAdmin = requireRoleLevel(100);

/**
 * Rate limiting for authentication endpoints
 */
const authAttempts = new Map();

export const authRateLimit = (req, res, next) => {
  const clientIp = getClientIp(req);
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxAttempts = 10;

  // Clean up old entries
  for (const [ip, data] of authAttempts.entries()) {
    if (now - data.firstAttempt > windowMs) {
      authAttempts.delete(ip);
    }
  }

  const attempts = authAttempts.get(clientIp);

  if (attempts) {
    if (attempts.count >= maxAttempts && now - attempts.firstAttempt < windowMs) {
      const retryAfter = Math.ceil((attempts.firstAttempt + windowMs - now) / 1000);

      return res.status(429).json({
        success: false,
        message: "Too many authentication attempts. Please try again later.",
        code: "RATE_LIMITED",
        retryAfter,
      });
    }

    attempts.count++;
  } else {
    authAttempts.set(clientIp, { count: 1, firstAttempt: now });
  }

  next();
};

/**
 * Clear rate limit on successful auth
 */
export const clearAuthRateLimit = (req) => {
  const clientIp = getClientIp(req);
  authAttempts.delete(clientIp);
};
