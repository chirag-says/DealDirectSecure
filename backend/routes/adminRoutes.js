import express from "express";
import {
  // registerAdmin - REMOVED: Admins are now created via database seeding only (security hardening)
  loginAdmin,
  logoutAdmin,
  logoutAllSessions,
  verifyMfa,
  setupMfa,
  confirmMfaSetup,
  disableMfa,
  getAdminProfile,
  getActiveSessions,
  revokeSession,
  changePassword,
  getDashboardStats,
  getAdminLeads,
  updateAdminLeadStatus,
  getAdminReports,
  updateReportStatus,
  getAuditLogs,
} from "../controllers/adminController.js";
import {
  protectAdmin,
  // requireRoleLevel - REMOVED: No longer needed (admin registration removed)
  requireSuperAdmin,
  authRateLimit,
} from "../middleware/authAdmin.js";
import { getAllLeads } from "../controllers/leadController.js";
import { getMetrics } from "../controllers/eventController.js";
import { setUserVerification } from "../controllers/adminController.js";

const router = express.Router();

// ============================================
// PUBLIC ROUTES (No authentication required)
// ============================================

// Authentication
router.post("/login", authRateLimit, loginAdmin);

// MFA verification (after login, before full session)
router.post("/mfa/verify", authRateLimit, verifyMfa);

// ============================================
// PROTECTED ROUTES (Authentication required)
// ============================================

// Session management
router.post("/logout", protectAdmin, logoutAdmin);
router.post("/logout-all", protectAdmin, logoutAllSessions);
router.get("/sessions", protectAdmin, getActiveSessions);
router.delete("/sessions/:sessionId", protectAdmin, revokeSession);

// Profile & Security
router.get("/profile", protectAdmin, getAdminProfile);
router.post("/change-password", protectAdmin, changePassword);

// MFA management
router.post("/mfa/setup", protectAdmin, setupMfa);
router.post("/mfa/confirm", protectAdmin, confirmMfaSetup);
router.post("/mfa/disable", protectAdmin, disableMfa);

// Dashboard & Analytics
router.get("/dashboard/stats", protectAdmin, getDashboardStats);
// Funnel metrics from usage events (Phase 0, F3).
router.get("/metrics", protectAdmin, getMetrics);
// Verification badge (Phase 3, F17).
router.put("/users/:id/verification", protectAdmin, setUserVerification);

// Leads Management
router.get("/leads", protectAdmin, getAllLeads);
router.put("/leads/:id", protectAdmin, updateAdminLeadStatus);

// Reports Management
router.get("/reports", protectAdmin, getAdminReports);
router.put("/reports/:id", protectAdmin, updateReportStatus);

// ============================================
// ADMIN MANAGEMENT ROUTES (High privilege)
// ============================================

// SECURITY: Admin registration endpoint REMOVED
// Admins are now created via database seeding only
// Run: node seedAdmin.js (from backend directory)
// This eliminates the registration attack surface entirely

import {
  getDealVerifications,
  approveDealVerification,
  rejectDealVerification,
} from "../controllers/adminController.js";

// ============================================
// Deal Verifications
//
// protectAdmin alone, like every other admin route.
//
// Commit 79ae3ab attached requirePermission("verifications:read" / ":approve")
// here. Those codes could never resolve: Permission.resource is a closed enum
// that does not contain "verifications", so no matching document could be
// created and no role could grant it. Every admin got a hard 403 including
// super_admin, the page rendered "No pending verifications found", deal
// closures piled up unapproved, and no user could claim a deal reward.
//
// The permission layer was retired entirely in Phase 3F, so the middleware that
// caused this no longer exists. See middleware/authAdmin.js for the reasoning.
// ============================================
router.get("/verifications", protectAdmin, getDealVerifications);
router.post("/verifications/:id/approve", protectAdmin, approveDealVerification);
router.post("/verifications/:id/reject", protectAdmin, rejectDealVerification);

// Audit Logs (Super Admin only)
router.get("/audit-logs", protectAdmin, requireSuperAdmin, getAuditLogs);

export default router;
