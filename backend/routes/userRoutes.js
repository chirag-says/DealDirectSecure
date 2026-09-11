/**
 * User Routes
 * Enterprise-grade authentication with secure endpoints
 */
import express from "express";
import {
  registerUser,
  registerUserDirect,
  verifyOtp,
  resendOtp,
  loginUser,
  logoutUser,
  logoutAllDevices,
  getProfile,
  updateProfile,
  changePassword,
  sendUpgradeOtp,
  verifyUpgradeOtp,
  forgotPassword,
  resetPassword,
  validateResetToken,
  getActiveSessions,
  revokeSession,
  getAllUsers,
  toggleBlockUser,
  exportUsersPDF,
  exportUsersCSV,
  exportOwnersPDF,
  exportOwnersCSV,
  deleteAccount
} from "../controllers/userController.js";
import { googleSignIn, googleLinkAccount } from "../controllers/authGoogleController.js";
import {
  sendPhoneOtp,
  verifyPhoneOtp,
  getPhoneStatus,
} from "../controllers/phoneVerificationController.js";
import { getOwnersWithProjects } from "../controllers/propertyController.js";
import {
  authMiddleware,
  optionalAuth,
  requireVerified,
  authRateLimit
} from "../middleware/authUser.js";
// `upload` (the legacy CloudinaryStorage export) was imported here and never
// used; dropped with the local-disk route.
import { memoryUpload, validateAndUploadToCloudinary, uploadConcurrencyGuard } from "../middleware/upload.js";
import { protectAdmin } from "../middleware/authAdmin.js";
import { validateProfileUpdate } from "../middleware/validators/index.js";
import { registerPushToken, removePushToken } from "../controllers/pushTokenController.js";
import { registerDevice } from "../controllers/userController.js";

const router = express.Router();

// Local disk storage removed with POST /api/users/add-property (see below).
// Every upload path now goes through middleware/upload.js, which validates
// magic bytes before anything reaches Cloudinary.

// ============================================
// PUBLIC AUTH ROUTES (Rate limited)
// ============================================

// Registration
router.post("/register", authRateLimit, registerUser);
router.post("/register-direct", authRateLimit, registerUserDirect);
router.post("/verify-otp", authRateLimit, verifyOtp);
router.post("/resend-otp", authRateLimit, resendOtp);

// Login
router.post("/login", authRateLimit, loginUser);

// Google Sign-In.
//
// Both share loginUser's rate limiter. /link in particular needs it: it takes a
// password, so without a limiter it would be an unthrottled guessing oracle for
// the very credential /login throttles.
router.post("/auth/google", authRateLimit, googleSignIn);
router.post("/auth/google/link", authRateLimit, googleLinkAccount);

// Password Reset (public)
router.post("/forgot-password", authRateLimit, forgotPassword);
router.get("/reset-password/validate/:token", validateResetToken);
router.post("/reset-password", authRateLimit, resetPassword);

// ============================================
// PROTECTED AUTH ROUTES
// ============================================

// Logout
router.post("/logout", authMiddleware, logoutUser);
router.post("/logout-all", authMiddleware, logoutAllDevices);

// Session Management
router.get("/sessions", authMiddleware, getActiveSessions);
router.delete("/sessions/:sessionId", authMiddleware, revokeSession);

// ============================================
// PROFILE ROUTES (Protected with validation)
// ============================================

router.get("/profile", authMiddleware, getProfile);
router.get("/me", authMiddleware, getProfile); // Alias for /profile - standard REST pattern
router.put("/profile", authMiddleware, validateProfileUpdate, uploadConcurrencyGuard, memoryUpload.single("profileImage"), validateAndUploadToCloudinary, updateProfile);
router.put("/change-password", authMiddleware, changePassword);
router.delete("/me", authMiddleware, deleteAccount);

// Push devices (Phase 0, F6). See controllers/pushTokenController.js.
router.post("/push-token", authMiddleware, registerPushToken);
router.delete("/push-token", authMiddleware, removePushToken);
// Device linkage input for the verified-close check (Phase 3, F15).
router.post("/device", authMiddleware, registerDevice);

// ============================================
// PHONE VERIFICATION (just-in-time)
// ============================================
//
// Reached when a gated action returns 403 PHONE_VERIFICATION_REQUIRED. No
// `requireVerified` here on purpose: an account that has not proved a phone is
// exactly the account that needs these, so gating them on verification would
// make the gate impossible to pass.
//
// Rate limiting lives inside the controller rather than in authRateLimit, which
// counts per IP. The meaningful limits here are per account and per phone
// number: one office behind one NAT is not three abusers, and an attacker on a
// phone network can change IP at will.

router.get("/phone/status", authMiddleware, getPhoneStatus);
router.post("/phone/send-otp", authMiddleware, sendPhoneOtp);
router.post("/phone/verify-otp", authMiddleware, verifyPhoneOtp);

// ============================================
// UPGRADE ROUTES (Buyer to Owner) — LEGACY
// ============================================
//
// Superseded by ensureOwnerRole, which promotes on the first listing attempt.
// Kept alive because published app builds still call them and cannot be forced
// to update. Retire once telemetry shows those builds are gone.

router.post("/send-upgrade-otp", authMiddleware, requireVerified, sendUpgradeOtp);
router.post("/verify-upgrade-otp", authMiddleware, requireVerified, verifyUpgradeOtp);

// ============================================
// PROPERTY ROUTES (Owner only)
// ============================================

// REMOVED 2026-08-16 — POST /api/users/add-property
//
// A second, unhardened duplicate of POST /api/properties/add. It used a bare
// multer.diskStorage with no fileFilter, no size limit and no magic-byte
// validation, writing caller-controlled bytes into ./uploads, which is served
// publicly. express.static derives Content-Type from the file extension, so an
// uploaded .html rendered on the API origin.
//
// It was also outside the CSRF guard list, and its uploads never worked:
// .array() puts req.files in an array while addProperty expects an object
// keyed by field name, so the files landed on disk and were never attached to
// the property.
//
// Verified before removal: zero references to "users/add-property" anywhere in
// backend, client-next, Admin or dealdirect-mobile. Use POST /api/properties/add,
// which runs the validated Cloudinary pipeline.

// ============================================
// ADMIN ROUTES (Admin protected)
// ============================================

router.get("/list", protectAdmin, getAllUsers);
router.put("/block/:id", protectAdmin, toggleBlockUser);
router.get("/owners-projects", protectAdmin, getOwnersWithProjects);
router.get("/export-csv", protectAdmin, exportUsersCSV);
router.get("/export-pdf", protectAdmin, exportUsersPDF);
router.get("/export-owners-csv", protectAdmin, exportOwnersCSV);
router.get("/export-owners-pdf", protectAdmin, exportOwnersPDF);

export default router;
