import express from "express";
import {
  addProperty,
  addPropertyForBuilder,
  getProperties,
  getPropertyById,
  updateProperty,
  deleteProperty,
  getAllPropertiesList,
  approveProperty,
  disapproveProperty,
  searchProperties,
  getMyProperties,
  getMyPropertyById,
  deleteMyProperty,
  updateMyProperty,
  markInterested,
  checkInterested,
  removeInterest,
  getSavedProperties,
  removeSavedProperty,
  getSuggestions,
  getAdminProperties,
  reportProperty,
  closeDeal,
  claimDealReward,
} from "../controllers/propertyController.js";
import { protectAdmin } from "../middleware/authAdmin.js";
import { authMiddleware } from "../middleware/authUser.js";
import { memoryUpload, validateAndUploadToCloudinary, uploadConcurrencyGuard } from "../middleware/upload.js";
import { documentUpload, uploadDocumentsToCloudinary } from "../middleware/documentUpload.js";
import { ownerOnlyListingAccess } from "../middleware/roleGuard.js";
import { requirePhoneVerified, ensureOwnerRole } from "../middleware/requirePhoneVerified.js";
import {
  validatePropertyCreate,
  validatePropertyUpdate,
  validatePropertyReport,
  validateMongoId,
} from "../middleware/validators/index.js";

const router = express.Router();

// ============================================
// PUBLIC ROUTES (No authentication required)
// ============================================

// Public listing routes
router.get("/list", getProperties);
router.get("/property-list", getAllPropertiesList); // For frontend home page

// Public search (MUST be before /:id). /filter was retired in Phase 4.3.
router.get("/search", searchProperties);
router.get("/suggestions", getSuggestions); // Fast autocomplete

// /filter was retired in Phase 4.3: unbounded, and zero call sites across
// client-next, Admin and mobile. Answered explicitly rather than deleted
// outright, because without this the path falls through to the "/:id" wildcard
// below and getPropertyById tries to cast "filter" to an ObjectId — which
// currently surfaces as a 500. A retired endpoint should say so.
router.get("/filter", (req, res) =>
  res.status(410).json({
    success: false,
    message: "This endpoint has been retired. Use /api/properties/search.",
    code: "ENDPOINT_RETIRED",
  })
);

// ============================================
// PROTECTED ROUTES - AUTHENTICATED USERS
// ============================================

// 🔒 Protected: User's Own Properties (Owners only)
router.get("/my-properties", authMiddleware, getMyProperties);

// 🔒 Protected: Add Property
//
// This is where an account becomes an owner. Registration no longer asks, so
// the phone gate runs first and the promotion follows it — in that order, since
// the verified phone is the whole justification for granting the role.
//
// `ownerOnlyListingAccess` is gone from THIS route only, because it would
// reject every buyer before ensureOwnerRole could promote them. It stays on
// every other listing route below, where the account is already an owner.
router.post(
  "/add",
  authMiddleware,
  requirePhoneVerified,
  ensureOwnerRole,
  uploadConcurrencyGuard, // SECURITY: Prevent DoS via concurrent uploads
  memoryUpload.fields([
    { name: "images", maxCount: 15 },
    { name: "categorizedImages", maxCount: 50 }
  ]),
  validateAndUploadToCloudinary, // SECURITY: Validate magic bytes then upload
  // validatePropertyCreate, // TODO: Re-enable after fixing field whitelist
  addProperty
);

// 🔒 Protected: Read own property, including a disapproved one (Owners only)
//
// Declared before the "/:id" wildcard further down, like every other literal
// path in this file. The public GET /properties/:id 404s on a disapproved
// listing, which locked owners out of the edit page for the one listing they
// needed to correct.
router.get(
  "/my-properties/:id",
  authMiddleware,
  ownerOnlyListingAccess,
  validateMongoId('id'),
  getMyPropertyById
);

// 🔒 Protected: Update own property (Owners only)
router.put(
  "/my-properties/:id",
  authMiddleware,
  requirePhoneVerified,
  ownerOnlyListingAccess,
  validateMongoId('id'),
  uploadConcurrencyGuard, // SECURITY: Prevent DoS via concurrent uploads
  memoryUpload.fields([
    { name: "images", maxCount: 15 },
    { name: "categorizedImages", maxCount: 50 }
  ]),
  validateAndUploadToCloudinary, // SECURITY: Validate magic bytes then upload
  updateMyProperty
);

// 🔒 Protected: Saved/Interested Properties routes (Buyers can access)
router.get("/saved", authMiddleware, getSavedProperties);
router.delete("/saved/:id", authMiddleware, validateMongoId('id'), removeSavedProperty);

// 🔒 Protected: Interest routes (Buyers can express interest)
//
// Gated: expressing interest puts the buyer in front of a real owner and
// creates a lead someone will act on. Checking and removing interest are not
// gated — they only touch the buyer's own record.
router.post("/interested/:id", authMiddleware, requirePhoneVerified, validateMongoId('id'), markInterested);
router.get("/interested/:id/check", authMiddleware, validateMongoId('id'), checkInterested);
router.delete("/interested/:id", authMiddleware, validateMongoId('id'), removeInterest);

// 🔒 Protected: Report property (Any authenticated user)
router.post("/:id/report", authMiddleware, validatePropertyReport, reportProperty);

// 🔒 Protected: Close Deal (Owner submits proof for admin verification)
router.post(
  "/:id/close-deal",
  authMiddleware,
  requirePhoneVerified,
  uploadConcurrencyGuard,
  documentUpload.fields([{ name: "documents", maxCount: 5 }]),
  uploadDocumentsToCloudinary,
  closeDeal
);

// 🔒 Protected: Claim deal reward (Owner or Buyer claims after admin approval)
router.post("/claim-deal-reward/:verificationId", authMiddleware, requirePhoneVerified, claimDealReward);

// ============================================
// ADMIN ROUTES (Admin authentication required)
// ============================================

// Admin: Get all properties with filters
router.get("/admin/all", protectAdmin, getAdminProperties);

// Admin: Create property for a builder (no owner auth — admin posts on behalf)
router.post(
  "/admin/add",
  protectAdmin,
  uploadConcurrencyGuard,
  memoryUpload.fields([
    { name: "images", maxCount: 15 },
    { name: "categorizedImages", maxCount: 50 }
  ]),
  validateAndUploadToCloudinary,
  addPropertyForBuilder
);

// Admin: Update property
router.put(
  "/edit/:id",
  protectAdmin,
  validateMongoId('id'),
  uploadConcurrencyGuard, // SECURITY: Prevent DoS via concurrent uploads
  memoryUpload.fields([
    { name: "images", maxCount: 15 },
    { name: "categorizedImages", maxCount: 50 }
  ]),
  validateAndUploadToCloudinary, // SECURITY: Validate magic bytes then upload
  updateProperty
);

// Admin: Delete property
router.delete("/delete/:id", protectAdmin, validateMongoId('id'), deleteProperty);

// Admin: Approve/Disapprove property
router.put("/approve/:id", protectAdmin, validateMongoId('id'), approveProperty);
router.put("/disapprove/:id", protectAdmin, validateMongoId('id'), disapproveProperty);

// ============================================
// DYNAMIC ID ROUTES (MUST be last)
// ============================================
router.get("/:id", getPropertyById);
router.delete("/:id", authMiddleware, validateMongoId('id'), deleteMyProperty);

export default router;