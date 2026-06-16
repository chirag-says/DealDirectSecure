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
  filterProperties,
  getMyProperties,
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

// Public search & filter (MUST be before /:id)
router.get("/search", searchProperties);
router.get("/suggestions", getSuggestions); // Fast autocomplete
router.get("/filter", filterProperties);

// ============================================
// PROTECTED ROUTES - AUTHENTICATED USERS
// ============================================

// 🔒 Protected: User's Own Properties (Owners only)
router.get("/my-properties", authMiddleware, getMyProperties);

// 🔒 Protected: Add Property (Owners only with validation)
router.post(
  "/add",
  authMiddleware,
  ownerOnlyListingAccess, // Role enforcement: only Owners can add
  uploadConcurrencyGuard, // SECURITY: Prevent DoS via concurrent uploads
  memoryUpload.fields([
    { name: "images", maxCount: 15 },
    { name: "categorizedImages", maxCount: 50 }
  ]),
  validateAndUploadToCloudinary, // SECURITY: Validate magic bytes then upload
  // validatePropertyCreate, // TODO: Re-enable after fixing field whitelist
  addProperty
);

// 🔒 Protected: Update own property (Owners only)
router.put(
  "/my-properties/:id",
  authMiddleware,
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
router.post("/interested/:id", authMiddleware, validateMongoId('id'), markInterested);
router.get("/interested/:id/check", authMiddleware, validateMongoId('id'), checkInterested);
router.delete("/interested/:id", authMiddleware, validateMongoId('id'), removeInterest);

// 🔒 Protected: Report property (Any authenticated user)
router.post("/:id/report", authMiddleware, validatePropertyReport, reportProperty);

// 🔒 Protected: Close Deal (Owner submits proof for admin verification)
router.post(
  "/:id/close-deal",
  authMiddleware,
  uploadConcurrencyGuard,
  documentUpload.fields([{ name: "documents", maxCount: 5 }]),
  uploadDocumentsToCloudinary,
  closeDeal
);

// 🔒 Protected: Claim deal reward (Owner or Buyer claims after admin approval)
router.post("/claim-deal-reward/:verificationId", authMiddleware, claimDealReward);

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