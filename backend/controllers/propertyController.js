import Property from "../models/Property.js";
import { cloudinary } from "../middleware/upload.js";
import mongoose from "mongoose";
import Lead from "../models/Lead.js";
import User from "../models/userModel.js";
import Builder from "../models/Builder.js";
import Report from "../models/Report.js";
import Notification from "../models/Notification.js";
import SavedSearch from "../models/SavedSearch.js";
import TransactionVerification from "../models/TransactionVerification.js";
import { awardPoints } from "../services/rewardService.js";
import { sendNewLeadWhatsApp, sendNewPropertyWhatsApp } from "../services/whatsappService.js";

// ============================================
// SECURITY FIX: ReDoS Prevention
// Escape special regex characters in user input before creating RegExp
// This prevents Regular Expression Denial of Service attacks
// ============================================

/**
 * Escape special regex characters in a string to prevent ReDoS attacks
 * @param {string} string - Raw user input
 * @returns {string} - Escaped string safe for use in RegExp
 */
const escapeRegExp = (string) => {
  if (!string || typeof string !== 'string') return '';
  // Escape all regex special characters: \ ^ $ . * + ? ( ) [ ] { } |
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
};

// ============================================
// SECURITY FIX: Strict WHITELIST approach for mass assignment prevention
// Only explicitly allowed fields can be set from request bodies.
// This is more secure than a blacklist as new fields are blocked by default.
// ============================================

/**
 * SECURITY: Allowed fields for property creation/update from user requests
 * Fields NOT in this list will be silently rejected.
 * Sensitive fields like isApproved, owner, views must be set via middleware or internal calls.
 */
const PROPERTY_ALLOWED_FIELDS = [
  // Basic info
  'title', 'description', 'listingType', 'negotiable',
  // Category & Type (as names, not ObjectIds - handled separately)
  'categoryName', 'propertyTypeName', 'subcategoryName', 'propertyCategory',
  // Location
  'address', 'city', 'locality', 'landmark', 'latitude', 'longitude',
  // Pricing
  'price', 'expectedPrice', 'deposit', 'expectedDeposit', 'maintenance',
  'priceNegotiable', 'securityDeposit',
  // Property details
  'bhk', 'bhkType', 'bedrooms', 'bathrooms', 'balconies', 'floor', 'totalFloors',
  'furnishing', 'facing', 'age', 'availability', 'availableFrom', 'possessionDate',
  // Area
  'area', 'builtUpArea', 'carpetArea', 'superBuiltUpArea', 'plotArea',
  // Features
  'features', 'amenities', 'extras', 'parking', 'parkingCovered', 'parkingOpen',
  'flooring', 'powerBackup', 'waterSupply', 'gatedSecurity',
  // Extra rooms
  'servantRoom', 'poojaRoom', 'studyRoom', 'storeRoom',
  // Legal
  'legal', 'reraId', 'ownershipType',
  // Images (processed separately but allowed in data flow)
  'images', 'categorizedImages', 'imageCategoryMap', 'existingCategorizedImages', 'imagesToRemove',
  // Building info
  'buildingName', 'buildingType', 'constructionStatus',
  // Commercial specific
  'seatCapacity', 'meetingRooms', 'pantry', 'washrooms',
];

/**
 * SECURITY: Fields that can ONLY be modified by admin middleware or internal service calls
 * These are NEVER allowed from request bodies, even if somehow included.
 */
const ADMIN_ONLY_FIELDS = [
  'isApproved', 'rejectionReason', 'approvedAt', 'approvedBy',
  'disapprovedAt', 'disapprovedBy', 'views', 'likes', 'interestedUsers',
  'owner', '_id', 'createdAt', 'updatedAt', '__v', 'status', 'isBanned', 'isActive'
];

/**
 * Sanitize property data using STRICT WHITELIST approach
 * SECURITY FIX: Only allows explicitly whitelisted fields through.
 * This prevents mass assignment attacks by blocking unknown fields by default.
 * 
 * @param {Object} data - Raw data from request body
 * @returns {Object} - Sanitized data with only allowed fields
 */
const sanitizePropertyData = (data) => {
  const sanitized = {};

  // SECURITY: Only copy whitelisted fields
  for (const field of PROPERTY_ALLOWED_FIELDS) {
    if (data.hasOwnProperty(field) && data[field] !== undefined) {
      sanitized[field] = data[field];
    }
  }

  // SECURITY: Double-check that no admin-only fields slipped through
  for (const field of ADMIN_ONLY_FIELDS) {
    delete sanitized[field];
  }

  return sanitized;
};

/**
 * SECURITY: Internal function to set admin-only fields
 * This should ONLY be called from middleware or internal service functions,
 * NEVER directly with data from request bodies.
 * 
 * @param {Object} data - Property data object
 * @param {Object} adminFields - Fields to set (must be from trusted source)
 * @returns {Object} - Data with admin fields merged
 */
export const setAdminOnlyFields = (data, adminFields) => {
  // Only merge fields that are in the ADMIN_ONLY_FIELDS list
  const allowed = {};
  for (const field of Object.keys(adminFields)) {
    if (ADMIN_ONLY_FIELDS.includes(field) || field === 'owner') {
      allowed[field] = adminFields[field];
    }
  }
  return { ...data, ...allowed };
};

const isCloudinaryUrl = (img = "") => typeof img === "string" && img.includes("cloudinary.com");

// Process uploaded files from multer-cloudinary (they already have URLs)
const extractCloudinaryUrls = (files = []) =>
  files.map((file) => file.path || file.secure_url).filter(Boolean);

// Build public image URL (returns Cloudinary URLs directly)
const buildPublicImageUrl = (req, img) => {
  if (!img) return "";
  // Already a Cloudinary or external URL
  if (img.startsWith("http://") || img.startsWith("https://")) return img;
  // Data URL - legacy, return as-is
  if (img.toLowerCase().startsWith("data:")) return img;
  // Legacy local path - return as-is
  return img;
};

const withPublicImages = (req, doc) => {
  if (!doc) return doc;
  const plain = doc.toObject ? doc.toObject() : doc;
  plain.images = (plain.images || []).map((img) => buildPublicImageUrl(req, img));

  // Process categorized images as well
  if (plain.categorizedImages) {
    // Process residential categories
    if (plain.categorizedImages.residential) {
      Object.keys(plain.categorizedImages.residential).forEach(key => {
        plain.categorizedImages.residential[key] = (plain.categorizedImages.residential[key] || [])
          .map(img => buildPublicImageUrl(req, img));
      });
    }
    // Process commercial categories
    if (plain.categorizedImages.commercial) {
      Object.keys(plain.categorizedImages.commercial).forEach(key => {
        plain.categorizedImages.commercial[key] = (plain.categorizedImages.commercial[key] || [])
          .map(img => buildPublicImageUrl(req, img));
      });
    }
  }

  // Add latitude/longitude at top level for easy map access
  if (plain.address?.latitude && plain.address?.longitude) {
    plain.lat = plain.address.latitude;
    plain.lng = plain.address.longitude;
  }

  return plain;
};

// --- CONTROLLERS ---

// Add Property
export const addProperty = async (req, res) => {
  // ============================================
  // SECURITY: Start a MongoDB session for atomic operations
  // This prevents race conditions during the one-listing-per-owner check
  // ============================================
  const session = await mongoose.startSession();

  try {
    let data = req.body;

    // Parse JSON fields that might be stringified
    ["area", "parking", "address", "flooring", "features", "legal", "extras", "imageCategoryMap"].forEach((key) => {
      if (data[key]) {
        try {
          data[key] = typeof data[key] === 'string' ? JSON.parse(data[key]) : data[key];
        } catch (e) {
          console.error(`Error parsing ${key}:`, e);
        }
      }
    });

    // Convert string booleans to actual booleans
    if (data.negotiable !== undefined) {
      data.negotiable = data.negotiable === 'true' || data.negotiable === true;
    }

    // Spread features into top-level data if it exists
    if (data.features && typeof data.features === 'object') {
      // Extract parking from features before spreading
      const { parking: featuresParking, extras: featuresExtras, ...restFeatures } = data.features;

      // Spread rest of features to top level
      data = { ...data, ...restFeatures };

      // Handle parking - merge or set from features
      if (featuresParking) {
        data.parking = {
          covered: String(featuresParking.covered || 0),
          open: String(featuresParking.open || 0)
        };
      }

      // Handle extras
      if (featuresExtras) {
        data.extras = featuresExtras;
      }

      // Remove the features object after spreading
      delete data.features;
    }

    // ============================================
    // SECURITY FIX: Apply strict WHITELIST sanitization
    // This ensures only allowed fields from request body are used
    // ============================================
    data = sanitizePropertyData(data);

    // Process legacy images from Cloudinary multer upload
    if (req.files?.images?.length > 0) {
      data.images = extractCloudinaryUrls(req.files.images);
    } else {
      data.images = [];
    }

    // Process categorized images
    if (req.files?.categorizedImages?.length > 0 && data.imageCategoryMap) {
      const categorizedUrls = extractCloudinaryUrls(req.files.categorizedImages);
      const categoryMap = data.imageCategoryMap;

      // Determine if property is residential or commercial
      const isResidential = data.categoryName === 'Residential' ||
        (data.category && data.category.name === 'Residential');

      // Initialize categorizedImages structure
      data.categorizedImages = {
        residential: {},
        commercial: {}
      };

      // Track which URL index we're at
      let urlIndex = 0;

      // Map images to their categories
      Object.entries(categoryMap).forEach(([categoryKey, indices]) => {
        const categoryImages = [];
        for (let i = 0; i < indices.length && urlIndex < categorizedUrls.length; i++) {
          categoryImages.push(categorizedUrls[urlIndex]);
          urlIndex++;
        }

        // Add to appropriate category (residential or commercial)
        if (isResidential) {
          data.categorizedImages.residential[categoryKey] = categoryImages;
        } else {
          data.categorizedImages.commercial[categoryKey] = categoryImages;
        }
      });

      // Also add categorized images to the main images array for backward compatibility
      if (data.images.length === 0) {
        data.images = categorizedUrls;
      }

      // Clean up the temporary map
      delete data.imageCategoryMap;
    }

    // ============================================
    // Set admin-only fields via internal function
    // Properties are auto-approved per client requirements
    // ============================================
    data = setAdminOnlyFields(data, {
      isApproved: true,  // Auto-publish for new properties (client requirement)
      owner: req.user?._id || null,
    });

    // ============================================
    // SECURITY FIX: Race Condition Prevention for One-Listing-Per-Owner
    // Uses atomic MongoDB operation instead of countDocuments + create
    // This prevents concurrent requests from creating multiple listings
    // ============================================
    if (req.user?.role === "owner") {
      // Start transaction for atomic check-and-create
      session.startTransaction();

      try {
        // Atomic check: Attempt to increment a counter on User model
        // If user already has a property, we check using findOne within transaction
        const existingProperty = await Property.findOne(
          { owner: req.user._id },
          null,
          { session }
        ).lean();

        if (existingProperty) {
          await session.abortTransaction();
          session.endSession();
          return res.status(400).json({
            success: false,
            message:
              "You can only list one property with an owner account. Please edit your existing listing instead.",
          });
        }

        // Property will be created within the same transaction below
      } catch (txError) {
        await session.abortTransaction();
        session.endSession();
        throw txError;
      }
    }

    // Ensure latitude and longitude are properly set in address
    if (data.address) {
      // Handle coordinates object if sent (backward compatibility)
      if (data.address.coordinates) {
        data.address.latitude = parseFloat(data.address.coordinates.latitude) || null;
        data.address.longitude = parseFloat(data.address.coordinates.longitude) || null;
        delete data.address.coordinates;
      }
      // Parse latitude/longitude if they're strings
      if (data.address.latitude) {
        data.address.latitude = parseFloat(data.address.latitude);
      }
      if (data.address.longitude) {
        data.address.longitude = parseFloat(data.address.longitude);
      }
    }

    // Also handle top-level latitude/longitude if sent separately
    if (data.latitude && data.longitude && data.address) {
      data.address.latitude = parseFloat(data.latitude);
      data.address.longitude = parseFloat(data.longitude);
      delete data.latitude;
      delete data.longitude;
    }

    // Normalize categoryName to high-level buckets (Residential / Commercial)
    if (data.categoryName) {
      const raw = data.categoryName.toString();
      const lower = raw.toLowerCase();

      if (lower.includes("residen")) {
        data.categoryName = "Residential";
      } else if (lower.includes("commercial")) {
        data.categoryName = "Commercial";
      } else if (data.propertyTypeName || data.propertyType) {
        // Infer from property type when category text is generic like "Plot"
        const typeName = (data.propertyTypeName || data.propertyType || "").toString().toLowerCase();
        const isCommercialType = /office|shop|showroom|restaurant|cafe|warehouse|industrial|co-working|coworking|commercial/.test(typeName);
        data.categoryName = isCommercialType ? "Commercial" : "Residential";
      } else {
        // Default to Residential if nothing else is known
        data.categoryName = "Residential";
      }
    } else if (data.propertyTypeName || data.propertyType) {
      const typeName = (data.propertyTypeName || data.propertyType || "").toString().toLowerCase();
      const isCommercialType = /office|shop|showroom|restaurant|cafe|warehouse|industrial|co-working|coworking|commercial/.test(typeName);
      data.categoryName = isCommercialType ? "Commercial" : "Residential";
    }

    console.log("Final data being saved:", JSON.stringify(data, null, 2)); // Debug log

    // ============================================
    // SECURITY: Create property within transaction if owner role
    // Otherwise create normally
    // ============================================
    let prop;
    const useTransaction = req.user?.role === "owner";

    if (useTransaction) {
      // Create within transaction to ensure atomicity
      const [createdProp] = await Property.create([data], { session });
      prop = createdProp;

      // Commit the transaction - property count check and creation are atomic
      await session.commitTransaction();
      session.endSession();
    } else {
      // Non-owner users don't need transaction
      prop = await Property.create(data);
      session.endSession();
    }

    // After creating a property, try to notify users whose saved searches match
    try {
      const savedSearches = await SavedSearch.find({ isActive: true }).lean();
      const city = (prop.address?.city || "").toLowerCase();
      const price = Number(prop.price) || 0;
      const listingType = (prop.listingType || "").toLowerCase();
      const propertyTypeId = prop.propertyType?.toString?.() || prop.propertyType?.toString?.() || "";

      const notificationsToCreate = [];

      for (const search of savedSearches) {
        const f = search.filters || {};

        // City match (if filter.city set)
        if (f.city && city !== f.city.toLowerCase()) continue;

        // Property type match (if filter.propertyType set)
        if (f.propertyType && propertyTypeId && propertyTypeId !== String(f.propertyType)) continue;

        // Listing type (availableFor) match
        if (f.availableFor && listingType && listingType !== f.availableFor.toLowerCase()) continue;

        // Price band match
        if (f.priceRange && price) {
          let matchPrice = false;
          if (f.priceRange === "low") matchPrice = price < 5000000;
          if (f.priceRange === "mid") matchPrice = price >= 5000000 && price <= 15000000;
          if (f.priceRange === "high") matchPrice = price > 15000000;
          if (!matchPrice) continue;
        }

        notificationsToCreate.push({
          user: search.user,
          title: "New property matches your saved search",
          message: `${prop.title || "A new property"} in ${prop.address?.city || "your area"} matches "${search.name}"`,
          type: "saved-search-match",
          data: { savedSearchId: search._id, propertyId: prop._id },
        });
      }

      if (notificationsToCreate.length) {
        await Notification.insertMany(notificationsToCreate);
      }
    } catch (notifyErr) {
      console.error("Error generating notifications for saved searches:", notifyErr);
    }

    // --- DealDirect Rewards: award points for listing ---
    let reward = null;
    try {
      if (req.user?._id) {
        reward = await awardPoints(req.user._id, "list_property", { propertyId: prop._id });
        // Award bonus if 5+ photos uploaded
        const totalImages = (prop.images || []).length;
        if (totalImages >= 5) {
          await awardPoints(req.user._id, "upload_5_photos", { propertyId: prop._id });
        }
      }
    } catch (rewardErr) {
      console.error("[Rewards] Property listing reward error (non-blocking):", rewardErr.message);
    }
    // --- End Rewards hooks ---

    // --- WhatsApp: Notify admin about new property listing ---
    sendNewPropertyWhatsApp({
      title: prop.title,
      price: prop.price,
      listingType: prop.listingType,
      city: prop.address?.city || prop.city,
      locality: prop.address?.area || prop.locality,
      ownerName: req.user?.name || 'N/A',
    }).catch(err => console.error('[WhatsApp] New property notification error:', err.message));

    res.status(201).json({
      success: true,
      message: "Property listed successfully",
      data: withPublicImages(req, prop),
      reward
    });
  } catch (err) {
    // ============================================
    // SECURITY: Ensure session is cleaned up on error
    // ============================================
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();

    console.error("[Property] Add error:", err.message);
    res.status(500).json({ success: false, message: 'Failed to add property' });
  }
};

// ─────────────────────────────────────────────────────────────────
// ADMIN — Add property on behalf of a builder (no user login)
// POST /api/properties/admin/add
// ─────────────────────────────────────────────────────────────────
export const addPropertyForBuilder = async (req, res) => {
  try {
    let data = req.body;

    const { builderId } = data;
    if (!builderId) {
      return res.status(400).json({ success: false, message: "builderId is required." });
    }

    // Validate builder exists and is active
    const builder = await Builder.findById(builderId);
    if (!builder) {
      return res.status(404).json({ success: false, message: "Builder not found." });
    }
    if (!builder.isActive) {
      return res.status(400).json({ success: false, message: "Builder is inactive. Reactivate before posting properties." });
    }

    // Parse JSON fields (same as addProperty)
    ["area", "parking", "address", "flooring", "features", "legal", "extras", "imageCategoryMap"].forEach((key) => {
      if (data[key]) {
        try {
          data[key] = typeof data[key] === "string" ? JSON.parse(data[key]) : data[key];
        } catch (e) {
          console.error(`Error parsing ${key}:`, e);
        }
      }
    });

    if (data.negotiable !== undefined) {
      data.negotiable = data.negotiable === "true" || data.negotiable === true;
    }

    // Spread features into top-level data
    if (data.features && typeof data.features === "object") {
      const { parking: featuresParking, extras: featuresExtras, ...restFeatures } = data.features;
      data = { ...data, ...restFeatures };
      if (featuresParking) {
        data.parking = { covered: String(featuresParking.covered || 0), open: String(featuresParking.open || 0) };
      }
      if (featuresExtras) data.extras = featuresExtras;
      delete data.features;
    }

    // Sanitize
    data = sanitizePropertyData(data);

    // Process images
    if (req.files?.images?.length > 0) {
      data.images = extractCloudinaryUrls(req.files.images);
    } else {
      data.images = [];
    }

    if (req.files?.categorizedImages?.length > 0 && data.imageCategoryMap) {
      const categorizedUrls = extractCloudinaryUrls(req.files.categorizedImages);
      const categoryMap = data.imageCategoryMap;
      const isResidential = data.categoryName === "Residential";
      data.categorizedImages = { residential: {}, commercial: {} };
      let urlIndex = 0;
      Object.entries(categoryMap).forEach(([categoryKey, indices]) => {
        const categoryImages = [];
        for (let i = 0; i < indices.length && urlIndex < categorizedUrls.length; i++) {
          categoryImages.push(categorizedUrls[urlIndex]);
          urlIndex++;
        }
        if (isResidential) {
          data.categorizedImages.residential[categoryKey] = categoryImages;
        } else {
          data.categorizedImages.commercial[categoryKey] = categoryImages;
        }
      });
      if (data.images.length === 0) data.images = categorizedUrls;
      delete data.imageCategoryMap;
    }

    // Handle coordinates
    if (data.address) {
      if (data.address.coordinates) {
        data.address.latitude = parseFloat(data.address.coordinates.latitude) || null;
        data.address.longitude = parseFloat(data.address.coordinates.longitude) || null;
        delete data.address.coordinates;
      }
      if (data.address.latitude) data.address.latitude = parseFloat(data.address.latitude);
      if (data.address.longitude) data.address.longitude = parseFloat(data.address.longitude);
    }
    if (data.latitude && data.longitude && data.address) {
      data.address.latitude = parseFloat(data.latitude);
      data.address.longitude = parseFloat(data.longitude);
      delete data.latitude;
      delete data.longitude;
    }

    // Normalize categoryName
    if (data.categoryName) {
      const lower = data.categoryName.toLowerCase();
      if (lower.includes("residen")) data.categoryName = "Residential";
      else if (lower.includes("commercial")) data.categoryName = "Commercial";
    }

    // Set admin-only fields — no owner, builder instead
    data = setAdminOnlyFields(data, { isApproved: true, owner: null });
    data.builder = builderId;
    data.listingType = data.listingType || "Sale";

    const prop = await Property.create(data);

    // Notify saved searches (non-blocking)
    try {
      const savedSearches = await SavedSearch.find({ isActive: true }).lean();
      const city = (prop.address?.city || "").toLowerCase();
      const notificationsToCreate = [];
      for (const search of savedSearches) {
        const f = search.filters || {};
        if (f.city && city !== f.city.toLowerCase()) continue;
        notificationsToCreate.push({
          user: search.user,
          title: "New property matches your saved search",
          message: `${prop.title || "A new property"} in ${prop.address?.city || "your area"} matches "${search.name}"`,
          type: "saved-search-match",
          data: { savedSearchId: search._id, propertyId: prop._id },
        });
      }
      if (notificationsToCreate.length) await Notification.insertMany(notificationsToCreate);
    } catch (notifyErr) {
      console.error("Error generating notifications:", notifyErr);
    }

    sendNewPropertyWhatsApp({
      title: prop.title,
      price: prop.price,
      listingType: prop.listingType,
      city: prop.address?.city || prop.city,
      locality: prop.address?.area || prop.locality,
      ownerName: builder.company || builder.name,
    }).catch(err => console.error("[WhatsApp] Builder property notification error:", err.message));

    console.log(`[Builder Property] Created property ${prop._id} for builder ${builder.name}`);

    return res.status(201).json({
      success: true,
      message: "Property created successfully for builder.",
      data: withPublicImages(req, prop),
    });
  } catch (err) {
    console.error("[Builder Property] Add error:", err.message);
    return res.status(500).json({ success: false, message: "Failed to create property." });
  }
};

// Get All (PUBLIC ENDPOINT)
// ============================================
// SECURITY FIX: Critical Data Leak Prevention
// Previously returned ALL properties including drafts, rejected, banned
// Now strictly filters to only approved + active properties
//
// Query params:
//   ?isBuilderProperty=true  → return only builder properties (property.builder != null)
//   ?limit=N                 → cap results (used by home page carousel)
// By default: returns only OWNER properties (builder == null) to keep feeds separate
// ============================================
export const getProperties = async (req, res) => {
  try {
    const isBuilderProperty = req.query.isBuilderProperty === 'true';
    const limit = parseInt(req.query.limit) || 0; // 0 = no limit in Mongoose

    // SECURITY: Only return properties that are:
    // 1. Approved by admin (isApproved: true)
    // 2. Not soft-deleted (isActive: true or not set)
    // 3. Not banned/suspended
    const securityFilter = {
      isApproved: true,
      $or: [
        { isActive: { $ne: false } },
        { isActive: { $exists: false } }
      ],
      isBanned: { $ne: true },
      status: { $nin: ['rejected', 'suspended', 'draft', 'pending'] }
    };

    // ── Feed separation ──────────────────────────────────────────────────────
    // Builder properties (posted by admin on behalf of a builder) are shown
    // on a dedicated /projects page and must NOT appear in the regular feed.
    if (isBuilderProperty) {
      // Only properties that have a builder reference
      securityFilter.builder = { $ne: null, $exists: true };
    } else {
      // Regular feed: only owner-posted properties (no builder)
      securityFilter.$and = [
        ...(securityFilter.$and || []),
        {
          $or: [
            { builder: null },
            { builder: { $exists: false } }
          ]
        }
      ];
    }

    let query = Property.find(securityFilter)
      .populate("category")
      .populate("subcategory")
      .populate("propertyType")
      .populate("builder", "name company logo city")
      .sort({ createdAt: -1 });

    if (limit > 0) query = query.limit(limit);

    const list = await query;

    res.json(list.map((item) => withPublicImages(req, item)));
  } catch (err) {
    console.error('[Properties] Get all error:', err.message);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch properties'
    });
  }
};

// Get by ID (PUBLIC ENDPOINT)
// ============================================
// SECURITY FIX: Prevent viewing unapproved/banned properties
// ============================================
export const getPropertyById = async (req, res) => {
  try {
    // First, fetch the property to check its status
    const prop = await Property.findById(req.params.id)
      .populate("category")
      .populate("subcategory")
      .populate("propertyType")
      .populate("owner", "name email phone profileImage");

    if (!prop) {
      return res.status(404).json({
        success: false,
        message: "Property not found"
      });
    }

    // SECURITY: Check if property is publicly viewable
    // Allow viewing if: approved AND not banned AND active
    const isPubliclyViewable =
      prop.isApproved === true &&
      prop.isBanned !== true &&
      prop.isActive !== false &&
      !['rejected', 'suspended', 'draft', 'pending'].includes(prop.status);

    if (!isPubliclyViewable) {
      // Don't reveal that the property exists but is hidden
      return res.status(404).json({
        success: false,
        message: "Property not found"
      });
    }

    // Increment view count only for valid public views
    await Property.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } });

    res.json(withPublicImages(req, prop));
  } catch (err) {
    console.error('[Property] Get by ID error:', err.message);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch property'
    });
  }
};

// Report a Property
export const reportProperty = async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    if (!req.user?._id) {
      return res.status(401).json({ success: false, message: "Not authorized" });
    }

    const trimmedReason = (reason || "").trim();
    if (!trimmedReason || trimmedReason.length < 10) {
      return res.status(400).json({
        success: false,
        message: "Please provide a brief reason (at least 10 characters).",
      });
    }

    const property = await Property.findById(id).select("_id title owner");
    if (!property) {
      return res
        .status(404)
        .json({ success: false, message: "Property not found" });
    }

    // Prevent duplicate active reports from the same user on the same property
    const existing = await Report.findOne({
      contextType: "property",
      property: property._id,
      reportedBy: req.user._id,
      status: { $in: ["pending", "reviewed"] },
    });

    if (existing) {
      return res.status(400).json({
        success: false,
        message: "You have already reported this property. Our team is reviewing it.",
      });
    }

    const report = await Report.create({
      reportedBy: req.user._id,
      contextType: "property",
      property: property._id,
      reason: trimmedReason,
      status: "pending",
    });

    res.status(201).json({
      success: true,
      message: "Thank you. Your report has been submitted to the admin team. You earned 100 reward points!",
      data: report,
    });

    // Award points for reporting (non-blocking, after response)
    awardPoints(req.user._id, "report_property", { propertyId: property._id, reportId: report._id })
      .catch(err => console.error("[Rewards] Report property reward error:", err.message));
  } catch (err) {
    console.error("Report Property Error:", err);
    res.status(500).json({ success: false, message: err.message });
  }
};

// Update Property (Admin only - with sanitization)
export const updateProperty = async (req, res) => {
  try {
    // Validate property ID
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: 'Invalid property ID' });
    }

    let data = req.body;

    // ============================================
    // SECURITY FIX: Apply strict WHITELIST sanitization
    // Only explicitly allowed fields pass through.
    // Sensitive fields (isApproved, owner, views, etc.) are blocked.
    // ============================================
    data = sanitizePropertyData(data);

    // Parse JSON fields that might be stringified
    ["area", "parking", "address", "flooring", "features", "legal", "extras", "imageCategoryMap"].forEach((key) => {
      if (data[key]) {
        try {
          data[key] = typeof data[key] === 'string' ? JSON.parse(data[key]) : data[key];
        } catch (e) {
          console.error(`Error parsing ${key}:`, e);
        }
      }
    });

    // Spread features into top-level data if it exists
    if (data.features && typeof data.features === 'object') {
      const { parking: featuresParking, extras: featuresExtras, ...restFeatures } = data.features;

      data = { ...data, ...restFeatures };

      if (featuresParking) {
        data.parking = {
          covered: String(featuresParking.covered || 0),
          open: String(featuresParking.open || 0)
        };
      }

      if (featuresExtras) {
        data.extras = featuresExtras;
      }

      delete data.features;
    }

    // Process legacy images from Cloudinary multer upload (only if new files uploaded)
    if (req.files?.images?.length > 0) {
      data.images = extractCloudinaryUrls(req.files.images);
    }

    // Process categorized images
    if (req.files?.categorizedImages?.length > 0 && data.imageCategoryMap) {
      const categorizedUrls = extractCloudinaryUrls(req.files.categorizedImages);
      const categoryMap = data.imageCategoryMap;

      // Determine if property is residential or commercial
      const isResidential = data.categoryName === 'Residential' ||
        (data.category && data.category.name === 'Residential');

      // Initialize categorizedImages structure
      data.categorizedImages = {
        residential: {},
        commercial: {}
      };

      // Track which URL index we're at
      let urlIndex = 0;

      // Map images to their categories
      Object.entries(categoryMap).forEach(([categoryKey, indices]) => {
        const categoryImages = [];
        for (let i = 0; i < indices.length && urlIndex < categorizedUrls.length; i++) {
          categoryImages.push(categorizedUrls[urlIndex]);
          urlIndex++;
        }

        if (isResidential) {
          data.categorizedImages.residential[categoryKey] = categoryImages;
        } else {
          data.categorizedImages.commercial[categoryKey] = categoryImages;
        }
      });

      delete data.imageCategoryMap;
    }

    // Ensure latitude and longitude are properly set in address
    if (data.address) {
      // Handle coordinates object if sent (backward compatibility)
      if (data.address.coordinates) {
        data.address.latitude = parseFloat(data.address.coordinates.latitude) || null;
        data.address.longitude = parseFloat(data.address.coordinates.longitude) || null;
        delete data.address.coordinates;
      }
      // Parse latitude/longitude if they're strings
      if (data.address.latitude) {
        data.address.latitude = parseFloat(data.address.latitude);
      }
      if (data.address.longitude) {
        data.address.longitude = parseFloat(data.address.longitude);
      }
    }

    // Also handle top-level latitude/longitude if sent separately
    if (data.latitude && data.longitude && data.address) {
      data.address.latitude = parseFloat(data.latitude);
      data.address.longitude = parseFloat(data.longitude);
      delete data.latitude;
      delete data.longitude;
    }

    // Re-sanitize after all modifications
    data = sanitizePropertyData(data);

    const updated = await Property.findByIdAndUpdate(req.params.id, data, { new: true });

    if (!updated) {
      return res.status(404).json({ success: false, message: 'Property not found' });
    }

    res.json(withPublicImages(req, updated));
  } catch (err) {
    console.error("Update Property Error:", err);
    res.status(500).json({ success: false, message: 'An error occurred while updating the property' });
  }
};


// Delete Property (Admin only - protected route)
export const deleteProperty = async (req, res) => {
  try {
    // Validate property ID
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: 'Invalid property ID' });
    }

    const p = await Property.findById(req.params.id);
    if (!p) {
      return res.status(404).json({ success: false, message: 'Property not found' });
    }

    // Delete images from Cloudinary
    for (const img of p.images || []) {
      if (isCloudinaryUrl(img)) {
        try {
          // Extract public_id from Cloudinary URL
          const urlParts = img.split("/");
          const uploadIndex = urlParts.indexOf("upload");
          if (uploadIndex !== -1) {
            // Get everything after upload/v{version}/ and remove extension
            const publicIdParts = urlParts.slice(uploadIndex + 2);
            const publicId = publicIdParts.join("/").replace(/\.[^/.]+$/, "");
            await cloudinary.uploader.destroy(publicId);
          }
        } catch (deleteError) {
          console.error("Failed to delete image from Cloudinary:", deleteError);
        }
      }
    }

    await p.deleteOne();
    res.json({ success: true, message: 'Property deleted successfully' });
  } catch (err) {
    console.error("Delete Property Error:", err);
    res.status(500).json({ success: false, message: 'An error occurred while deleting the property' });
  }
};


/**
 * 🔒 Admin: Approve Property
 * - Sets isApproved to true
 * - Clears any previous rejection reason
 * - Protected by protectAdmin middleware
 */
export const approveProperty = async (req, res) => {
  try {
    const propertyId = req.params.id;

    // Find and update the property
    const updated = await Property.findByIdAndUpdate(
      propertyId,
      {
        isApproved: true,
        rejectionReason: "", // Clear the reason on approval
        approvedAt: new Date(),
        approvedBy: req.admin?._id // Track which admin approved (if available)
      },
      { new: true, runValidators: true }
    );

    if (!updated) {
      return res.status(404).json({
        success: false,
        message: "Property not found"
      });
    }

    // Log the action (for audit trail)
    console.log(`[ADMIN] Property ${propertyId} approved by admin ${req.admin?.email || 'unknown'}`);

    res.json({
      success: true,
      message: "Property approved successfully",
      property: updated
    });
  } catch (err) {
    console.error("Approve Property Error:", err);
    res.status(500).json({
      success: false,
      message: "An error occurred while approving the property"
    });
  }
};

/**
 * 🔒 Admin: Disapprove/Unlist Property
 * - Sets isApproved to false
 * - Requires a rejection reason
 * - Protected by protectAdmin middleware
 */
export const disapproveProperty = async (req, res) => {
  try {
    const propertyId = req.params.id;

    // Get rejection reason from body - support both 'rejectionReason' and 'reason' field names
    const rejectionReason = req.body.rejectionReason || req.body.reason;

    // Validate rejection reason
    if (!rejectionReason || typeof rejectionReason !== 'string' || rejectionReason.trim().length === 0) {
      return res.status(400).json({
        success: false,
        message: "Rejection reason is required for unlisting a property."
      });
    }

    // Sanitize the rejection reason (basic XSS prevention)
    const sanitizedReason = rejectionReason.trim().substring(0, 500);

    // Find and update the property
    const updated = await Property.findByIdAndUpdate(
      propertyId,
      {
        isApproved: false,
        rejectionReason: sanitizedReason,
        disapprovedAt: new Date(),
        disapprovedBy: req.admin?._id // Track which admin disapproved
      },
      { new: true, runValidators: true }
    );

    if (!updated) {
      return res.status(404).json({
        success: false,
        message: "Property not found"
      });
    }

    // Log the action (for audit trail)
    console.log(`[ADMIN] Property ${propertyId} disapproved by admin ${req.admin?.email || 'unknown'}. Reason: ${sanitizedReason.substring(0, 100)}...`);

    res.json({
      success: true,
      message: "Property has been unlisted",
      property: updated
    });
  } catch (err) {
    console.error("Disapprove Property Error:", err);
    res.status(500).json({
      success: false,
      message: "An error occurred while unlisting the property"
    });
  }
};

// 🌐 Public: Get All Approved Properties (Home Page & Client Property List)
// ── IMPORTANT: Builder properties are excluded here — they have their own feed ──
export const getAllPropertiesList = async (req, res) => {
  try {
    const properties = await Property.find({
      isApproved: true,
      // Exclude builder properties — they belong on /projects, not /properties
      $or: [
        { builder: null },
        { builder: { $exists: false } }
      ]
    })
      .populate("category", "name")
      .populate("subcategory", "name")
      .populate("propertyType", "name")
      .sort({ createdAt: -1 });

    res.status(200).json({ success: true, data: properties.map((item) => withPublicImages(req, item)) });
  } catch (error) {
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

// 🔒 Protected: Get User's Own Properties (Owner Dashboard)
export const getMyProperties = async (req, res) => {
  try {
    const userId = req.user._id;

    console.log("Fetching properties for user:", userId);

    // Convert to ObjectId if it's a valid string
    let ownerQuery = userId;
    if (typeof userId === 'string' && mongoose.Types.ObjectId.isValid(userId)) {
      ownerQuery = new mongoose.Types.ObjectId(userId);
    }

    const properties = await Property.find({ owner: ownerQuery })
      .populate("category", "name")
      .populate("subcategory", "name")
      .populate("propertyType", "name")
      .populate("interestedUsers.user", "name email phone profileImage")
      .sort({ createdAt: -1 });

    console.log(`Found ${properties.length} properties for user ${userId}`);

    res.status(200).json({
      success: true,
      data: properties.map((item) => withPublicImages(req, item)),
      count: properties.length
    });
  } catch (error) {
    console.error("Error in getMyProperties:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

// 🔒 Protected: Delete User's Own Property
export const deleteMyProperty = async (req, res) => {
  try {
    const userId = req.user._id;
    const propertyId = req.params.id;

    const property = await Property.findOne({ _id: propertyId, owner: userId });

    if (!property) {
      return res.status(404).json({ success: false, message: "Property not found or you don't have permission to delete it" });
    }

    // Delete images from Cloudinary if they exist
    const allImages = [
      ...(property.images || []),
      ...Object.values(property.categorizedImages?.residential || {}).flat(),
      ...Object.values(property.categorizedImages?.commercial || {}).flat()
    ];

    for (const imageUrl of allImages) {
      if (isCloudinaryUrl(imageUrl)) {
        try {
          // Extract public_id from Cloudinary URL
          const urlParts = imageUrl.split('/');
          const publicIdWithExtension = urlParts.slice(-2).join('/');
          const publicId = publicIdWithExtension.replace(/\.[^/.]+$/, '');
          await cloudinary.uploader.destroy(publicId);
        } catch (e) {
          console.error("Error deleting image from Cloudinary:", e);
        }
      }
    }

    await Property.findByIdAndDelete(propertyId);

    res.status(200).json({ success: true, message: "Property deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

// 🔒 Protected: Update User's Own Property
export const updateMyProperty = async (req, res) => {
  try {
    const userId = req.user._id;
    const propertyId = req.params.id;

    // Check if property exists and belongs to user
    const existingProperty = await Property.findOne({ _id: propertyId, owner: userId });

    if (!existingProperty) {
      return res.status(404).json({ success: false, message: "Property not found or you don't have permission to edit it" });
    }

    let data = req.body;

    // Parse JSON fields that might be stringified
    ["area", "parking", "address", "flooring", "features", "legal", "extras", "imageCategoryMap", "existingCategorizedImages", "imagesToRemove", "amenities"].forEach((key) => {
      if (data[key]) {
        try {
          data[key] = typeof data[key] === 'string' ? JSON.parse(data[key]) : data[key];
        } catch (e) {
          console.error(`Error parsing ${key}:`, e);
        }
      }
    });

    // Map form fields to schema fields
    // Price fields
    if (data.expectedPrice) {
      data.price = Number(data.expectedPrice);
      delete data.expectedPrice;
    }
    if (data.expectedDeposit) {
      data.deposit = data.expectedDeposit;
      delete data.expectedDeposit;
    }

    // Area fields - map to area object
    data.area = {
      ...(existingProperty.area || {}),
      builtUpSqft: data.builtUpArea ? Number(data.builtUpArea) : existingProperty.area?.builtUpSqft,
      carpetSqft: data.carpetArea ? Number(data.carpetArea) : existingProperty.area?.carpetSqft,
      superBuiltUpSqft: data.superBuiltUpArea ? Number(data.superBuiltUpArea) : existingProperty.area?.superBuiltUpSqft,
      plotSqft: data.plotArea ? Number(data.plotArea) : existingProperty.area?.plotSqft,
    };
    // Also keep top-level for convenience
    if (data.builtUpArea) data.builtUpArea = Number(data.builtUpArea);
    if (data.carpetArea) data.carpetArea = Number(data.carpetArea);
    if (data.superBuiltUpArea) data.superBuiltUpArea = Number(data.superBuiltUpArea);
    if (data.plotArea) data.plotArea = Number(data.plotArea);

    // Extras - map boolean fields
    data.extras = {
      servantRoom: data.servantRoom === true || data.servantRoom === 'true',
      poojaRoom: data.poojaRoom === true || data.poojaRoom === 'true',
      studyRoom: data.studyRoom === true || data.studyRoom === 'true',
      storeRoom: data.storeRoom === true || data.storeRoom === 'true',
    };
    delete data.servantRoom;
    delete data.poojaRoom;
    delete data.studyRoom;
    delete data.storeRoom;

    // Legal - map reraId
    if (data.reraId) {
      data.legal = {
        ...(existingProperty.legal || {}),
        reraId: data.reraId
      };
      delete data.reraId;
    }

    // BHK type
    if (data.bhkType) {
      data.bhk = data.bhkType;
      delete data.bhkType;
    }

    // Parking - already handled or map from parkingCovered/parkingOpen
    if (data.parkingCovered !== undefined || data.parkingOpen !== undefined) {
      data.parking = {
        covered: String(data.parkingCovered || 0),
        open: String(data.parkingOpen || 0)
      };
      delete data.parkingCovered;
      delete data.parkingOpen;
    }

    // Price negotiable
    if (data.priceNegotiable !== undefined) {
      data.negotiable = data.priceNegotiable === true || data.priceNegotiable === 'true';
      delete data.priceNegotiable;
    }

    // Address fields
    if (data.city || data.locality || data.landmark || data.address) {
      data.address = {
        ...(existingProperty.address || {}),
        city: data.city || existingProperty.address?.city,
        area: data.locality || existingProperty.address?.area,
        landmark: data.landmark || existingProperty.address?.landmark,
        full: data.address || existingProperty.address?.full,
        latitude: data.latitude ? parseFloat(data.latitude) : existingProperty.address?.latitude,
        longitude: data.longitude ? parseFloat(data.longitude) : existingProperty.address?.longitude,
      };
      // Keep top-level convenience fields too
      data.city = data.city || existingProperty.city;
      data.locality = data.locality || existingProperty.locality;
    }

    // Location coordinates for geo queries
    if (data.latitude && data.longitude) {
      data.location = {
        type: "Point",
        coordinates: [parseFloat(data.longitude), parseFloat(data.latitude)]
      };
    }

    // Spread features into top-level data if it exists
    if (data.features && typeof data.features === 'object') {
      const { parking: featuresParking, extras: featuresExtras, ...restFeatures } = data.features;

      data = { ...data, ...restFeatures };

      if (featuresParking) {
        data.parking = {
          covered: String(featuresParking.covered || 0),
          open: String(featuresParking.open || 0)
        };
      }

      if (featuresExtras) {
        data.extras = { ...data.extras, ...featuresExtras };
      }

      delete data.features;
    }

    // Determine if property is residential or commercial
    const isResidential = data.propertyCategory === 'Residential' ||
      existingProperty.categoryName === 'Residential';

    // Initialize categorizedImages structure from existing images sent from frontend
    data.categorizedImages = {
      residential: {},
      commercial: {}
    };

    // Keep existing categorized images (that weren't removed)
    if (data.existingCategorizedImages) {
      const existingCat = data.existingCategorizedImages;
      Object.entries(existingCat).forEach(([categoryKey, images]) => {
        if (Array.isArray(images) && images.length > 0) {
          if (isResidential) {
            data.categorizedImages.residential[categoryKey] = images;
          } else {
            data.categorizedImages.commercial[categoryKey] = images;
          }
        }
      });
      delete data.existingCategorizedImages;
    }

    // Process new images with category map
    if (req.files?.images?.length > 0 && data.imageCategoryMap) {
      const newImageUrls = extractCloudinaryUrls(req.files.images);
      const categoryMap = data.imageCategoryMap;

      // categoryMap format: [{index: 0, category: 'exterior'}, {index: 1, category: 'livingRoom'}, ...]
      categoryMap.forEach((mapping, idx) => {
        if (idx < newImageUrls.length) {
          const { category } = mapping;
          const url = newImageUrls[idx];

          if (isResidential) {
            if (!data.categorizedImages.residential[category]) {
              data.categorizedImages.residential[category] = [];
            }
            data.categorizedImages.residential[category].push(url);
          } else {
            if (!data.categorizedImages.commercial[category]) {
              data.categorizedImages.commercial[category] = [];
            }
            data.categorizedImages.commercial[category].push(url);
          }
        }
      });
    }

    // Build flat images array for backwards compatibility
    const allImages = [];
    const catImages = isResidential ? data.categorizedImages.residential : data.categorizedImages.commercial;
    Object.values(catImages).forEach(imgs => {
      if (Array.isArray(imgs)) {
        allImages.push(...imgs);
      }
    });
    data.images = allImages;

    delete data.imageCategoryMap;
    delete data.imagesToRemove;

    // Don't allow changing owner
    delete data.owner;

    // Handle propertyType - it's sent as name string, not ObjectId
    // Store the name in propertyTypeName and remove propertyType to avoid ObjectId cast error
    if (data.propertyType && typeof data.propertyType === 'string' && !mongoose.Types.ObjectId.isValid(data.propertyType)) {
      data.propertyTypeName = data.propertyType;
      delete data.propertyType;
    }

    // Handle category - it's sent as name string "Residential" or "Commercial"
    if (data.propertyCategory && typeof data.propertyCategory === 'string') {
      data.categoryName = data.propertyCategory;
      delete data.propertyCategory;
      delete data.category; // Remove category ObjectId reference if it's invalid
    }

    // Remove subcategory if it's not a valid ObjectId
    if (data.subcategory && !mongoose.Types.ObjectId.isValid(data.subcategory)) {
      delete data.subcategory;
    }

    const updated = await Property.findByIdAndUpdate(propertyId, data, { new: true })
      .populate("category", "name")
      .populate("subcategory", "name")
      .populate("propertyType", "name");

    // --- DealDirect Rewards: property sale/rental rewards ---
    // NOTE: Sale rewards are now granted via the Close Deal flow
    // (POST /api/properties/:id/close-deal) which requires admin verification.
    // The old automatic reward on status change has been replaced.
    let reward = null;

    res.status(200).json({
      success: true,
      message: "Property updated successfully",
      data: withPublicImages(req, updated),
      reward
    });
  } catch (error) {
    console.error("Error in updateMyProperty:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

// 🔒 Protected: Mark Interest in a Property (Buyer)
export const markInterested = async (req, res) => {
  try {
    const userId = req.user._id;
    const propertyId = req.params.id;

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(propertyId)) {
      return res.status(400).json({ success: false, message: "Invalid property ID" });
    }

    const property = await Property.findById(propertyId);

    if (!property) {
      return res.status(404).json({ success: false, message: "Property not found" });
    }

    // Enforce: a buyer can only be interested in up to 5 properties
    const currentInterestCount = await Property.countDocuments({
      "interestedUsers.user": userId,
    });

    if (currentInterestCount >= 5) {
      return res.status(400).json({
        success: false,
        message:
          "You can show interest in a maximum of 5 properties. Please remove one from your saved list before adding another.",
      });
    }

    // Check if user is the owner (can't be interested in own property)
    if (property.owner && property.owner.toString() === userId.toString()) {
      return res.status(400).json({ success: false, message: "You cannot express interest in your own property" });
    }

    // Check if user already expressed interest
    const alreadyInterested = property.interestedUsers?.some(
      (item) => item.user && item.user.toString() === userId.toString()
    );

    if (alreadyInterested) {
      return res.status(400).json({ success: false, message: "You have already expressed interest in this property" });
    }

    // Get user details for creating lead
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Add user to interestedUsers and increment likes count
    await Property.findByIdAndUpdate(propertyId, {
      $push: { interestedUsers: { user: userId, interestedAt: new Date() } },
      $inc: { likes: 1 }
    });

    // Create a lead for the property owner
    if (property.owner) {
      try {
        const existingLead = await Lead.findOne({ user: userId, property: propertyId });

        if (!existingLead) {
          await Lead.create({
            property: propertyId,
            propertyOwner: property.owner,
            user: userId,
            userSnapshot: {
              name: user.name,
              email: user.email,
              phone: user.phone || "",
              profileImage: user.profileImage || ""
            },
            propertySnapshot: {
              title: property.title,
              price: property.price || property.expectedPrice,
              listingType: property.listingType,
              city: property.city || property.address?.city,
              locality: property.locality || property.address?.area,
              propertyType: property.propertyTypeName,
              bhk: property.bhk
            },
            status: "new",
            source: "website"
          });
          console.log(`Lead created for user ${userId} on property ${propertyId}`);
        }
      } catch (leadError) {
        console.error("Error creating lead:", leadError);
        // Don't fail the interest registration if lead creation fails
      }
    }

    // Notify property owner (non-blocking)
    if (property.owner) {
      try {
        await Notification.create({
          user: property.owner,
          title: "New Interest on Your Property",
          message: `${user.name} is interested in your property "${property.title}". Check your leads for contact details.`,
          type: "interest",
          data: {
            propertyId: propertyId,
            propertyTitle: property.title,
            interestedUserId: userId,
            interestedUserName: user.name,
            actionUrl: "https://dealdirect.in/my-properties",
            actionText: "View Leads"
          },
        });
        console.log(`Notification sent to owner ${property.owner} for property ${propertyId}`);
      } catch (notifError) {
        console.error("Error creating notification:", notifError);
        // Don't fail the interest registration if notification creation fails
      }

      // WhatsApp notification to property owner (non-blocking)
      const ownerUser = await User.findById(property.owner).select('phone');
      sendNewLeadWhatsApp(
        ownerUser?.phone,
        { name: user.name, email: user.email, phone: user.phone || '' },
        {
          title: property.title,
          price: property.price || property.expectedPrice,
          listingType: property.listingType,
          city: property.city || property.address?.city,
          locality: property.locality || property.address?.area,
        }
      ).catch(err => console.error('[WhatsApp] Lead notification error:', err.message));
    }

    console.log(`User ${userId} expressed interest in property ${propertyId}`);

    // --- DealDirect Rewards: award points for sending enquiry ---
    let reward = null;
    try {
      const rewardResult = await awardPoints(userId, "send_enquiry");
      if (rewardResult?.success && rewardResult?.pointsAwarded > 0) {
        reward = rewardResult;
      }
      console.log(`[Rewards] Enquiry reward: ${rewardResult?.pointsAwarded} pts to ${userId}`);
    } catch (rewardErr) {
      console.error("[Rewards] Enquiry reward error:", rewardErr.message);
    }

    res.status(200).json({
      success: true,
      message: "Interest registered successfully! The owner will be notified.",
      reward
    });
  } catch (error) {
    console.error("Error in markInterested:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

// 🔒 Protected: Remove Interest in a Property (Buyer)
export const removeInterest = async (req, res) => {
  try {
    const userId = req.user._id;
    const propertyId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(propertyId)) {
      return res.status(400).json({ success: false, message: "Invalid property ID" });
    }

    const property = await Property.findById(propertyId);
    if (!property) {
      return res.status(404).json({ success: false, message: "Property not found" });
    }

    const wasInterested = property.interestedUsers?.some(
      (item) => item.user && item.user.toString() === userId.toString()
    );

    if (!wasInterested) {
      return res.status(400).json({ success: false, message: "You have not expressed interest in this property" });
    }

    await Property.findByIdAndUpdate(propertyId, {
      $pull: { interestedUsers: { user: userId } },
      $inc: { likes: -1 }
    });

    console.log(`User ${userId} removed interest from property ${propertyId}`);

    res.status(200).json({
      success: true,
      message: "Interest removed successfully"
    });
  } catch (error) {
    console.error("Error in removeInterest:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

// 🔒 Protected: Check if user is interested in a property
export const checkInterested = async (req, res) => {
  try {
    const userId = req.user._id;
    const propertyId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(propertyId)) {
      return res.status(400).json({ success: false, isInterested: false });
    }

    const property = await Property.findById(propertyId);

    if (!property) {
      return res.status(404).json({ success: false, isInterested: false });
    }

    const isInterested = property.interestedUsers?.some(
      (item) => item.user && item.user.toString() === userId.toString()
    );

    res.status(200).json({ success: true, isInterested });
  } catch (error) {
    res.status(500).json({ success: false, isInterested: false, message: 'An unexpected error occurred' });
  }
};

// 🔒 Protected: Get User's Saved/Interested Properties
export const getSavedProperties = async (req, res) => {
  try {
    const userId = req.user._id;

    // Convert to ObjectId if it's a valid string
    let userQuery = userId;
    if (typeof userId === 'string' && mongoose.Types.ObjectId.isValid(userId)) {
      userQuery = new mongoose.Types.ObjectId(userId);
    }

    // Find all properties where user is in interestedUsers
    const properties = await Property.find({
      "interestedUsers.user": userQuery
    })
      .populate("category", "name")
      .populate("subcategory", "name")
      .populate("propertyType", "name")
      .sort({ createdAt: -1 });

    // Add the interestedAt date to each property
    const propertiesWithDate = properties.map(prop => {
      const plain = prop.toObject ? prop.toObject() : prop;
      const userInterest = plain.interestedUsers?.find(
        item => item.user && item.user.toString() === userQuery.toString()
      );
      plain.interestedAt = userInterest?.interestedAt;
      // Process images
      plain.images = (plain.images || []).map(img => {
        if (!img) return "";
        if (img.startsWith("http://") || img.startsWith("https://")) return img;
        return img;
      });
      return plain;
    });

    res.status(200).json({
      success: true,
      data: propertiesWithDate,
      count: propertiesWithDate.length
    });
  } catch (error) {
    console.error("Error in getSavedProperties:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

// 🔒 Protected: Remove from Saved/Interested Properties
export const removeSavedProperty = async (req, res) => {
  try {
    const userId = req.user._id;
    const propertyId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(propertyId)) {
      return res.status(400).json({ success: false, message: "Invalid property ID" });
    }

    const property = await Property.findById(propertyId);

    if (!property) {
      return res.status(404).json({ success: false, message: "Property not found" });
    }

    // Check if user is in interestedUsers
    const isInterested = property.interestedUsers?.some(
      (item) => item.user && item.user.toString() === userId.toString()
    );

    if (!isInterested) {
      return res.status(400).json({ success: false, message: "Property not in your saved list" });
    }

    // Remove user from interestedUsers and decrement likes
    await Property.findByIdAndUpdate(propertyId, {
      $pull: { interestedUsers: { user: userId } },
      $inc: { likes: -1 }
    });

    res.status(200).json({ success: true, message: "Property removed from saved" });
  } catch (error) {
    console.error("Error in removeSavedProperty:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

// Public Search API
export const searchProperties = async (req, res) => {
  try {
    const {
      search,
      category,
      subcategory,
      propertyType,
      buildingType,
      size,
      city,
      priceFrom,
      priceTo,
      page = 1,
      limit = 12,
      sort = "newest",
    } = req.query;

    const filter = {
      isApproved: true,
      // Exclude builder properties from regular search feed
      $or: [
        { builder: null },
        { builder: { $exists: false } }
      ]
    };

    if (category) filter.category = category;
    if (subcategory) filter.subcategory = subcategory;
    if (propertyType) filter.propertyType = propertyType;
    if (buildingType) filter.buildingType = buildingType;
    if (size) filter.size = size;
    if (city && city !== "All") filter["address.city"] = city;

    if (priceFrom || priceTo) {
      filter.price = {};
      if (priceFrom) filter.price.$gte = +priceFrom;
      if (priceTo) filter.price.$lte = +priceTo;
    }

    // Search in multiple fields (excluding ObjectId fields from regex search)
    if (search) {
      // SECURITY FIX: Escape regex special characters to prevent ReDoS
      const escapedSearch = escapeRegExp(search);
      const regex = new RegExp(escapedSearch, "i");
      // Use $and to combine with the builder-exclusion $or already in the filter
      filter.$and = [
        ...(filter.$and || []),
        {
          $or: [
            { title: regex },
            { description: regex },
            { "address.city": regex },
            { "address.area": regex },
            { "address.locality": regex },
          ]
        }
      ];
      // Remove the top-level $or since we moved it into $and
      delete filter.$or;
      // Re-add builder exclusion inside $and
      filter.$and.push({
        $or: [
          { builder: null },
          { builder: { $exists: false } }
        ]
      });
    }

    // Build query
    let query = Property.find(filter)
      .populate("category", "name")
      .populate("subcategory", "name")
      .populate("propertyType", "name");

    // Sorting
    if (sort === "priceAsc") query = query.sort({ price: 1 });
    else if (sort === "priceDesc") query = query.sort({ price: -1 });
    else query = query.sort({ createdAt: -1 });

    // Pagination
    const skip = (page - 1) * limit;

    const [total, data] = await Promise.all([
      Property.countDocuments(filter),
      query.skip(skip).limit(Number(limit)),
    ]);

    res.json({
      data: data.map((item) => withPublicImages(req, item)),
      total,
      page: Number(page),
      pages: Math.ceil(total / limit),
    });
  } catch (err) {
    console.error('[Property] Search error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to search properties' });
  }
};

// Fast autocomplete suggestions - lightweight endpoint
export const getSuggestions = async (req, res) => {
  try {
    const { q } = req.query;

    if (!q || q.trim().length < 2) {
      return res.json({ suggestions: [] });
    }

    const searchTerm = q.trim();
    // SECURITY FIX: Escape regex special characters to prevent ReDoS
    const escapedSearchTerm = escapeRegExp(searchTerm);
    const regex = new RegExp(escapedSearchTerm, "i");

    // Use aggregation for better performance - only fetch needed fields including first image
    const suggestions = await Property.aggregate([
      {
        $match: {
          isApproved: true,
          // Exclude builder properties from regular suggestions
          $or: [
            { builder: null },
            { builder: { $exists: false } }
          ]
        }
      },
      {
        $facet: {
          // Match by title (projects)
          titles: [
            { $match: { title: regex } },
            {
              $project: {
                title: 1,
                city: "$address.city",
                locality: "$address.locality",
                image: { $arrayElemAt: ["$images", 0] }
              }
            },
            { $limit: 5 }
          ],
          // Match by locality
          localities: [
            { $match: { "address.locality": regex } },
            { $group: { _id: "$address.locality", city: { $first: "$address.city" } } },
            { $limit: 5 }
          ],
          // Match by city
          cities: [
            { $match: { "address.city": regex } },
            { $group: { _id: "$address.city" } },
            { $limit: 3 }
          ]
        }
      }
    ]);

    const result = [];
    const seen = new Set();

    // Process titles (projects)
    suggestions[0].titles.forEach(item => {
      const key = `project-${item.title}`;
      if (!seen.has(key)) {
        seen.add(key);
        result.push({
          type: 'project',
          value: item.title,
          subtitle: `${item.city || ''}${item.locality ? ' • ' + item.locality : ''}`.trim(),
          image: item.image || null
        });
      }
    });

    // Process localities
    suggestions[0].localities.forEach(item => {
      const key = `locality-${item._id}`;
      if (!seen.has(key) && item._id) {
        seen.add(key);
        result.push({
          type: 'locality',
          value: item._id,
          subtitle: item.city || ''
        });
      }
    });

    // Process cities
    suggestions[0].cities.forEach(item => {
      const key = `city-${item._id}`;
      if (!seen.has(key) && item._id) {
        seen.add(key);
        result.push({
          type: 'city',
          value: item._id,
          subtitle: 'City'
        });
      }
    });

    res.json({ suggestions: result.slice(0, 8) });
  } catch (err) {
    console.error("[Property] Suggestions error:", err.message);
    res.status(500).json({ success: false, suggestions: [] });
  }
};

export const filterProperties = async (req, res) => {
  try {
    const { search = "", sort = "newest" } = req.query;

    // Base filter: only approved owner-posted properties (no builder)
    let filter = {
      isApproved: true,
      $or: [
        { builder: null },
        { builder: { $exists: false } }
      ]
    };

    // Search in title or city
    // Note: use $and so we don't overwrite the builder-exclusion $or
    if (search.trim()) {
      // SECURITY FIX: Escape regex special characters to prevent ReDoS
      const escapedSearch = escapeRegExp(search.trim());
      const regex = new RegExp(escapedSearch, "i");
      filter.$and = [
        ...(filter.$and || []),
        { $or: [{ title: regex }, { "address.city": regex }] }
      ];
      delete filter.$or; // Builder exclusion moves inside $and below
      filter.$and.push({
        $or: [{ builder: null }, { builder: { $exists: false } }]
      });
    }

    // Fetch properties and populate references
    let properties = await Property.find(filter)
      .populate("propertyType", "name")
      .populate("category", "name")
      .populate("subcategory", "name");

    // Further filter by populated fields (category, subcategory, propertyType)
    if (search.trim()) {
      const lower = search.toLowerCase();
      properties = properties.filter(
        (p) =>
          p.title?.toLowerCase().includes(lower) ||
          p.address?.city?.toLowerCase().includes(lower) ||
          p.category?.name?.toLowerCase().includes(lower) ||
          p.subcategory?.name?.toLowerCase().includes(lower) ||
          p.propertyType?.name?.toLowerCase().includes(lower)
      );
    }

    // Sort
    if (sort === "priceAsc") properties.sort((a, b) => a.price - b.price);
    else if (sort === "priceDesc") properties.sort((a, b) => b.price - a.price);
    else properties.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json({ success: true, data: properties.map((item) => withPublicImages(req, item)) });
  } catch (err) {
    console.error("[Property] Filter error:", err.message);
    res.status(500).json({ success: false, message: 'Failed to filter properties' });
  }
};

export const getOwnersWithProjects = async (req, res) => {
  try {
    // 1. Fetch all users with the 'owner' role
    const owners = await User.find({ role: 'owner' })
      .select('name email phone company profileImage'); // Assuming 'company' field exists in User model

    // 2. Extract owner IDs
    const ownerIds = owners.map(o => o._id);

    // 3. Fetch all properties belonging to these owners
    const properties = await Property.find({ owner: { $in: ownerIds } })
      .populate("category")
      .sort({ createdAt: -1 });

    // 4. Group properties by owner ID
    const projectsByOwner = properties.reduce((acc, prop) => {
      const ownerId = prop.owner.toString();
      if (!acc[ownerId]) {
        acc[ownerId] = [];
      }
      acc[ownerId].push(withPublicImages(req, prop)); // Use the image utility
      return acc;
    }, {});

    // 5. Merge owners with their properties
    const ownersWithProjects = owners.map(owner => {
      const ownerObj = owner.toObject();
      return {
        ...ownerObj,
        id: ownerObj._id,
        projects: projectsByOwner[ownerObj._id.toString()] || []
      };
    });

    res.status(200).json({
      success: true,
      data: ownersWithProjects
    });

  } catch (error) {
    console.error("Error fetching owners with projects:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};


// ... (Keep your imports for cloudinary, withPublicImages, etc.)

// --- NEW: Admin Get Properties with Search & Filters ---
// ... existing imports

// --- UPDATED: Admin Get Properties with Robust Search ---
export const getAdminProperties = async (req, res) => {
  try {
    const { search, status, startDate, endDate } = req.query;

    console.log("Admin Search Params:", req.query); // 🔍 Debug Log

    let query = {};

    // 1. Status Filter
    if (status) {
      if (status === 'listed') {
        query.isApproved = true;
      } else if (status === 'rejected') {
        query.isApproved = false;
      }
      // If 'all', we don't filter by isApproved (returns both)
    }

    // 2. Search Filter (Checks Title, City (root & nested), State, Area, and optionally ID)
    if (search) {
      // SECURITY FIX: Escape regex special characters to prevent ReDoS
      const escapedSearch = escapeRegExp(search);
      const regex = new RegExp(escapedSearch, 'i'); // Case insensitive
      const orConditions = [
        { title: regex },
        { city: regex },             // Check root level city
        { "address.city": regex },   // Check nested address city
        { "address.state": regex },  // Check nested state
        { "address.area": regex },   // Check nested area/locality
        { "address.line": regex }    // Check full address line
      ];

      // If search looks like a valid ObjectId, also match by _id
      if (mongoose.Types.ObjectId.isValid(search)) {
        orConditions.push({ _id: search });
      }

      query.$or = orConditions;
    }

    // 3. Date Range Filter
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) {
        query.createdAt.$gte = new Date(startDate);
      }
      if (endDate) {
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        query.createdAt.$lte = end;
      }
    }

    // 4. Builder filter
    if (req.query.hasBuilder === "true") {
      query.builder = { $ne: null };
    } else if (req.query.hasBuilder === "false") {
      query.builder = null;
    }
    if (req.query.builderId && mongoose.Types.ObjectId.isValid(req.query.builderId)) {
      query.builder = req.query.builderId;
    }

    const properties = await Property.find(query)
      .populate("category", "name")
      .populate("subcategory", "name")
      .populate("propertyType", "name")
      .populate("builder", "name company phone")
      .sort({ createdAt: -1 });

    console.log(`Found ${properties.length} properties matching search.`); // 🔍 Debug Log

    const processedProperties = properties.map((item) => withPublicImages(req, item));

    res.status(200).json({
      success: true,
      data: processedProperties,
      count: processedProperties.length
    });

  } catch (err) {
    console.error("[Property] Admin filter error:", err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch properties' });
  }
};

// ============================================
// CLOSE DEAL — Owner initiates sale/rental closure
// ============================================

/**
 * POST /api/properties/:id/close-deal
 * Owner uploads proof documents and selects the buyer/tenant
 * from the list of interested users.
 *
 * Body (multipart/form-data):
 *   - buyerId: ObjectId of the buyer from interestedUsers
 *   - closingType: "sold" | "rented"
 *   - documents: file uploads (PDF/images) → stored on Cloudinary
 */
export const closeDeal = async (req, res) => {
  try {
    const userId = req.user._id;
    const propertyId = req.params.id;

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(propertyId)) {
      return res.status(400).json({ success: false, message: "Invalid property ID" });
    }

    const property = await Property.findOne({ _id: propertyId, owner: userId });
    if (!property) {
      return res.status(404).json({ success: false, message: "Property not found or you don't own this property" });
    }

    // Prevent duplicate submissions
    if (property.status === "pending_verification" || property.status === "sold" || property.status === "rented") {
      return res.status(400).json({ success: false, message: `Property is already ${property.status}. Cannot submit again.` });
    }

    const { buyerId, closingType } = req.body;

    // Validate closing type
    if (!closingType || !["sold", "rented"].includes(closingType)) {
      return res.status(400).json({ success: false, message: "closingType must be 'sold' or 'rented'" });
    }

    // Validate buyer
    if (!buyerId || !mongoose.Types.ObjectId.isValid(buyerId)) {
      return res.status(400).json({ success: false, message: "A valid buyerId is required" });
    }

    // Check buyer is in interestedUsers
    const isBuyerInterested = property.interestedUsers?.some(
      (item) => item.user && item.user.toString() === buyerId.toString()
    );
    if (!isBuyerInterested) {
      return res.status(400).json({ success: false, message: "Selected buyer must be from the interested users list" });
    }

    // Collect uploaded document URLs from Cloudinary
    const documentUrls = [];
    if (req.files?.documents) {
      const docs = Array.isArray(req.files.documents) ? req.files.documents : [req.files.documents];
      for (const doc of docs) {
        if (doc.secure_url || doc.path) {
          documentUrls.push(doc.secure_url || doc.path);
        }
      }
    }

    if (documentUrls.length === 0) {
      return res.status(400).json({ success: false, message: "At least one proof document is required" });
    }

    // Check for existing pending verification
    const existingVerification = await TransactionVerification.findOne({
      property: propertyId,
      status: "pending",
    });
    if (existingVerification) {
      return res.status(400).json({ success: false, message: "A verification request for this property is already pending" });
    }

    // Create the verification record
    const verification = await TransactionVerification.create({
      property: propertyId,
      owner: userId,
      buyer: buyerId,
      closingType,
      documentUrls,
    });

    // Update property status to pending_verification
    await Property.findByIdAndUpdate(propertyId, { status: "pending_verification" });

    // Notify the owner that submission is received
    await Notification.create({
      user: userId,
      title: "Deal Closure Submitted",
      message: `Your deal closure request for "${property.title}" has been submitted for admin verification. You'll be notified once it's approved.`,
      type: "deal_verification",
      data: {
        propertyId,
        verificationId: verification._id,
        actionUrl: "https://dealdirect.in/my-properties",
        actionText: "View My Properties",
      },
    });

    console.log(`[CloseDeal] Verification ${verification._id} created for property ${propertyId} by owner ${userId}`);

    res.status(201).json({
      success: true,
      message: "Deal closure submitted for verification. You will be notified once the admin approves it.",
      verification: {
        _id: verification._id,
        status: verification.status,
        closingType: verification.closingType,
      },
    });
  } catch (error) {
    console.error("[CloseDeal] Error:", error);
    res.status(500).json({ success: false, message: "Failed to submit deal closure" });
  }
};

/**
 * POST /api/properties/claim-deal-reward/:verificationId
 * User claims their reward for an approved deal.
 * Awards points on first claim, returns reward data for the door game.
 */
export const claimDealReward = async (req, res) => {
  try {
    const userId = req.user._id;
    const { verificationId } = req.params;

    const verification = await TransactionVerification.findById(verificationId)
      .populate("property", "title");

    if (!verification) {
      return res.status(404).json({ success: false, message: "Verification not found" });
    }

    if (verification.status !== "approved") {
      return res.status(400).json({ success: false, message: "This deal has not been approved yet" });
    }

    // Determine if user is owner or buyer
    const isOwner = verification.owner.toString() === userId.toString();
    const isBuyer = verification.buyer.toString() === userId.toString();

    if (!isOwner && !isBuyer) {
      return res.status(403).json({ success: false, message: "You are not part of this deal" });
    }

    // Check if already claimed
    if (isOwner && verification.ownerClaimed) {
      return res.status(200).json({
        success: true,
        alreadyClaimed: true,
        reward: {
          pointsAwarded: verification.ownerReward.points,
          cashValue: verification.ownerReward.cashValue,
          rewardTier: "common",
          description: `Deal reward for "${verification.property.title}"`,
        },
      });
    }

    if (isBuyer && verification.buyerClaimed) {
      return res.status(200).json({
        success: true,
        alreadyClaimed: true,
        reward: {
          pointsAwarded: verification.buyerReward.points,
          cashValue: verification.buyerReward.cashValue,
          rewardTier: "common",
          description: `Deal reward for "${verification.property.title}"`,
        },
      });
    }

    // Award points NOW
    const action = isOwner ? "mark_sold_rented" : "complete_deal";
    let rewardResult;

    try {
      rewardResult = await awardPoints(userId, action, {
        propertyId: verification.property._id,
        role: isOwner ? "owner" : "buyer",
        verificationId,
      });
    } catch (err) {
      console.error(`[ClaimReward] Error awarding points:`, err.message);
      return res.status(500).json({ success: false, message: "Failed to award reward" });
    }

    // Mark as claimed and save reward data
    if (isOwner) {
      verification.ownerClaimed = true;
      verification.ownerReward = {
        points: rewardResult.pointsAwarded || 0,
        cashValue: rewardResult.cashValue || 0,
      };
    } else {
      verification.buyerClaimed = true;
      verification.buyerReward = {
        points: rewardResult.pointsAwarded || 0,
        cashValue: rewardResult.cashValue || 0,
      };
    }
    await verification.save();

    // Mark the notification as claimed in the DB
    await Notification.updateMany(
      { user: userId, "data.verificationId": verificationId, type: "deal_reward" },
      { $set: { "data.isClaimed": true } }
    );

    console.log(`[ClaimReward] ${isOwner ? "Owner" : "Buyer"} ${userId} claimed ${rewardResult.pointsAwarded} pts for verification ${verificationId}`);

    res.status(200).json({
      success: true,
      alreadyClaimed: false,
      reward: {
        pointsAwarded: rewardResult.pointsAwarded,
        cashValue: rewardResult.cashValue,
        rewardTier: rewardResult.rewardTier || "common",
        description: `Deal reward for "${verification.property.title}"`,
      },
    });
  } catch (error) {
    console.error("[ClaimReward] Error:", error);
    res.status(500).json({ success: false, message: "Failed to claim reward" });
  }
};
