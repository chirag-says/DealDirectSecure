import Property from "../models/Property.js";
import { cloudinary } from "../middleware/upload.js";
import mongoose from "mongoose";
import Lead from "../models/Lead.js";
import User from "../models/userModel.js";
import Report from "../models/Report.js";
import SavedSearch from "../models/SavedSearch.js";
import Notification from "../models/Notification.js";

// ============================================
// SECURITY: Field blacklist for mass assignment prevention
// ============================================
const PROPERTY_FORBIDDEN_FIELDS = [
  'owner', 'isApproved', 'rejectionReason', 'views', 'likes',
  'interestedUsers', '_id', 'createdAt', 'updatedAt', '__v'
];

/**
 * Sanitize property data by removing forbidden fields
 * Prevents mass assignment attacks
 */
const sanitizePropertyData = (data) => {
  const sanitized = { ...data };
  for (const field of PROPERTY_FORBIDDEN_FIELDS) {
    delete sanitized[field];
  }
  return sanitized;
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

    // Explicitly set isApproved to true for all new properties (Auto-publish)
    data.isApproved = true;

    // Set owner from auth token if available
    if (req.user?._id) {
      data.owner = req.user._id;
    }

    // Business rule: a real owner account can publish only one property
    if (req.user?.role === "owner") {
      const existingCount = await Property.countDocuments({ owner: req.user._id });
      if (existingCount >= 1) {
        return res.status(400).json({
          success: false,
          message:
            "You can only list one property with an owner account. Please edit your existing listing instead.",
        });
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

    const prop = await Property.create(data);

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

    res.status(201).json(withPublicImages(req, prop));
  } catch (err) {
    console.error("Add Property Error:", err);
    res.status(500).json({ error: err.message });
  }
};

// Get All
export const getProperties = async (req, res) => {
  try {
    const list = await Property.find()
      .populate("category")
      .populate("subcategory")
      .populate("propertyType")
      .sort({ createdAt: -1 });

    res.json(list.map((item) => withPublicImages(req, item)));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Get by ID
export const getPropertyById = async (req, res) => {
  try {
    // Increment view count
    const prop = await Property.findByIdAndUpdate(
      req.params.id,
      { $inc: { views: 1 } },
      { new: true }
    )
      .populate("category")
      .populate("subcategory")
      .populate("propertyType")
      .populate("owner", "name email phone profileImage");

    if (!prop) return res.status(404).json({ message: "Not found" });

    res.json(withPublicImages(req, prop));
  } catch (err) {
    res.status(500).json({ error: err.message });
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
      message: "Thank you. Your report has been submitted to the admin team.",
      data: report,
    });
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
    // SECURITY: Sanitize data - remove forbidden fields
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


// export const approveProperty = async (req, res) => {
//   try {
//     // When approving, set isApproved to true AND clear the rejectionReason
//     const updated = await Property.findByIdAndUpdate(
//       req.params.id,
//       { 
//         isApproved: true, 
//         rejectionReason: "" // Clear the reason on approval
//       },
//       { new: true }
//     );
//     if (!updated) return res.status(404).json({ message: "Property not found" });
//     res.json(updated);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// };

// // --- MODIFIED Disapprove Controller ---
// export const disapproveProperty = async (req, res) => {
//   try {
//     const { rejectionReason } = req.body; // Expecting the reason in the request body

//     if (!rejectionReason) {
//         return res.status(400).json({ message: "Rejection reason is required for unlisting." });
//     }

//     // When disapproving, set isApproved to false AND save the rejectionReason
//     const updated = await Property.findByIdAndUpdate(
//       req.params.id,
//       { 
//         isApproved: false, 
//         rejectionReason: rejectionReason 
//       },
//       { new: true }
//     );
//     if (!updated) return res.status(404).json({ message: "Property not found" });
//     res.json(updated);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// };

// 🌐 Public: Get All Approved Properties (Home Page)
export const getAllPropertiesList = async (req, res) => {
  try {
    const properties = await Property.find({ isApproved: true })
      .populate("category", "name")
      .populate("subcategory", "name")
      .populate("propertyType", "name")
      .sort({ createdAt: -1 });

    res.status(200).json({ success: true, data: properties.map((item) => withPublicImages(req, item)) });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
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
      .sort({ createdAt: -1 });

    console.log(`Found ${properties.length} properties for user ${userId}`);

    res.status(200).json({
      success: true,
      data: properties.map((item) => withPublicImages(req, item)),
      count: properties.length
    });
  } catch (error) {
    console.error("Error in getMyProperties:", error);
    res.status(500).json({ success: false, message: error.message });
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
    res.status(500).json({ success: false, message: error.message });
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

    res.status(200).json({
      success: true,
      message: "Property updated successfully",
      data: withPublicImages(req, updated)
    });
  } catch (error) {
    console.error("Error in updateMyProperty:", error);
    res.status(500).json({ success: false, message: error.message });
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

    console.log(`User ${userId} expressed interest in property ${propertyId}`);

    res.status(200).json({
      success: true,
      message: "Interest registered successfully! The owner will be notified."
    });
  } catch (error) {
    console.error("Error in markInterested:", error);
    res.status(500).json({ success: false, message: error.message });
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
    res.status(500).json({ success: false, message: error.message });
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
    res.status(500).json({ success: false, isInterested: false, message: error.message });
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
    res.status(500).json({ success: false, message: error.message });
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
    res.status(500).json({ success: false, message: error.message });
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

    const filter = { isApproved: true };

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
      const regex = new RegExp(search, "i");
      filter.$or = [
        { title: regex },
        { description: regex },
        { "address.city": regex },
        { "address.area": regex },
        { "address.locality": regex },
      ];
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
    res.status(500).json({ error: err.message });
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
    const regex = new RegExp(searchTerm, "i");

    // Use aggregation for better performance - only fetch needed fields including first image
    const suggestions = await Property.aggregate([
      { $match: { isApproved: true } },
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
    console.error("Error in getSuggestions:", err);
    res.status(500).json({ suggestions: [], error: err.message });
  }
};

export const filterProperties = async (req, res) => {
  try {
    const { search = "", sort = "newest" } = req.query;

    // Base filter: only approved properties
    let filter = { isApproved: true };

    // Search in title or city
    if (search.trim()) {
      const regex = new RegExp(search.trim(), "i");
      filter.$or = [{ title: regex }, { "address.city": regex }];
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
    console.error("Error in filterProperties:", err);
    res.status(500).json({ success: false, error: err.message });
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
    res.status(500).json({ success: false, message: error.message });
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
      const regex = new RegExp(search, 'i'); // Case insensitive
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

    const properties = await Property.find(query)
      .populate("category", "name")
      .populate("subcategory", "name")
      .populate("propertyType", "name")
      .sort({ createdAt: -1 });

    console.log(`Found ${properties.length} properties matching search.`); // 🔍 Debug Log

    const processedProperties = properties.map((item) => withPublicImages(req, item));

    res.status(200).json({
      success: true,
      data: processedProperties,
      count: processedProperties.length
    });

  } catch (err) {
    console.error("Admin Filter Error:", err);
    res.status(500).json({ error: err.message });
  }
};

// ... keep approveProperty, disapproveProperty etc.
// --- UPDATED: Approve Property (Remove Rejection Reason) ---
export const approveProperty = async (req, res) => {
  try {
    const updated = await Property.findByIdAndUpdate(
      req.params.id,
      {
        isApproved: true,
        rejectionReason: "" // ✅ Clear the rejection reason when re-listing
      },
      { new: true }
    );
    if (!updated) return res.status(404).json({ message: "Property not found" });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// --- UPDATED: Disapprove Property (Require Reason) ---
export const disapproveProperty = async (req, res) => {
  try {
    const { rejectionReason } = req.body;

    if (!rejectionReason || rejectionReason.trim() === "") {
      return res.status(400).json({ message: "A reason is required to reject a property." });
    }

    const updated = await Property.findByIdAndUpdate(
      req.params.id,
      {
        isApproved: false,
        rejectionReason: rejectionReason // ✅ Save the reason
      },
      { new: true }
    );
    if (!updated) return res.status(404).json({ message: "Property not found" });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// ... (Keep the rest of your controllers like addProperty, deleteProperty, etc.)