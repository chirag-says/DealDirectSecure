/**
 * UnitType Controller — DealDirect
 * Admin-only CRUD for unit types within a project.
 * Pricing auto-calculation happens in the model's pre-save hook.
 */
import UnitType from "../models/UnitType.js";
import Project from "../models/Project.js";
import { cloudinary } from "../middleware/upload.js";
import { Readable } from "stream";

// ── Helper ────────────────────────────────────────────────────────────────────
/**
 * Upload a single buffer to Cloudinary under a unit-type-scoped folder.
 * Hardened identically to projectController.uploadToCloudinary:
 *  - timeout: 120s so Cloudinary fires the callback on hung uploads
 *  - chunk_size: 6 MB chunks to avoid single-shot timeout on large images
 *  - source .on('error', reject): routes stream errors into the Promise chain
 */
const uploadToCloudinary = (buffer, folder, resourceType = "image") =>
  new Promise((resolve, reject) => {
    const opts = {
      folder: `dealdirect/unit-types/${folder}`,
      resource_type: resourceType,
      timeout: 120_000,
      chunk_size: 6_000_000,
    };
    if (resourceType === "image") {
      opts.transformation = [
        { width: 1400, height: 900, crop: "limit", quality: "auto", fetch_format: "auto" },
      ];
    }
    const stream = cloudinary.uploader.upload_stream(
      opts,
      (err, result) => (err ? reject(err) : resolve(result.secure_url))
    );
    Readable.from(buffer).on("error", reject).pipe(stream);
  });

// ── Helper: Recalculate price range on parent project ─────────────────────────
const recalcPriceRange = async (projectId) => {
  try {
    const result = await UnitType.aggregate([
      { $match: { project: projectId, isActive: true, "pricing.effectivePrice": { $gt: 0 } } },
      { $group: {
        _id: null,
        min: { $min: "$pricing.effectivePrice" },
        max: { $max: "$pricing.effectivePrice" },
      }},
    ]);
    const range = result[0] || { min: 0, max: 0 };
    await Project.findByIdAndUpdate(projectId, {
      "priceRange.min": range.min || 0,
      "priceRange.max": range.max || 0,
    });
  } catch (err) {
    console.error("[recalcPriceRange] Non-blocking error:", err.message);
  }
};

// ── Create UnitType ───────────────────────────────────────────────────────────
export const createUnitType = async (req, res) => {
  try {
    const body = req.body;
    const files = req.files || {};

    // Validate parent project exists
    const project = await Project.findById(body.projectId).lean();
    if (!project) {
      return res.status(404).json({ success: false, message: "Project not found." });
    }

    // Upload floor plans + interior photos in parallel
    const folder = `${project.builder}/${project._id}`;
    const photoRooms = JSON.parse(body.unitPhotoRooms || "[]"); // parallel array of room tags

    const [twoDUrl, threeDUrl, ...uploadedPhotos] = await Promise.all([
      files.twoDFloorPlan?.[0]
        ? uploadToCloudinary(files.twoDFloorPlan[0].buffer, folder)
        : Promise.resolve(""),
      files.threeDFloorPlan?.[0]
        ? uploadToCloudinary(files.threeDFloorPlan[0].buffer, folder)
        : Promise.resolve(""),
      ...(files.unitPhotos || []).map((f, i) =>
        uploadToCloudinary(f.buffer, `${folder}/photos`).then(url => ({
          url,
          room: photoRooms[i] || "Other",
          caption: "",
        }))
      ),
    ]);

    const photos = uploadedPhotos.filter(Boolean);

    const unitType = await UnitType.create({
      project: body.projectId,
      builder: project.builder,
      createdBy: req.admin._id,
      config: {
        name: body.name || undefined,
        bedrooms: body.bedrooms ? Number(body.bedrooms) : undefined,
        bathrooms: body.bathrooms ? Number(body.bathrooms) : undefined,
        balconies: body.balconies ? Number(body.balconies) : undefined,
        hasUtilityArea: body.hasUtilityArea === "true",
      },
      area: {
        carpetSqft:      body.carpetSqft      ? Number(body.carpetSqft)      : undefined,
        builtUpSqft:     body.builtUpSqft     ? Number(body.builtUpSqft)     : undefined,
        superBuiltUpSqft: body.superBuiltUpSqft ? Number(body.superBuiltUpSqft) : undefined,
        // Feature 4 — plot fields
        plotAreaSqft:    body.plotAreaSqft    ? Number(body.plotAreaSqft)    : undefined,
        plotDimensions:  body.plotLength && body.plotWidth ? {
          length: Number(body.plotLength),
          width:  Number(body.plotWidth),
        } : undefined,
      },
      facing: body.facing ? JSON.parse(body.facing) : [],
      // Blank would fail the enum — send undefined so the schema default applies.
      furnishing: body.furnishing || undefined,
      parking: {
        covered: body.coveredParking ? Number(body.coveredParking) : 0,
        open: body.openParking ? Number(body.openParking) : 0,
        ev: body.evParking ? Number(body.evParking) : 0,
      },
      specifications: body.specifications ? JSON.parse(body.specifications) : {},
      floorPlans: {
        twoDUrl,
        threeDUrl,
        videoUrl: body.videoTourUrl || "", // Feature 8
      },
      pricing: {
        basePrice: body.basePrice ? Number(body.basePrice) : undefined,
        additionalCharges: {
          plc: body.plc ? Number(body.plc) : 0,
          parking: body.parkingCharges ? Number(body.parkingCharges) : 0,
          clubhouse: body.clubhouse ? Number(body.clubhouse) : 0,
          legal: body.legal ? Number(body.legal) : 0,
          maintenance: body.maintenance ? Number(body.maintenance) : 0,
        },
        floorRisePerSqft: body.floorRisePerSqft ? Number(body.floorRisePerSqft) : 0,
        viewPremium: body.viewPremium ? Number(body.viewPremium) : 0,
        // pricePerSqft and effectivePrice auto-calculated in pre-save
      },
      inventory: {
        totalUnits: body.totalUnits ? Number(body.totalUnits) : undefined,
        availableUnits: body.availableUnits ? Number(body.availableUnits) : undefined,
        bookedUnits: body.bookedUnits ? Number(body.bookedUnits) : 0,
        blockedUnits: body.blockedUnits ? Number(body.blockedUnits) : 0,
        towerAllocation: body.towerAllocation ? JSON.parse(body.towerAllocation) : [],
      },
      highlights: body.highlights ? JSON.parse(body.highlights) : [],
      photos, // Feature 3 — interior photos (empty array if none uploaded)
      paymentTerms: {
        bookingAmount:       body.bookingAmount       ? Number(body.bookingAmount)       : undefined,
        gstPercentage:       body.gstPercentage       ? Number(body.gstPercentage)       : undefined,
        stampDutyPercentage: body.stampDutyPercentage ? Number(body.stampDutyPercentage) : undefined,
        registrationCharges: body.registrationCharges ? Number(body.registrationCharges) : undefined,
      },
    });

    // Increment parent project's unit type count
    await Project.findByIdAndUpdate(body.projectId, { $inc: { unitTypeCount: 1 } });

    // Recalculate denormalized price range on parent project
    await recalcPriceRange(project._id);

    return res.status(201).json({
      success: true,
      message: "Unit type created successfully.",
      data: unitType,
    });
  } catch (error) {
    console.error("[unitTypeController.createUnitType]", error);
    if (error.name === "ValidationError") {
      const messages = Object.values(error.errors).map((e) => e.message);
      return res.status(400).json({ success: false, message: messages.join(", ") });
    }
    return res.status(500).json({ success: false, message: "Server error creating unit type." });
  }
};

// ── Get Single UnitType ───────────────────────────────────────────────────────
export const getUnitType = async (req, res) => {
  try {
    const unitType = await UnitType.findById(req.params.id)
      .populate("project", "basics.name location.city")
      .populate("builder", "name company logoUrl")
      .lean();

    if (!unitType) {
      return res.status(404).json({ success: false, message: "Unit type not found." });
    }

    // Inactive unit types are not publicly viewable.
    if (req.isAdminViewer !== true && unitType.isActive === false) {
      return res.status(404).json({ success: false, message: "Unit type not found." });
    }

    return res.status(200).json({ success: true, data: unitType });
  } catch (error) {
    console.error("[unitTypeController.getUnitType]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── List UnitTypes by Project ─────────────────────────────────────────────────
export const listByProject = async (req, res) => {
  try {
    const filter = { project: req.params.projectId };
    // Public callers only see active unit types, regardless of query param.
    if (req.isAdminViewer === true) {
      if (req.query.isActive !== undefined) {
        filter.isActive = req.query.isActive === "true";
      }
    } else {
      filter.isActive = true;
    }

    const unitTypes = await UnitType.find(filter).sort({ createdAt: 1 }).lean();

    return res.status(200).json({ success: true, data: unitTypes });
  } catch (error) {
    console.error("[unitTypeController.listByProject]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── Update UnitType ───────────────────────────────────────────────────────────
export const updateUnitType = async (req, res) => {
  try {
    const unitType = await UnitType.findById(req.params.id);
    if (!unitType) {
      return res.status(404).json({ success: false, message: "Unit type not found." });
    }

    const body = req.body;
    const files = req.files || {};

    // Update floor plan uploads if provided
    if (files.twoDFloorPlan?.[0]) {
      const folder = `${unitType.builder}/${unitType.project}`;
      unitType.floorPlans.twoDUrl = await uploadToCloudinary(
        files.twoDFloorPlan[0].buffer,
        folder
      );
    }
    if (files.threeDFloorPlan?.[0]) {
      const folder = `${unitType.builder}/${unitType.project}`;
      unitType.floorPlans.threeDUrl = await uploadToCloudinary(
        files.threeDFloorPlan[0].buffer,
        folder
      );
    }

    // Merge allowed fields
    const directFields = ["config", "area", "furnishing", "parking", "specifications", "floorPlans", "pricing", "inventory", "highlights"];
    directFields.forEach((key) => {
      if (body[key] !== undefined) {
        try {
          unitType[key] = typeof body[key] === "string" ? JSON.parse(body[key]) : body[key];
        } catch { /* leave as-is */ }
      }
    });

    // Payment terms arrive as FLAT fields from the form (not a nested object),
    // so map them explicitly — mirrors createUnitType.
    const ptKeys = ["bookingAmount", "gstPercentage", "stampDutyPercentage", "registrationCharges"];
    if (ptKeys.some((k) => body[k] !== undefined)) {
      unitType.paymentTerms = {
        bookingAmount:       body.bookingAmount       ? Number(body.bookingAmount)       : undefined,
        gstPercentage:       body.gstPercentage       ? Number(body.gstPercentage)       : undefined,
        stampDutyPercentage: body.stampDutyPercentage ? Number(body.stampDutyPercentage) : undefined,
        registrationCharges: body.registrationCharges ? Number(body.registrationCharges) : undefined,
      };
    }

    if (body.facing) unitType.facing = JSON.parse(body.facing);
    if (body.isActive !== undefined) unitType.isActive = body.isActive === "true" || body.isActive === true;

    // Feature 4: explicit flat-field mapping for plot (body sends flat, not a JSON blob)
    if (body.plotAreaSqft !== undefined) {
      if (!unitType.area) unitType.area = {};
      unitType.area.plotAreaSqft = body.plotAreaSqft ? Number(body.plotAreaSqft) : undefined;
    }
    if (body.plotLength && body.plotWidth) {
      if (!unitType.area) unitType.area = {};
      unitType.area.plotDimensions = { length: Number(body.plotLength), width: Number(body.plotWidth) };
    }

    // Feature 8: video tour URL
    if (body.videoTourUrl !== undefined) {
      unitType.floorPlans = unitType.floorPlans || {};
      unitType.floorPlans.videoUrl = body.videoTourUrl;
    }

    // Feature 3: interior photos
    const photoRooms = JSON.parse(body.unitPhotoRooms || "[]");
    if (files.unitPhotos?.length) {
      const folder = `${unitType.project}/photos`;
      // First remove any URLs the admin explicitly wants deleted
      if (body.removePhotoUrls) {
        const toRemove = new Set(JSON.parse(body.removePhotoUrls));
        unitType.photos = (unitType.photos || []).filter(p => !toRemove.has(p.url));
      }
      const newPhotos = await Promise.all(
        files.unitPhotos.map((f, i) =>
          uploadToCloudinary(f.buffer, folder).then(url => ({
            url,
            room: photoRooms[i] || "Other",
            caption: "",
          }))
        )
      );
      unitType.photos = [...(unitType.photos || []), ...newPhotos];
    } else if (body.removePhotoUrls) {
      // Allow removal even without new uploads
      const toRemove = new Set(JSON.parse(body.removePhotoUrls));
      unitType.photos = (unitType.photos || []).filter(p => !toRemove.has(p.url));
    }

    await unitType.save(); // triggers pre-save auto-calc

    // Recalculate denormalized price range on parent project
    await recalcPriceRange(unitType.project);

    return res.status(200).json({
      success: true,
      message: "Unit type updated.",
      data: unitType,
    });
  } catch (error) {
    console.error("[unitTypeController.updateUnitType]", error);
    if (error.name === "ValidationError") {
      const messages = Object.values(error.errors).map((e) => e.message);
      return res.status(400).json({ success: false, message: messages.join(", ") });
    }
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── Delete UnitType ───────────────────────────────────────────────────────────
export const deleteUnitType = async (req, res) => {
  try {
    const unitType = await UnitType.findById(req.params.id);
    if (!unitType) {
      return res.status(404).json({ success: false, message: "Unit type not found." });
    }

    // Block if active campaigns exist
    if (unitType.activeCampaignCount > 0) {
      return res.status(400).json({
        success: false,
        message: `Cannot delete unit type with ${unitType.activeCampaignCount} active campaign(s).`,
      });
    }

    const projectId = unitType.project;
    await unitType.deleteOne();

    // Decrement parent project's unit type count
    await Project.findByIdAndUpdate(projectId, { $inc: { unitTypeCount: -1 } });

    // Recalculate denormalized price range on parent project
    await recalcPriceRange(projectId);

    return res.status(200).json({ success: true, message: "Unit type deleted." });
  } catch (error) {
    console.error("[unitTypeController.deleteUnitType]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};
