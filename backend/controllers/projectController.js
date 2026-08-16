/**
 * Project Controller — DealDirect
 * Admin-only CRUD for builder projects.
 * All routes protected by protectAdmin middleware.
 */
import Project from "../models/Project.js";
import Builder from "../models/Builder.js";
import UnitType from "../models/UnitType.js";
import { cloudinary, isCloudinaryConfigured } from "../middleware/upload.js";
import { Readable } from "stream";
import { escapeRegExp } from "../utils/escapeRegExp.js";

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Upload a single buffer to Cloudinary under a project-scoped folder.
 *
 * Key hardening applied here:
 *  1. `timeout` — Cloudinary will fire the callback with a TimeoutError instead
 *     of silently hanging, so the Promise rejects cleanly rather than leaking.
 *  2. `chunk_size` — breaks large files into 6 MB chunks so each HTTP leg
 *     completes well within the timeout window.
 *  3. Source `.on('error', reject)` — ensures stream-level errors (e.g. premature
 *     close, ECONNRESET) route into the Promise reject chain and never reach the
 *     global unhandled-rejection handler.
 */
const uploadToCloudinary = (buffer, folder, resourceType = "image") =>
  new Promise((resolve, reject) => {
    const uploadOptions = {
      folder: `dealdirect/projects/${folder}`,
      resource_type: resourceType,
      timeout: 120_000,      // 2 min: Cloudinary calls cb with TimeoutError if exceeded
      chunk_size: 6_000_000, // 6 MB chunks — prevents single-shot timeouts on large images
    };

    // Resize & optimise images on the Cloudinary side (reduces round-trip bytes).
    // Capped at 1400 × 900 — sufficient for web/retina, faster transfer than 2 K+.
    if (resourceType === "image") {
      uploadOptions.transformation = [
        { width: 1400, height: 900, crop: "limit", quality: "auto", fetch_format: "auto" },
      ];
    }

    const stream = cloudinary.uploader.upload_stream(
      uploadOptions,
      (err, result) => (err ? reject(err) : resolve(result.secure_url))
    );

    // Route source stream errors → Promise reject (prevents unhandled-rejection).
    Readable.from(buffer).on("error", reject).pipe(stream);
  });

/**
 * Upload multiple files from req.files[fieldName] array.
 * Returns array of Cloudinary URLs.
 */
const uploadMany = async (files = [], folder, resourceType = "image") =>
  Promise.all(files.map((f) => uploadToCloudinary(f.buffer, folder, resourceType)));

// ── Create Project ────────────────────────────────────────────────────────────
export const createProject = async (req, res) => {
  try {
    // FAIL FAST: reject before any DB / Cloudinary work if storage is not configured.
    // Mirrors the same guard in validateAndUploadToCloudinary (upload.js:379).
    if (!isCloudinaryConfigured()) {
      console.error('[projectController.createProject] Cloudinary not configured — rejecting request');
      return res.status(503).json({
        success: false,
        message: 'Image upload service is not configured. Please contact support.',
        code: 'STORAGE_NOT_CONFIGURED',
      });
    }

    const body = req.body;
    const files = req.files || {};

    // Validate builder exists and is active
    const builder = await Builder.findById(body.builderId).lean();
    if (!builder) {
      return res.status(404).json({ success: false, message: "Builder not found." });
    }
    if (!builder.isActive) {
      return res.status(400).json({ success: false, message: "Builder is inactive." });
    }

    // ── Media & Document uploads ───────────────────────────────────────────────
    const projectFolder = `${builder._id}`;
    let exteriorImages, droneImages, masterPlan, locationMap, constructionProgressImages,
        brochureUrl = "",
        reraCertificateUrl, commencementCertificateUrl, occupancyCertificateUrl,
        environmentalClearanceUrl, approvalDocumentUrls,
        amenityImages = [];

    try {
      [exteriorImages, droneImages, masterPlan, locationMap, constructionProgressImages, amenityImages] =
        await Promise.all([
          uploadMany(files.exteriorImages, `${projectFolder}/exterior`),
          uploadMany(files.droneImages, `${projectFolder}/drone`),
          uploadMany(files.masterPlan, `${projectFolder}/masterplan`),
          uploadMany(files.locationMap, `${projectFolder}/locationmap`),
          uploadMany(files.constructionProgressImages, `${projectFolder}/progress`),
          uploadMany(files.amenityImages, `${projectFolder}/amenities`), // Feature 5
        ]);

      if (files.brochureUrl?.[0]) {
        brochureUrl = await uploadToCloudinary(
          files.brochureUrl[0].buffer,
          `${projectFolder}/docs`,
          "raw"
        );
      }

      [
        reraCertificateUrl,
        commencementCertificateUrl,
        occupancyCertificateUrl,
        environmentalClearanceUrl,
      ] = await Promise.all([
        files.reraCertificateUrl?.[0]
          ? uploadToCloudinary(files.reraCertificateUrl[0].buffer, `${projectFolder}/docs`, "raw")
          : Promise.resolve(""),
        files.commencementCertificateUrl?.[0]
          ? uploadToCloudinary(files.commencementCertificateUrl[0].buffer, `${projectFolder}/docs`, "raw")
          : Promise.resolve(""),
        files.occupancyCertificateUrl?.[0]
          ? uploadToCloudinary(files.occupancyCertificateUrl[0].buffer, `${projectFolder}/docs`, "raw")
          : Promise.resolve(""),
        files.environmentalClearanceUrl?.[0]
          ? uploadToCloudinary(files.environmentalClearanceUrl[0].buffer, `${projectFolder}/docs`, "raw")
          : Promise.resolve(""),
      ]);

      approvalDocumentUrls = await uploadMany(
        files.approvalDocumentUrls,
        `${projectFolder}/docs`,
        "raw"
      );
    } catch (uploadErr) {
      console.error('[projectController.createProject] Upload failed:', uploadErr.message);
      return res.status(500).json({
        success: false,
        message: 'Failed to upload project media/documents to storage.',
        code: 'UPLOAD_FAILED',
        ...(process.env.NODE_ENV !== 'production' && { debugInfo: uploadErr.message }),
      });
    }

    // ── Build and save ─────────────────────────────────────────────────────────
    // Helper: safely parse JSON from FormData (which sends everything as strings)
    const safeParse = (val, fallback = []) => {
      if (!val) return fallback;
      try { return JSON.parse(val); } catch { return fallback; }
    };

    // Helper: convert empty strings to undefined (prevents Mongoose CastError on Date/Number fields)
    const emptyToUndef = (val) => (val === "" || val === undefined || val === null) ? undefined : val;

    const project = await Project.create({
      builder: body.builderId,
      createdBy: req.admin._id,
      basics: {
        name: emptyToUndef(body.name),
        description: body.description,
        // Enum fields: a blank string would fail enum validation, so send undefined
        // and let the schema default (or nothing) apply.
        category: emptyToUndef(body.category),
        subType: emptyToUndef(body.subType),
        status: emptyToUndef(body.status),
        ownershipType: emptyToUndef(body.ownershipType),
        isVastuCompliant: body.isVastuCompliant === "true",
        highlights: safeParse(body.highlights),
        reraNumber: emptyToUndef(body.reraNumber),
        reraCertificateUrl: body.reraCertificateUrl || reraCertificateUrl,
      },
      location: {
        country: body.country || "India",
        state: emptyToUndef(body.state),
        city: emptyToUndef(body.city),
        locality: emptyToUndef(body.locality),
        microMarket: emptyToUndef(body.microMarket),
        addressLine: emptyToUndef(body.addressLine),
        landmark: emptyToUndef(body.landmark),
        pincode: emptyToUndef(body.pincode),
        coordinates: body.lat && body.lng
          ? { lat: parseFloat(body.lat), lng: parseFloat(body.lng) }
          : undefined,
        connectivity: {
          distanceToMetro: emptyToUndef(body.distanceToMetro),
          distanceToAirport: emptyToUndef(body.distanceToAirport),
          distanceToRailway: emptyToUndef(body.distanceToRailway),
          distanceToBusStop: emptyToUndef(body.distanceToBusStop),
        },
      },
      nearbyPlaces: safeParse(body.nearbyPlaces),
      overview: {
        launchDate: emptyToUndef(body.launchDate) || undefined,
        possessionDate: emptyToUndef(body.possessionDate) || undefined,
        totalLandArea: emptyToUndef(body.totalLandArea),
        totalTowers: body.totalTowers ? Number(body.totalTowers) : undefined,
        floorsPerTower: emptyToUndef(body.floorsPerTower),
        totalUnits: body.totalUnits ? Number(body.totalUnits) : undefined,
        openSpacePercentage: body.openSpacePercentage ? Number(body.openSpacePercentage) : undefined,
      },
      amenities: safeParse(body.amenities),
      media: {
        exteriorImages,
        droneImages,
        masterPlan,
        locationMap,
        brochureUrl,
        walkthroughVideoUrl: emptyToUndef(body.walkthroughVideoUrl),
        constructionProgressImages,
        amenityImages, // Feature 5 — already uploaded in try/catch block above
      },
      documents: {
        reraCertificateUrl,
        commencementCertificateUrl,
        occupancyCertificateUrl,
        environmentalClearanceUrl,
        approvalDocumentUrls,
      },
      legal: {
        landTitleType: emptyToUndef(body.landTitleType),
        titleClear: body.titleClear !== "false",
        encumbrances: emptyToUndef(body.encumbrances),
        litigationStatus: body.litigationStatus || "None",
        litigationDetails: emptyToUndef(body.litigationDetails),
      },
      paymentPlans: safeParse(body.paymentPlans),
      // NOTE: financials (bookingAmount, gstPercentage, etc.) are no longer written at the project
      // level. They have moved to UnitType.paymentTerms so they can vary per unit type.
      // The field is kept in Project.js schema for back-compat reads of legacy records.
      bankApprovals: safeParse(body.bankApprovals),
      // DealDirect is always the buyer contact — never the builder.
      salesContact: {
        managerName: "DealDirect Admin",
        phone: "6360122696",
        whatsapp: "6360122696",
        email: "admin@dealdirect.in",
      },
    });

    return res.status(201).json({
      success: true,
      message: "Project created successfully.",
      data: project,
    });
  } catch (error) {
    console.error("[projectController.createProject]", error);
    if (error.name === "ValidationError") {
      const messages = Object.values(error.errors).map((e) => e.message);
      return res.status(400).json({ success: false, message: messages.join(", ") });
    }
    return res.status(500).json({
      success: false,
      message: "Server error creating project.",
      ...(process.env.NODE_ENV !== 'production' && { debugInfo: error.message }),
    });
  }
};

// ── Get Single Project ────────────────────────────────────────────────────────
export const getProject = async (req, res) => {
  try {
    const isAdmin = req.isAdminViewer === true;

    // Buyers must never receive the builder's direct phone/email — DealDirect is the
    // sole point of contact. Contact fields are exposed to admin viewers only; the
    // public payload carries marketing fields (name/company/logo/track record) only.
    const builderFields = isAdmin
      ? "name company phone email logoUrl description yearEstablished totalProjectsDelivered"
      : "name company logoUrl description yearEstablished totalProjectsDelivered";

    let query = Project.findById(req.params.id)
      .populate("builder", builderFields);

    // Only expose the creating admin (name/email) to other admins — never publicly.
    if (isAdmin) query = query.populate("createdBy", "name email");

    const project = await query.lean();

    if (!project) {
      return res.status(404).json({ success: false, message: "Project not found." });
    }

    // Inactive/deactivated projects are not publicly viewable.
    if (!isAdmin && project.isActive === false) {
      return res.status(404).json({ success: false, message: "Project not found." });
    }

    // Strip internal-only fields from the public response.
    if (!isAdmin) {
      delete project.createdBy;
      if (project.legal) {
        delete project.legal.litigationDetails;
        delete project.legal.encumbrances;
      }
    }

    return res.status(200).json({ success: true, data: project });
  } catch (error) {
    console.error("[projectController.getProject]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── List Projects (with filters) ──────────────────────────────────────────────
export const listProjects = async (req, res) => {
  try {
    const { search = "", city, category, status, isActive, page = 1, limit = 20 } = req.query;

    const filter = {};
    // Public callers may only ever see active projects, regardless of query param.
    if (req.isAdminViewer === true) {
      if (isActive !== undefined) filter.isActive = isActive === "true";
    } else {
      filter.isActive = true;
    }
    if (city) filter["location.city"] = { $regex: escapeRegExp(city), $options: "i" };
    if (category) filter["basics.category"] = category;
    if (status) filter["basics.status"] = status;
    if (search.trim()) {
      filter.$text = { $search: search.trim() };
    }

    const skip = (Number(page) - 1) * Number(limit);

    const [projects, total] = await Promise.all([
      Project.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .populate("builder", "name company logoUrl")
        .lean(),
      Project.countDocuments(filter),
    ]);

    return res.status(200).json({
      success: true,
      data: projects,
      pagination: {
        total,
        page: Number(page),
        pages: Math.ceil(total / Number(limit)),
      },
    });
  } catch (error) {
    console.error("[projectController.listProjects]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── List Projects by Builder ──────────────────────────────────────────────────
export const listProjectsByBuilder = async (req, res) => {
  try {
    const filter = { builder: req.params.builderId };
    // Public callers only see active projects; admins see all.
    if (req.isAdminViewer !== true) filter.isActive = true;

    const projects = await Project.find(filter)
      .sort({ createdAt: -1 })
      .populate("builder", "name company logoUrl")
      .lean();

    return res.status(200).json({ success: true, data: projects });
  } catch (error) {
    console.error("[projectController.listProjectsByBuilder]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── Update Project ────────────────────────────────────────────────────────────
export const updateProject = async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) {
      return res.status(404).json({ success: false, message: "Project not found." });
    }

    // Merge top-level fields carefully — avoid overwriting nested objects wholesale
    const allowed = [
      "basics", "location", "nearbyPlaces", "overview", "amenities",
      "legal", "paymentPlans", "financials", "bankApprovals", "salesContact",
    ];
    allowed.forEach((key) => {
      if (req.body[key] !== undefined) {
        if (typeof req.body[key] === "string") {
          try { project[key] = JSON.parse(req.body[key]); } catch { /* leave as-is */ }
        } else {
          project[key] = req.body[key];
        }
      }
    });

    if (req.body.isActive !== undefined) {
      project.isActive = req.body.isActive === "true" || req.body.isActive === true;
    }

    // ── Handle file uploads (if any) ────────────────────────────────────────
    const files = req.files || {};
    const projectFolder = `${project.builder}`;

    if (Object.keys(files).length > 0) {
      // Upload new images and APPEND to existing arrays (don't replace)
      const mediaFields = [
        ["exteriorImages", "exterior"],
        ["droneImages", "drone"],
        ["masterPlan", "masterplan"],
        ["locationMap", "locationmap"],
        ["constructionProgressImages", "progress"],
        ["amenityImages", "amenities"], // Feature 5
      ];

      for (const [field, subfolder] of mediaFields) {
        if (files[field]?.length) {
          const newUrls = await uploadMany(files[field], `${projectFolder}/${subfolder}`);
          const existing = Array.isArray(project.media?.[field]) ? project.media[field] : [];
          project.media[field] = [...existing, ...newUrls];
        }
      }

      // Brochure replaces (not appends — there's only one)
      if (files.brochureUrl?.[0]) {
        project.media.brochureUrl = await uploadToCloudinary(
          files.brochureUrl[0].buffer,
          `${projectFolder}/docs`,
          "raw"
        );
      }
    }

    await project.save();

    return res.status(200).json({
      success: true,
      message: "Project updated.",
      data: project,
    });
  } catch (error) {
    console.error("[projectController.updateProject]", error);
    if (error.name === "ValidationError") {
      const messages = Object.values(error.errors).map((e) => e.message);
      return res.status(400).json({ success: false, message: messages.join(", ") });
    }
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── Add Construction Update ───────────────────────────────────────────────────
export const addConstructionUpdate = async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) {
      return res.status(404).json({ success: false, message: "Project not found." });
    }

    const files = req.files?.images || [];
    const images = await uploadMany(files, `${project.builder}/progress`);

    project.constructionUpdates.push({
      title: req.body.title,
      description: req.body.description,
      images,
      percentComplete: req.body.percentComplete ? Number(req.body.percentComplete) : undefined,
    });

    await project.save();

    return res.status(200).json({
      success: true,
      message: "Construction update added.",
      data: project.constructionUpdates,
    });
  } catch (error) {
    console.error("[projectController.addConstructionUpdate]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── Delete Project ────────────────────────────────────────────────────────────
export const deleteProject = async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) {
      return res.status(404).json({ success: false, message: "Project not found." });
    }

    // Block deletion if unit types exist
    const unitTypeCount = await UnitType.countDocuments({ project: project._id });
    if (unitTypeCount > 0) {
      return res.status(400).json({
        success: false,
        message: `Cannot delete project with ${unitTypeCount} unit type(s). Remove unit types first.`,
      });
    }

    await project.deleteOne();

    return res.status(200).json({ success: true, message: "Project deleted." });
  } catch (error) {
    console.error("[projectController.deleteProject]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};
