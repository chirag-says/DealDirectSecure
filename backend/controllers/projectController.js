/**
 * Project Controller — DealDirect
 * Admin-only CRUD for builder projects.
 * All routes protected by protectAdmin middleware.
 */
import Project from "../models/Project.js";
import Builder from "../models/Builder.js";
import UnitType from "../models/UnitType.js";
import { cloudinary } from "../middleware/upload.js";
import { Readable } from "stream";

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Upload a single buffer to Cloudinary under a project-scoped folder.
 * Applies same transformations as property pipeline for image optimization.
 */
const uploadToCloudinary = (buffer, folder, resourceType = "image") =>
  new Promise((resolve, reject) => {
    const uploadOptions = {
      folder: `dealdirect/projects/${folder}`,
      resource_type: resourceType,
    };

    // Apply image transformations (same as property upload pipeline)
    // This also prevents transparent PNGs from appearing blank
    if (resourceType === "image") {
      uploadOptions.transformation = [
        { width: 1200, height: 800, crop: "limit", quality: "auto", fetch_format: "auto" },
      ];
    }

    const stream = cloudinary.uploader.upload_stream(
      uploadOptions,
      (err, result) => (err ? reject(err) : resolve(result.secure_url))
    );
    Readable.from(buffer).pipe(stream);
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

    // ── Media uploads ──────────────────────────────────────────────────────────
    const projectFolder = `${builder._id}`;
    const [exteriorImages, droneImages, masterPlan, locationMap, constructionProgressImages] =
      await Promise.all([
        uploadMany(files.exteriorImages, `${projectFolder}/exterior`),
        uploadMany(files.droneImages, `${projectFolder}/drone`),
        uploadMany(files.masterPlan, `${projectFolder}/masterplan`),
        uploadMany(files.locationMap, `${projectFolder}/locationmap`),
        uploadMany(files.constructionProgressImages, `${projectFolder}/progress`),
      ]);

    let brochureUrl = "";
    if (files.brochureUrl?.[0]) {
      brochureUrl = await uploadToCloudinary(
        files.brochureUrl[0].buffer,
        `${projectFolder}/docs`,
        "raw"
      );
    }

    // ── Document uploads ───────────────────────────────────────────────────────
    const [
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

    const approvalDocumentUrls = await uploadMany(
      files.approvalDocumentUrls,
      `${projectFolder}/docs`,
      "raw"
    );

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
        name: body.name,
        description: body.description,
        category: body.category,
        subType: body.subType,
        status: body.status,
        ownershipType: body.ownershipType,
        isVastuCompliant: body.isVastuCompliant === "true",
        highlights: safeParse(body.highlights),
        reraNumber: emptyToUndef(body.reraNumber),
        reraCertificateUrl: body.reraCertificateUrl || reraCertificateUrl,
      },
      location: {
        country: body.country || "India",
        state: body.state,
        city: body.city,
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
      },
      documents: {
        reraCertificateUrl,
        commencementCertificateUrl,
        occupancyCertificateUrl,
        environmentalClearanceUrl,
        approvalDocumentUrls,
      },
      legal: {
        landTitleType: body.landTitleType,
        titleClear: body.titleClear !== "false",
        encumbrances: emptyToUndef(body.encumbrances),
        litigationStatus: body.litigationStatus || "None",
        litigationDetails: emptyToUndef(body.litigationDetails),
      },
      paymentPlans: safeParse(body.paymentPlans),
      financials: {
        bookingAmount: body.bookingAmount ? Number(body.bookingAmount) : undefined,
        gstPercentage: body.gstPercentage ? Number(body.gstPercentage) : undefined,
        stampDutyPercentage: body.stampDutyPercentage ? Number(body.stampDutyPercentage) : undefined,
        registrationCharges: body.registrationCharges ? Number(body.registrationCharges) : undefined,
      },
      bankApprovals: safeParse(body.bankApprovals),
      salesContact: {
        managerName: emptyToUndef(body.managerName),
        phone: emptyToUndef(body.salesPhone),
        whatsapp: emptyToUndef(body.salesWhatsapp),
        email: emptyToUndef(body.salesEmail),
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
    return res.status(500).json({ success: false, message: "Server error creating project." });
  }
};

// ── Get Single Project ────────────────────────────────────────────────────────
export const getProject = async (req, res) => {
  try {
    const project = await Project.findById(req.params.id)
      .populate("builder", "name company phone email logoUrl description")
      .populate("createdBy", "name email")
      .lean();

    if (!project) {
      return res.status(404).json({ success: false, message: "Project not found." });
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
    if (isActive !== undefined) filter.isActive = isActive === "true";
    if (city) filter["location.city"] = { $regex: city, $options: "i" };
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
    const projects = await Project.find({ builder: req.params.builderId })
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
