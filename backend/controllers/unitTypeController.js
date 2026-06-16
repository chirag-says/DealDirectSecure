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
const uploadToCloudinary = (buffer, folder, resourceType = "image") =>
  new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: `dealdirect/unit-types/${folder}`, resource_type: resourceType },
      (err, result) => (err ? reject(err) : resolve(result.secure_url))
    );
    Readable.from(buffer).pipe(stream);
  });

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

    // Upload floor plans
    const folder = `${project.builder}/${project._id}`;
    const [twoDUrl, threeDUrl] = await Promise.all([
      files.twoDFloorPlan?.[0]
        ? uploadToCloudinary(files.twoDFloorPlan[0].buffer, folder)
        : Promise.resolve(""),
      files.threeDFloorPlan?.[0]
        ? uploadToCloudinary(files.threeDFloorPlan[0].buffer, folder)
        : Promise.resolve(""),
    ]);

    const unitType = await UnitType.create({
      project: body.projectId,
      builder: project.builder,
      createdBy: req.admin._id,
      config: {
        name: body.name,
        bedrooms: body.bedrooms ? Number(body.bedrooms) : undefined,
        bathrooms: body.bathrooms ? Number(body.bathrooms) : undefined,
        balconies: body.balconies ? Number(body.balconies) : undefined,
        hasUtilityArea: body.hasUtilityArea === "true",
      },
      area: {
        carpetSqft: body.carpetSqft ? Number(body.carpetSqft) : undefined,
        builtUpSqft: body.builtUpSqft ? Number(body.builtUpSqft) : undefined,
        superBuiltUpSqft: body.superBuiltUpSqft ? Number(body.superBuiltUpSqft) : undefined,
      },
      facing: body.facing ? JSON.parse(body.facing) : [],
      furnishing: body.furnishing,
      parking: {
        covered: body.coveredParking ? Number(body.coveredParking) : 0,
        open: body.openParking ? Number(body.openParking) : 0,
        ev: body.evParking ? Number(body.evParking) : 0,
      },
      specifications: body.specifications ? JSON.parse(body.specifications) : {},
      floorPlans: { twoDUrl, threeDUrl },
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
    });

    // Increment parent project's unit type count
    await Project.findByIdAndUpdate(body.projectId, { $inc: { unitTypeCount: 1 } });

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
    if (req.query.isActive !== undefined) {
      filter.isActive = req.query.isActive === "true";
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

    if (body.facing) unitType.facing = JSON.parse(body.facing);
    if (body.isActive !== undefined) unitType.isActive = body.isActive === "true" || body.isActive === true;

    await unitType.save(); // triggers pre-save auto-calc

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

    return res.status(200).json({ success: true, message: "Unit type deleted." });
  } catch (error) {
    console.error("[unitTypeController.deleteUnitType]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};
