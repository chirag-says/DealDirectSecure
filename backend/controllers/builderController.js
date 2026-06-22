/**
 * Builder Controller — DealDirect
 * Admin-only CRUD for builder contact cards.
 * Builders have NO login — admin manages everything.
 */
import Builder from "../models/Builder.js";
import Property from "../models/Property.js";
import Project from "../models/Project.js";
import { cloudinary } from "../middleware/upload.js";
import { Readable } from "stream";

// ── List Builders ─────────────────────────────────────────────────────────────
export const listBuilders = async (req, res) => {
  try {
    const {
      search = "",
      page = 1,
      limit = 20,
      isActive,
    } = req.query;

    const filter = {};

    // Active filter
    if (isActive !== undefined) {
      filter.isActive = isActive === "true";
    }

    // Text search
    if (search.trim()) {
      filter.$or = [
        { name: { $regex: search.trim(), $options: "i" } },
        { company: { $regex: search.trim(), $options: "i" } },
        { phone: { $regex: search.trim(), $options: "i" } },
        { email: { $regex: search.trim(), $options: "i" } },
      ];
    }

    const skip = (Number(page) - 1) * Number(limit);

    const [builders, total] = await Promise.all([
      Builder.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .populate("addedBy", "name email")
        .lean(),
      Builder.countDocuments(filter),
    ]);

    // Attach project count per builder (using Project model, not legacy Property)
    const builderIds = builders.map((b) => b._id);
    const projectCounts = await Project.aggregate([
      { $match: { builder: { $in: builderIds }, isActive: true } },
      { $group: { _id: "$builder", count: { $sum: 1 } } },
    ]);

    const countMap = {};
    projectCounts.forEach((p) => {
      countMap[p._id.toString()] = p.count;
    });

    const enriched = builders.map((b) => ({
      ...b,
      projectCount: countMap[b._id.toString()] || 0,
    }));

    return res.status(200).json({
      success: true,
      data: enriched,
      pagination: {
        total,
        page: Number(page),
        limit: Number(limit),
        totalPages: Math.ceil(total / Number(limit)),
      },
    });
  } catch (err) {
    console.error("[Builder] listBuilders error:", err);
    return res.status(500).json({ success: false, message: "Failed to fetch builders." });
  }
};

// ── Get Single Builder ────────────────────────────────────────────────────────
export const getBuilder = async (req, res) => {
  try {
    const builder = await Builder.findById(req.params.id)
      .populate("addedBy", "name email")
      .lean();

    if (!builder) {
      return res.status(404).json({ success: false, message: "Builder not found." });
    }

    // Fetch their projects (not legacy properties)
    const projects = await Project.find({ builder: builder._id, isActive: true })
      .select("basics.name basics.status basics.category location.city overview.totalUnits media.exteriorImages priceRange createdAt")
      .sort({ createdAt: -1 })
      .lean();

    return res.status(200).json({
      success: true,
      data: { ...builder, projects },
    });
  } catch (err) {
    console.error("[Builder] getBuilder error:", err);
    return res.status(500).json({ success: false, message: "Failed to fetch builder." });
  }
};

// ── Create Builder ────────────────────────────────────────────────────────────
export const createBuilder = async (req, res) => {
  try {
    const {
      name, company, phone, alternatePhone,
      email, reraNumber, gstNumber,
      address, notes,
      description, yearEstablished, totalProjectsDelivered,
      totalSqFtDelivered, websiteUrl, operatingCities, awards,
    } = req.body;

    if (!name?.trim()) {
      return res.status(400).json({ success: false, message: "Builder name is required." });
    }
    if (!phone?.trim()) {
      return res.status(400).json({ success: false, message: "Phone number is required." });
    }

    // Check unique phone
    const existing = await Builder.findOne({ phone: phone.trim() });
    if (existing) {
      return res.status(409).json({
        success: false,
        message: `A builder with phone ${phone.trim()} already exists.`,
      });
    }

    // Handle logo upload if provided
    let logoUrl;
    if (req.file && req.file.buffer) {
      logoUrl = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          {
            folder: "dealdirect/builders/logos",
            resource_type: "image",
            transformation: [{ width: 400, height: 400, crop: "limit", quality: "auto", format: "auto" }],
          },
          (err, result) => (err ? reject(err) : resolve(result.secure_url))
        );
        Readable.from(req.file.buffer).pipe(stream);
      });
    }

    // Parse JSON strings from FormData for arrays/objects
    const parseJSON = (val, fallback) => {
      if (!val) return fallback;
      if (typeof val !== "string") return val;
      try { return JSON.parse(val); } catch { return fallback; }
    };

    const builder = await Builder.create({
      name: name.trim(),
      company: company?.trim(),
      phone: phone.trim(),
      alternatePhone: alternatePhone?.trim(),
      email: email?.trim().toLowerCase(),
      reraNumber: reraNumber?.trim(),
      gstNumber: gstNumber?.trim(),
      address: typeof address === "string" ? (() => { try { return JSON.parse(address); } catch { return address; } })() : address,
      notes: notes?.trim(),
      description: description?.trim(),
      yearEstablished: yearEstablished || undefined,
      totalProjectsDelivered: totalProjectsDelivered || undefined,
      totalSqFtDelivered: totalSqFtDelivered?.trim?.() || totalSqFtDelivered,
      websiteUrl: websiteUrl?.trim(),
      operatingCities: parseJSON(operatingCities, []),
      awards: parseJSON(awards, []),
      addedBy: req.admin?._id,
      ...(logoUrl && { logoUrl }),
    });

    return res.status(201).json({
      success: true,
      message: "Builder created successfully.",
      data: builder,
    });
  } catch (err) {
    console.error("[Builder] createBuilder error:", err);
    if (err.code === 11000) {
      return res.status(409).json({ success: false, message: "A builder with this phone/email already exists." });
    }
    return res.status(500).json({ success: false, message: "Failed to create builder." });
  }
};

// ── Update Builder ────────────────────────────────────────────────────────────
export const updateBuilder = async (req, res) => {
  try {
    const builder = await Builder.findById(req.params.id);
    if (!builder) {
      return res.status(404).json({ success: false, message: "Builder not found." });
    }

    const allowed = [
      "name", "company", "phone", "alternatePhone",
      "email", "reraNumber", "gstNumber", "address", "notes", "isActive",
      "description", "yearEstablished", "totalProjectsDelivered",
      "totalSqFtDelivered", "operatingCities", "awards", "websiteUrl",
    ];

    allowed.forEach((key) => {
      if (req.body[key] !== undefined) {
        let val = req.body[key];
        // Parse JSON strings (from FormData) for nested objects/arrays
        if (["address", "operatingCities", "awards"].includes(key) && typeof val === "string") {
          try { val = JSON.parse(val); } catch { /* keep as-is */ }
        }
        builder[key] = val;
      }
    });

    // Handle logo upload if provided
    if (req.file && req.file.buffer) {
      builder.logoUrl = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          {
            folder: "dealdirect/builders/logos",
            resource_type: "image",
            transformation: [{ width: 400, height: 400, crop: "limit", quality: "auto", format: "auto" }],
          },
          (err, result) => (err ? reject(err) : resolve(result.secure_url))
        );
        Readable.from(req.file.buffer).pipe(stream);
      });
    }

    // Check phone uniqueness if changed
    if (req.body.phone && req.body.phone !== builder.phone) {
      const conflict = await Builder.findOne({
        phone: req.body.phone,
        _id: { $ne: builder._id },
      });
      if (conflict) {
        return res.status(409).json({
          success: false,
          message: `Phone ${req.body.phone} is already used by another builder.`,
        });
      }
    }

    await builder.save();

    return res.status(200).json({
      success: true,
      message: "Builder updated successfully.",
      data: builder,
    });
  } catch (err) {
    console.error("[Builder] updateBuilder error:", err);
    return res.status(500).json({ success: false, message: "Failed to update builder." });
  }
};

// ── Delete Builder (soft) ─────────────────────────────────────────────────────
export const deleteBuilder = async (req, res) => {
  try {
    const builder = await Builder.findById(req.params.id);
    if (!builder) {
      return res.status(404).json({ success: false, message: "Builder not found." });
    }

    // Check if they have active properties
    const activePropertyCount = await Property.countDocuments({
      builder: builder._id,
      isApproved: true,
    });

    if (activePropertyCount > 0) {
      return res.status(400).json({
        success: false,
        message: `Cannot deactivate builder — they have ${activePropertyCount} active approved propert${activePropertyCount === 1 ? "y" : "ies"}. Disapprove properties first.`,
      });
    }

    builder.isActive = false;
    await builder.save();

    return res.status(200).json({
      success: true,
      message: "Builder deactivated successfully.",
    });
  } catch (err) {
    console.error("[Builder] deleteBuilder error:", err);
    return res.status(500).json({ success: false, message: "Failed to deactivate builder." });
  }
};
