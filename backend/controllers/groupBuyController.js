/**
 * Group Buy Controller — Phase 1 (Foundation)
 * Handles: project CRUD, join/exit flow, "My Groups" for buyers
 */
import GroupBuyProject from "../models/GroupBuyProject.js";
import GroupBuyMember from "../models/GroupBuyMember.js";
import Property from "../models/Property.js";
import Builder from "../models/Builder.js";
import Notification from "../models/Notification.js";
import mongoose from "mongoose";

// ─────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────

const buildPropertySnapshot = (property) => ({
  title: property.title,
  price: property.price,
  priceUnit: property.priceUnit,
  city: property.city || property.address?.city,
  locality: property.locality || property.address?.area,
  bhk: property.bhk,
  propertyType: property.propertyTypeName,
  image: property.images?.[0] || null,
});

// ─────────────────────────────────────────────────────────────────
// PUBLIC — List active group buy projects
// GET /api/group-buy/projects
// ─────────────────────────────────────────────────────────────────
export const listProjects = async (req, res) => {
  try {
    const { city, status = "forming", page = 1, limit = 12 } = req.query;

    const filter = { status };
    if (city) filter["propertySnapshot.city"] = { $regex: city, $options: "i" };

    const skip = (Number(page) - 1) * Number(limit);

    const [projects, total] = await Promise.all([
      GroupBuyProject.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .select("-adminNotes -createdBy")
        .lean(),
      GroupBuyProject.countDocuments(filter),
    ]);

    return res.json({
      success: true,
      data: projects,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total,
        totalPages: Math.ceil(total / Number(limit)),
      },
    });
  } catch (err) {
    console.error("[GroupBuy] listProjects error:", err.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

// ─────────────────────────────────────────────────────────────────
// PUBLIC — Get single project detail
// GET /api/group-buy/projects/:id
// ─────────────────────────────────────────────────────────────────
export const getProject = async (req, res) => {
  try {
    const project = await GroupBuyProject.findById(req.params.id)
      .select("-adminNotes -createdBy")
      .lean();

    if (!project) {
      return res.status(404).json({ success: false, message: "Group not found" });
    }

    // Attach whether current user is already a member (if logged in)
    let isMember = false;
    let memberStatus = null;
    if (req.user) {
      const membership = await GroupBuyMember.findOne({
        group: project._id,
        user: req.user._id,
      }).select("status tokenStatus dealResponse").lean();
      if (membership) {
        isMember = true;
        memberStatus = membership;
      }
    }

    return res.json({ success: true, data: { ...project, isMember, memberStatus } });
  } catch (err) {
    console.error("[GroupBuy] getProject error:", err.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

// ─────────────────────────────────────────────────────────────────
// ADMIN — Create group buy project
// POST /api/group-buy/projects
// ─────────────────────────────────────────────────────────────────
export const createProject = async (req, res) => {
  try {
    const {
      propertyId,
      minGroupSize = 3,
      maxDiscount,
      tokenAmount,
      deadlineDays = 30,
      perks = [],
      closureThreshold = 75,
      adminNotes = "",
    } = req.body;

    // Validate property exists
    const property = await Property.findById(propertyId).lean();
    if (!property) {
      return res.status(404).json({ success: false, message: "Property not found" });
    }

    // RULE: Only builder properties can have group buy projects
    if (!property.builder) {
      return res.status(400).json({
        success: false,
        message: "Only builder properties can have Group Buy projects. Assign a builder to this property first.",
      });
    }

    // Verify builder is still active
    const builder = await Builder.findById(property.builder).lean();
    if (!builder || !builder.isActive) {
      return res.status(400).json({
        success: false,
        message: "The builder linked to this property is inactive.",
      });
    }

    // Prevent duplicate active group for same property
    const existing = await GroupBuyProject.findOne({
      property: propertyId,
      status: { $in: ["forming", "locked", "negotiating", "terms_shared"] },
    }).lean();

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "An active Group Buy already exists for this property",
      });
    }

    // Calculate deadline
    const formingDeadline = new Date();
    formingDeadline.setDate(formingDeadline.getDate() + Number(deadlineDays));

    const project = await GroupBuyProject.create({
      property: propertyId,
      builder: property.builder,          // Link to Builder model, not User
      createdBy: req.admin._id,
      config: {
        minGroupSize: Number(minGroupSize),
        maxDiscount: maxDiscount ? Number(maxDiscount) : undefined,
        tokenAmount: Number(tokenAmount),
        deadlineDays: Number(deadlineDays),
        perks,
        closureThreshold: Number(closureThreshold),
      },
      formingDeadline,
      propertySnapshot: buildPropertySnapshot(property),
      adminNotes,
    });

    // Enable group buy flag on property
    await Property.findByIdAndUpdate(propertyId, {
      groupBuyEnabled: true,
      groupBuyProject: project._id,
    });

    console.log(`[GroupBuy] Project created: ${project._id} for property ${propertyId}`);

    return res.status(201).json({ success: true, data: project });
  } catch (err) {
    console.error("[GroupBuy] createProject error:", err.message);
    if (err.name === "ValidationError") {
      return res.status(400).json({ success: false, message: err.message });
    }
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

// ─────────────────────────────────────────────────────────────────
// ADMIN — Update project config
// PUT /api/group-buy/projects/:id
// ─────────────────────────────────────────────────────────────────
export const updateProject = async (req, res) => {
  try {
    const project = await GroupBuyProject.findById(req.params.id);
    if (!project) {
      return res.status(404).json({ success: false, message: "Group not found" });
    }

    // Can only edit while forming
    if (project.status !== "forming") {
      return res.status(400).json({
        success: false,
        message: `Cannot edit a group in "${project.status}" status`,
      });
    }

    const allowed = [
      "minGroupSize", "maxDiscount", "tokenAmount",
      "deadlineDays", "perks", "closureThreshold",
    ];

    allowed.forEach((key) => {
      if (req.body[key] !== undefined) {
        project.config[key] = req.body[key];
      }
    });

    if (req.body.adminNotes !== undefined) project.adminNotes = req.body.adminNotes;

    // Recalculate deadline if deadlineDays changed
    if (req.body.deadlineDays !== undefined) {
      const deadline = new Date(project.createdAt);
      deadline.setDate(deadline.getDate() + Number(req.body.deadlineDays));
      project.formingDeadline = deadline;
    }

    await project.save();
    return res.json({ success: true, data: project });
  } catch (err) {
    console.error("[GroupBuy] updateProject error:", err.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

// ─────────────────────────────────────────────────────────────────
// USER — Join a group buy project
// POST /api/group-buy/projects/:id/join
// ─────────────────────────────────────────────────────────────────
export const joinGroup = async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const project = await GroupBuyProject.findById(req.params.id).session(session);
    if (!project) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: "Group not found" });
    }

    if (project.status !== "forming") {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: "This group is no longer accepting members",
      });
    }

    if (new Date() > project.formingDeadline) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: "This group's deadline has passed",
      });
    }

    // Check not already a member
    const existing = await GroupBuyMember.findOne({
      group: project._id,
      user: req.user._id,
    }).session(session);

    if (existing) {
      await session.abortTransaction();
      return res.status(409).json({
        success: false,
        message: "You are already a member of this group",
      });
    }

    const { preferredUnitType, budgetRange } = req.body;

    // Create membership
    const member = await GroupBuyMember.create(
      [{
        group: project._id,
        user: req.user._id,
        preferredUnitType: preferredUnitType?.trim(),
        budgetRange: budgetRange || {},
        tokenAmount: project.config.tokenAmount,
        userSnapshot: {
          name: req.user.name,
          email: req.user.email,
          phone: req.user.phone || "",
        },
      }],
      { session }
    );

    // Increment member count
    project.memberCount += 1;
    await project.save({ session });

    await session.commitTransaction();

    // Notify user (outside transaction — non-critical)
    await Notification.create({
      user: req.user._id,
      title: "You've Joined a Group Buy!",
      message: `You've successfully joined the group for "${project.propertySnapshot.title}". Pay your token of ₹${project.config.tokenAmount.toLocaleString("en-IN")} to confirm your spot.`,
      type: "group_buy_joined",
      data: {
        groupId: project._id,
        actionUrl: `/group-buy/${project._id}`,
        actionText: "View Group",
      },
    });

    console.log(`[GroupBuy] User ${req.user._id} joined group ${project._id}`);

    return res.status(201).json({
      success: true,
      message: "Successfully joined the group",
      data: member[0],
    });
  } catch (err) {
    await session.abortTransaction();
    if (err.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "You are already a member of this group",
      });
    }
    console.error("[GroupBuy] joinGroup error:", err.message);
    return res.status(500).json({ success: false, message: "Server error" });
  } finally {
    session.endSession();
  }
};

// ─────────────────────────────────────────────────────────────────
// USER — Exit a group buy project
// POST /api/group-buy/projects/:id/exit
// ─────────────────────────────────────────────────────────────────
export const exitGroup = async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const project = await GroupBuyProject.findById(req.params.id).session(session);
    if (!project) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: "Group not found" });
    }

    // Can only exit before deal is closed/terms shared
    if (["closed", "expired", "cancelled"].includes(project.status)) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: "Cannot exit a group that is already closed or expired",
      });
    }

    const member = await GroupBuyMember.findOne({
      group: project._id,
      user: req.user._id,
      status: "active",
    }).session(session);

    if (!member) {
      await session.abortTransaction();
      return res.status(404).json({
        success: false,
        message: "Active membership not found",
      });
    }

    // Mark as exited
    member.status = "exited";
    member.exitReason = req.body.reason?.trim() || "User requested exit";
    member.exitedAt = new Date();
    await member.save({ session });

    // Decrement member count
    project.memberCount = Math.max(0, project.memberCount - 1);
    if (member.tokenStatus === "paid") {
      project.paidMemberCount = Math.max(0, project.paidMemberCount - 1);
    }
    await project.save({ session });

    await session.commitTransaction();

    // Notify user about refund (if applicable)
    if (member.tokenStatus === "paid") {
      await Notification.create({
        user: req.user._id,
        title: "Exit Confirmed — Refund Initiated",
        message: `You've exited the group for "${project.propertySnapshot.title}". Your token refund of ₹${project.config.tokenAmount.toLocaleString("en-IN")} will be processed within 5–7 business days.`,
        type: "group_buy_exited",
        data: { groupId: project._id },
      });
    }

    console.log(`[GroupBuy] User ${req.user._id} exited group ${project._id}`);

    return res.json({
      success: true,
      message: "Successfully exited the group",
      refundPending: member.tokenStatus === "paid",
    });
  } catch (err) {
    await session.abortTransaction();
    console.error("[GroupBuy] exitGroup error:", err.message);
    return res.status(500).json({ success: false, message: "Server error" });
  } finally {
    session.endSession();
  }
};

// ─────────────────────────────────────────────────────────────────
// USER — Get current user's group memberships
// GET /api/group-buy/my-groups
// ─────────────────────────────────────────────────────────────────
export const getMyGroups = async (req, res) => {
  try {
    const memberships = await GroupBuyMember.find({ user: req.user._id })
      .populate({
        path: "group",
        select: "-adminNotes -createdBy",
      })
      .sort({ createdAt: -1 })
      .lean();

    return res.json({ success: true, data: memberships });
  } catch (err) {
    console.error("[GroupBuy] getMyGroups error:", err.message);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};
