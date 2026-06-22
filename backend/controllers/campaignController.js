/**
 * Campaign Controller — DealDirect
 * Handles GroupBuyCampaign lifecycle and CampaignMember management.
 *
 * Admin: create, update, verify payments, list pending payments.
 * User: join campaign, exit campaign, upload payment proof.
 */
import GroupBuyCampaign from "../models/GroupBuyCampaign.js";
import CampaignMember from "../models/CampaignMember.js";
import UnitType from "../models/UnitType.js";
import User from "../models/userModel.js";
import { cloudinary } from "../middleware/upload.js";
import { Readable } from "stream";

// ── Helper ────────────────────────────────────────────────────────────────────
const uploadProof = (buffer, campaignId) =>
  new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: `dealdirect/payment-proofs/${campaignId}` },
      (err, result) => (err ? reject(err) : resolve(result.secure_url))
    );
    Readable.from(buffer).pipe(stream);
  });

// ── Create Campaign ───────────────────────────────────────────────────────────
export const createCampaign = async (req, res) => {
  try {
    const body = req.body;

    const unitType = await UnitType.findById(body.unitTypeId).lean();
    if (!unitType) {
      return res.status(404).json({ success: false, message: "Unit type not found." });
    }

    // Validate inventory allocation doesn't exceed available
    const unitsReserved = Number(body.unitsReserved);
    if (unitsReserved > (unitType.inventory?.availableUnits || 0)) {
      return res.status(400).json({
        success: false,
        message: `Cannot reserve ${unitsReserved} units. Only ${unitType.inventory?.availableUnits} available.`,
      });
    }

    // Validate pricing
    if (Number(body.groupBuyPrice) >= Number(body.regularPrice)) {
      return res.status(400).json({
        success: false,
        message: "Group buy price must be less than regular price.",
      });
    }

    const campaign = await GroupBuyCampaign.create({
      unitType: body.unitTypeId,
      project: unitType.project,
      builder: unitType.builder,
      createdBy: req.admin._id,
      basics: {
        name: body.name,
        description: body.description,
      },
      buyerTargets: {
        minBuyers: Number(body.minBuyers),
        maxBuyers: Number(body.maxBuyers),
      },
      duration: {
        startDate: body.startDate,
        endDate: body.endDate,
      },
      pricing: {
        regularPrice: Number(body.regularPrice),
        groupBuyPrice: Number(body.groupBuyPrice),
        // savings auto-calc in pre-save
      },
      tokenAmount: Number(body.tokenAmount),
      inventoryAllocation: { unitsReserved },
      milestones: body.milestones ? JSON.parse(body.milestones) : [],
    });

    // Increment unit type's active campaign count
    await UnitType.findByIdAndUpdate(body.unitTypeId, { $inc: { activeCampaignCount: 1 } });

    return res.status(201).json({
      success: true,
      message: "Campaign created successfully.",
      data: campaign,
    });
  } catch (error) {
    console.error("[campaignController.createCampaign]", error);
    if (error.name === "ValidationError") {
      const messages = Object.values(error.errors).map((e) => e.message);
      return res.status(400).json({ success: false, message: messages.join(", ") });
    }
    return res.status(500).json({ success: false, message: "Server error creating campaign." });
  }
};

// ── Get Single Campaign ───────────────────────────────────────────────────────
export const getCampaign = async (req, res) => {
  try {
    const campaign = await GroupBuyCampaign.findById(req.params.id)
      .populate("unitType", "config area pricing")
      .populate("project", "basics.name location.city basics.status")
      .populate("builder", "name company logoUrl")
      .lean();

    if (!campaign) {
      return res.status(404).json({ success: false, message: "Campaign not found." });
    }

    return res.status(200).json({ success: true, data: campaign });
  } catch (error) {
    console.error("[campaignController.getCampaign]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── List Campaigns by UnitType ────────────────────────────────────────────────
export const listByUnitType = async (req, res) => {
  try {
    const filter = { unitType: req.params.unitTypeId };
    if (req.query.status) filter.status = req.query.status;

    const campaigns = await GroupBuyCampaign.find(filter).sort({ createdAt: -1 }).lean();

    return res.status(200).json({ success: true, data: campaigns });
  } catch (error) {
    console.error("[campaignController.listByUnitType]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── List Campaigns by Project ─────────────────────────────────────────────────
export const listByProject = async (req, res) => {
  try {
    const filter = { project: req.params.projectId };
    if (req.query.status) filter.status = req.query.status;

    const campaigns = await GroupBuyCampaign.find(filter)
      .populate("unitType", "config.name config.bedrooms pricing.effectivePrice")
      .sort({ createdAt: -1 })
      .lean();

    return res.status(200).json({ success: true, data: campaigns });
  } catch (error) {
    console.error("[campaignController.listByProject]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── Update Campaign ───────────────────────────────────────────────────────────
export const updateCampaign = async (req, res) => {
  try {
    const campaign = await GroupBuyCampaign.findById(req.params.id);
    if (!campaign) {
      return res.status(404).json({ success: false, message: "Campaign not found." });
    }

    const allowed = ["basics", "buyerTargets", "duration", "pricing", "milestones", "status"];
    allowed.forEach((key) => {
      if (req.body[key] !== undefined) {
        try {
          campaign[key] = typeof req.body[key] === "string"
            ? JSON.parse(req.body[key])
            : req.body[key];
        } catch { /* leave as-is */ }
      }
    });

    if (req.body.tokenAmount !== undefined) {
      campaign.tokenAmount = Number(req.body.tokenAmount);
    }

    await campaign.save(); // pre-save recalculates savings

    return res.status(200).json({ success: true, message: "Campaign updated.", data: campaign });
  } catch (error) {
    console.error("[campaignController.updateCampaign]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── Join Campaign (User) ──────────────────────────────────────────────────────
export const joinCampaign = async (req, res) => {
  try {
    // H11 FIX: Atomic increment with condition to prevent exceeding maxBuyers.
    // Two concurrent joins both reading memberCount=9 (max=10) would both pass
    // a simple check. findOneAndUpdate with $lt ensures only one succeeds.
    const campaign = await GroupBuyCampaign.findOneAndUpdate(
      {
        _id: req.params.id,
        status: "active",
        $expr: { $lt: ["$memberCount", "$buyerTargets.maxBuyers"] },
        "duration.endDate": { $gt: new Date() },
      },
      { $inc: { memberCount: 1 } },
      { new: true }
    ).lean();

    if (!campaign) {
      // Could be: not found, not active, full, or ended — check which
      const raw = await GroupBuyCampaign.findById(req.params.id).lean();
      if (!raw) return res.status(404).json({ success: false, message: "Campaign not found." });
      if (raw.status !== "active") return res.status(400).json({ success: false, message: "Campaign is not active." });
      if (new Date() > new Date(raw.duration.endDate)) return res.status(400).json({ success: false, message: "Campaign has ended." });
      return res.status(400).json({ success: false, message: "Campaign is full." });
    }

    // Get user snapshot
    const user = await User.findById(req.user._id).select("name email phone").lean();

    // Create member record
    let member;
    try {
      member = await CampaignMember.create({
        campaign: campaign._id,
        user: req.user._id,
        tokenAmount: campaign.tokenAmount,
        tokenStatus: "pending",
        userSnapshot: {
          name: user?.name,
          email: user?.email,
          phone: user?.phone,
        },
      });
    } catch (createError) {
      // If member creation fails (e.g., duplicate), roll back the memberCount increment
      await GroupBuyCampaign.findByIdAndUpdate(campaign._id, { $inc: { memberCount: -1 } });

      if (createError.code === 11000) {
        return res.status(409).json({ success: false, message: "You have already joined this campaign." });
      }
      throw createError;
    }

    return res.status(201).json({
      success: true,
      message: "You have joined the campaign. Please pay the token amount to confirm your spot.",
      data: {
        memberId: member._id,
        tokenAmount: campaign.tokenAmount,
        campaignName: campaign.basics.name,
      },
    });
  } catch (error) {
    console.error("[campaignController.joinCampaign]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── Upload Payment Proof (User) ───────────────────────────────────────────────
export const uploadPaymentProof = async (req, res) => {
  try {
    const member = await CampaignMember.findOne({
      campaign: req.params.id,
      user: req.user._id,
    });

    if (!member) {
      return res.status(404).json({ success: false, message: "You are not a member of this campaign." });
    }
    if (member.tokenStatus === "paid") {
      return res.status(400).json({ success: false, message: "Payment already verified." });
    }

    let paymentProofUrl = member.paymentProofUrl;
    if (req.file) {
      paymentProofUrl = await uploadProof(req.file.buffer, req.params.id);
    }

    member.paymentReference = req.body.paymentReference || member.paymentReference;
    member.paymentProofUrl = paymentProofUrl;
    await member.save();

    return res.status(200).json({
      success: true,
      message: "Payment proof submitted. Admin will verify shortly.",
    });
  } catch (error) {
    console.error("[campaignController.uploadPaymentProof]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── Verify Payment (Admin) ────────────────────────────────────────────────────
export const verifyPayment = async (req, res) => {
  try {
    const member = await CampaignMember.findById(req.params.memberId);
    if (!member) {
      return res.status(404).json({ success: false, message: "Campaign member not found." });
    }
    if (member.tokenStatus === "paid") {
      return res.status(400).json({ success: false, message: "Payment already verified." });
    }

    member.tokenStatus = "paid";
    member.tokenPaidAt = new Date();
    member.paymentRecordedBy = req.admin._id;
    if (req.body.paymentReference) {
      member.paymentReference = req.body.paymentReference;
    }

    await member.save(); // post-save hook syncs paidMemberCount + milestone check

    return res.status(200).json({
      success: true,
      message: "Payment verified. Member confirmed.",
      data: member,
    });
  } catch (error) {
    console.error("[campaignController.verifyPayment]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── List Pending Payments (Admin) ─────────────────────────────────────────────
export const listPendingPayments = async (req, res) => {
  try {
    const members = await CampaignMember.find({
      campaign: req.params.id,
      status: "active",
      tokenStatus: "pending",
    })
      .populate("user", "name email phone")
      .sort({ createdAt: 1 })
      .lean();

    return res.status(200).json({ success: true, data: members });
  } catch (error) {
    console.error("[campaignController.listPendingPayments]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── Exit Campaign (User) ──────────────────────────────────────────────────────
export const exitCampaign = async (req, res) => {
  try {
    const member = await CampaignMember.findOne({
      campaign: req.params.id,
      user: req.user._id,
      status: "active",
    });

    if (!member) {
      return res.status(404).json({ success: false, message: "Active membership not found." });
    }

    member.status = "exited";
    member.exitReason = req.body.reason || "";
    member.exitedAt = new Date();

    await member.save(); // post-save hook decrements memberCount

    return res.status(200).json({
      success: true,
      message: "You have exited the campaign. Refund (if applicable) will be processed manually.",
    });
  } catch (error) {
    console.error("[campaignController.exitCampaign]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── List Campaign Members (Admin) ─────────────────────────────────────────────
export const listCampaignMembers = async (req, res) => {
  try {
    const { status, tokenStatus, page = 1, limit = 50 } = req.query;
    const filter = { campaign: req.params.id };
    if (status) filter.status = status;
    if (tokenStatus) filter.tokenStatus = tokenStatus;

    const skip = (Number(page) - 1) * Number(limit);

    const [members, total] = await Promise.all([
      CampaignMember.find(filter)
        .populate("user", "name email phone")
        .populate("paymentRecordedBy", "name")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .lean(),
      CampaignMember.countDocuments(filter),
    ]);

    return res.status(200).json({
      success: true,
      data: members,
      pagination: { total, page: Number(page), pages: Math.ceil(total / Number(limit)) },
    });
  } catch (error) {
    console.error("[campaignController.listCampaignMembers]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};
