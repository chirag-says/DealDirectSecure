/**
 * Campaign Controller — DealDirect
 * Handles GroupBuyCampaign lifecycle and CampaignMember management.
 *
 * Admin: create, update, verify payments, list pending payments.
 * User: join campaign, exit campaign, upload payment proof.
 *
 * No negotiations. Admin sets everything upfront (discount, perks, min buyers).
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

// ── Create Campaign (Admin) ───────────────────────────────────────────────────
export const createCampaign = async (req, res) => {
  try {
    const body = req.body;

    const unitType = await UnitType.findById(body.unitTypeId).lean();
    if (!unitType) {
      return res.status(404).json({ success: false, message: "Unit type not found." });
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
        maxBuyers: body.maxBuyers ? Number(body.maxBuyers) : null,
      },
      duration: {
        startDate: body.startDate,
        endDate: body.endDate,
      },
      discountPerBuyer: Number(body.discountPerBuyer),
      perks: body.perks
        ? (typeof body.perks === "string" ? body.perks.split(",").map(p => p.trim()).filter(Boolean) : body.perks)
        : [],
      adminNotes: body.adminNotes || "",
    });

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

// ── Update Campaign (Admin) ───────────────────────────────────────────────────
export const updateCampaign = async (req, res) => {
  try {
    const campaign = await GroupBuyCampaign.findById(req.params.id);
    if (!campaign) {
      return res.status(404).json({ success: false, message: "Campaign not found." });
    }

    const body = req.body;

    // Update allowed fields
    if (body.name !== undefined) campaign.basics.name = body.name;
    if (body.description !== undefined) campaign.basics.description = body.description;
    if (body.minBuyers !== undefined) campaign.buyerTargets.minBuyers = Number(body.minBuyers);
    if (body.maxBuyers !== undefined) campaign.buyerTargets.maxBuyers = body.maxBuyers ? Number(body.maxBuyers) : null;
    if (body.startDate !== undefined) campaign.duration.startDate = body.startDate;
    if (body.endDate !== undefined) campaign.duration.endDate = body.endDate;
    if (body.discountPerBuyer !== undefined) campaign.discountPerBuyer = Number(body.discountPerBuyer);
    if (body.status !== undefined) campaign.status = body.status;
    if (body.adminNotes !== undefined) campaign.adminNotes = body.adminNotes;
    if (body.perks !== undefined) {
      campaign.perks = typeof body.perks === "string"
        ? body.perks.split(",").map(p => p.trim()).filter(Boolean)
        : body.perks;
    }

    await campaign.save();

    return res.status(200).json({ success: true, message: "Campaign updated.", data: campaign });
  } catch (error) {
    console.error("[campaignController.updateCampaign]", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};

// ── Join Campaign (User) ──────────────────────────────────────────────────────
export const joinCampaign = async (req, res) => {
  try {
    // Build atomic update filter
    const filter = {
      _id: req.params.id,
      status: "active",
      "duration.endDate": { $gt: new Date() },
    };

    // If maxBuyers is set, enforce it atomically
    const raw = await GroupBuyCampaign.findById(req.params.id).lean();
    if (!raw) return res.status(404).json({ success: false, message: "Campaign not found." });
    if (raw.status !== "active") return res.status(400).json({ success: false, message: "Campaign is not active." });
    if (new Date() > new Date(raw.duration.endDate)) return res.status(400).json({ success: false, message: "Campaign has ended." });

    if (raw.buyerTargets.maxBuyers) {
      filter.$expr = { $lt: ["$memberCount", "$buyerTargets.maxBuyers"] };
    }

    const campaign = await GroupBuyCampaign.findOneAndUpdate(
      filter,
      { $inc: { memberCount: 1 } },
      { new: true }
    ).lean();

    if (!campaign) {
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
        campaignName: campaign.basics.name,
        discountPerBuyer: campaign.discountPerBuyer,
        perks: campaign.perks,
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

    await member.save(); // post-save hook syncs paidMemberCount

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
