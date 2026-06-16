/**
 * CampaignMember Model — DealDirect
 * Records a user's participation in a GroupBuyCampaign.
 *
 * Payment flow (admin-mediated, no payment gateway):
 * 1. User joins → CampaignMember created (tokenStatus: pending)
 * 2. User pays DealDirect's UPI/bank account
 * 3. User uploads payment proof screenshot
 * 4. Admin verifies in admin panel → sets tokenStatus: paid
 * 5. Campaign memberCount and paidMemberCount increment
 * 6. Milestone checks run post-verification
 *
 * Separate from GroupBuyMember — no negotiation lifecycle states.
 */
import mongoose from "mongoose";
import GroupBuyCampaign from "./GroupBuyCampaign.js";

const campaignMemberSchema = new mongoose.Schema(
  {
    campaign: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "GroupBuyCampaign",
      required: [true, "Campaign reference is required"],
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User reference is required"],
    },

    // ── Membership Status ─────────────────────────────────────────────────────
    status: {
      type: String,
      enum: ["active", "exited"],
      default: "active",
    },

    // ── Token Payment (DealDirect collects via UPI/Netbanking) ────────────────
    tokenAmount: { type: Number, min: 0 },
    tokenStatus: {
      type: String,
      enum: ["pending", "paid", "refunded"],
      default: "pending",
    },
    tokenPaidAt: { type: Date },
    paymentReference: { type: String, trim: true }, // UPI txn ID or bank ref no.
    paymentProofUrl: { type: String, trim: true },  // Screenshot uploaded by user
    paymentRecordedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
    }, // Admin who verified the payment

    // ── User Snapshot (preserve data if user account changes) ─────────────────
    userSnapshot: {
      name: { type: String, trim: true },
      email: { type: String, trim: true },
      phone: { type: String, trim: true },
    },

    // ── Exit Tracking ─────────────────────────────────────────────────────────
    exitReason: { type: String, trim: true },
    exitedAt: { type: Date },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ── Post-save: Sync campaign counters and check milestones ────────────────────
campaignMemberSchema.post("save", async function (doc) {
  try {
    const campaign = await GroupBuyCampaign.findById(doc.campaign);
    if (!campaign) return;

    // Recount from DB to stay consistent (avoids race conditions)
    const CampaignMember = mongoose.model("CampaignMember");
    const [memberCount, paidMemberCount] = await Promise.all([
      CampaignMember.countDocuments({ campaign: doc.campaign, status: "active" }),
      CampaignMember.countDocuments({ campaign: doc.campaign, status: "active", tokenStatus: "paid" }),
    ]);

    campaign.memberCount = memberCount;
    campaign.paidMemberCount = paidMemberCount;

    // Check milestones against active member count
    let milestonesUpdated = false;
    campaign.milestones.forEach((m) => {
      if (!m.isAchieved && memberCount >= m.buyerCount) {
        m.isAchieved = true;
        milestonesUpdated = true;
      }
    });

    await campaign.save();
  } catch (err) {
    // Non-fatal — log but don't crash the request
    console.error("[CampaignMember] Post-save hook error:", err.message);
  }
});

// ── Indexes ───────────────────────────────────────────────────────────────────
// Unique: one user per campaign
campaignMemberSchema.index({ campaign: 1, user: 1 }, { unique: true });
campaignMemberSchema.index({ user: 1 });
campaignMemberSchema.index({ campaign: 1, status: 1 });
campaignMemberSchema.index({ campaign: 1, tokenStatus: 1 });

const CampaignMember = mongoose.model("CampaignMember", campaignMemberSchema);
export default CampaignMember;
