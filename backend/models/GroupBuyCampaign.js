/**
 * GroupBuyCampaign Model — DealDirect
 * 
 * DealDirect's core USP — group buying for a specific UnitType within a Project.
 * Admin creates the campaign with pre-agreed terms from the builder.
 * No negotiation. Admin sets discount, min buyers, perks — all finalized upfront.
 *
 * Flow:
 *   1. Builder agrees to group discount terms with DealDirect admin
 *   2. Admin creates campaign on a UnitType (e.g., 2BHK in Project X)
 *   3. Users see Group Buy banner on the project page, join & pay token
 *   4. Once min buyers threshold met → all buyers get the flat ₹ discount
 *
 * Token payments are collected by DealDirect admin via UPI/Netbanking.
 * No payment gateway. Admin verifies manually via CampaignMember.
 *
 * Hierarchy: Builder → Project → UnitType → GroupBuyCampaign
 */
import mongoose from "mongoose";

const groupBuyCampaignSchema = new mongoose.Schema(
  {
    unitType: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "UnitType",
      required: [true, "UnitType reference is required"],
    },
    // Denormalized for efficient queries (e.g., show all campaigns for a project)
    project: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Project",
      required: [true, "Project reference is required"],
    },
    builder: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Builder",
      required: [true, "Builder reference is required"],
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      required: [true, "Admin reference is required"],
    },

    // ── Campaign Basics ───────────────────────────────────────────────────────
    basics: {
      name: {
        type: String,
        required: [true, "Campaign name is required"],
        trim: true,
        maxlength: [200, "Name cannot exceed 200 characters"],
      },
      description: {
        type: String,
        trim: true,
        maxlength: [2000, "Description cannot exceed 2000 characters"],
      },
    },

    // ── Buyer Targets ─────────────────────────────────────────────────────────
    buyerTargets: {
      minBuyers: {
        type: Number,
        required: [true, "Minimum buyers is required"],
        min: [2, "Minimum 2 buyers required for a group buy"],
      },
      maxBuyers: {
        type: Number,
        default: null, // null = unlimited
      },
    },

    // ── Duration ──────────────────────────────────────────────────────────────
    duration: {
      startDate: { type: Date, required: [true, "Start date is required"] },
      endDate: { type: Date, required: [true, "End date is required"] },
    },

    // ── Discount ──────────────────────────────────────────────────────────────
    // Flat ₹ discount per buyer (e.g., 10000000 = ₹1 Cr off per buyer)
    // NOT percentage-based. Builder pre-agrees to this amount.
    discountPerBuyer: {
      type: Number,
      required: [true, "Discount per buyer is required"],
      min: [1, "Discount must be at least ₹1"],
    },

    // ── Perks ─────────────────────────────────────────────────────────────────
    // Additional benefits offered by DealDirect or builder
    // e.g., ["DealDirect covers GST", "Free stamp duty", "Free parking"]
    perks: {
      type: [String],
      default: [],
    },


    // ── Status & Counters ─────────────────────────────────────────────────────
    status: {
      type: String,
      enum: ["active", "paused", "completed", "expired", "cancelled"],
      default: "active",
    },
    memberCount: { type: Number, default: 0, min: 0 },
    paidMemberCount: { type: Number, default: 0, min: 0 },

    // ── Admin Notes (internal, not visible to buyers) ─────────────────────────
    adminNotes: {
      type: String,
      trim: true,
      maxlength: [2000, "Notes cannot exceed 2000 characters"],
      default: "",
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ── Indexes ───────────────────────────────────────────────────────────────────
groupBuyCampaignSchema.index({ unitType: 1, status: 1 });
groupBuyCampaignSchema.index({ project: 1, status: 1 }); // All campaigns for a project
groupBuyCampaignSchema.index({ builder: 1, status: 1 });
groupBuyCampaignSchema.index({ "duration.endDate": 1 }); // For expiry checks
groupBuyCampaignSchema.index({ createdAt: -1 });

const GroupBuyCampaign = mongoose.model("GroupBuyCampaign", groupBuyCampaignSchema);
export default GroupBuyCampaign;
