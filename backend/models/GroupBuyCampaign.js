/**
 * GroupBuyCampaign Model — DealDirect
 * DealDirect's core USP — milestone-based group buying for a specific UnitType.
 * Campaign pricing uses fixed tiers, NOT negotiation (that's GroupBuyProject's domain).
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
    // Denormalized for efficient queries
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
        min: [3, "Minimum 3 buyers required for a group buy"],
      },
      maxBuyers: {
        type: Number,
        required: [true, "Maximum buyers is required"],
      },
    },

    // ── Duration ──────────────────────────────────────────────────────────────
    duration: {
      startDate: { type: Date, required: [true, "Start date is required"] },
      endDate: { type: Date, required: [true, "End date is required"] },
    },

    // ── Pricing ───────────────────────────────────────────────────────────────
    pricing: {
      regularPrice: {
        type: Number,
        required: [true, "Regular price is required"],
        min: 0,
      },
      groupBuyPrice: {
        type: Number,
        required: [true, "Group buy price is required"],
        min: 0,
      },
      savings: { type: Number, min: 0 }, // Auto-calculated
    },

    // ── Token Amount (collected by DealDirect admin via UPI/Netbanking) ────────
    tokenAmount: {
      type: Number,
      required: [true, "Token amount is required"],
      min: [1, "Token amount must be at least ₹1"],
    },

    // ── Inventory Allocation ──────────────────────────────────────────────────
    inventoryAllocation: {
      unitsReserved: {
        type: Number,
        required: [true, "Units reserved is required"],
        min: [1, "At least 1 unit must be reserved"],
      },
    },

    // ── Milestone Benefits ────────────────────────────────────────────────────
    // e.g. "5 buyers joined → Free Modular Kitchen"
    milestones: [
      {
        buyerCount: {
          type: Number,
          required: true,
          min: 1,
        },
        benefit: {
          type: String,
          required: true,
          trim: true,
        },
        isAchieved: { type: Boolean, default: false },
      },
    ],

    // ── Status & Counters ─────────────────────────────────────────────────────
    status: {
      type: String,
      enum: ["active", "paused", "completed", "expired", "cancelled"],
      default: "active",
    },
    memberCount: { type: Number, default: 0, min: 0 },
    paidMemberCount: { type: Number, default: 0, min: 0 },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ── Pre-save: Auto-calculate savings ─────────────────────────────────────────
groupBuyCampaignSchema.pre("save", function (next) {
  if (this.pricing?.regularPrice >= 0 && this.pricing?.groupBuyPrice >= 0) {
    this.pricing.savings = Math.max(
      0,
      this.pricing.regularPrice - this.pricing.groupBuyPrice
    );
  }
  next();
});

// ── Indexes ───────────────────────────────────────────────────────────────────
groupBuyCampaignSchema.index({ unitType: 1, status: 1 });
groupBuyCampaignSchema.index({ project: 1 });
groupBuyCampaignSchema.index({ builder: 1, status: 1 });
groupBuyCampaignSchema.index({ "duration.endDate": 1 });
groupBuyCampaignSchema.index({ createdAt: -1 });

const GroupBuyCampaign = mongoose.model("GroupBuyCampaign", groupBuyCampaignSchema);
export default GroupBuyCampaign;
