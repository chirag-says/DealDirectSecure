/**
 * RedemptionRequest Model — DealDirect Rewards
 * Tracks voucher / cash / listing-boost redemptions.
 */
import mongoose from "mongoose";

const redemptionRequestSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    rewardType: {
      type: String,
      enum: [
        "voucher",
        "listing_boost",
        "premium_listing",
        "cash_transfer",
        "valuation_report",
        "priority_support",
        "rewardport_product",
      ],
      required: true,
    },
    rewardName: {
      type: String,
      required: true,
      trim: true,
    },
    pointsSpent: {
      type: Number,
      required: true,
      min: 1,
    },
    status: {
      type: String,
      enum: ["pending", "processing", "fulfilled", "failed", "cancelled"],
      default: "pending",
    },

    // Voucher / product delivery
    voucherCode: {
      type: String,
      default: null,
    },
    deliveredAt: {
      type: Date,
      default: null,
    },

    // RewardPort integration
    rewardPortOrderId: {
      type: String,
      default: null,
    },
    rewardPortProductId: {
      type: String,
      default: null,
    },

    // Cash transfer
    bankDetails: {
      accountName: { type: String },
      accountNumber: { type: String },
      ifscCode: { type: String },
      upiId: { type: String },
    },

    // Admin notes / failure reason
    adminNotes: {
      type: String,
      default: "",
    },
    failureReason: {
      type: String,
      default: "",
    },

    // Generic metadata
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
redemptionRequestSchema.index({ user: 1, createdAt: -1 });
redemptionRequestSchema.index({ status: 1 });

const RedemptionRequest = mongoose.model("RedemptionRequest", redemptionRequestSchema);
export default RedemptionRequest;
