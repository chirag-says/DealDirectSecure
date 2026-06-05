/**
 * TransactionVerification Model — DealDirect
 * Tracks property sale/rental closures pending admin verification.
 * Once approved, rewards are dispensed to both owner and buyer.
 */
import mongoose from "mongoose";

const transactionVerificationSchema = new mongoose.Schema(
  {
    property: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Property",
      required: true,
    },
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    buyer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    // "sold" or "rented"
    closingType: {
      type: String,
      enum: ["sold", "rented"],
      required: true,
    },
    // Cloudinary URLs for uploaded proof documents (PDF/images)
    documentUrls: {
      type: [String],
      default: [],
      validate: {
        validator: (v) => v.length > 0,
        message: "At least one proof document is required.",
      },
    },
    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },
    adminNotes: {
      type: String,
      default: "",
    },
    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      default: null,
    },
    reviewedAt: {
      type: Date,
      default: null,
    },
    // Reward tracking — filled when each party claims
    ownerReward: {
      points: { type: Number, default: 0 },
      cashValue: { type: Number, default: 0 },
    },
    buyerReward: {
      points: { type: Number, default: 0 },
      cashValue: { type: Number, default: 0 },
    },
    ownerClaimed: { type: Boolean, default: false },
    buyerClaimed: { type: Boolean, default: false },
  },
  { timestamps: true }
);

// Indexes
transactionVerificationSchema.index({ status: 1 });
transactionVerificationSchema.index({ property: 1 });
transactionVerificationSchema.index({ owner: 1 });
transactionVerificationSchema.index({ buyer: 1 });

const TransactionVerification = mongoose.model(
  "TransactionVerification",
  transactionVerificationSchema
);

export default TransactionVerification;
