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

// At most one PENDING verification per property, enforced by the database.
//
// closeDeal checks for an existing pending verification and then creates one.
// Between those two statements a second request can pass the same check, so an
// owner submitting twice (or naming two different buyers concurrently) produced
// two pending verifications for one property. If an admin approved both, two
// people were told they had bought the same unit and the owner collected two
// payouts — each verification tracks ownerClaimed separately.
//
// Partial, so it constrains only pending rows: a property may accumulate any
// number of approved or rejected verifications over its life.
//
// The key is { property, status } rather than { property } alone because a
// plain property_1 index already exists, and MongoDB will not build a second
// index with an identical key pattern — it fails silently at boot, leaving the
// constraint declared but not enforced. Within the partial set every document
// has status:"pending", so uniqueness on the pair reduces to uniqueness on
// property, which is the rule we want.
//
// Verified before adding (2026-08-16): 7 documents, all approved, zero
// duplicate pending pairs — this builds without a data migration.
transactionVerificationSchema.index(
  { property: 1, status: 1 },
  {
    unique: true,
    partialFilterExpression: { status: "pending" },
    name: "uniq_pending_verification_per_property",
  }
);

const TransactionVerification = mongoose.model(
  "TransactionVerification",
  transactionVerificationSchema
);

export default TransactionVerification;
