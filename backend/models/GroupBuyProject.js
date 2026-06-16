/**
 * GroupBuyProject Model — DealDirect Group Buying
 *
 * Represents one group buy consortium tied to a specific property/project.
 * Admin creates this, buyers join it, admin negotiates on their behalf.
 *
 * Status lifecycle:
 *   forming → locked → negotiating → terms_shared → closed
 *                                                  → expired (deadline passed, < minGroupSize)
 *                                                  → cancelled (admin cancelled)
 */
import mongoose from "mongoose";

const groupBuyProjectSchema = new mongoose.Schema(
  {
    // Which property this group is buying
    property: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Property",
      required: [true, "Property is required"],
    },

    // The builder/owner of the property
    builder: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "Builder is required"],
    },

    // Created by which admin
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      required: true,
    },

    // ── Configuration (set at creation, editable until locked) ──────────────
    config: {
      minGroupSize: {
        type: Number,
        default: 3,
        min: [3, "Minimum group size is 3"],
      },
      // No maxGroupSize — client requirement: unlimited
      maxDiscount: {
        type: Number,
        min: 0,
        max: [30, "Maximum discount is 30%"],
      },
      tokenAmount: {
        type: Number,
        required: [true, "Token amount is required"],
        min: [25000, "Minimum token is ₹25,000"],
        max: [500000, "Maximum token is ₹5,00,000"],
      },
      deadlineDays: {
        type: Number,
        default: 30,
        min: [30, "Minimum deadline is 30 days"],
        max: [90, "Maximum deadline is 90 days"],
      },
      perks: {
        type: [String],
        default: [],
      },
      // % of active members that must accept for deal to close
      closureThreshold: {
        type: Number,
        default: 75,
        min: 1,
        max: 100,
      },
    },

    // ── State ────────────────────────────────────────────────────────────────
    status: {
      type: String,
      enum: [
        "forming",       // Accepting members, deadline not yet passed
        "locked",        // Min threshold met, moving to negotiation
        "negotiating",   // Admin is negotiating with builder
        "terms_shared",  // Final terms sent to members for acceptance
        "closed",        // 75%+ members accepted — deal done
        "expired",       // Deadline passed without hitting min group size
        "cancelled",     // Admin cancelled manually
      ],
      default: "forming",
    },

    // ── Key Dates ────────────────────────────────────────────────────────────
    // Auto-calculated: createdAt + config.deadlineDays
    formingDeadline: {
      type: Date,
      required: true,
    },
    lockedAt: { type: Date, default: null },
    closedAt: { type: Date, default: null },
    expiredAt: { type: Date, default: null },

    // ── Denormalized counts (updated on member join/exit for fast reads) ─────
    memberCount: { type: Number, default: 0, min: 0 },
    paidMemberCount: { type: Number, default: 0, min: 0 },

    // ── Negotiation tracking ─────────────────────────────────────────────────
    currentRound: {
      type: Number,
      default: 0,
      min: 0,
      max: 3,
    },

    // ── Property snapshot (preserved even if property is later edited) ───────
    propertySnapshot: {
      title: String,
      price: Number,
      priceUnit: String,
      city: String,
      locality: String,
      bhk: String,
      propertyType: String,
      image: String, // First image URL
    },

    // ── Admin notes ──────────────────────────────────────────────────────────
    adminNotes: { type: String, default: "" },
  },
  { timestamps: true }
);

// ── Indexes ──────────────────────────────────────────────────────────────────
groupBuyProjectSchema.index({ property: 1 });
groupBuyProjectSchema.index({ builder: 1 });
groupBuyProjectSchema.index({ status: 1 });
groupBuyProjectSchema.index({ formingDeadline: 1 }); // For expiry cron
groupBuyProjectSchema.index({ "propertySnapshot.city": 1, status: 1 }); // Browse by city
groupBuyProjectSchema.index({ createdAt: -1 });

const GroupBuyProject = mongoose.model("GroupBuyProject", groupBuyProjectSchema);
export default GroupBuyProject;
