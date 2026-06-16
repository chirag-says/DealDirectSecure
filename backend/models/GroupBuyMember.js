/**
 * GroupBuyMember Model — DealDirect Group Buying
 *
 * One document per buyer per group. Tracks their participation,
 * token payment (manual QR), and final deal response.
 *
 * Payment flow:
 *   User joins → tokenStatus: "pending"
 *   User pays via QR → Admin records payment → tokenStatus: "paid"
 *   User exits / deal rejected → Admin processes refund → tokenStatus: "refunded"
 */
import mongoose from "mongoose";

const groupBuyMemberSchema = new mongoose.Schema(
  {
    group: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "GroupBuyProject",
      required: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    // ── Buyer preferences (captured at join time) ────────────────────────────
    preferredUnitType: { type: String, trim: true }, // "2BHK", "3BHK", etc.
    budgetRange: {
      min: { type: Number },
      max: { type: Number },
    },

    // ── Token Payment (Manual QR flow) ───────────────────────────────────────
    tokenAmount: { type: Number }, // Amount they need to pay (from group config)
    tokenStatus: {
      type: String,
      enum: ["pending", "paid", "refunded"],
      default: "pending",
    },
    tokenPaidAt: { type: Date, default: null },
    tokenRefundedAt: { type: Date, default: null },

    // Admin records this after verifying QR payment screenshot
    paymentReference: { type: String, trim: true }, // e.g. UPI transaction ID
    paymentProofUrl: { type: String }, // Cloudinary URL of payment screenshot
    paymentRecordedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      default: null,
    },

    // ── Deal Response (Phase 3 — after terms are shared) ─────────────────────
    dealResponse: {
      type: String,
      enum: ["pending", "accepted", "rejected"],
      default: "pending",
    },
    dealRespondedAt: { type: Date, default: null },

    // ── Member Status ─────────────────────────────────────────────────────────
    status: {
      type: String,
      enum: [
        "active",          // In the group, participating
        "exited",          // Left voluntarily before deal closed
        "deal_accepted",   // Accepted final terms
        "deal_rejected",   // Rejected final terms
      ],
      default: "active",
    },
    exitReason: { type: String, trim: true },
    exitedAt: { type: Date, default: null },

    // ── User snapshot at join time ────────────────────────────────────────────
    // Preserved in case user updates profile later
    userSnapshot: {
      name: { type: String },
      email: { type: String },
      phone: { type: String },
    },
  },
  { timestamps: true }
);

// ── Indexes ───────────────────────────────────────────────────────────────────
// Unique: one membership per user per group
groupBuyMemberSchema.index({ group: 1, user: 1 }, { unique: true });
groupBuyMemberSchema.index({ user: 1 });                    // "My Groups" query
groupBuyMemberSchema.index({ group: 1, status: 1 });       // Active members per group
groupBuyMemberSchema.index({ group: 1, tokenStatus: 1 });  // Payment tracking
groupBuyMemberSchema.index({ group: 1, dealResponse: 1 }); // Acceptance tracking

const GroupBuyMember = mongoose.model("GroupBuyMember", groupBuyMemberSchema);
export default GroupBuyMember;
