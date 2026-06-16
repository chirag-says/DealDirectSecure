/**
 * GroupBuyNegotiation Model — DealDirect Group Buying
 *
 * One document per negotiation round (max 3 rounds).
 * Admin submits an offer to the builder. Builder responds (admin enters on their behalf).
 * When accepted, finalTerms are set and shared with all group members.
 *
 * Round lifecycle:
 *   Admin submits offer → status: "offer_sent"
 *   Builder counters (admin records) → status: "countered"
 *   Admin accepts counter → status: "accepted", finalTerms populated
 *   Builder rejects (no deal) → status: "rejected"
 */
import mongoose from "mongoose";

const groupBuyNegotiationSchema = new mongoose.Schema(
  {
    group: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "GroupBuyProject",
      required: true,
    },

    // Round number: 1, 2, or 3 (max 3 per proposal rules)
    round: {
      type: Number,
      required: true,
      min: 1,
      max: 3,
    },

    // ── DealDirect's offer to the builder ─────────────────────────────────────
    offer: {
      discountPercent: { type: Number, min: 0, max: 30 },
      perks: { type: [String], default: [] },
      notes: { type: String, trim: true },
      submittedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Admin",
      },
      submittedAt: { type: Date },
    },

    // ── Builder's counter-offer (entered by admin on builder's behalf) ────────
    counterOffer: {
      discountPercent: { type: Number, min: 0, max: 30 },
      perks: { type: [String], default: [] },
      notes: { type: String, trim: true },
      respondedAt: { type: Date },
    },

    // ── Round resolution ──────────────────────────────────────────────────────
    status: {
      type: String,
      enum: [
        "offer_sent",  // Admin submitted, waiting on builder
        "countered",   // Builder countered (admin recorded)
        "accepted",    // Terms accepted — finalTerms populated
        "rejected",    // Builder rejected, no deal this round
      ],
      default: "offer_sent",
    },

    // ── Final agreed terms (populated when status → "accepted") ──────────────
    finalTerms: {
      discountPercent: { type: Number },
      perks: { type: [String], default: [] },
      priceAfterDiscount: { type: Number }, // Calculated: originalPrice * (1 - discount/100)
      validUntil: { type: Date },           // How long buyers have to respond
    },

    // Admin who accepted/resolved this round
    resolvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      default: null,
    },
    resolvedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

// ── Indexes ───────────────────────────────────────────────────────────────────
// Unique: one document per round per group
groupBuyNegotiationSchema.index({ group: 1, round: 1 }, { unique: true });
groupBuyNegotiationSchema.index({ group: 1, status: 1 });
groupBuyNegotiationSchema.index({ status: 1 });

const GroupBuyNegotiation = mongoose.model(
  "GroupBuyNegotiation",
  groupBuyNegotiationSchema
);
export default GroupBuyNegotiation;
