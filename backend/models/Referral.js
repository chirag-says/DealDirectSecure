/**
 * Referral Model — DealDirect Rewards
 * Tracks each referral relationship and milestone completions.
 */
import mongoose from "mongoose";

const referralSchema = new mongoose.Schema(
  {
    referrer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    referred: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    // Milestone tracking
    signupPointsAwarded: {
      type: Boolean,
      default: false,
    },
    signupPointsAwardedAt: {
      type: Date,
      default: null,
    },

    firstActionPointsAwarded: {
      type: Boolean,
      default: false,
    },
    firstActionPointsAwardedAt: {
      type: Date,
      default: null,
    },

    dealClosurePointsAwarded: {
      type: Boolean,
      default: false,
    },
    dealClosurePointsAwardedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

// Compound unique index — one referral record per referred user
referralSchema.index({ referrer: 1, referred: 1 }, { unique: true });
referralSchema.index({ referred: 1 }, { unique: true }); // a user can only be referred once

const Referral = mongoose.model("Referral", referralSchema);
export default Referral;
