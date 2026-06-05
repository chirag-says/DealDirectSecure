/**
 * Reward Model — DealDirect Rewards
 * Represents a user's points wallet with transaction history and tier tracking.
 */
import mongoose from "mongoose";

// ============================================
// TRANSACTION SUB-SCHEMA
// ============================================

const transactionSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: ["earn", "redeem", "forfeit", "adjustment"],
      required: true,
    },
    action: {
      type: String,
      required: true,
      trim: true,
    },
    points: {
      type: Number,
      required: true, // positive for earn, negative for redeem/forfeit
    },
    basePoints: {
      type: Number,
      default: 0, // original points before tier multiplier
    },
    multiplier: {
      type: Number,
      default: 1.0, // tier multiplier applied
    },
    description: {
      type: String,
      trim: true,
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed, // propertyId, referredUserId, redemptionId, etc.
      default: {},
    },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
  }
);

// ============================================
// REWARD WALLET SCHEMA
// ============================================

const rewardSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    totalPoints: {
      type: Number,
      default: 0,
      min: 0,
    },
    availablePoints: {
      type: Number,
      default: 0,
      min: 0,
    },
    tier: {
      type: String,
      enum: ["bronze", "silver", "gold", "diamond"],
      default: "bronze",
    },
    transactions: [transactionSchema],

    // Rolling 12-month tracking for tier review
    lastTierReviewAt: {
      type: Date,
      default: null,
    },

    // Monthly login tracking for the "15+ days login" bonus
    monthlyLoginDays: {
      type: Map,
      of: Number, // key: "YYYY-MM", value: count of unique login days
      default: {},
    },
    lastLoginDate: {
      type: String, // "YYYY-MM-DD" to deduplicate same-day logins
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

// ============================================
// TIER THRESHOLDS
// ============================================

const TIER_THRESHOLDS = {
  bronze: { min: 0, max: 999 },
  silver: { min: 1000, max: 4999 },
  gold: { min: 5000, max: 14999 },
  diamond: { min: 15000, max: Infinity },
};

const TIER_MULTIPLIERS = {
  bronze: 1.0,
  silver: 1.1,
  gold: 1.25,
  diamond: 1.5,
};

// Static getters
rewardSchema.statics.TIER_THRESHOLDS = TIER_THRESHOLDS;
rewardSchema.statics.TIER_MULTIPLIERS = TIER_MULTIPLIERS;

// ============================================
// INSTANCE METHODS
// ============================================

/**
 * Recalculate tier based on totalPoints
 */
rewardSchema.methods.recalculateTier = function () {
  const pts = this.totalPoints;
  if (pts >= 15000) this.tier = "diamond";
  else if (pts >= 5000) this.tier = "gold";
  else if (pts >= 1000) this.tier = "silver";
  else this.tier = "bronze";
  return this.tier;
};

/**
 * Get current tier multiplier
 */
rewardSchema.methods.getTierMultiplier = function () {
  return TIER_MULTIPLIERS[this.tier] || 1.0;
};

/**
 * Progress to next tier (percentage)
 */
rewardSchema.methods.getNextTierProgress = function () {
  const thresholds = TIER_THRESHOLDS;
  const pts = this.totalPoints;

  if (this.tier === "diamond") return { nextTier: null, progress: 100, pointsNeeded: 0 };

  const tierOrder = ["bronze", "silver", "gold", "diamond"];
  const currentIndex = tierOrder.indexOf(this.tier);
  const nextTier = tierOrder[currentIndex + 1];
  const nextMin = thresholds[nextTier].min;
  const currentMin = thresholds[this.tier].min;
  const range = nextMin - currentMin;
  const progress = Math.min(100, Math.round(((pts - currentMin) / range) * 100));
  const pointsNeeded = Math.max(0, nextMin - pts);

  return { nextTier, progress, pointsNeeded };
};

/**
 * Add a transaction and update balances
 */
rewardSchema.methods.addTransaction = function (txn) {
  this.transactions.push(txn);

  if (txn.type === "earn") {
    this.totalPoints += txn.points;
    this.availablePoints += txn.points;
  } else if (txn.type === "redeem" || txn.type === "forfeit") {
    // points is negative for these types
    this.availablePoints += txn.points; // subtracts since points is negative
  } else if (txn.type === "adjustment") {
    this.totalPoints += txn.points;
    this.availablePoints += txn.points;
  }

  // Ensure non-negative
  if (this.availablePoints < 0) this.availablePoints = 0;
  if (this.totalPoints < 0) this.totalPoints = 0;

  this.recalculateTier();
};

// ============================================
// INDEXES
// ============================================

rewardSchema.index({ user: 1 }, { unique: true });
rewardSchema.index({ tier: 1 });
rewardSchema.index({ totalPoints: -1 });

const Reward = mongoose.model("Reward", rewardSchema);
export default Reward;
