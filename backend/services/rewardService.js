/**
 * Reward Service — DealDirect Rewards
 * Core business logic for points economy: earning, redeeming, tier management, referrals.
 *
 * Gamified rewards system — 4 earning categories:
 *   1. Property Posting  → random from weighted tiers
 *   2. Property Sale     → random from weighted tiers
 *   3. Property Enquiry  → random from weighted tiers
 *   4. Referral          → fixed 100 pts
 *   5. Report Property   → fixed 100 pts
 *
 * Conversion: 1 point = ₹0.05
 */
import Reward from "../models/Reward.js";
import Referral from "../models/Referral.js";
import RedemptionRequest from "../models/RedemptionRequest.js";
import User from "../models/userModel.js";

// ============================================
// CONVERSION RATE
// ============================================
export const POINTS_TO_RUPEES = 0.05; // 1 point = ₹0.05

// ============================================
// WEIGHTED REWARD TIERS (from client spreadsheet)
// Higher weight = more likely to be picked
// ============================================

export const REWARD_TIERS = {
  // Property Posting Rewards — awarded when user lists a property
  property_posting: [
    { points: 40, cashValue: 2, weight: 150000 },
    { points: 100, cashValue: 5, weight: 50000 },
    { points: 200, cashValue: 10, weight: 20000 },
    { points: 400, cashValue: 20, weight: 11000 },
    { points: 600, cashValue: 30, weight: 2100 },
    { points: 800, cashValue: 40, weight: 1100 },
    { points: 1000, cashValue: 50, weight: 500 },
    { points: 2000, cashValue: 100, weight: 200 },
    { points: 4000, cashValue: 200, weight: 200 },
    { points: 5000, cashValue: 250, weight: 200 },
    { points: 6000, cashValue: 300, weight: 40 },
    { points: 7000, cashValue: 350, weight: 40 },
    { points: 8000, cashValue: 400, weight: 20 },
    { points: 10000, cashValue: 500, weight: 10 },
    { points: 20000, cashValue: 1000, weight: 5 },
    { points: 30000, cashValue: 1500, weight: 5 },
    { points: 40000, cashValue: 2000, weight: 5 },
    { points: 60000, cashValue: 3000, weight: 3 },
    { points: 70000, cashValue: 3500, weight: 3 },
    { points: 80000, cashValue: 4000, weight: 2 },
    { points: 90000, cashValue: 4500, weight: 2 },
    { points: 100000, cashValue: 5000, weight: 2 },
  ],

  // Property Sale Rewards — awarded when property is marked sold/rented
  property_sale: [
    { points: 1000, cashValue: 50, weight: 10000 },
    { points: 2000, cashValue: 100, weight: 5000 },
    { points: 10000, cashValue: 500, weight: 1200 },
    { points: 15000, cashValue: 750, weight: 50 },
    { points: 18000, cashValue: 900, weight: 50 },
    { points: 20000, cashValue: 1000, weight: 50 },
    { points: 22000, cashValue: 1100, weight: 50 },
    { points: 30000, cashValue: 1500, weight: 50 },
    { points: 42000, cashValue: 2100, weight: 40 },
    { points: 50000, cashValue: 2500, weight: 30 },
    { points: 62000, cashValue: 3100, weight: 20 },
    { points: 82000, cashValue: 4100, weight: 10 },
    { points: 102000, cashValue: 5100, weight: 5 },
    { points: 220000, cashValue: 11000, weight: 3 },
    { points: 300000, cashValue: 15000, weight: 2 },
    { points: 420000, cashValue: 21000, weight: 1 },
    { points: 500000, cashValue: 25000, weight: 1 },
  ],

  // Property Enquiry Rewards — awarded when buyer sends an enquiry
  property_enquiry: [
    { points: 20, cashValue: 1, weight: 500000 },
    { points: 40, cashValue: 2, weight: 200000 },
    { points: 60, cashValue: 3, weight: 30000 },
    { points: 80, cashValue: 4, weight: 10000 },
    { points: 100, cashValue: 5, weight: 6000 },
    { points: 120, cashValue: 6, weight: 5000 },
    { points: 140, cashValue: 7, weight: 4000 },
    { points: 160, cashValue: 8, weight: 3000 },
    { points: 180, cashValue: 9, weight: 3000 },
    { points: 200, cashValue: 10, weight: 2000 },
    { points: 400, cashValue: 20, weight: 900 },
    { points: 600, cashValue: 30, weight: 800 },
    { points: 800, cashValue: 40, weight: 700 },
    { points: 1000, cashValue: 50, weight: 600 },
    { points: 1200, cashValue: 60, weight: 500 },
    { points: 1400, cashValue: 70, weight: 400 },
    { points: 1600, cashValue: 80, weight: 300 },
    { points: 1800, cashValue: 90, weight: 200 },
    { points: 2000, cashValue: 100, weight: 110 },
  ],
};

// ============================================
// FIXED POINT VALUES (non-random actions)
// ============================================
export const FIXED_POINTS = {
  referral_signup: 100,
  report_property: 100,
};

// Maps action keys → which random category to use (or null for fixed)
const ACTION_CATEGORY_MAP = {
  list_property: "property_posting",
  mark_sold_rented: "property_sale",
  complete_deal: "property_sale",
  send_enquiry: "property_enquiry",
  referral_signup: null, // fixed
  report_property: null, // fixed
};

// Human-readable descriptions
const ACTION_DESCRIPTIONS = {
  list_property: "Property Posting Reward",
  mark_sold_rented: "Property Sale Shagun",
  complete_deal: "Deal Closure Shagun",
  send_enquiry: "Property Enquiry Reward",
  referral_signup: "Referral — friend signed up",
  report_property: "Reported a misleading property",
};

// Keep POINT_VALUES export for backward compatibility (used in referral stats calculation)
export const POINT_VALUES = {
  referral_signup: 100,
  report_property: 100,
};

// ============================================
// WEIGHTED RANDOM REWARD PICKER
// ============================================

/**
 * Pick a random reward tier using weighted random selection.
 * Lower rewards have much higher weights → much more likely.
 *
 * @param {string} category - 'property_posting' | 'property_sale' | 'property_enquiry'
 * @returns {{ points: number, cashValue: number }}
 */
export const getRandomReward = (category) => {
  const tiers = REWARD_TIERS[category];
  if (!tiers || tiers.length === 0) {
    return { points: 0, cashValue: 0 };
  }

  // Calculate total weight
  const totalWeight = tiers.reduce((sum, tier) => sum + tier.weight, 0);

  // Pick a random number in [0, totalWeight)
  let random = Math.random() * totalWeight;

  // Walk through tiers until we find the selected one
  for (const tier of tiers) {
    random -= tier.weight;
    if (random <= 0) {
      return { points: tier.points, cashValue: tier.cashValue };
    }
  }

  // Fallback to lowest tier
  return { points: tiers[0].points, cashValue: tiers[0].cashValue };
};

// ============================================
// REWARDS STORE — available redemptions
// ============================================

export const REWARDS_STORE = [
  // On-Platform Rewards
  {
    slug: "featured_listing_500",
    name: "₹500 off a Featured Listing",
    pointsCost: 10000,
    category: "on_platform",
    rewardType: "listing_boost",
  },
  {
    slug: "premium_listing_30d",
    name: "30-day Premium Listing Placement",
    pointsCost: 20000,
    category: "on_platform",
    rewardType: "premium_listing",
  },
  {
    slug: "valuation_report",
    name: "1 Free Property Valuation Report",
    pointsCost: 10000,
    category: "on_platform",
    rewardType: "valuation_report",
  },
  {
    slug: "priority_support_3m",
    name: "Priority Customer Support (3 months)",
    pointsCost: 20000,
    category: "on_platform",
    rewardType: "priority_support",
  },
  // Lifestyle Vouchers
  {
    slug: "amazon_250",
    name: "Amazon ₹250 Gift Voucher",
    pointsCost: 5000,
    category: "lifestyle",
    rewardType: "voucher",
  },
  {
    slug: "swiggy_zomato_300",
    name: "Swiggy / Zomato ₹300 Voucher",
    pointsCost: 6000,
    category: "lifestyle",
    rewardType: "voucher",
  },
  {
    slug: "starbucks_200",
    name: "Starbucks ₹200 Gift Card",
    pointsCost: 4000,
    category: "lifestyle",
    rewardType: "voucher",
  },
  // Cash
  {
    slug: "bank_transfer_1000",
    name: "₹1,000 Bank Transfer",
    pointsCost: 20000,
    category: "cash",
    rewardType: "cash_transfer",
  },
];

// ============================================
// CORE SERVICE FUNCTIONS
// ============================================

/**
 * Get or create a reward wallet for a user
 */
export const getOrCreateWallet = async (userId) => {
  let wallet = await Reward.findOne({ user: userId });
  if (!wallet) {
    try {
      wallet = await Reward.create({ user: userId });
    } catch (err) {
      // Handle race condition: another request may have created it
      if (err.code === 11000) {
        wallet = await Reward.findOne({ user: userId });
      }
      if (!wallet) throw err;
    }
  }
  return wallet;
};

/**
 * Award points to a user for a qualifying action.
 * Applies tier multiplier automatically.
 *
 * @param {string} userId - User ObjectId
 * @param {string} action - Action key from POINT_VALUES
 * @param {Object} [metadata={}] - Optional metadata (propertyId, etc.)
 * @returns {{ success: boolean, pointsAwarded: number, newBalance: number, tier: string }}
 */
export const awardPoints = async (userId, action, metadata = {}) => {
  try {
    // Check if this action is recognized
    const category = ACTION_CATEGORY_MAP[action];
    if (category === undefined) {
      console.warn(`[RewardService] Unknown action: ${action}`);
      return { success: false, error: `Unknown action: ${action}` };
    }

    const wallet = await getOrCreateWallet(userId);

    // DAILY LIMIT CHECK FOR ENQUIRIES
    if (action === "send_enquiry") {
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      const todaysEnquiriesCount = wallet.transactions.filter(
        (t) => t.action === "send_enquiry" && t.createdAt >= today
      ).length;

      if (todaysEnquiriesCount >= 5) {
        console.log(`[RewardService] User ${userId} reached daily limit (5) for ${action}`);
        return { 
          success: true, 
          pointsAwarded: 0, 
          message: "Daily limit reached for property enquiries" 
        };
      }
    }

    let basePoints;
    let cashValue;
    let tierName = 'common';

    if (category) {
      // Randomized reward from weighted tiers
      const reward = getRandomReward(category);
      basePoints = reward.points;
      cashValue = reward.cashValue;
      tierName = reward.tier;
    } else {
      // Fixed-point action (referral, report)
      basePoints = FIXED_POINTS[action] || 100;
      cashValue = basePoints * POINTS_TO_RUPEES;
    }
    const multiplier = wallet.getTierMultiplier();
    const finalPoints = Math.round(basePoints * multiplier);
    const finalCashValue = +(finalPoints * POINTS_TO_RUPEES).toFixed(2);

    wallet.addTransaction({
      type: "earn",
      action,
      points: finalPoints,
      basePoints,
      multiplier,
      description: ACTION_DESCRIPTIONS[action] || action,
      metadata: {
        ...metadata,
        cashValue: finalCashValue,
        rewardCategory: category || action,
      },
    });

    await wallet.save();

    console.log(
      `[RewardService] 🎲 +${finalPoints} pts (₹${finalCashValue}) to user ${userId} for ${action} (base ${basePoints}, x${multiplier})`
    );

    return {
      success: true,
      pointsAwarded: finalPoints,
      cashValue: finalCashValue,
      newBalance: wallet.availablePoints,
      totalPoints: wallet.totalPoints,
      tier: wallet.tier,
      rewardCategory: category || action,
      rewardTier: tierName,
      description: ACTION_DESCRIPTIONS[action] || action,
    };
  } catch (error) {
    console.error(`[RewardService] awardPoints error for ${userId}/${action}:`, error.message);
    return { success: false, error: error.message };
  }
};

/**
 * Redeem points for a reward from the store
 *
 * @param {string} userId
 * @param {string} rewardSlug - slug from REWARDS_STORE
 * @param {Object} [extraData={}] - bankDetails for cash, etc.
 */
export const redeemPoints = async (userId, rewardSlug, extraData = {}) => {
  try {
    const reward = REWARDS_STORE.find((r) => r.slug === rewardSlug);
    if (!reward) {
      return { success: false, error: "Invalid reward selection" };
    }

    const wallet = await getOrCreateWallet(userId);
    if (wallet.availablePoints < reward.pointsCost) {
      return {
        success: false,
        error: `Insufficient points. You have ${wallet.availablePoints} pts, need ${reward.pointsCost} pts.`,
      };
    }

    // Create redemption request
    const redemption = await RedemptionRequest.create({
      user: userId,
      rewardType: reward.rewardType,
      rewardName: reward.name,
      pointsSpent: reward.pointsCost,
      status: "pending",
      bankDetails: reward.rewardType === "cash_transfer" ? extraData.bankDetails : undefined,
      metadata: extraData,
    });

    // Deduct points
    wallet.addTransaction({
      type: "redeem",
      action: `redeem_${rewardSlug}`,
      points: -reward.pointsCost,
      basePoints: reward.pointsCost,
      multiplier: 1,
      description: `Redeemed: ${reward.name}`,
      metadata: { redemptionId: redemption._id },
    });

    await wallet.save();

    console.log(
      `[RewardService] -${reward.pointsCost} pts from user ${userId} for ${reward.name}`
    );

    return {
      success: true,
      redemption,
      newBalance: wallet.availablePoints,
    };
  } catch (error) {
    console.error(`[RewardService] redeemPoints error:`, error.message);
    return { success: false, error: error.message };
  }
};

/**
 * Get wallet summary for a user
 */
export const getWallet = async (userId) => {
  const wallet = await getOrCreateWallet(userId);
  const progress = wallet.getNextTierProgress();

  return {
    totalPoints: wallet.totalPoints,
    availablePoints: wallet.availablePoints,
    tier: wallet.tier,
    tierMultiplier: wallet.getTierMultiplier(),
    nextTierProgress: progress,
    recentTransactions: wallet.transactions
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, 10),
  };
};

/**
 * Get paginated transaction history
 */
export const getTransactionHistory = async (userId, page = 1, limit = 20) => {
  const wallet = await getOrCreateWallet(userId);
  const total = wallet.transactions.length;
  const sorted = wallet.transactions.sort((a, b) => b.createdAt - a.createdAt);
  const start = (page - 1) * limit;
  const transactions = sorted.slice(start, start + limit);

  return {
    transactions,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  };
};

/**
 * Handle referral milestones — award points to referrer
 *
 * @param {string} referredUserId - The new user who was referred
 * @param {'signup' | 'first_action' | 'deal_closure'} milestone
 */
export const handleReferralMilestone = async (referredUserId, milestone) => {
  try {
    const referral = await Referral.findOne({ referred: referredUserId });
    if (!referral) return { success: false, reason: "No referral record found" };

    const milestoneMap = {
      signup: {
        flag: "signupPointsAwarded",
        dateFlag: "signupPointsAwardedAt",
        action: "referral_signup",
      },
      first_action: {
        flag: "firstActionPointsAwarded",
        dateFlag: "firstActionPointsAwardedAt",
        action: "referral_first_action",
      },
      deal_closure: {
        flag: "dealClosurePointsAwarded",
        dateFlag: "dealClosurePointsAwardedAt",
        action: "referral_deal_closure",
      },
    };

    const m = milestoneMap[milestone];
    if (!m) return { success: false, reason: `Invalid milestone: ${milestone}` };

    // Check if already awarded
    if (referral[m.flag]) {
      return { success: false, reason: `${milestone} points already awarded` };
    }

    // Award points to referrer
    const result = await awardPoints(referral.referrer, m.action, {
      referredUserId,
      milestone,
    });

    if (result.success) {
      referral[m.flag] = true;
      referral[m.dateFlag] = new Date();
      await referral.save();
    }

    return result;
  } catch (error) {
    console.error(`[RewardService] handleReferralMilestone error:`, error.message);
    return { success: false, error: error.message };
  }
};

/**
 * Create a referral record when a new user signs up with a referral code
 *
 * @param {string} referrerCode - The referral code used
 * @param {string} referredUserId - The new user's ID
 */
export const createReferralFromCode = async (referrerCode, referredUserId) => {
  try {
    if (!referrerCode) return { success: false, reason: "No referral code provided" };

    // Find the referrer by their code
    const referrer = await User.findOne({ referralCode: referrerCode.toUpperCase().trim() });
    if (!referrer) return { success: false, reason: "Invalid referral code" };

    // Don't allow self-referral
    if (referrer._id.toString() === referredUserId.toString()) {
      return { success: false, reason: "Self-referral not allowed" };
    }

    // Check if already referred
    const existing = await Referral.findOne({ referred: referredUserId });
    if (existing) return { success: false, reason: "User already has a referrer" };

    // Create referral record
    const referral = await Referral.create({
      referrer: referrer._id,
      referred: referredUserId,
    });

    // Update referredBy on user
    await User.findByIdAndUpdate(referredUserId, { referredBy: referrer._id });

    // Award signup milestone to referrer
    await handleReferralMilestone(referredUserId, "signup");

    console.log(
      `[RewardService] Referral created: ${referrer._id} → ${referredUserId} via code ${referrerCode}`
    );

    return { success: true, referral };
  } catch (error) {
    // Handle duplicate key error gracefully
    if (error.code === 11000) {
      return { success: false, reason: "Referral already exists" };
    }
    console.error("[RewardService] createReferralFromCode error:", error.message);
    return { success: false, error: error.message };
  }
};

/**
 * Get referral stats for a user (how many people they've referred)
 */
export const getReferralStats = async (userId) => {
  const referrals = await Referral.find({ referrer: userId })
    .populate("referred", "name email createdAt")
    .sort({ createdAt: -1 })
    .lean();

  const stats = {
    totalReferred: referrals.length,
    signups: referrals.filter((r) => r.signupPointsAwarded).length,
    firstActions: referrals.filter((r) => r.firstActionPointsAwarded).length,
    dealClosures: referrals.filter((r) => r.dealClosurePointsAwarded).length,
    totalPointsEarned:
      referrals.reduce((sum, r) => {
        let pts = 0;
        if (r.signupPointsAwarded) pts += FIXED_POINTS.referral_signup;
        return sum + pts;
      }, 0),
    referrals: referrals.map((r) => ({
      id: r._id,
      referredUser: r.referred
        ? { name: r.referred.name, joinedAt: r.referred.createdAt }
        : null,
      milestones: {
        signup: r.signupPointsAwarded,
        firstAction: r.firstActionPointsAwarded,
        dealClosure: r.dealClosurePointsAwarded,
      },
      createdAt: r.createdAt,
    })),
  };

  return stats;
};

/**
 * Track daily login (does not award points in current model)
 */
export const trackDailyLogin = async (userId) => {
  try {
    const wallet = await getOrCreateWallet(userId);
    const today = new Date().toISOString().split("T")[0];
    
    if (wallet.lastLoginDate === today) return { success: true, message: "Already tracked today" };

    const currentMonth = today.substring(0, 7);
    wallet.lastLoginDate = today;
    const currentCount = wallet.monthlyLoginDays.get(currentMonth) || 0;
    wallet.monthlyLoginDays.set(currentMonth, currentCount + 1);
    
    await wallet.save();
    return { success: true, message: "Login tracked" };
  } catch (error) {
    console.error("[RewardService] trackDailyLogin error:", error.message);
    return { success: false, error: error.message };
  }
};

/**
 * Admin: manually adjust points
 */
export const adminAdjustPoints = async (userId, points, reason, adminId) => {
  try {
    const wallet = await getOrCreateWallet(userId);

    wallet.addTransaction({
      type: "adjustment",
      action: "admin_adjustment",
      points,
      basePoints: Math.abs(points),
      multiplier: 1,
      description: reason || "Admin adjustment",
      metadata: { adminId },
    });

    await wallet.save();

    return {
      success: true,
      newBalance: wallet.availablePoints,
      totalPoints: wallet.totalPoints,
      tier: wallet.tier,
    };
  } catch (error) {
    console.error("[RewardService] adminAdjustPoints error:", error.message);
    return { success: false, error: error.message };
  }
};

/**
 * Admin: get redemption requests
 */
export const getRedemptionRequests = async (status, page = 1, limit = 20) => {
  const filter = status ? { status } : {};
  const total = await RedemptionRequest.countDocuments(filter);
  const requests = await RedemptionRequest.find(filter)
    .populate("user", "name email phone")
    .sort({ createdAt: -1 })
    .skip((page - 1) * limit)
    .limit(limit)
    .lean();

  return {
    requests,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  };
};

/**
 * Admin: update redemption status
 */
export const updateRedemptionStatus = async (redemptionId, status, adminNotes, voucherCode) => {
  try {
    const updates = { status };
    if (adminNotes) updates.adminNotes = adminNotes;
    if (voucherCode) updates.voucherCode = voucherCode;
    if (status === "fulfilled") updates.deliveredAt = new Date();
    if (status === "failed") updates.failureReason = adminNotes || "Failed";

    const redemption = await RedemptionRequest.findByIdAndUpdate(
      redemptionId,
      { $set: updates },
      { new: true }
    ).populate("user", "name email");

    if (!redemption) return { success: false, error: "Redemption not found" };

    // If failed, refund points
    if (status === "failed") {
      const wallet = await getOrCreateWallet(redemption.user._id);
      wallet.addTransaction({
        type: "adjustment",
        action: "redemption_refund",
        points: redemption.pointsSpent,
        basePoints: redemption.pointsSpent,
        multiplier: 1,
        description: `Refund: ${redemption.rewardName} (failed)`,
        metadata: { redemptionId },
      });
      await wallet.save();
    }

    return { success: true, redemption };
  } catch (error) {
    console.error("[RewardService] updateRedemptionStatus error:", error.message);
    return { success: false, error: error.message };
  }
};

export default {
  POINT_VALUES,
  FIXED_POINTS,
  POINTS_TO_RUPEES,
  REWARD_TIERS,
  REWARDS_STORE,
  getRandomReward,
  getOrCreateWallet,
  awardPoints,
  redeemPoints,
  getWallet,
  getTransactionHistory,
  handleReferralMilestone,
  createReferralFromCode,
  getReferralStats,
  trackDailyLogin,
  adminAdjustPoints,
  getRedemptionRequests,
  updateRedemptionStatus,
};
