/**
 * Rewards Controller — DealDirect Rewards
 * API endpoints for the rewards/points system.
 */
import {
  getWallet,
  getTransactionHistory,
  redeemPoints,
  getReferralStats,
  awardPoints,
  adminAdjustPoints,
  getRedemptionRequests,
  updateRedemptionStatus,
  REWARDS_STORE,
} from "../services/rewardService.js";
import {
  getCategories,
  getSubCategories,
  getAllProducts,
  getProductsByCategory,
  getProductDetails,
  isRewardPortConfigured,
} from "../services/rewardPortService.js";
import User from "../models/userModel.js";
import Reward from "../models/Reward.js";

// ============================================
// USER-FACING ENDPOINTS
// ============================================

/**
 * GET /api/rewards/wallet
 * Get current user's wallet summary
 */
export const getUserWallet = async (req, res) => {
  try {
    const wallet = await getWallet(req.user._id);
    res.status(200).json({ success: true, wallet });
  } catch (error) {
    console.error("[RewardsCtrl] getUserWallet error:", error.message, error.stack);
    res.status(500).json({ success: false, message: "Failed to fetch wallet", debug: error.message });
  }
};

/**
 * GET /api/rewards/transactions?page=1&limit=20
 * Get paginated transaction history
 */
export const getUserTransactions = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const result = await getTransactionHistory(req.user._id, page, limit);
    res.status(200).json({ success: true, ...result });
  } catch (error) {
    console.error("[RewardsCtrl] getUserTransactions error:", error.message, error.stack);
    res.status(500).json({ success: false, message: "Failed to fetch transactions", debug: error.message });
  }
};

/**
 * GET /api/rewards/referral-code
 * Get user's referral code and referral stats
 */
export const getUserReferralCode = async (req, res) => {
  try {
    let user = await User.findById(req.user._id).select("referralCode name").lean();

    // If user exists but has no referral code (pre-existing user), generate one now
    if (user && !user.referralCode) {
      const crypto = await import("crypto");
      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      let code;
      let isUnique = false;
      let attempts = 0;

      while (!isUnique && attempts < 10) {
        code = "DD";
        for (let i = 0; i < 4; i++) {
          code += chars.charAt(crypto.default.randomInt(0, chars.length));
        }
        const existing = await User.findOne({ referralCode: code }).lean();
        if (!existing) isUnique = true;
        attempts++;
      }

      if (isUnique) {
        await User.findByIdAndUpdate(req.user._id, { referralCode: code });
        user = { ...user, referralCode: code };
      }
    }

    const stats = await getReferralStats(req.user._id);

    res.status(200).json({
      success: true,
      referralCode: user?.referralCode || null,
      referralLink: user?.referralCode
        ? `${process.env.CLIENT_URL || "https://dealdirect.in"}/register?ref=${user.referralCode}`
        : null,
      stats,
    });
  } catch (error) {
    console.error("[RewardsCtrl] getUserReferralCode error:", error.message);
    res.status(500).json({ success: false, message: "Failed to fetch referral info" });
  }
};

/**
 * GET /api/rewards/referrals
 * Get list of referred users and their milestone status
 */
export const getUserReferrals = async (req, res) => {
  try {
    const stats = await getReferralStats(req.user._id);
    res.status(200).json({ success: true, ...stats });
  } catch (error) {
    console.error("[RewardsCtrl] getUserReferrals error:", error.message);
    res.status(500).json({ success: false, message: "Failed to fetch referrals" });
  }
};

/**
 * POST /api/rewards/redeem
 * Redeem points for a reward
 * Body: { rewardSlug, bankDetails? }
 */
export const redeemReward = async (req, res) => {
  try {
    const { rewardSlug, bankDetails } = req.body;

    if (!rewardSlug) {
      return res.status(400).json({ success: false, message: "Reward selection is required" });
    }

    const result = await redeemPoints(req.user._id, rewardSlug, { bankDetails });

    if (!result.success) {
      return res.status(400).json({ success: false, message: result.error });
    }

    res.status(200).json({
      success: true,
      message: "Redemption request submitted successfully!",
      redemption: result.redemption,
      newBalance: result.newBalance,
    });
  } catch (error) {
    console.error("[RewardsCtrl] redeemReward error:", error.message);
    res.status(500).json({ success: false, message: "Redemption failed" });
  }
};

/**
 * GET /api/rewards/store
 * Get available rewards for redemption (public)
 */
export const getRewardsStore = async (req, res) => {
  try {
    res.status(200).json({ success: true, rewards: REWARDS_STORE });
  } catch (error) {
    console.error("[RewardsCtrl] getRewardsStore error:", error.message);
    res.status(500).json({ success: false, message: "Failed to fetch rewards store" });
  }
};

// ============================================
// REWARDPORT CATALOGUE ENDPOINTS (Public)
// ============================================

/**
 * GET /api/rewards/catalogue/categories
 */
export const getCatalogueCategories = async (req, res) => {
  try {
    if (!isRewardPortConfigured()) {
      return res.status(503).json({ success: false, message: "Catalogue not configured" });
    }
    const result = await getCategories();
    res.status(200).json({ success: result.success, categories: result.categories });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to fetch categories" });
  }
};

/**
 * GET /api/rewards/catalogue/subcategories/:categoryId
 */
export const getCatalogueSubCategories = async (req, res) => {
  try {
    const result = await getSubCategories(req.params.categoryId);
    res.status(200).json({ success: result.success, subCategories: result.subCategories });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to fetch sub-categories" });
  }
};

/**
 * GET /api/rewards/catalogue/products
 */
export const getCatalogueProducts = async (req, res) => {
  try {
    const result = await getAllProducts();
    res.status(200).json({ success: result.success, products: result.products });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to fetch products" });
  }
};

/**
 * POST /api/rewards/catalogue/products/filter
 * Body: { categoryId, subCategoryId, sortBy }
 */
export const filterCatalogueProducts = async (req, res) => {
  try {
    const result = await getProductsByCategory(req.body);
    res.status(200).json({ success: result.success, products: result.products });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to filter products" });
  }
};

/**
 * POST /api/rewards/catalogue/products/details
 * Body: { productId }
 */
export const getCatalogueProductDetails = async (req, res) => {
  try {
    const result = await getProductDetails(req.body.productId);
    res.status(200).json({ success: result.success, product: result.product });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to fetch product details" });
  }
};

// ============================================
// ADMIN ENDPOINTS
// ============================================

/**
 * POST /api/rewards/admin/adjust-points
 * Body: { userId, points, reason }
 */
export const adminAdjust = async (req, res) => {
  try {
    const { userId, points, reason } = req.body;

    if (!userId || points === undefined) {
      return res.status(400).json({ success: false, message: "userId and points are required" });
    }

    const result = await adminAdjustPoints(userId, parseInt(points), reason, req.admin?._id);

    if (!result.success) {
      return res.status(400).json({ success: false, message: result.error });
    }

    res.status(200).json({
      success: true,
      message: `Points adjusted by ${points} for user ${userId}`,
      ...result,
    });
  } catch (error) {
    console.error("[RewardsCtrl] adminAdjust error:", error.message);
    res.status(500).json({ success: false, message: "Failed to adjust points" });
  }
};

/**
 * GET /api/rewards/admin/redemptions?status=pending&page=1&limit=20
 */
export const adminGetRedemptions = async (req, res) => {
  try {
    const { status, page, limit } = req.query;
    const result = await getRedemptionRequests(status, parseInt(page) || 1, parseInt(limit) || 20);
    res.status(200).json({ success: true, ...result });
  } catch (error) {
    console.error("[RewardsCtrl] adminGetRedemptions error:", error.message);
    res.status(500).json({ success: false, message: "Failed to fetch redemptions" });
  }
};

/**
 * PUT /api/rewards/admin/redemptions/:id
 * Body: { status, adminNotes, voucherCode }
 */
export const adminUpdateRedemption = async (req, res) => {
  try {
    const { status, adminNotes, voucherCode } = req.body;

    if (!status) {
      return res.status(400).json({ success: false, message: "Status is required" });
    }

    const result = await updateRedemptionStatus(req.params.id, status, adminNotes, voucherCode);

    if (!result.success) {
      return res.status(400).json({ success: false, message: result.error });
    }

    res.status(200).json({
      success: true,
      message: `Redemption updated to ${status}`,
      redemption: result.redemption,
    });
  } catch (error) {
    console.error("[RewardsCtrl] adminUpdateRedemption error:", error.message);
    res.status(500).json({ success: false, message: "Failed to update redemption" });
  }
};

/**
 * GET /api/rewards/admin/user/:userId/wallet
 * Admin view of any user's wallet
 */
export const adminGetUserWallet = async (req, res) => {
  try {
    const wallet = await getWallet(req.params.userId);
    const user = await User.findById(req.params.userId).select("name email phone referralCode").lean();
    res.status(200).json({ success: true, user, wallet });
  } catch (error) {
    console.error("[RewardsCtrl] adminGetUserWallet error:", error.message);
    res.status(500).json({ success: false, message: "Failed to fetch user wallet" });
  }
};

/**
 * GET /api/rewards/admin/overview?page=1&limit=20&sort=totalPoints&order=desc&search=john
 * Admin overview of all rewards — aggregate stats + paginated user wallets
 */
export const adminGetOverview = async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const sortField = req.query.sort || "totalPoints";
    const sortOrder = req.query.order === "asc" ? 1 : -1;
    const search = (req.query.search || "").trim();

    // ---------- 1. Aggregate summary stats ----------
    const [summaryResult] = await Reward.aggregate([
      {
        $group: {
          _id: null,
          totalWallets: { $sum: 1 },
          totalPointsDistributed: { $sum: "$totalPoints" },
          totalAvailablePoints: { $sum: "$availablePoints" },
          bronzeCount: { $sum: { $cond: [{ $eq: ["$tier", "bronze"] }, 1, 0] } },
          silverCount: { $sum: { $cond: [{ $eq: ["$tier", "silver"] }, 1, 0] } },
          goldCount: { $sum: { $cond: [{ $eq: ["$tier", "gold"] }, 1, 0] } },
          diamondCount: { $sum: { $cond: [{ $eq: ["$tier", "diamond"] }, 1, 0] } },
        },
      },
    ]);

    const summary = summaryResult || {
      totalWallets: 0,
      totalPointsDistributed: 0,
      totalAvailablePoints: 0,
      bronzeCount: 0,
      silverCount: 0,
      goldCount: 0,
      diamondCount: 0,
    };

    // ---------- 2. Paginated user wallets with user info ----------
    const allowedSortFields = ["totalPoints", "availablePoints", "tier", "updatedAt"];
    const safeSortField = allowedSortFields.includes(sortField) ? sortField : "totalPoints";

    // Build aggregation pipeline
    const pipeline = [
      // Join with users collection
      {
        $lookup: {
          from: "users",
          localField: "user",
          foreignField: "_id",
          as: "userInfo",
        },
      },
      { $unwind: { path: "$userInfo", preserveNullAndEmptyArrays: true } },
    ];

    // Add search filter if provided
    if (search) {
      pipeline.push({
        $match: {
          $or: [
            { "userInfo.name": { $regex: search, $options: "i" } },
            { "userInfo.email": { $regex: search, $options: "i" } },
          ],
        },
      });
    }

    // Get total count for pagination (after search filter)
    const countPipeline = [...pipeline, { $count: "total" }];
    const [countResult] = await Reward.aggregate(countPipeline);
    const total = countResult?.total || 0;

    // Add sort, skip, limit, and projection
    pipeline.push(
      { $sort: { [safeSortField]: sortOrder } },
      { $skip: (page - 1) * limit },
      { $limit: limit },
      {
        $project: {
          _id: 1,
          user: 1,
          totalPoints: 1,
          availablePoints: 1,
          tier: 1,
          updatedAt: 1,
          userName: "$userInfo.name",
          userEmail: "$userInfo.email",
          lastTransactionDate: { $arrayElemAt: [{ $slice: ["$transactions.createdAt", -1] }, 0] },
        },
      }
    );

    const wallets = await Reward.aggregate(pipeline);

    res.status(200).json({
      success: true,
      summary: {
        totalWallets: summary.totalWallets,
        totalPointsDistributed: summary.totalPointsDistributed,
        totalAvailablePoints: summary.totalAvailablePoints,
        tierBreakdown: {
          bronze: summary.bronzeCount,
          silver: summary.silverCount,
          gold: summary.goldCount,
          diamond: summary.diamondCount,
        },
      },
      wallets,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("[RewardsCtrl] adminGetOverview error:", error.message, error.stack);
    res.status(500).json({ success: false, message: "Failed to fetch rewards overview" });
  }
};
