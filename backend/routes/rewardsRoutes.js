/**
 * Rewards Routes — DealDirect Rewards
 * API routes for the rewards/points system.
 */
import express from "express";
import {
  getUserWallet,
  getUserTransactions,
  getUserReferralCode,
  getUserReferrals,
  redeemReward,
  getRewardsStore,
  getCatalogueCategories,
  getCatalogueSubCategories,
  getCatalogueProducts,
  filterCatalogueProducts,
  getCatalogueProductDetails,
  adminAdjust,
  adminGetRedemptions,
  adminUpdateRedemption,
  adminGetUserWallet,
  adminGetOverview,
} from "../controllers/rewardsController.js";
import { authMiddleware } from "../middleware/authUser.js";
import { protectAdmin } from "../middleware/authAdmin.js";

const router = express.Router();

// ============================================
// PUBLIC ROUTES
// ============================================

// Rewards store (available rewards & costs)
router.get("/store", getRewardsStore);

// ============================================
// REWARDPORT CATALOGUE (Public browsing)
// ============================================

router.get("/catalogue/categories", getCatalogueCategories);
router.get("/catalogue/subcategories/:categoryId", getCatalogueSubCategories);
router.get("/catalogue/products", getCatalogueProducts);
router.post("/catalogue/products/filter", filterCatalogueProducts);
router.post("/catalogue/products/details", getCatalogueProductDetails);

// ============================================
// PROTECTED USER ROUTES
// ============================================

router.get("/wallet", authMiddleware, getUserWallet);
router.get("/transactions", authMiddleware, getUserTransactions);
router.get("/referral-code", authMiddleware, getUserReferralCode);
router.get("/referrals", authMiddleware, getUserReferrals);
router.post("/redeem", authMiddleware, redeemReward);

// ============================================
// ADMIN ROUTES
// ============================================

router.get("/admin/overview", protectAdmin, adminGetOverview);
router.post("/admin/adjust-points", protectAdmin, adminAdjust);
router.get("/admin/redemptions", protectAdmin, adminGetRedemptions);
router.put("/admin/redemptions/:id", protectAdmin, adminUpdateRedemption);
router.get("/admin/user/:userId/wallet", protectAdmin, adminGetUserWallet);

export default router;
