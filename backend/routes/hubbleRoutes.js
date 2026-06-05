/**
 * Hubble Routes — DealDirect Rewards
 *
 * Routes for Hubble gift card SDK integration.
 * SSO + Coin endpoints are PUBLIC (called by Hubble's servers, secured via X-Hubble-Secret).
 * Token and config endpoints require authenticated user.
 */
import express from "express";
import {
  getHubbleConfig,
  getHubbleToken,
  handleHubbleSSO,
  getHubbleBalance,
  handleHubbleDebit,
  handleHubbleReverse,
} from "../controllers/hubbleController.js";
import { authMiddleware } from "../middleware/authUser.js";

const router = express.Router();

// ============================================
// PUBLIC: Called by Hubble's backend servers
// Auth is via X-Hubble-Secret header (verified in controller)
// ============================================
router.post("/sso", handleHubbleSSO);

// Coin APIs — Hubble calls these to manage the points economy
router.get("/balance", getHubbleBalance);
router.post("/debit", handleHubbleDebit);
router.post("/reverse", handleHubbleReverse);

// ============================================
// PROTECTED: Called by our frontend
// ============================================
router.get("/config", authMiddleware, getHubbleConfig);
router.get("/token", authMiddleware, getHubbleToken);

export default router;
