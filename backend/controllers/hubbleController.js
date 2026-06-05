/**
 * Hubble Controller — DealDirect Rewards
 *
 * Endpoints:
 *  1. GET  /api/rewards/hubble/config   — Frontend gets SDK URL parameters
 *  2. GET  /api/rewards/hubble/token    — Frontend calls this to get an SSO token
 *  3. POST /api/rewards/hubble/sso      — Hubble calls this to validate the token
 *  4. GET  /api/rewards/hubble/balance  — Hubble calls this to get user's coin balance
 *  5. POST /api/rewards/hubble/debit    — Hubble calls this to deduct coins
 *  6. POST /api/rewards/hubble/reverse  — Hubble calls this to reverse a debit
 */

import {
  generateHubbleToken,
  validateHubbleToken,
  isHubbleConfigured,
} from "../services/hubbleService.js";
import User from "../models/userModel.js";
import Reward from "../models/Reward.js";

/**
 * Verify the X-Hubble-Secret header.
 * Shared helper used by SSO and Coin endpoints.
 * Returns true if valid, sends error response and returns false otherwise.
 */
function verifyHubbleSecret(req, res) {
  const hubbleSecret = req.headers["x-hubble-secret"];
  const expectedSecret = process.env.HUBBLE_WEBHOOK_SECRET;

  if (!expectedSecret) {
    console.error("[HubbleCtrl] HUBBLE_WEBHOOK_SECRET not configured");
    res.status(500).json({ success: false, message: "Server misconfiguration" });
    return false;
  }

  if (!hubbleSecret || hubbleSecret !== expectedSecret) {
    console.warn(`[HubbleCtrl] Invalid X-Hubble-Secret from ${req.ip}`);
    res.status(401).json({ success: false, message: "Unauthorized" });
    return false;
  }

  return true;
}

/**
 * GET /api/rewards/hubble/config
 * Returns the SDK configuration for the frontend to build the iframe URL.
 * Requires authenticated user.
 */
export const getHubbleConfig = async (req, res) => {
  try {
    if (!isHubbleConfigured()) {
      return res.status(503).json({
        success: false,
        message: "Hubble rewards integration is not configured.",
      });
    }

    // Use explicit env var to control which Hubble environment we target.
    // This prevents staging credentials from being sent to the production SDK.
    const baseUrl = process.env.HUBBLE_SDK_BASE_URL || "https://sdk.myhubble.money/";

    res.status(200).json({
      success: true,
      config: {
        clientId: process.env.HUBBLE_CLIENT_ID,
        appSecret: process.env.HUBBLE_APP_SECRET,
        sdkBaseUrl: baseUrl,
        theme: process.env.HUBBLE_THEME || "light",
      },
    });
  } catch (error) {
    console.error("[HubbleCtrl] getHubbleConfig error:", error.message);
    res.status(500).json({ success: false, message: "Failed to get SDK config" });
  }
};

/**
 * GET /api/rewards/hubble/token
 * Generate a short-lived SSO token for the current user.
 * Frontend calls this, then passes the token to the Hubble SDK URL.
 */
export const getHubbleToken = async (req, res) => {
  try {
    if (!isHubbleConfigured()) {
      return res.status(503).json({
        success: false,
        message: "Hubble rewards integration is not configured.",
      });
    }

    // req.user is populated by authMiddleware
    const user = req.user;
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    // Fetch full user data including phone (authMiddleware may not include it)
    const fullUser = await User.findById(user._id)
      .select("name email phone")
      .lean();

    if (!fullUser) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    const token = generateHubbleToken(fullUser);

    res.status(200).json({
      success: true,
      token,
    });
  } catch (error) {
    console.error("[HubbleCtrl] getHubbleToken error:", error.message);
    res.status(500).json({ success: false, message: "Failed to generate token" });
  }
};

/**
 * POST /api/rewards/hubble/sso
 * Called BY Hubble's backend to validate an SSO token.
 *
 * Hubble sends:
 *   Headers: { X-Hubble-Secret: "..." }
 *   Body:    { token: "..." }
 *
 * We return user details if valid, or userId: null if invalid.
 */
export const handleHubbleSSO = async (req, res) => {
  try {
    // 1. Verify the X-Hubble-Secret header
    const hubbleSecret = req.headers["x-hubble-secret"];
    const expectedSecret = process.env.HUBBLE_WEBHOOK_SECRET;

    if (!expectedSecret) {
      console.error("[HubbleCtrl] HUBBLE_WEBHOOK_SECRET not configured");
      return res.status(500).json({ userId: null });
    }

    if (!hubbleSecret || hubbleSecret !== expectedSecret) {
      console.warn(
        `[HubbleCtrl] SSO request with invalid X-Hubble-Secret from ${req.ip}`
      );
      return res.status(401).json({ userId: null });
    }

    // 2. Extract and validate the token
    const { token } = req.body;

    if (!token || typeof token !== "string") {
      console.warn("[HubbleCtrl] SSO request with missing/invalid token");
      return res.status(400).json({ userId: null });
    }

    // 3. Validate the token and get user data
    const userData = validateHubbleToken(token);

    if (!userData) {
      console.warn(`[HubbleCtrl] SSO token validation failed: ${token.substring(0, 8)}...`);
      return res.status(401).json({ userId: null });
    }

    // 4. Return user details to Hubble
    console.log(`[HubbleCtrl] SSO success for user ${userData.userId}`);
    res.status(200).json({
      userId: userData.userId,
      firstName: userData.firstName,
      lastName: userData.lastName,
      email: userData.email,
      phoneNumber: userData.phoneNumber,
    });
  } catch (error) {
    console.error("[HubbleCtrl] handleHubbleSSO error:", error.message);
    res.status(500).json({ userId: null });
  }
};

// ============================================
// COIN APIS — Called by Hubble's backend
// These enable the points economy in the SDK
// ============================================

/**
 * GET /api/rewards/hubble/balance?userId=<userId>
 * Called BY Hubble to check a user's available coin balance.
 *
 * Returns: { userId, totalCoins }
 */
export const getHubbleBalance = async (req, res) => {
  try {
    if (!verifyHubbleSecret(req, res)) return;

    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ userId: null, totalCoins: 0, message: "userId required" });
    }

    const reward = await Reward.findOne({ user: userId }).select("availablePoints").lean();

    const totalCoins = reward ? reward.availablePoints : 0;
    console.log(`[HubbleCtrl] Balance check for ${userId}: ${totalCoins} coins`);

    res.status(200).json({ userId, totalCoins });
  } catch (error) {
    console.error("[HubbleCtrl] getHubbleBalance error:", error.message);
    res.status(500).json({ userId: null, totalCoins: 0, message: "Internal error" });
  }
};

/**
 * POST /api/rewards/hubble/debit
 * Called BY Hubble to deduct coins when a user purchases a gift card.
 *
 * Body: { userId, coins, referenceId, note }
 * Returns: { success: true, balance: <remaining> }
 */
export const handleHubbleDebit = async (req, res) => {
  try {
    if (!verifyHubbleSecret(req, res)) return;

    const { userId, coins, referenceId, note } = req.body;

    if (!userId || coins === undefined || !referenceId) {
      return res.status(400).json({
        success: false,
        message: "userId, coins, and referenceId are required",
      });
    }

    const debitAmount = Number(coins);
    if (isNaN(debitAmount) || debitAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: "coins must be a positive number",
      });
    }

    // Find the user's reward wallet
    const reward = await Reward.findOne({ user: userId });
    if (!reward) {
      return res.status(404).json({
        success: false,
        message: "User wallet not found",
      });
    }

    // Check for duplicate referenceId (idempotency)
    const existingTxn = reward.transactions.find(
      (t) => t.metadata?.referenceId === referenceId && t.type === "redeem"
    );
    if (existingTxn) {
      console.warn(`[HubbleCtrl] Duplicate debit referenceId: ${referenceId}`);
      return res.status(200).json({
        status: "SUCCESS",
        transactionId: existingTxn._id.toString(),
        referenceId,
        balance: reward.availablePoints,
        message: "Already processed",
      });
    }

    // Check sufficient balance
    if (reward.availablePoints < debitAmount) {
      return res.status(400).json({
        status: "failed",
        message: "Insufficient balance",
        balance: reward.availablePoints,
      });
    }

    // Add redemption transaction (points is negative for redeems)
    reward.addTransaction({
      type: "redeem",
      action: "hubble_gift_card",
      points: -debitAmount,
      description: note || `Gift card redemption via Hubble`,
      metadata: { referenceId, source: "hubble" },
    });

    await reward.save();

    // Get the newly created transaction's ID
    const newTxn = reward.transactions[reward.transactions.length - 1];

    console.log(
      `[HubbleCtrl] Debit ${debitAmount} coins for ${userId} (ref: ${referenceId}). Remaining: ${reward.availablePoints}`
    );

    res.status(200).json({
      status: "SUCCESS",
      transactionId: newTxn._id.toString(),
      referenceId,
      balance: reward.availablePoints,
    });
  } catch (error) {
    console.error("[HubbleCtrl] handleHubbleDebit error:", error.message);
    res.status(500).json({ success: false, message: "Internal error" });
  }
};

/**
 * POST /api/rewards/hubble/reverse
 * Called BY Hubble to reverse a previous debit (refund).
 *
 * Body: { userId, referenceId, note }
 * Returns: { success: true, balance: <new balance> }
 */
export const handleHubbleReverse = async (req, res) => {
  try {
    if (!verifyHubbleSecret(req, res)) return;

    const { userId, referenceId, note } = req.body;

    if (!userId || !referenceId) {
      return res.status(400).json({
        success: false,
        message: "userId and referenceId are required",
      });
    }

    const reward = await Reward.findOne({ user: userId });
    if (!reward) {
      return res.status(404).json({
        success: false,
        message: "User wallet not found",
      });
    }

    // Check for duplicate reversal (idempotency)
    const existingReversal = reward.transactions.find(
      (t) => t.metadata?.referenceId === referenceId && t.action === "hubble_reversal"
    );
    if (existingReversal) {
      console.warn(`[HubbleCtrl] Duplicate reversal for referenceId: ${referenceId}`);
      return res.status(200).json({
        status: "SUCCESS",
        transactionId: existingReversal._id.toString(),
        referenceId,
        balance: reward.availablePoints,
        message: "Already reversed",
      });
    }

    // Find the original debit transaction
    const originalDebit = reward.transactions.find(
      (t) => t.metadata?.referenceId === referenceId && t.type === "redeem"
    );

    if (!originalDebit) {
      return res.status(404).json({
        success: false,
        message: `No debit found with referenceId: ${referenceId}`,
      });
    }

    // Reverse: add back the points (originalDebit.points is negative, so negate it)
    const refundAmount = Math.abs(originalDebit.points);

    reward.addTransaction({
      type: "adjustment",
      action: "hubble_reversal",
      points: refundAmount,
      description: note || `Reversal of Hubble gift card redemption`,
      metadata: { referenceId, source: "hubble", originalTransactionId: originalDebit._id },
    });

    await reward.save();

    // Get the newly created reversal transaction's ID
    const reversalTxn = reward.transactions[reward.transactions.length - 1];

    console.log(
      `[HubbleCtrl] Reversed ${refundAmount} coins for ${userId} (ref: ${referenceId}). New balance: ${reward.availablePoints}`
    );

    res.status(200).json({
      status: "SUCCESS",
      transactionId: reversalTxn._id.toString(),
      referenceId,
      balance: reward.availablePoints,
    });
  } catch (error) {
    console.error("[HubbleCtrl] handleHubbleReverse error:", error.message);
    res.status(500).json({ success: false, message: "Internal error" });
  }
};
