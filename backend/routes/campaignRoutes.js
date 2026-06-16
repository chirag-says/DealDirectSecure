/**
 * Campaign Routes — DealDirect
 * Mounted at: /api/campaigns
 *
 * Admin: create, update, verify payments, list members
 * User (protectUser): join, exit, upload payment proof
 * Public: GET campaign detail, list by project/unit-type
 */
import express from "express";
import {
  createCampaign,
  getCampaign,
  listByUnitType,
  listByProject,
  updateCampaign,
  joinCampaign,
  exitCampaign,
  uploadPaymentProof,
  verifyPayment,
  listPendingPayments,
  listCampaignMembers,
} from "../controllers/campaignController.js";
import { protectAdmin } from "../middleware/authAdmin.js";
import { memoryUpload, uploadConcurrencyGuard } from "../middleware/upload.js";

// User auth middleware — using same pattern as existing routes
import { authMiddleware } from "../middleware/authUser.js";

const router = express.Router();

// ── Public routes ─────────────────────────────────────────────────────────────
router.get("/unit-type/:unitTypeId", listByUnitType); // MUST be before /:id
router.get("/project/:projectId", listByProject);   // MUST be before /:id
router.get("/:id", getCampaign);

// ── Admin — member verify (no :id prefix collision) ──────────────────────────
router.put("/members/:memberId/verify", protectAdmin, verifyPayment);

// ── User routes (authenticated buyers) ───────────────────────────────────────
router.post("/:id/join", authMiddleware, joinCampaign);
router.post("/:id/exit", authMiddleware, exitCampaign);
router.post(
  "/:id/payment-proof",
  authMiddleware,
  uploadConcurrencyGuard,
  memoryUpload.single("paymentProof"),
  uploadPaymentProof
);

// ── Admin routes ──────────────────────────────────────────────────────────────
router.post("/", protectAdmin, createCampaign);
router.put("/:id", protectAdmin, updateCampaign);
router.get("/:id/members", protectAdmin, listCampaignMembers);
router.get("/:id/pending-payments", protectAdmin, listPendingPayments);

export default router;
