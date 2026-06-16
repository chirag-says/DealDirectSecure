/**
 * UnitType Routes — DealDirect
 * Mounted at: /api/unit-types
 *
 * Admin routes: protected by protectAdmin
 * Public routes: GET (for client display) — no auth required
 */
import express from "express";
import {
  createUnitType,
  getUnitType,
  listByProject,
  updateUnitType,
  deleteUnitType,
} from "../controllers/unitTypeController.js";
import { protectAdmin } from "../middleware/authAdmin.js";
import { memoryUpload, uploadConcurrencyGuard } from "../middleware/upload.js";

const router = express.Router();

// ── Public routes ─────────────────────────────────────────────────────────────
router.get("/project/:projectId", listByProject); // MUST be before /:id
router.get("/:id", getUnitType);

// ── Admin routes ──────────────────────────────────────────────────────────────
router.post(
  "/",
  protectAdmin,
  uploadConcurrencyGuard,
  memoryUpload.fields([
    { name: "twoDFloorPlan", maxCount: 1 },
    { name: "threeDFloorPlan", maxCount: 1 },
  ]),
  createUnitType
);

router.put(
  "/:id",
  protectAdmin,
  uploadConcurrencyGuard,
  memoryUpload.fields([
    { name: "twoDFloorPlan", maxCount: 1 },
    { name: "threeDFloorPlan", maxCount: 1 },
  ]),
  updateUnitType
);

router.delete("/:id", protectAdmin, deleteUnitType);

export default router;
