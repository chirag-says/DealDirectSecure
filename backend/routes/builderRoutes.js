/**
 * Builder Routes — DealDirect
 * Mounted at: /api/builders
 * All routes are admin-only.
 */
import express from "express";
import {
  listBuilders,
  getBuilder,
  createBuilder,
  updateBuilder,
  deleteBuilder,
} from "../controllers/builderController.js";
import { protectAdmin } from "../middleware/authAdmin.js";
import { memoryUpload } from "../middleware/upload.js";

const router = express.Router();

// All builder routes require admin session
router.use(protectAdmin);

router.get("/", listBuilders);
router.get("/:id", getBuilder);
router.post("/", memoryUpload.single("logo"), createBuilder);
router.put("/:id", memoryUpload.single("logo"), updateBuilder);
router.delete("/:id", deleteBuilder);

export default router;
