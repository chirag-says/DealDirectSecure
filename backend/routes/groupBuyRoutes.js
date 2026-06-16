/**
 * Group Buy Routes — DealDirect
 * Mounted at: /api/group-buy
 */
import express from "express";
import {
  listProjects,
  getProject,
  createProject,
  updateProject,
  joinGroup,
  exitGroup,
  getMyGroups,
} from "../controllers/groupBuyController.js";
import { authMiddleware, optionalAuth } from "../middleware/authUser.js";
import { protectAdmin } from "../middleware/authAdmin.js";

const router = express.Router();

// ── Public (with optional user attach for isMember check) ─────────
router.get("/projects", optionalAuth, listProjects);
router.get("/projects/:id", optionalAuth, getProject);

// ── User (authenticated) ──────────────────────────────────────────
router.get("/my-groups", authMiddleware, getMyGroups);
router.post("/projects/:id/join", authMiddleware, joinGroup);
router.post("/projects/:id/exit", authMiddleware, exitGroup);

// ── Admin ─────────────────────────────────────────────────────────
router.post("/projects", protectAdmin, createProject);
router.put("/projects/:id", protectAdmin, updateProject);

export default router;
