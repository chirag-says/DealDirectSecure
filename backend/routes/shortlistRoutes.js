import express from "express";
import { authMiddleware } from "../middleware/authUser.js";
import {
  addToShortlist,
  createShortlistShare,
  getMyShortlist,
  getSharedShortlist,
  getShortlistIds,
  mergeShortlist,
  removeFromShortlist,
  revokeShortlistShare,
  updateShortlistNote,
} from "../controllers/shortlistController.js";
import { validateMongoId } from "../middleware/validators/index.js";

/**
 * The shortlist (Phase 1, F7). Mounted at /api/shortlist.
 *
 * ROUTE ORDER IS LOAD-BEARING. `/ids`, `/merge`, `/share` and `/shared/:token`
 * are literal paths and must be declared before `/:propertyId`, or Express
 * matches the parameterised route first and every one of them becomes a cast
 * error. This file has bitten the codebase before on `/notifications`.
 *
 * `/shared/:token` is the one public route and is declared above the
 * `authMiddleware` gate.
 */
const router = express.Router();

router.get("/shared/:token", getSharedShortlist);

router.use(authMiddleware);

router.get("/", getMyShortlist);
router.get("/ids", getShortlistIds);
router.post("/", addToShortlist);
router.post("/merge", mergeShortlist);
router.post("/share", createShortlistShare);
router.delete("/share", revokeShortlistShare);

router.patch("/:propertyId", validateMongoId("propertyId"), updateShortlistNote);
router.delete("/:propertyId", validateMongoId("propertyId"), removeFromShortlist);

export default router;
