import express from "express";
import { authMiddleware } from "../middleware/authUser.js";
import {
  attestClose,
  getDeal,
  listMyDeals,
  openConversation,
  proposeVisit,
  updateVisit,
  visitFeedback,
} from "../controllers/dealController.js";
import { validateMongoId } from "../middleware/validators/index.js";

/**
 * The deal room (Phase 2). Mounted at /api/deals. Every route requires a
 * user session and every handler re-checks that the caller is one of the two
 * parties of the lead; see controllers/dealController.js.
 */
const router = express.Router();

router.use(authMiddleware);

router.get("/", listMyDeals);
router.get("/:leadId", validateMongoId("leadId"), getDeal);

router.post("/:leadId/visits", validateMongoId("leadId"), proposeVisit);
router.put("/:leadId/visits/:visitId", validateMongoId("leadId"), validateMongoId("visitId"), updateVisit);
router.post("/:leadId/visits/:visitId/feedback", validateMongoId("leadId"), validateMongoId("visitId"), visitFeedback);

router.post("/:leadId/conversation", validateMongoId("leadId"), openConversation);

router.post("/:leadId/attest", validateMongoId("leadId"), attestClose);

export default router;
