import express from "express";
import { authMiddleware } from "../middleware/authUser.js";
import { getEligibility, getMyReviews, getUserReviews, submitReview } from "../controllers/reviewController.js";
import { validateMongoId } from "../middleware/validators/index.js";

/**
 * Verified-deal reviews (Phase 3). Mounted at /api/reviews.
 * Reading someone's published reviews is public; everything else needs a session.
 */
const router = express.Router();

router.get("/user/:userId", validateMongoId("userId"), getUserReviews);

router.use(authMiddleware);
router.get("/mine", getMyReviews);
router.get("/eligibility/:verificationId", validateMongoId("verificationId"), getEligibility);
router.post("/", submitReview);

export default router;
