import express from "express";
import { authMiddleware } from "../middleware/authUser.js";
import {
  createSavedSearch,
  getMySavedSearches,
  toggleSavedSearchActive,
} from "../controllers/savedSearchController.js";

const router = express.Router();

// All saved-search endpoints require auth
router.use(authMiddleware);

router.post("/", createSavedSearch);
router.get("/mine", getMySavedSearches);
router.patch("/:id/toggle", toggleSavedSearchActive);

export default router;
