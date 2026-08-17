import express from "express";
import { authMiddleware } from "../middleware/authUser.js";
import {
  getMyNotifications,
  markNotificationRead,
  markAllNotificationsRead,
} from "../controllers/notificationController.js";

const router = express.Router();

router.use(authMiddleware);

router.get("/", getMyNotifications);

// The literal path is declared before the "/:id/read" wildcard.
//
// Express matches in declaration order, so with the wildcard first every
// request to /mark-all/read was handled by markNotificationRead with
// id = "mark-all". That failed the ObjectId cast and returned 500, which means
// mark-all-as-read never worked. Order is the whole fix; both handlers were
// already correct.
router.patch("/mark-all/read", markAllNotificationsRead);
router.patch("/:id/read", markNotificationRead);

export default router;
