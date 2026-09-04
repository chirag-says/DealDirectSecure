import express from "express";
import rateLimit from "express-rate-limit";
import { optionalAuth } from "../middleware/authUser.js";
import { ingestEvents } from "../controllers/eventController.js";

const router = express.Router();

/**
 * Events are cheap to write and worthless to flood. One batch every few
 * seconds per device is the honest ceiling; anything past this is a client
 * bug or abuse, and dropping it costs nothing.
 */
const eventLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Too many event batches" },
});

router.post("/", eventLimiter, optionalAuth, ingestEvents);

export default router;
