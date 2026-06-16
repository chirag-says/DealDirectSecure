/**
 * Booking Routes — DealDirect Projects
 * Mounted at: /api/bookings
 */
import express from "express";
import {
  createBooking,
  submitPayment,
  getMyBookings,
  listBookings,
  verifyPayment,
  updateBookingStatus,
} from "../controllers/bookingController.js";
import { authMiddleware, optionalAuth } from "../middleware/authUser.js";
import { protectAdmin } from "../middleware/authAdmin.js";
import { memoryUpload } from "../middleware/upload.js";

const router = express.Router();

// ── Public (optional auth to attach user) ─────────────────────────────────────
router.post("/", optionalAuth, createBooking);

// Submit payment proof (UTR + screenshot)
router.post(
  "/:id/payment",
  memoryUpload.single("screenshot"),
  submitPayment
);

// ── Authenticated user ─────────────────────────────────────────────────────────
router.get("/my", authMiddleware, getMyBookings);

// ── Admin ─────────────────────────────────────────────────────────────────────
router.get("/", protectAdmin, listBookings);
router.put("/:id/verify", protectAdmin, verifyPayment);
router.put("/:id/status", protectAdmin, updateBookingStatus);

export default router;
