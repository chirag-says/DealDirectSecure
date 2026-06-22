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
  getPaymentConfig,
} from "../controllers/bookingController.js";
import { authMiddleware } from "../middleware/authUser.js";
import { protectAdmin } from "../middleware/authAdmin.js";
import { memoryUpload } from "../middleware/upload.js";

const router = express.Router();

// ── Authenticated user — login required to book (same as "I'm Interested" for properties)
router.post("/", authMiddleware, createBooking);

// Submit payment proof (UTR + screenshot) — must be the booking's owner
router.post(
  "/:id/payment",
  authMiddleware,
  memoryUpload.single("screenshot"),
  submitPayment
);

// ── Authenticated user ─────────────────────────────────────────────────────────
router.get("/my", authMiddleware, getMyBookings);
router.get("/payment-config", authMiddleware, getPaymentConfig);

// ── Admin ─────────────────────────────────────────────────────────────────────
router.get("/", protectAdmin, listBookings);
router.put("/:id/verify", protectAdmin, verifyPayment);
router.put("/:id/status", protectAdmin, updateBookingStatus);

export default router;
