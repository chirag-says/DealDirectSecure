/**
 * Booking Controller — DealDirect Projects
 * Handles the full QR-based token payment booking lifecycle.
 *
 * User (login required):
 *   POST /api/bookings              — create enquiry (auto-linked to req.user)
 *   POST /api/bookings/:id/payment  — submit UTR + screenshot (owner only)
 *   GET  /api/bookings/my           — list my bookings
 *   GET  /api/bookings/payment-config — QR/UPI details
 *
 * Admin:
 *   GET  /api/bookings              — list all bookings (with filters)
 *   PUT  /api/bookings/:id/verify   — verify / reject payment
 *   PUT  /api/bookings/:id/status   — update booking status
 */
import ProjectBooking from "../models/ProjectBooking.js";
import UnitType from "../models/UnitType.js";
import Project from "../models/Project.js";
import GroupBuyCampaign from "../models/GroupBuyCampaign.js";
import CampaignMember from "../models/CampaignMember.js";
import User from "../models/userModel.js";
import { cloudinary } from "../middleware/upload.js";
import { sendBookingAlert, sendGeneralNotification } from "../utils/emailService.js";
import { Readable } from "stream";

// ── Helper: Sync a confirmed booking to the Group Buy campaign ────────────────
// When a booking is confirmed/completed, auto-enroll the buyer as a paid member
// in the active campaign for that project+unitType (if one exists).
// This keeps the Group Buy banner's "joined" count in sync with actual bookings.
const syncBookingToCampaign = async (booking, adminId) => {
  try {
    if (!booking.user || !booking.project || !booking.unitType) return;

    const projectId = booking.project._id || booking.project;
    const unitTypeId = booking.unitType._id || booking.unitType;
    const userId = booking.user._id || booking.user;

    // Find active campaign for this project+unitType
    const campaign = await GroupBuyCampaign.findOne({
      project: projectId,
      unitType: unitTypeId,
      status: "active",
    });
    if (!campaign) return; // No active campaign — nothing to sync

    // Check if user is already a campaign member
    const existing = await CampaignMember.findOne({
      campaign: campaign._id,
      user: userId,
    });

    if (existing) {
      // Already a member — just ensure they're marked as paid
      if (existing.tokenStatus !== "paid") {
        existing.tokenStatus = "paid";
        existing.tokenPaidAt = new Date();
        existing.paymentRecordedBy = adminId;
        existing.paymentReference = booking.payment?.utrNumber || existing.paymentReference;
        await existing.save(); // post-save hook syncs campaign counters
      }
      return;
    }

    // Get user snapshot for the campaign member record
    const user = await User.findById(userId).select("name email phone").lean();

    // Auto-create as a paid campaign member
    await CampaignMember.create({
      campaign: campaign._id,
      user: userId,
      status: "active",
      tokenStatus: "paid",
      tokenPaidAt: new Date(),
      paymentRecordedBy: adminId,
      paymentReference: booking.payment?.utrNumber || "",
      userSnapshot: {
        name: user?.name || booking.clientName,
        email: user?.email || booking.clientEmail,
        phone: user?.phone || booking.clientPhone,
      },
    }); // post-save hook auto-syncs memberCount + paidMemberCount on campaign

    console.log(`[Booking→Campaign] Auto-enrolled user ${userId} as paid member in campaign ${campaign._id}`);
  } catch (err) {
    // Non-fatal — log but don't block the booking response
    if (err.code === 11000) {
      // Duplicate key — user already in campaign, ignore
      console.log(`[Booking→Campaign] User already in campaign (duplicate key), skipping.`);
    } else {
      console.error("[Booking→Campaign] Sync error:", err.message);
    }
  }
};

// ── Helper: upload buffer to Cloudinary ───────────────────────────────────────
const uploadToCloudinary = (buffer, options = {}) =>
  new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(options, (err, result) => {
      if (err) return reject(err);
      resolve(result);
    });
    Readable.from(buffer).pipe(stream);
  });

// ── POST /api/bookings ─────────────────────────────────────────────────────────
// Create an enquiry booking (step 1 — before payment)
export const createBooking = async (req, res) => {
  try {
    const { projectId, unitTypeId, clientName, clientPhone, clientEmail, notes } = req.body;

    if (!projectId || !unitTypeId || !clientName || !clientPhone) {
      return res.status(400).json({ success: false, message: "projectId, unitTypeId, clientName, and clientPhone are required." });
    }

    const [project, unitType] = await Promise.all([
      Project.findById(projectId).select("basics builder financials").lean(),
      UnitType.findById(unitTypeId).select("config pricing paymentTerms inventory builder isActive").lean(),
    ]);

    if (!project) return res.status(404).json({ success: false, message: "Project not found." });
    if (!unitType) return res.status(404).json({ success: false, message: "Unit type not found." });
    if (!unitType.isActive) return res.status(400).json({ success: false, message: "This unit type is not available for booking." });
    if (unitType.inventory?.availableUnits === 0) {
      return res.status(400).json({ success: false, message: "No units available for this configuration." });
    }

    const booking = await ProjectBooking.create({
      project: projectId,
      unitType: unitTypeId,
      builder: unitType.builder,
      user: req.user._id,
      clientName: clientName.trim(),
      clientPhone: clientPhone.trim(),
      clientEmail: clientEmail?.trim() || undefined,
      notes: notes?.trim() || undefined,
      status: "enquiry",
      // Unit-level first, project-level only as a legacy fallback.
      //
      // createProject stopped writing project.financials when booking amounts
      // moved to UnitType.paymentTerms (projectController.js), so reading the
      // project alone resolved to 0 for every project created since. The client
      // quoted the real unit-level amount and the user paid it, while the
      // figure stored here — the one shown in the admin verification modal and
      // in both the confirmation and rejection emails — was ₹0.
      //
      // This mirrors the client's own resolution order in
      // UnitDetailContent.jsx, so the quoted and persisted amounts agree.
      "payment.tokenAmount":
        unitType.paymentTerms?.bookingAmount ?? project.financials?.bookingAmount ?? 0,
      statusHistory: [{ status: "enquiry", changedBy: "user", note: "Booking enquiry created" }],
    });

    return res.status(201).json({
      success: true,
      message: "Booking created. Please complete the token payment.",
      data: {
        bookingId: booking._id,
        tokenAmount: booking.payment.tokenAmount,
        status: booking.status,
      },
    });
  } catch (err) {
    console.error("[Booking] createBooking error:", err);
    return res.status(500).json({ success: false, message: "Failed to create booking." });
  }
};

// ── POST /api/bookings/:id/payment ────────────────────────────────────────────
// Submit UTR + payment screenshot after QR payment
export const submitPayment = async (req, res) => {
  try {
    const { id } = req.params;
    const { utrNumber } = req.body;
    const file = req.file; // multer single("screenshot")

    if (!utrNumber && !file) {
      return res.status(400).json({ success: false, message: "Please provide UTR number or payment screenshot." });
    }

    const booking = await ProjectBooking.findById(id);
    if (!booking) return res.status(404).json({ success: false, message: "Booking not found." });

    // C3 FIX: Ownership check — if user is authenticated and booking has a user, they must match
    if (req.user && booking.user && booking.user.toString() !== req.user._id.toString()) {
      console.warn(`⚠️ IDOR attempt: User ${req.user._id} tried to submit payment for booking owned by ${booking.user}`);
      return res.status(403).json({ success: false, message: "You are not authorized to submit payment for this booking." });
    }

    if (booking.status !== "enquiry") {
      return res.status(400).json({ success: false, message: `Booking is already in '${booking.status}' state.` });
    }

    let screenshotUrl;
    if (file) {
      const result = await uploadToCloudinary(file.buffer, {
        folder: "dealdirect/booking-payments",
        resource_type: "image",
        allowed_formats: ["jpg", "jpeg", "png", "webp", "pdf"],
      });
      screenshotUrl = result.secure_url;
    }

    booking.payment.utrNumber = utrNumber?.trim() || booking.payment.utrNumber;
    booking.payment.screenshotUrl = screenshotUrl || booking.payment.screenshotUrl;
    booking.payment.submittedAt = new Date();
    booking.payment.status = "submitted";
    booking.status = "payment_submitted";
    booking.statusHistory.push({
      status: "payment_submitted",
      changedBy: "user",
      note: `UTR submitted: ${utrNumber || "screenshot only"}`,
    });

    await booking.save();

    // Notify admin — fire and forget, never blocks client response
    Promise.all([
      Project.findById(booking.project).select('basics.name').lean(),
      UnitType.findById(booking.unitType).select('config.name').lean(),
    ]).then(([proj, ut]) => sendBookingAlert(
      booking,
      proj?.basics?.name || 'Unknown Project',
      ut?.config?.name || 'Unknown Unit'
    ).catch(() => {})).catch(() => {});

    return res.json({
      success: true,
      message: "Payment details submitted. We will verify and confirm your booking within 24 hours.",
      data: { bookingId: booking._id, status: booking.status },
    });
  } catch (err) {
    console.error("[Booking] submitPayment error:", err);
    return res.status(500).json({ success: false, message: "Failed to submit payment details." });
  }
};

// ── GET /api/bookings/my ──────────────────────────────────────────────────────
// Authenticated user's own bookings
export const getMyBookings = async (req, res) => {
  try {
    const bookings = await ProjectBooking.find({ user: req.user._id })
      .populate("project", "basics.name location.city salesContact")
      .populate("unitType", "config pricing")
      .sort({ createdAt: -1 })
      .lean();

    return res.json({ success: true, data: bookings });
  } catch (err) {
    console.error("[Booking] getMyBookings error:", err);
    return res.status(500).json({ success: false, message: "Failed to fetch bookings." });
  }
};

// ── GET /api/bookings ─────────────────────────────────────────────────────────
// Admin: list all bookings with optional filters
export const listBookings = async (req, res) => {
  try {
    const { status, projectId, page = 1, limit = 20 } = req.query;
    const filter = {};
    if (status) filter.status = status;
    if (projectId) filter.project = projectId;

    const [bookings, total] = await Promise.all([
      ProjectBooking.find(filter)
        .populate("project", "basics.name")
        .populate("unitType", "config")
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(Number(limit))
        .lean(),
      ProjectBooking.countDocuments(filter),
    ]);

    return res.json({ success: true, data: bookings, total, page: Number(page), pages: Math.ceil(total / limit) });
  } catch (err) {
    console.error("[Booking] listBookings error:", err);
    return res.status(500).json({ success: false, message: "Failed to fetch bookings." });
  }
};

// ── PUT /api/bookings/:id/verify ──────────────────────────────────────────────
// Admin: verify or reject payment screenshot/UTR
export const verifyPayment = async (req, res) => {
  try {
    const { id } = req.params;
    const { action, adminNotes } = req.body; // action: "approve" | "reject"

    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ success: false, message: "action must be 'approve' or 'reject'" });
    }

    const booking = await ProjectBooking.findById(id)
      .populate("project", "basics.name salesContact")
      .populate("unitType", "config inventory");
    if (!booking) return res.status(404).json({ success: false, message: "Booking not found." });
    if (booking.status !== "payment_submitted") {
      return res.status(400).json({ success: false, message: "Booking payment is not pending verification." });
    }

    if (action === "approve") {
      // ORDERING: secure inventory BEFORE persisting the confirmation.
      //
      // This previously saved the booking as confirmed + payment verified and
      // only then attempted the decrement. Two problems followed. A crash
      // between the two writes left a confirmed booking against untouched
      // inventory — an oversell, the exact failure the $gte:1 guard exists to
      // prevent. And on the race path the booking was written twice, passing
      // through a persisted state (confirmed, verified, no inventory) that was
      // never true.
      //
      // Reserving first inverts the failure mode: if the save below fails, a
      // unit is held by no booking. That is visible to an admin and harms no
      // customer, whereas overselling does both.
      //
      // The decrement itself is unchanged — same filter, same $inc, same
      // options. Only its position moved.

      // 1. Decrement inventory atomically — C6 FIX: prevent negative inventory
      //    Uses $gte:1 filter so only one concurrent approval can succeed for the last unit
      const inventoryResult = await UnitType.findOneAndUpdate(
        {
          _id: booking.unitType._id,
          "inventory.availableUnits": { $gte: 1 },
        },
        {
          $inc: {
            "inventory.availableUnits": -1,
            "inventory.bookedUnits": 1,
          },
        },
        { new: true }
      );

      if (!inventoryResult) {
        // Race: the last unit went to a concurrent approval.
        //
        // payment.status stays "verified" deliberately. The admin did check the
        // UTR and the money was received, so recording anything else would
        // erase the refund obligation — and "rejected" would be a lie. The
        // combination (payment verified + booking cancelled) now means exactly
        // one thing, a refund is owed, and it is stated in the notes and the
        // status history rather than left to be inferred.
        booking.payment.status = "verified";
        booking.payment.verifiedAt = new Date();
        booking.payment.verifiedBy = req.admin._id;
        booking.status = "cancelled";
        booking.adminNotes =
          (adminNotes || "") +
          " [Auto-cancelled: unit no longer available. Payment was verified — REFUND DUE.]";
        booking.reviewedBy = req.admin._id;
        booking.reviewedAt = new Date();
        booking.statusHistory.push({
          status: "cancelled",
          changedBy: "admin",
          note: "Auto-cancelled: no inventory available (race condition). Payment verified, refund due.",
        });
        await booking.save();

        // Notify client if possible
        if (booking.clientEmail) {
          const projectName = booking.project?.basics?.name || "the project";
          sendGeneralNotification(
            booking.clientEmail,
            booking.clientName,
            "Booking Could Not Be Confirmed",
            `We're sorry, but the unit you selected at <strong>${projectName}</strong> is no longer available. All units of this type have been booked. Our team will contact you about alternative options.`,
            null, null
          ).catch(() => {});
        }

        return res.status(409).json({
          success: false,
          message: "No units available. This unit type is fully booked.",
        });
      }

      // 2. Inventory is secured — now persist the confirmation, in one write.
      booking.payment.status = "verified";
      booking.payment.verifiedAt = new Date();
      booking.payment.verifiedBy = req.admin._id;
      booking.status = "confirmed";
      booking.statusHistory.push({ status: "confirmed", changedBy: "admin", note: adminNotes || "Payment verified" });
      booking.adminNotes = adminNotes || booking.adminNotes;
      booking.reviewedBy = req.admin._id;
      booking.reviewedAt = new Date();
      await booking.save();

      // 3. Notify client — fire and forget
      if (booking.clientEmail) {
        const projectName = booking.project?.basics?.name || "your project";
        const unitName = booking.unitType?.config?.name || "your unit";
        const salesPhone = booking.project?.salesContact?.phone || "";
        sendGeneralNotification(
          booking.clientEmail,
          booking.clientName,
          "🎉 Your Booking is Confirmed!",
          `Congratulations! Your booking for <strong>${unitName}</strong> at <strong>${projectName}</strong> has been confirmed by our team.<br><br>
          Your token payment of <strong>₹${booking.payment.tokenAmount?.toLocaleString("en-IN")}</strong> has been verified.<br><br>
          Our sales team will contact you shortly to guide you through the next steps.
          ${salesPhone ? `<br><br>You can also reach us at <a href="tel:${salesPhone}">${salesPhone}</a>.` : ""}
          <br><br>Booking Reference: <strong>${booking._id.toString().slice(-8).toUpperCase()}</strong>`,
          null, null
        ).catch(() => {});
      }

      // 4. Sync to Group Buy campaign — auto-enroll as paid member
      syncBookingToCampaign(booking, req.admin._id).catch(() => {});

    } else {
      // Reject — revert so client can resubmit
      booking.payment.status = "rejected";
      booking.payment.rejectionReason = adminNotes || "Payment could not be verified";
      booking.status = "enquiry";
      booking.statusHistory.push({ status: "enquiry", changedBy: "admin", note: `Payment rejected: ${adminNotes}` });
      booking.adminNotes = adminNotes || booking.adminNotes;
      booking.reviewedBy = req.admin._id;
      booking.reviewedAt = new Date();
      await booking.save();

      // Notify client of rejection — fire and forget
      if (booking.clientEmail) {
        sendGeneralNotification(
          booking.clientEmail,
          booking.clientName,
          "Payment Verification Failed",
          `We were unable to verify your payment of <strong>₹${booking.payment.tokenAmount?.toLocaleString("en-IN")}</strong> for your booking.<br><br>
          <strong>Reason:</strong> ${adminNotes || "Payment could not be verified"}<br><br>
          Please re-submit your payment proof with the correct UTR number or a clear screenshot.
          Your booking reference <strong>${booking._id.toString().slice(-8).toUpperCase()}</strong> is still active.`,
          null, null
        ).catch(() => {});
      }
    }

    return res.json({
      success: true,
      message: action === "approve" ? "Payment verified. Booking confirmed & inventory updated." : "Payment rejected.",
      data: { status: booking.status },
    });
  } catch (err) {
    console.error("[Booking] verifyPayment error:", err);
    return res.status(500).json({ success: false, message: "Failed to verify payment." });
  }
};

/**
 * Legal manual status transitions, keyed by the booking's current status.
 *
 * Derived from the states that already exist on ProjectBooking — this is a
 * guard over current behaviour, not a redesign.
 *
 * `confirmed` is deliberately not a target from any state. Confirmation is
 * reached only through PUT /:id/verify, which is the path that checks the
 * payment and takes a unit out of inventory under the $gte:1 guard. Allowing it
 * here let an admin move enquiry → confirmed with no payment, no verification
 * and no decrement, and then auto-enrol the user as a *paid* campaign member.
 *
 * `cancelled` and `completed` are terminal.
 */
export const BOOKING_STATUS_TRANSITIONS = {
  enquiry: ["cancelled"],
  payment_submitted: ["cancelled"],
  confirmed: ["completed", "cancelled"],
  completed: ["cancelled"],
  cancelled: [],
};

/** Statuses in which a unit is held out of inventory. */
export const STATUSES_HOLDING_INVENTORY = ["confirmed", "completed"];

// ── PUT /api/bookings/:id/status ──────────────────────────────────────────────
// Admin: general status update (confirmed → completed, non-terminal → cancelled)
export const updateBookingStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status, adminNotes } = req.body;
    const allowed = ["cancelled", "completed"];

    if (!allowed.includes(status)) {
      return res.status(400).json({
        success: false,
        message: `Status must be one of: ${allowed.join(", ")}. To confirm a booking, verify its payment instead.`,
        code: "INVALID_STATUS",
      });
    }

    const booking = await ProjectBooking.findById(id);
    if (!booking) return res.status(404).json({ success: false, message: "Booking not found." });

    const legal = BOOKING_STATUS_TRANSITIONS[booking.status] || [];
    if (!legal.includes(status)) {
      return res.status(400).json({
        success: false,
        message: legal.length
          ? `A booking in "${booking.status}" can only move to: ${legal.join(", ")}.`
          : `A booking in "${booking.status}" is final and cannot change status.`,
        code: "ILLEGAL_TRANSITION",
      });
    }

    // Return the unit to inventory when cancelling out of a state that held one.
    // Guarded on the transition rather than the target so a second cancel — which
    // the transition table already rejects — could not double-restore.
    const releasesInventory =
      status === "cancelled" && STATUSES_HOLDING_INVENTORY.includes(booking.status);

    if (releasesInventory) {
      // Mirror of the approve-path decrement. bookedUnits is floored at 0 by the
      // filter so a mis-counted record cannot be driven negative.
      const restored = await UnitType.findOneAndUpdate(
        { _id: booking.unitType, "inventory.bookedUnits": { $gte: 1 } },
        { $inc: { "inventory.availableUnits": 1, "inventory.bookedUnits": -1 } },
        { new: true }
      );
      if (!restored) {
        console.warn(
          `[Booking] Cancelled ${booking._id} from ${booking.status} but could not restore inventory ` +
          `on unit ${booking.unitType} (bookedUnits already 0). Inventory may need manual correction.`
        );
      }
    }

    const previousStatus = booking.status;
    booking.status = status;
    if (adminNotes) booking.adminNotes = adminNotes;
    booking.reviewedBy = req.admin._id;
    booking.reviewedAt = new Date();
    booking.statusHistory.push({
      status,
      changedBy: "admin",
      note: adminNotes || `${previousStatus} → ${status}`,
    });
    await booking.save();

    // Sync to Group Buy campaign when booking reaches completed.
    // `confirmed` is no longer reachable here, so verifyPayment is the only
    // path that enrols a member on confirmation.
    if (status === "completed") {
      syncBookingToCampaign(booking, req.admin._id).catch(() => {});
    }

    return res.json({ success: true, data: { status: booking.status, previousStatus } });
  } catch (err) {
    console.error("[Booking] updateBookingStatus error:", err);
    return res.status(500).json({ success: false, message: "Failed to update booking status." });
  }
};

// ── GET /api/bookings/payment-config ──────────────────────────────────────────
// Returns QR URL + UPI ID from server env. Auth-gated so QR is never in client code.
export const getPaymentConfig = async (req, res) => {
  try {
    const qrUrl = process.env.DEALDIRECT_PAYMENT_QR_URL;
    const upiId = process.env.DEALDIRECT_UPI_ID || "dealdirect@upi";

    if (!qrUrl) {
      return res.status(503).json({
        success: false,
        message: "Payment configuration not available. Please contact support.",
      });
    }

    return res.json({
      success: true,
      data: { qrUrl, upiId },
    });
  } catch (err) {
    console.error("[Booking] getPaymentConfig error:", err);
    return res.status(500).json({ success: false, message: "Server error." });
  }
};
