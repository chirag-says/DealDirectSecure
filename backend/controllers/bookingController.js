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
import mongoose from "mongoose";
import ProjectBooking from "../models/ProjectBooking.js";
import UnitType from "../models/UnitType.js";
import Project from "../models/Project.js";
import GroupBuyCampaign from "../models/GroupBuyCampaign.js";
import CampaignMember from "../models/CampaignMember.js";
import User from "../models/userModel.js";
import { cloudinary } from "../middleware/upload.js";
import { sendBookingAlert, sendGeneralNotification } from "../utils/emailService.js";
import { Readable } from "stream";
import { reverseMembershipForCancelledBooking } from "../utils/campaignMemberState.js";
import AuditLog from "../models/AuditLog.js";

// ── Helper: record an admin action on a booking ───────────────────────────────
/**
 * Write one audit entry for a money-touching admin action.
 *
 * `statusHistory` on the document is good and stays, but it is not an audit
 * log: it is deleted with the booking and cannot be queried by admin or by
 * date. Payments here are settled by a human reading a UPI reference, with no
 * gateway to reconstruct the decision from afterwards.
 *
 * Never throws. An audit write failing must not roll back a verification that
 * has already moved inventory and told the buyer they are confirmed — the
 * error is logged loudly instead.
 */
const auditBooking = async (req, booking, action, metadata = {}) => {
  try {
    await AuditLog.log({
      admin: req.admin?._id,
      category: "booking_management",
      action,
      resourceType: "ProjectBooking",
      resourceId: booking._id,
      description: `${action} on booking ${String(booking._id).slice(-8).toUpperCase()}`,
      req,
      severity: "medium",
      metadata,
    });
  } catch (err) {
    console.error(`[Booking] AUDIT WRITE FAILED for ${action} on ${booking._id}:`, err.message);
  }
};

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
    const { projectId, unitTypeId, clientName, clientPhone, clientEmail, notes, intent } = req.body;

    // An enquiry is a question; a booking is a payment.
    //
    // Same document, same `enquiry` status — what differs is what the buyer was
    // asked for, and therefore which guards apply. Asking a question must not be
    // gated on the thing that gates paying: three of eight real unit types have
    // no booking amount, and those are exactly the ones an admin most needs to
    // hear demand about.
    const isEnquiry = intent === "enquiry";

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

    // Inventory must be CONFIGURED, not merely non-zero.
    //
    // The old test was `availableUnits === 0`, which is false for undefined. A
    // unit type whose inventory was never filled in therefore accepted
    // enquiries and payments, and every verification then failed the $gte:1
    // decrement and auto-cancelled with "REFUND DUE" — money taken against
    // stock that never existed, by construction rather than by accident.
    if (!(unitType.inventory?.availableUnits >= 1)) {
      return res.status(400).json({
        success: false,
        message: "No units are available for this configuration.",
        code: "NO_INVENTORY",
      });
    }

    // Resolve the token amount BEFORE creating anything, and refuse zero.
    //
    // Three of eight real unit types in the development database carry no
    // paymentTerms.bookingAmount. Where the project has no legacy fallback
    // either, this resolved to 0 and the client rendered "Pay exactly ₹0",
    // after which an admin was asked to verify a payment of nothing.
    //
    // The resolution order is unchanged and still mirrors the client's.
    const tokenAmount =
      unitType.paymentTerms?.bookingAmount ?? project.financials?.bookingAmount ?? 0;

    // Only a BOOKING needs a payable amount. An enquiry with tokenAmount 0 is
    // correct — nobody is being asked to pay anything.
    if (!isEnquiry && !(tokenAmount > 0)) {
      return res.status(400).json({
        success: false,
        message: "Booking is not configured for this unit type yet. Please contact us.",
        code: "BOOKING_NOT_CONFIGURED",
      });
    }

    // One open enquiry per user per unit type.
    //
    // Nothing stopped a user creating hundreds of enquiries on the same unit,
    // which is admin-queue noise rather than data damage — but the queue is
    // how bookings get seen at all. Cancelled and terminal bookings do not
    // count, so withdrawing frees the slot immediately.
    const openStates = ["enquiry", "payment_submitted"];
    const alreadyOpen = await ProjectBooking.countDocuments({
      user: req.user._id,
      unitType: unitTypeId,
      status: { $in: openStates },
    });
    if (alreadyOpen > 0) {
      return res.status(409).json({
        success: false,
        message: "You already have an open enquiry for this unit type.",
        code: "DUPLICATE_ENQUIRY",
      });
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
      source: isEnquiry ? "enquiry" : "booking",
      // Resolved and validated above. Unit-level first, project-level only as a
      // legacy fallback — the same order the client uses, so the quoted and the
      // persisted amounts always agree.
      "payment.tokenAmount": tokenAmount,
      statusHistory: [{
        status: "enquiry",
        changedBy: "user",
        note: isEnquiry ? "Enquiry submitted" : "Booking enquiry created",
      }],
    });

    return res.status(201).json({
      success: true,
      message: isEnquiry
        ? "Thanks — our team will call you shortly."
        : "Booking created. Please complete the token payment.",
      data: {
        bookingId: booking._id,
        tokenAmount: booking.payment.tokenAmount,
        status: booking.status,
        source: booking.source,
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
    const { status, projectId, source, assignedTo, page = 1, limit = 20 } = req.query;
    const filter = {};
    if (status) filter.status = status;
    if (projectId) filter.project = projectId;
    // Enquiries and bookings share a queue and a status; the source is what
    // lets an admin work them differently.
    if (source) filter.source = source;
    if (assignedTo) filter.assignedTo = assignedTo === "none" ? null : assignedTo;

    const [bookings, total] = await Promise.all([
      ProjectBooking.find(filter)
        .populate("project", "basics.name")
        .populate("unitType", "config")
        .populate("assignedTo", "name email")
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
    const { action, adminNotes, overrideDuplicateUtr } = req.body; // action: "approve" | "reject"

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
      // A UTR that already backs another live booking.
      //
      // `payment.utrNumber` is indexed but not unique, and nothing compared it
      // across bookings — so one real ₹50,000 transfer could be screenshotted
      // into two bookings and the verifying admin would see nothing unusual in
      // either. This does not block the legitimate cases (a bank re-using a
      // reference across retries, a corrected typo); it makes them a decision
      // that is stated and recorded rather than one made unknowingly.
      //
      // Cancelled and rejected bookings are excluded: a withdrawn attempt must
      // not block the buyer re-submitting the same genuine payment.
      const utr = booking.payment?.utrNumber?.trim();
      if (utr) {
        const duplicates = await ProjectBooking.find({
          _id: { $ne: booking._id },
          "payment.utrNumber": utr,
          status: { $nin: ["cancelled"] },
        })
          .select("clientName status payment.tokenAmount payment.status createdAt")
          .lean();

        if (duplicates.length > 0 && !overrideDuplicateUtr) {
          return res.status(409).json({
            success: false,
            code: "DUPLICATE_UTR",
            message:
              `UTR ${utr} is already recorded against ${duplicates.length} other ` +
              `booking${duplicates.length === 1 ? "" : "s"}. Confirm the payment is genuinely ` +
              `separate, then re-submit with an explanatory note.`,
            duplicates,
          });
        }

        // An override is only an override if it says why. The note is the
        // whole audit trail for a deliberate duplicate approval.
        if (duplicates.length > 0 && overrideDuplicateUtr && !adminNotes?.trim()) {
          return res.status(400).json({
            success: false,
            code: "OVERRIDE_NEEDS_NOTE",
            message: "Approving a duplicate UTR requires a note explaining why.",
          });
        }
      }

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

      // 5. Audit. statusHistory already records the transition, but it lives on
      //    the booking and dies with it, and it cannot answer "what did this
      //    admin approve last week". Awaited, unlike the notification: the
      //    record of who released money is not fire-and-forget.
      await auditBooking(req, booking, "booking_payment_verified", {
        tokenAmount: booking.payment.tokenAmount,
        utrNumber: booking.payment.utrNumber,
        overrodeDuplicateUtr: Boolean(overrideDuplicateUtr),
        note: adminNotes || null,
      });

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

      await auditBooking(req, booking, "booking_payment_rejected", {
        tokenAmount: booking.payment.tokenAmount,
        utrNumber: booking.payment.utrNumber,
        reason: adminNotes || null,
      });
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

    // ...and reverse it when the booking is cancelled out of a state that had
    // enrolled someone. The sync ran forward only, so a cancelled booking left
    // behind the paid member it created, still counted in paidMemberCount with
    // nothing pointing at the cancellation.
    //
    // Only `confirmed` and `completed` enrol, so only those reverse. Cancelling
    // from `enquiry` or `payment_submitted` invalidates no membership because
    // none was ever created, and treating every cancellation as a reversal
    // would exit members who joined the campaign directly.
    //
    // This is not a refund. tokenStatus stays `paid` because it is true and it
    // is evidence; the booking remains the authoritative payment record.
    if (status === "cancelled") {
      await reverseMembershipForCancelledBooking(booking, previousStatus);
    }

    await auditBooking(req, booking, "booking_status_changed", {
      from: previousStatus,
      to: status,
      releasedInventory: releasesInventory,
      note: adminNotes || null,
    });

    return res.json({ success: true, data: { status: booking.status, previousStatus } });
  } catch (err) {
    console.error("[Booking] updateBookingStatus error:", err);
    return res.status(500).json({ success: false, message: "Failed to update booking status." });
  }
};

// ── POST /api/bookings/:id/contact ────────────────────────────────────────────
// Admin: record a contact attempt.
//
// Appends. `adminNotes` is one mutable string and every verification cycle
// overwrote the last note, so the record of a three-call chase was whatever was
// typed most recently. Lead has modelled this properly all along.
export const addBookingContact = async (req, res) => {
  try {
    const { action = "note", note } = req.body;
    const ALLOWED = ["called", "emailed", "whatsapp", "met", "site_visit", "note"];
    if (!ALLOWED.includes(action)) {
      return res.status(400).json({
        success: false, message: `action must be one of: ${ALLOWED.join(", ")}`,
      });
    }
    if (!note?.trim()) {
      return res.status(400).json({ success: false, message: "A note is required." });
    }

    const booking = await ProjectBooking.findById(req.params.id);
    if (!booking) return res.status(404).json({ success: false, message: "Booking not found." });

    booking.contactHistory.push({
      action, note: note.trim(), by: req.admin._id, at: new Date(),
    });
    await booking.save();

    return res.json({
      success: true,
      message: "Contact recorded.",
      data: { contactHistory: booking.contactHistory },
    });
  } catch (err) {
    console.error("[Booking] addBookingContact error:", err);
    return res.status(500).json({ success: false, message: "Failed to record contact." });
  }
};

// ── PUT /api/bookings/:id/assign ──────────────────────────────────────────────
// Admin: take ownership of an enquiry, or hand it over. `adminId: null` clears.
export const assignBooking = async (req, res) => {
  try {
    const { adminId } = req.body;

    const booking = await ProjectBooking.findById(req.params.id);
    if (!booking) return res.status(404).json({ success: false, message: "Booking not found." });

    if (adminId) {
      const exists = await mongoose.model("Admin").exists({ _id: adminId });
      if (!exists) return res.status(400).json({ success: false, message: "No such admin." });
    }

    booking.assignedTo = adminId || null;
    await booking.save();

    return res.json({
      success: true,
      message: adminId ? "Assigned." : "Assignment cleared.",
      data: { assignedTo: booking.assignedTo },
    });
  } catch (err) {
    console.error("[Booking] assignBooking error:", err);
    return res.status(500).json({ success: false, message: "Failed to assign." });
  }
};

/**
 * States a user may withdraw from themselves.
 *
 * Deliberately stops short of `confirmed`: at that point a unit is held out of
 * inventory and, on the group-buy path, a membership exists. Releasing those is
 * an admin decision with side effects, and it already has a route.
 *
 * `payment_submitted` IS included. A user who paid and wants out should not have
 * to wait for an admin to notice — but see below on what cancelling does NOT do.
 */
export const USER_CANCELLABLE_STATES = ["enquiry", "payment_submitted"];

// ── POST /api/bookings/:id/cancel ─────────────────────────────────────────────
// Withdraw your own booking before it is confirmed.
export const cancelOwnBooking = async (req, res) => {
  try {
    const booking = await ProjectBooking.findById(req.params.id);
    if (!booking) {
      return res.status(404).json({ success: false, message: "Booking not found." });
    }

    // Ownership, checked the same way submitPayment checks it.
    if (!booking.user || booking.user.toString() !== req.user._id.toString()) {
      console.warn(
        `⚠️ IDOR attempt: user ${req.user._id} tried to cancel booking owned by ${booking.user}`
      );
      return res.status(403).json({
        success: false,
        message: "You are not authorized to cancel this booking.",
      });
    }

    if (!USER_CANCELLABLE_STATES.includes(booking.status)) {
      return res.status(400).json({
        success: false,
        code: "NOT_CANCELLABLE",
        message:
          booking.status === "cancelled"
            ? "This booking is already cancelled."
            : `A booking in "${booking.status}" can only be changed by our team. Please contact us.`,
      });
    }

    const previousStatus = booking.status;
    const reason = req.body?.reason?.trim();

    // NOT a refund, and the payment fields are not touched.
    //
    // If the buyer already submitted a UTR and a screenshot, that evidence is
    // the only record the money moved — there is no gateway behind it. It stays
    // exactly as submitted; what changes is the booking's status. The response
    // says so rather than implying the money comes back automatically.
    booking.status = "cancelled";
    booking.statusHistory.push({
      status: "cancelled",
      changedBy: "user",
      note: reason ? `Cancelled by user: ${reason}` : "Cancelled by user",
    });
    await booking.save();

    const hadPayment = previousStatus === "payment_submitted";
    return res.json({
      success: true,
      message: hadPayment
        ? "Booking cancelled. If you have already paid, contact us and we will arrange the refund — your payment details are on record."
        : "Booking cancelled.",
      data: { status: booking.status, previousStatus, refundMayBeDue: hadPayment },
    });
  } catch (err) {
    console.error("[Booking] cancelOwnBooking error:", err);
    return res.status(500).json({ success: false, message: "Failed to cancel booking." });
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
