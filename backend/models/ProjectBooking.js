/**
 * ProjectBooking Model — DealDirect
 * Tracks a client's booking request for a specific unit type in a project.
 *
 * Payment Flow (QR-based):
 *   1. Client fills booking form → status: "enquiry"
 *   2. Client shown DealDirect UPI QR code for token amount
 *   3. Client pays, enters UTR number + uploads screenshot → status: "payment_submitted"
 *   4. Admin verifies payment → status: "confirmed"
 *   5. Deal proceeds offline → status: "completed"
 */
import mongoose from "mongoose";

const projectBookingSchema = new mongoose.Schema(
  {
    // ── References ─────────────────────────────────────────────────────────────
    project: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Project",
      required: [true, "Project reference is required"],
    },
    unitType: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "UnitType",
      required: [true, "Unit type reference is required"],
    },
    builder: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Builder",
      required: [true, "Builder reference is required"],
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    // ── Client Contact Details ────────────────────────────────────────────────
    clientName: {
      type: String,
      required: [true, "Client name is required"],
      trim: true,
      maxlength: [100, "Name cannot exceed 100 characters"],
    },
    clientPhone: {
      type: String,
      required: [true, "Client phone is required"],
      trim: true,
      match: [/^\+?[0-9]{10,15}$/, "Invalid phone number"],
    },
    clientEmail: {
      type: String,
      trim: true,
      lowercase: true,
      match: [/^\S+@\S+\.\S+$/, "Invalid email"],
    },
    notes: {
      type: String,
      trim: true,
      maxlength: [500, "Notes cannot exceed 500 characters"],
    },

    // ── How this record started ───────────────────────────────────────────────
    //
    // Both an enquiry and a booking are the same document in the same `enquiry`
    // status; what differs is what the buyer was asked for. Until now the only
    // buyer CTA on a project opened with a QR code and a demand for money, and
    // seven live projects produced zero bookings. This lets a buyer ask a
    // question, and lets an admin tell the two apart in the queue.
    source: {
      type: String,
      enum: ["enquiry", "booking"],
      default: "booking",
      index: true,
    },

    // ── Pipeline ──────────────────────────────────────────────────────────────
    //
    // `adminNotes` below is a single mutable string: every verification or
    // rejection cycle overwrote the previous note. Lead already models this
    // properly, and project demand deserves the same — who called, when, and
    // what happened.
    contactHistory: [
      {
        action: {
          type: String,
          enum: ["called", "emailed", "whatsapp", "met", "site_visit", "note"],
          default: "note",
        },
        note: { type: String, trim: true, maxlength: 1000 },
        by: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" },
        at: { type: Date, default: Date.now },
      },
    ],

    // Which admin owns this one. Without it, "who is handling this?" has no
    // answer and every enquiry is everybody's and nobody's.
    assignedTo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      default: null,
      index: true,
    },

    // ── Status Lifecycle ──────────────────────────────────────────────────────
    // enquiry → payment_submitted → confirmed → cancelled / completed
    status: {
      type: String,
      enum: ["enquiry", "payment_submitted", "confirmed", "cancelled", "completed"],
      default: "enquiry",
    },
    statusHistory: [
      {
        status: { type: String },
        changedBy: { type: String },
        changedAt: { type: Date, default: Date.now },
        note: { type: String },
      },
    ],

    // ── QR Payment Details ────────────────────────────────────────────────────
    // Client pays token amount via DealDirect UPI QR code
    payment: {
      tokenAmount: { type: Number, default: 0 },   // Amount shown on QR screen
      utrNumber: { type: String, trim: true },       // Client-entered UTR / Ref ID
      screenshotUrl: { type: String, trim: true },   // Cloudinary URL of payment proof
      submittedAt: { type: Date },
      verifiedAt: { type: Date },
      verifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: "Admin", default: null },
      status: {
        type: String,
        enum: ["pending", "submitted", "verified", "rejected"],
        default: "pending",
      },
      rejectionReason: { type: String, trim: true },
    },

    // ── Admin ─────────────────────────────────────────────────────────────────
    adminNotes: { type: String, trim: true },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: "Admin", default: null },
    reviewedAt: { type: Date, default: null },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ── Indexes ───────────────────────────────────────────────────────────────────
projectBookingSchema.index({ project: 1, status: 1 });
projectBookingSchema.index({ unitType: 1, status: 1 });
projectBookingSchema.index({ user: 1 });
projectBookingSchema.index({ clientPhone: 1 });
projectBookingSchema.index({ "payment.utrNumber": 1 });
projectBookingSchema.index({ createdAt: -1 });

const ProjectBooking = mongoose.model("ProjectBooking", projectBookingSchema);
export default ProjectBooking;
