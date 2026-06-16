/**
 * Builder Model — DealDirect
 * Builder profile + contact card. Builders do NOT log in.
 * Admin creates builders and manages all projects on their behalf.
 * Extended with profile fields for the project listing "About the Developer" section.
 */
import mongoose from "mongoose";

const builderSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Builder name is required"],
      trim: true,
      maxlength: [150, "Name cannot exceed 150 characters"],
    },
    company: {
      type: String,
      trim: true,
      maxlength: [200, "Company name cannot exceed 200 characters"],
    },
    phone: {
      type: String,
      required: [true, "Phone number is required"],
      trim: true,
    },
    alternatePhone: {
      type: String,
      trim: true,
    },
    email: {
      type: String,
      lowercase: true,
      trim: true,
    },

    // Credentials (stored for reference, not validated)
    reraNumber: { type: String, trim: true },
    gstNumber: { type: String, trim: true },

    // Location
    address: {
      line: { type: String },
      city: { type: String },
      state: { type: String },
    },

    // ── Builder Profile (displayed on project listing pages) ──────────────────
    description: {
      type: String,
      maxlength: [2000, "Description cannot exceed 2000 characters"],
    },
    yearEstablished: { type: Number, min: 1900, max: new Date().getFullYear() },
    totalProjectsDelivered: { type: Number, default: 0, min: 0 },
    totalSqFtDelivered: { type: String, trim: true }, // e.g. "10 million sq ft"
    operatingCities: [{ type: String, trim: true }],
    awards: [
      {
        name: { type: String, trim: true },
        year: { type: Number },
      },
    ],
    websiteUrl: { type: String, trim: true },
    logoUrl: { type: String, trim: true }, // Cloudinary URL

    // ── Admin metadata ────────────────────────────────────────────────────────
    notes: {
      type: String,
      maxlength: [1000, "Notes cannot exceed 1000 characters"],
    },
    isActive: { type: Boolean, default: true },
    addedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ── Indexes ──────────────────────────────────────────────────────────────────
builderSchema.index({ phone: 1 }, { unique: true });
builderSchema.index({ email: 1 }, { sparse: true });
builderSchema.index({ name: "text", company: "text" }); // Full-text search
builderSchema.index({ isActive: 1 });
builderSchema.index({ createdAt: -1 });

// ── Virtual: property count (populated on demand) ────────────────────────────
// Not stored — queried separately when needed

const Builder = mongoose.model("Builder", builderSchema);
export default Builder;
