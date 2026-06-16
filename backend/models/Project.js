/**
 * Project Model — DealDirect
 * A builder's development project. One project contains multiple UnitTypes.
 * Amenities, media, and documents belong to the project — never per-flat.
 *
 * Hierarchy: Builder → Project → UnitType → GroupBuyCampaign
 */
import mongoose from "mongoose";

const projectSchema = new mongoose.Schema(
  {
    builder: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Builder",
      required: [true, "Builder reference is required"],
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      required: [true, "Admin reference is required"],
    },

    // ── Project Basics ────────────────────────────────────────────────────────
    basics: {
      name: {
        type: String,
        required: [true, "Project name is required"],
        trim: true,
        maxlength: [200, "Project name cannot exceed 200 characters"],
      },
      description: {
        type: String,
        maxlength: [5000, "Description cannot exceed 5000 characters"],
      },
      category: {
        type: String,
        enum: ["Residential", "Commercial", "Mixed Use"],
        required: [true, "Category is required"],
      },
      subType: {
        type: String,
        enum: [
          "Apartment",
          "Villa Community",
          "Plotted Development",
          "Commercial Office",
          "Retail",
          "Mall",
          "Business Park",
        ],
      },
      status: {
        type: String,
        enum: ["New Launch", "Under Construction", "Ready To Move", "Completed"],
        default: "New Launch",
      },
      ownershipType: {
        type: String,
        enum: ["Freehold", "Leasehold", "Cooperative Housing Society", "Power of Attorney"],
        default: "Freehold",
      },
      isVastuCompliant: { type: Boolean, default: false },
      highlights: [{ type: String, trim: true }], // USP bullet points
      reraNumber: { type: String, trim: true },
      reraCertificateUrl: { type: String, trim: true },
    },

    // ── Location ──────────────────────────────────────────────────────────────
    location: {
      country: { type: String, trim: true, default: "India" },
      state: { type: String, required: [true, "State is required"], trim: true },
      city: { type: String, required: [true, "City is required"], trim: true },
      locality: { type: String, trim: true },
      microMarket: { type: String, trim: true },
      addressLine: { type: String, trim: true },
      landmark: { type: String, trim: true },
      pincode: { type: String, trim: true },
      coordinates: {
        lat: { type: Number },
        lng: { type: Number },
      },
      connectivity: {
        distanceToMetro: { type: String, trim: true },
        distanceToAirport: { type: String, trim: true },
        distanceToRailway: { type: String, trim: true },
        distanceToBusStop: { type: String, trim: true },
      },
    },

    // ── Nearby Social Infrastructure ──────────────────────────────────────────
    nearbyPlaces: [
      {
        category: {
          type: String,
          enum: [
            "Education",
            "Healthcare",
            "Shopping",
            "Business",
            "Entertainment",
            "Worship",
            "Government",
            "Transit",
          ],
        },
        name: { type: String, trim: true },
        distance: { type: String, trim: true }, // e.g. "1.2 km"
      },
    ],

    // ── Project Overview ──────────────────────────────────────────────────────
    overview: {
      launchDate: { type: Date },
      possessionDate: { type: Date },
      totalLandArea: { type: String, trim: true }, // e.g. "10 Acres"
      totalTowers: { type: Number, min: 0 },
      floorsPerTower: { type: String, trim: true }, // e.g. "G+25"
      totalUnits: { type: Number, min: 0 },
      openSpacePercentage: { type: Number, min: 0, max: 100 },
    },

    // ── Amenities (shared by all units — never per-flat) ──────────────────────
    amenities: [
      {
        category: {
          type: String,
          enum: ["Lifestyle", "Fitness", "Recreation", "Safety", "Utilities"],
        },
        name: { type: String, trim: true },
        icon: { type: String, trim: true }, // optional icon identifier
      },
    ],

    // ── Media ─────────────────────────────────────────────────────────────────
    media: {
      exteriorImages: [{ type: String }],          // Cloudinary URLs
      droneImages: [{ type: String }],
      masterPlan: [{ type: String }],
      locationMap: [{ type: String }],
      brochureUrl: { type: String, trim: true },
      walkthroughVideoUrl: { type: String, trim: true },
      constructionProgressImages: [{ type: String }],
    },

    // ── Legal Documents ───────────────────────────────────────────────────────
    documents: {
      reraCertificateUrl: { type: String, trim: true },
      commencementCertificateUrl: { type: String, trim: true },
      occupancyCertificateUrl: { type: String, trim: true },
      environmentalClearanceUrl: { type: String, trim: true },
      approvalDocumentUrls: [{ type: String }],
    },

    // ── Legal Status ──────────────────────────────────────────────────────────
    legal: {
      landTitleType: {
        type: String,
        enum: ["Freehold", "Leasehold"],
        default: "Freehold",
      },
      titleClear: { type: Boolean, default: true },
      encumbrances: { type: String, trim: true },
      litigationStatus: {
        type: String,
        enum: ["None", "Pending", "Resolved"],
        default: "None",
      },
      litigationDetails: { type: String, trim: true },
    },

    // ── Payment Plans (informational — how builder expects buyers to pay) ──────
    paymentPlans: [
      {
        planType: {
          type: String,
          enum: ["CLP", "Down Payment", "Flexi", "Subvention"],
        },
        schedule: [
          {
            stage: { type: String, trim: true },   // e.g. "On Booking"
            percentage: { type: Number, min: 0, max: 100 },
          },
        ],
        description: { type: String, trim: true },
      },
    ],

    // ── Financials ────────────────────────────────────────────────────────────
    financials: {
      bookingAmount: { type: Number, min: 0 },     // Amount to book with builder
      gstPercentage: { type: Number, min: 0, max: 28 },
      stampDutyPercentage: { type: Number, min: 0, max: 20 },
      registrationCharges: { type: Number, min: 0 },
    },

    // ── Bank Approvals ────────────────────────────────────────────────────────
    bankApprovals: [
      {
        bankName: { type: String, trim: true },
        loanType: { type: String, trim: true, default: "Home Loan" },
        approvedDate: { type: Date },
      },
    ],

    // ── Construction Updates (quarterly progress) ─────────────────────────────
    constructionUpdates: [
      {
        date: { type: Date, default: Date.now },
        title: { type: String, trim: true },
        description: { type: String, trim: true },
        images: [{ type: String }],
        percentComplete: { type: Number, min: 0, max: 100 },
      },
    ],

    // ── Sales Contact ─────────────────────────────────────────────────────────
    salesContact: {
      managerName: { type: String, trim: true },
      phone: { type: String, trim: true },
      whatsapp: { type: String, trim: true },
      email: { type: String, trim: true, lowercase: true },
    },

    // ── Meta ──────────────────────────────────────────────────────────────────
    isActive: { type: Boolean, default: true },
    unitTypeCount: { type: Number, default: 0, min: 0 }, // denormalized for listing cards
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ── Indexes ───────────────────────────────────────────────────────────────────
projectSchema.index({ builder: 1 });
projectSchema.index({ "location.city": 1, isActive: 1 });
projectSchema.index({ "basics.category": 1, isActive: 1 });
projectSchema.index({ "basics.status": 1 });
projectSchema.index({ createdAt: -1 });
projectSchema.index(
  { "basics.name": "text", "location.city": "text", "location.locality": "text" },
  { name: "project_search_text" }
);

const Project = mongoose.model("Project", projectSchema);
export default Project;
