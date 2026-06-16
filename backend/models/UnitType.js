/**
 * UnitType Model — DealDirect
 * A purchasable unit configuration within a Project.
 * One project has multiple unit types (2BHK, 3BHK, Penthouse, etc.)
 * Each unit type has its own pricing, specs, floor plans, and inventory.
 *
 * Hierarchy: Builder → Project → UnitType → GroupBuyCampaign
 */
import mongoose from "mongoose";

const unitTypeSchema = new mongoose.Schema(
  {
    project: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Project",
      required: [true, "Project reference is required"],
    },
    // Denormalized for efficient queries without populate
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

    // ── Unit Configuration ────────────────────────────────────────────────────
    config: {
      name: {
        type: String,
        required: [true, "Unit type name is required"],
        trim: true,
        maxlength: [100, "Name cannot exceed 100 characters"],
      }, // e.g. "2 BHK Premium"
      bedrooms: { type: Number, min: 0 },
      bathrooms: { type: Number, min: 0 },
      balconies: { type: Number, min: 0 },
      hasUtilityArea: { type: Boolean, default: false },
    },

    // ── Area ──────────────────────────────────────────────────────────────────
    area: {
      carpetSqft: { type: Number, min: 0 },
      builtUpSqft: { type: Number, min: 0 },
      superBuiltUpSqft: { type: Number, min: 0 },
    },

    // ── Facing ────────────────────────────────────────────────────────────────
    facing: [
      {
        type: String,
        enum: ["East", "West", "North", "South", "North East", "North West", "South East", "South West"],
      },
    ],

    // ── Furnishing ────────────────────────────────────────────────────────────
    furnishing: {
      type: String,
      enum: ["Bare Shell", "Unfurnished", "Semi Furnished", "Fully Furnished"],
      default: "Bare Shell",
    },

    // ── Parking ───────────────────────────────────────────────────────────────
    parking: {
      covered: { type: Number, default: 0, min: 0 },
      open: { type: Number, default: 0, min: 0 },
      ev: { type: Number, default: 0, min: 0 },
    },

    // ── Construction Specifications ───────────────────────────────────────────
    // Industry standard — buyers compare specs across projects
    specifications: {
      structure: { type: String, trim: true }, // e.g. "RCC Framed, Seismic Zone II"
      flooring: {
        livingDining: { type: String, trim: true },
        bedrooms: { type: String, trim: true },
        kitchen: { type: String, trim: true },
        bathroom: { type: String, trim: true },
        balcony: { type: String, trim: true },
      },
      kitchen: {
        countertop: { type: String, trim: true },
        isModular: { type: Boolean, default: false },
        chimney: { type: Boolean, default: false },
        sink: { type: String, trim: true },
      },
      bathroom: {
        sanitaryBrand: { type: String, trim: true },
        fittingsBrand: { type: String, trim: true },
        dadoHeight: { type: String, trim: true }, // e.g. "Up to door height"
      },
      doors: {
        mainDoor: { type: String, trim: true },
        internalDoors: { type: String, trim: true },
        finish: { type: String, trim: true },
      },
      windows: {
        type: { type: String, trim: true }, // e.g. "UPVC Sliding"
        mosquitoMesh: { type: Boolean, default: false },
      },
      electrical: {
        wiringType: { type: String, trim: true },   // e.g. "Concealed Copper"
        switchBrand: { type: String, trim: true },  // e.g. "Legrand"
        acPointsPerRoom: { type: Number, min: 0 },
      },
    },

    // ── Floor Plans ───────────────────────────────────────────────────────────
    floorPlans: {
      twoDUrl: { type: String, trim: true },
      threeDUrl: { type: String, trim: true },
    },

    // ── Pricing ───────────────────────────────────────────────────────────────
    pricing: {
      basePrice: { type: Number, min: 0 },        // Total unit base price
      pricePerSqft: { type: Number, min: 0 },     // Auto-calculated
      additionalCharges: {
        plc: { type: Number, default: 0, min: 0 },
        parking: { type: Number, default: 0, min: 0 },
        clubhouse: { type: Number, default: 0, min: 0 },
        legal: { type: Number, default: 0, min: 0 },
        maintenance: { type: Number, default: 0, min: 0 },
      },
      floorRisePerSqft: { type: Number, default: 0, min: 0 }, // ₹ per sqft per floor
      viewPremium: { type: Number, default: 0, min: 0 },      // Premium for view-facing
      effectivePrice: { type: Number, min: 0 },               // Auto-calculated
    },

    // ── Inventory ─────────────────────────────────────────────────────────────
    inventory: {
      totalUnits: { type: Number, min: 0 },
      availableUnits: { type: Number, min: 0 },
      bookedUnits: { type: Number, default: 0, min: 0 },
      blockedUnits: { type: Number, default: 0, min: 0 }, // Admin-blocked units
      towerAllocation: [
        {
          tower: { type: String, trim: true },
          units: { type: Number, min: 0 },
        },
      ],
    },

    // ── Highlights ────────────────────────────────────────────────────────────
    highlights: [{ type: String, trim: true }], // Unit-specific USPs

    // ── Meta ──────────────────────────────────────────────────────────────────
    isActive: { type: Boolean, default: true },
    activeCampaignCount: { type: Number, default: 0, min: 0 }, // denormalized
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ── Pre-save: Auto-calculate derived pricing fields ───────────────────────────
unitTypeSchema.pre("save", function (next) {
  const p = this.pricing;
  if (!p) return next();

  // Price per sqft from carpet area
  if (p.basePrice > 0 && this.area?.carpetSqft > 0) {
    p.pricePerSqft = Math.round(p.basePrice / this.area.carpetSqft);
  }

  // Effective price = base + all additional charges + view premium
  const charges = p.additionalCharges || {};
  p.effectivePrice =
    (p.basePrice || 0) +
    (charges.plc || 0) +
    (charges.parking || 0) +
    (charges.clubhouse || 0) +
    (charges.legal || 0) +
    (charges.maintenance || 0) +
    (p.viewPremium || 0);

  next();
});

// ── Indexes ───────────────────────────────────────────────────────────────────
unitTypeSchema.index({ project: 1, isActive: 1 });
unitTypeSchema.index({ builder: 1 });
unitTypeSchema.index({ "pricing.basePrice": 1 });
unitTypeSchema.index({ "config.bedrooms": 1 });

const UnitType = mongoose.model("UnitType", unitTypeSchema);
export default UnitType;
