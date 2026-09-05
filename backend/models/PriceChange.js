import mongoose from "mongoose";

/**
 * One recorded change of a listing's asking price (Phase 1 + 4, engine E4).
 *
 * Written from the single place a price is edited, and read by four
 * different features, which is why it is a log rather than a field:
 *
 *   the price-drop alert scan (Phase 1, F9)
 *   price history on the listing (Phase 4, F19)
 *   "asks 8% below the locality median" (Phase 4, F19)
 *   the nightly locality aggregation (Phase 4, E4)
 *
 * `from` is null for the first row of a listing, which is its creation. That
 * row is what makes "days listed" and "no price change since listing"
 * answerable without joining back to the property.
 *
 * Locality and configuration are denormalised because the aggregation groups
 * on them and a listing may be re-localised or re-configured later; the log
 * records what was true when the price was set.
 */
const priceChangeSchema = new mongoose.Schema(
  {
    property: { type: mongoose.Schema.Types.ObjectId, ref: "Property", required: true },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    /** null on the listing row. */
    from: { type: Number, default: null },
    to: { type: Number, required: true },
    /** Negative for a drop. Absent on the listing row. */
    deltaPct: { type: Number, default: null },
    at: { type: Date, default: Date.now, required: true },
    /** "listed" | "edit" | "admin". Who moved it, for the history copy. */
    source: { type: String, enum: ["listed", "edit", "admin"], default: "edit" },

    // Denormalised for the aggregation and the alert scan.
    listingType: { type: String, default: "" },
    city: { type: String, default: "" },
    locality: { type: String, default: "" },
    bhk: { type: String, default: "" },
    propertyTypeName: { type: String, default: "" },
  },
  { versionKey: false }
);

priceChangeSchema.index({ property: 1, at: -1 });
// The scan reads "every drop since the cursor", newest first.
priceChangeSchema.index({ at: -1, deltaPct: 1 });
priceChangeSchema.index({ city: 1, locality: 1, at: -1 });

const PriceChange = mongoose.model("PriceChange", priceChangeSchema);
export default PriceChange;
