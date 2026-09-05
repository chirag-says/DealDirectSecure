import mongoose from "mongoose";

/**
 * Aggregated asking prices for one locality (Phase 4, engine E4).
 *
 * Produced nightly from DealDirect's own live listings. Two rules make this
 * honest rather than an estimate dressed up as data:
 *
 *   1. THE SAMPLE FLOOR. A row with fewer than `SAMPLE_FLOOR` listings is
 *      computed and stored but never published — `published: false` — so the
 *      public pages and the "below the locality median" line simply do not
 *      appear for a locality with three listings. A median of three is a
 *      coincidence, not a market.
 *
 *   2. IT IS ASKING PRICE, NOT VALUE. India has no public sold-price
 *      registry, so an automated valuation is not buildable here and is not
 *      attempted. Every label the clients render says "asking".
 *
 * One row per (city, locality, listingType, bhk, period). `bhk: "all"` is the
 * locality headline; the specific rows drive "similar 2BHKs ask ...".
 */

export const SAMPLE_FLOOR = 5;

const localityStatSchema = new mongoose.Schema(
  {
    city: { type: String, required: true },
    locality: { type: String, required: true },
    /** Stable url segment for the public page: `city-locality`, lowercased. */
    slug: { type: String, required: true },
    listingType: { type: String, enum: ["rent", "sale"], required: true },
    /** "all" for the locality headline, otherwise "1", "2", "3", "4+". */
    bhk: { type: String, required: true },
    /** `YYYY-Qn`, the quarter the sample was taken in. */
    period: { type: String, required: true },

    count: { type: Number, default: 0 },
    medianAsking: { type: Number, default: 0 },
    p25: { type: Number, default: 0 },
    p75: { type: Number, default: 0 },
    medianPerSqft: { type: Number, default: null },
    /** Percent change against the previous quarter's row, when one exists. */
    qoqPct: { type: Number, default: null },
    published: { type: Boolean, default: false },
    computedAt: { type: Date, default: Date.now },
  },
  { versionKey: false }
);

localityStatSchema.index(
  { city: 1, locality: 1, listingType: 1, bhk: 1, period: 1 },
  { unique: true, name: "uniq_locality_bucket" }
);
localityStatSchema.index({ slug: 1, period: -1 });
localityStatSchema.index({ published: 1, period: -1 });

const LocalityStat = mongoose.model("LocalityStat", localityStatSchema);
export default LocalityStat;
