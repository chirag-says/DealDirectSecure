import LocalityStat, { SAMPLE_FLOOR } from "../models/LocalityStat.js";
import { localityPage, priceGuidanceFor } from "../services/localityService.js";
import { quarterOf } from "../utils/locality.js";

/**
 * Public locality price pages (Phase 4, F18).
 *
 * These exist for two reasons, in this order: they are the cheapest honest
 * research surface a portal can offer, and they are the only part of this
 * plan that earns organic search traffic. The web app renders them server
 * side for exactly that reason; the mobile screen is a convenience.
 *
 * Everything served here is DealDirect's own asking-price data, published
 * only above the sample floor. There is no valuation, no estimate, and no
 * claim about what anything sold for, because India has no public sold-price
 * registry to build one from.
 */

const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

// ---------------------------------------------------------------------------
// GET /localities?city=&listingType=&limit=
// ---------------------------------------------------------------------------
export const listLocalities = async (req, res) => {
  try {
    const listingType = req.query.listingType === "rent" ? "rent" : "sale";
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 60));
    const city = typeof req.query.city === "string" ? req.query.city.trim().slice(0, 80) : "";

    const filter = { bhk: "all", listingType, published: true, period: { $lte: quarterOf(new Date()) } };
    if (city) filter.city = new RegExp(`^${city.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "i");

    // One row per locality, newest published quarter first.
    const rows = await LocalityStat.find(filter).sort({ period: -1, count: -1 }).limit(limit * 4).lean();

    const seen = new Set();
    const data = [];
    for (const row of rows) {
      if (seen.has(row.slug)) continue;
      seen.add(row.slug);
      data.push({
        slug: row.slug,
        city: row.city,
        locality: row.locality,
        listingType: row.listingType,
        period: row.period,
        count: row.count,
        medianAsking: row.medianAsking,
        qoqPct: row.qoqPct,
      });
      if (data.length >= limit) break;
    }

    res.status(200).json({ success: true, data, sampleFloor: SAMPLE_FLOOR });
  } catch (error) {
    console.error("[locality] list failed:", error);
    res.status(500).json({ success: false, message: "Could not load localities" });
  }
};

// ---------------------------------------------------------------------------
// GET /localities/:slug?listingType=
// ---------------------------------------------------------------------------
export const getLocality = async (req, res) => {
  try {
    const { slug } = req.params;
    if (typeof slug !== "string" || slug.length > 120 || !SLUG_RE.test(slug)) {
      return res.status(404).json({ success: false, code: "LOCALITY_NOT_FOUND", message: "No data for this locality yet" });
    }

    const listingType = req.query.listingType === "rent" ? "rent" : "sale";
    const page = await localityPage(slug, { listingType });

    // A locality below the sample floor is indistinguishable from one that
    // does not exist, deliberately: publishing "we have 3 listings here"
    // invites exactly the inference the floor exists to prevent.
    if (!page) {
      return res.status(404).json({
        success: false,
        code: "LOCALITY_NOT_FOUND",
        message: "We do not have enough listings here to publish a price yet",
      });
    }

    res.status(200).json({ success: true, data: page });
  } catch (error) {
    console.error("[locality] page failed:", error);
    res.status(500).json({ success: false, message: "Could not load this locality" });
  }
};

// ---------------------------------------------------------------------------
// GET /localities/guidance?city=&locality=&listingType=&bhk=
//
// What comparable homes ask, for an owner mid-listing (F19). Public because
// the listing form is reachable before the session settles, and because the
// answer is the same public statistic the locality page shows.
// ---------------------------------------------------------------------------
export const getPriceGuidance = async (req, res) => {
  try {
    const city = typeof req.query.city === "string" ? req.query.city.trim().slice(0, 80) : "";
    const locality = typeof req.query.locality === "string" ? req.query.locality.trim().slice(0, 120) : "";
    if (!city || !locality) {
      return res.status(400).json({ success: false, code: "LOCATION_REQUIRED", message: "city and locality are required" });
    }

    const guidance = await priceGuidanceFor({
      city,
      locality,
      listingType: req.query.listingType,
      bhk: req.query.bhk,
    });

    // 200 with null, not 404: "we have nothing to compare against" is a
    // normal answer for a new locality and the form must not treat it as an
    // error.
    res.status(200).json({ success: true, data: guidance, sampleFloor: SAMPLE_FLOOR });
  } catch (error) {
    console.error("[locality] guidance failed:", error);
    res.status(500).json({ success: false, message: "Could not load price guidance" });
  }
};
