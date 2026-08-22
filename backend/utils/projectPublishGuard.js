/**
 * What a project must have before the public can see it.
 *
 * WHY THIS EXISTS
 *
 * A project used to be public the instant an admin clicked create. The schema
 * deliberately requires almost nothing — "no data field is compulsory"
 * (Project.js) — because an admin transcribes a builder's brochure over days,
 * and a form that refuses to save half-finished work just moves the work into a
 * notepad. That part is right.
 *
 * The missing half was a moment where "finished" is asserted. `isActive`
 * defaulted true, so intent (author incrementally) and mechanism (public
 * immediately) contradicted each other, and the buyer got whatever had been
 * typed so far — including, on real data, unit types with no booking amount
 * that produced "Pay exactly ₹0".
 *
 * So: everything stays optional to SAVE. The rules below apply only to PUBLISH.
 *
 * BLOCK vs WARN
 *
 * A BLOCK rule exists only where publishing without it produces something
 * actively wrong: a card that renders blank, a unit nobody can buy, a builder
 * who is no longer trading. Each traces to an observed failure, not to an
 * opinion about completeness.
 *
 * A WARN is everything worth having that admins demonstrably skip. The dev
 * census is unambiguous: 0 of 7 projects have a brochure, 1 of 7 has an
 * occupancy certificate, 5 of 7 have a RERA number. Making those blockers would
 * mean no project could be published at all, and a gate nobody can pass is a
 * gate somebody removes.
 *
 * RERA is deliberately a WARN (ratified 2026-08-22). The registration number is
 * DISPLAYED prominently — that part shipped — but it does not gate publishing.
 * The exposure is recorded in DEALDIRECT-PROJECT-AUTHORING-PIPELINE.md §3.1.
 *
 * ONE SOURCE OF TRUTH
 *
 * Both the publish endpoint and the Admin readiness panel call this. A checklist
 * that is computed twice is a checklist that disagrees with itself, and the
 * admin-facing copy is the half that goes stale.
 */

/** A rule: id, level, human message, and a predicate over the loaded documents. */
const rule = (id, level, message, test) => ({ id, level, message, test });

// ---------------------------------------------------------------------------
// Unit types
// ---------------------------------------------------------------------------

/**
 * Area is measured differently by product type.
 *
 * Carpet area is the legal basis of sale under RERA and is what the price
 * display divides by to show ₹/sqft — so it blocks a residential unit type.
 * A plotted development has no carpet area at all; demanding one there would be
 * asking for a number that does not exist, so plot area blocks instead.
 */
const PLOT_CATEGORIES = ["Plotted Development"];

export const UNIT_BLOCK_RULES = Object.freeze([
  "config.name",
  "pricing.basePrice > 0",
  "inventory.totalUnits >= 1",
  "inventory.availableUnits is set",
  "paymentTerms.bookingAmount > 0",
  "area (carpet, or plot for plotted developments)",
  "isActive",
]);

/**
 * Can a buyer actually purchase this configuration?
 *
 * @param {object} unitType
 * @param {object} [ctx] `{ category }` — the project's subType/category, which
 *   decides whether carpet or plot area is the required measurement.
 * @returns {{ ok: boolean, reasons: string[] }}
 */
export function isUnitTypePublishable(unitType, ctx = {}) {
  const reasons = [];
  if (!unitType) return { ok: false, reasons: ["no unit type"] };

  if (!unitType.config?.name?.trim()) reasons.push("needs a name");
  if (!(unitType.pricing?.basePrice > 0)) reasons.push("needs a base price");
  if (!(unitType.inventory?.totalUnits >= 1)) reasons.push("needs a total unit count");

  // 0 is a legitimate value — a sold-out configuration is still a real, listable
  // product. What is not legitimate is never having said. `== null` catches
  // undefined and null while letting 0 through.
  if (unitType.inventory?.availableUnits == null) {
    reasons.push("needs an available-units figure (0 is fine for sold out)");
  }

  // The ₹0-token defect, closed at the gate as well as at booking time.
  if (!(unitType.paymentTerms?.bookingAmount > 0)) {
    reasons.push("needs a booking amount — buyers cannot pay ₹0");
  }

  const isPlot = PLOT_CATEGORIES.includes(ctx.category);
  if (isPlot) {
    if (!(unitType.area?.plotAreaSqft > 0)) reasons.push("needs a plot area");
  } else if (!(unitType.area?.carpetSqft > 0)) {
    reasons.push("needs a carpet area (the legal basis of sale)");
  }

  if (unitType.isActive === false) reasons.push("is deactivated");

  return { ok: reasons.length === 0, reasons };
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

const anyImage = (p) =>
  [p?.media?.exteriorImages, p?.media?.droneImages, p?.media?.masterPlan]
    .some((arr) => Array.isArray(arr) && arr.length > 0);

export const PROJECT_BLOCK_RULES = Object.freeze([
  "basics.name",
  "basics.category",
  "location.city",
  "at least one image",
  "an active builder",
  "at least one sellable unit type",
]);

const RULES = [
  // ── BLOCK ────────────────────────────────────────────────────────────────
  rule("name", "block", "The project needs a name — it is the listing headline.",
    (p) => Boolean(p.basics?.name?.trim())),

  rule("category", "block", "Pick Residential, Commercial or Mixed Use — buyers filter on it.",
    (p) => Boolean(p.basics?.category)),

  rule("city", "block", "The project needs a city — search and the listing card both use it.",
    (p) => Boolean(p.location?.city?.trim())),

  rule("image", "block", "Add at least one image. A listing card with no picture is not a listing.",
    (p) => anyImage(p)),

  rule("builder", "block", "The builder must be active. A deactivated builder's projects must not stay on sale.",
    (p, { builder }) => Boolean(builder) && builder.isActive !== false),

  rule(
    "sellableUnitType", "block",
    "At least one unit type must be complete enough to buy: name, base price, " +
    "inventory, booking amount and area.",
    (p, { unitTypes = [] }) =>
      unitTypes.some((ut) => isUnitTypePublishable(ut, { category: p.basics?.subType || p.basics?.category }).ok)
  ),

  // ── WARN ─────────────────────────────────────────────────────────────────
  rule("rera", "warn", "No RERA registration number. It is displayed on the listing when present.",
    (p) => Boolean(p.basics?.reraNumber?.trim())),

  rule("brochure", "warn", "No brochure. Buyers ask for it first — 0 of 7 live projects have one.",
    (p) => Boolean(p.media?.brochureUrl?.trim())),

  rule("coordinates", "warn", "No map pin, so the location map cannot render.",
    (p) => Number.isFinite(p.location?.coordinates?.lat) && Number.isFinite(p.location?.coordinates?.lng)),

  rule("description", "warn", "No description. This is the only prose a buyer reads.",
    (p) => Boolean(p.basics?.description?.trim())),

  rule("possession", "warn", "No possession date — the question every buyer asks.",
    (p) => Boolean(p.overview?.possessionDate)),

  rule("amenities", "warn", "No amenities selected.",
    (p) => Array.isArray(p.amenities) && p.amenities.length > 0),

  rule("floorPlan", "warn", "No unit type has a floor plan.",
    (p, { unitTypes = [] }) => unitTypes.some((ut) => ut.floorPlans?.twoDUrl)),
];

/**
 * Evaluate a project against every rule.
 *
 * Returns the FULL checklist, not just the failures: the Admin panel shows what
 * is already done as well as what is missing, and an admin who can only see
 * complaints cannot tell progress from stagnation.
 *
 * @param {object|null} project
 * @param {{ builder?: object, unitTypes?: object[] }} context
 * @returns {{ canPublish: boolean, blockers: object[], warnings: object[], checklist: object[] }}
 */
export function evaluateProjectReadiness(project, context = {}) {
  if (!project) {
    return {
      canPublish: false,
      blockers: [{ rule: "exists", level: "block", message: "Project not found.", passed: false }],
      warnings: [],
      checklist: [],
    };
  }

  const checklist = RULES.map(({ id, level, message, test }) => {
    let passed = false;
    try {
      passed = Boolean(test(project, context));
    } catch {
      // A rule that throws on odd data must not take the whole gate down; it
      // reports as unmet, which is the safe direction.
      passed = false;
    }
    return { rule: id, level, message, passed };
  });

  const blockers = checklist.filter((c) => c.level === "block" && !c.passed);
  const warnings = checklist.filter((c) => c.level === "warn" && !c.passed);

  return { canPublish: blockers.length === 0, blockers, warnings, checklist };
}

/**
 * Is this project visible to the public right now?
 *
 * Backwards compatible on purpose. The live projects predate `publication`
 * entirely, so a strict `status === "published"` read would have made every one
 * of them 404 the moment this deployed. Absent field falls back to `isActive`,
 * which is what those records actually carry.
 */
export function isPubliclyVisible(project) {
  if (!project) return false;
  if (project.publication?.status) return project.publication.status === "published";
  return project.isActive !== false;
}

/**
 * The Mongo filter form of `isPubliclyVisible`, for list queries.
 *
 * Two clauses, not three. An earlier version also carried
 * `{ publication: { $exists: false }, ... }`, which is redundant: if the
 * `publication` subdocument is absent then `publication.status` is absent too,
 * so the second clause already matches. Mutation testing found it — breaking
 * the redundant clause changed no behaviour and killed no test, which is the
 * signal that a line is not earning its place.
 */
export function publicProjectFilter() {
  return {
    $or: [
      { "publication.status": "published" },
      // Legacy records, written before the lifecycle field existed. Judged on
      // `isActive`, which is what they actually carry. Without this every live
      // project would disappear from the site the moment this deployed.
      { "publication.status": { $exists: false }, isActive: { $ne: false } },
    ],
  };
}
