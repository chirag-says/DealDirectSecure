/**
 * The unit-type inventory invariant, and the only safe way to correct it.
 *
 * WHY
 *
 * `updateUnitType` accepted a wholesale `inventory` object from the admin form.
 * Nothing checked that the numbers agreed with each other, and nothing
 * reconciled them against confirmed bookings — so one careless edit silently
 * desynchronised counters that the booking engine maintains atomically. The
 * engine is careful ($gte:1 decrement before the confirmation persists, restore
 * on cancel); the edit form could undo all of it in a keystroke.
 *
 * Corrections ARE legitimately needed. Builders sell through channels DealDirect
 * cannot see, and the cancel path already logs "inventory may need manual
 * correction". The answer is not to forbid edits, it is to make them deltas with
 * a stated reason instead of blind overwrites.
 *
 * THE INVARIANT
 *
 *   totalUnits = availableUnits + bookedUnits + blockedUnits
 *
 * with every term >= 0, and the tower split never claiming more units than exist.
 */

export class InventoryError extends Error {
  constructor(message, code = "INVENTORY_INVALID") {
    super(message);
    this.name = "InventoryError";
    this.code = code;
    this.status = 400;
  }
}

/** Fields an adjustment may move. `totalUnits` is deliberately included. */
export const ADJUSTABLE_FIELDS = Object.freeze([
  "totalUnits",
  "availableUnits",
  "bookedUnits",
  "blockedUnits",
]);

const n = (v) => (Number.isFinite(v) ? v : 0);

/**
 * Check an inventory object against the invariant.
 *
 * @param {object} inventory
 * @param {object} [opts]
 * @param {number} [opts.totalTowers] project.overview.totalTowers, when set
 * @returns {string[]} problems, empty when valid
 */
export function inventoryProblems(inventory = {}, opts = {}) {
  const problems = [];

  const total = inventory.totalUnits;
  const available = inventory.availableUnits;
  const booked = n(inventory.bookedUnits);
  const blocked = n(inventory.blockedUnits);

  // An unconfigured unit type is not "invalid" — it is a draft. The publish
  // gate is what refuses to sell it; this function only judges arithmetic on
  // numbers that are actually present.
  if (total == null && available == null) return problems;

  for (const [label, value] of [
    ["totalUnits", total], ["availableUnits", available],
    ["bookedUnits", booked], ["blockedUnits", blocked],
  ]) {
    if (value != null && (!Number.isFinite(value) || value < 0)) {
      problems.push(`${label} must be zero or more`);
    }
  }
  if (problems.length) return problems;

  if (total != null && available != null) {
    const sum = n(available) + booked + blocked;
    if (sum !== total) {
      problems.push(
        `available (${available}) + booked (${booked}) + blocked (${blocked}) = ${sum}, ` +
        `which does not match totalUnits (${total})`
      );
    }
  }

  const towers = Array.isArray(inventory.towerAllocation) ? inventory.towerAllocation : [];
  if (towers.length) {
    const names = towers.map((t) => (t?.tower || "").trim().toLowerCase()).filter(Boolean);
    if (new Set(names).size !== names.length) {
      problems.push("the same tower is listed more than once");
    }
    const allocated = towers.reduce((acc, t) => acc + n(t?.units), 0);
    if (total != null && allocated > total) {
      problems.push(`the tower split allocates ${allocated} units but only ${total} exist`);
    }
    if (Number.isFinite(opts.totalTowers) && opts.totalTowers > 0 && names.length > opts.totalTowers) {
      problems.push(
        `${names.length} towers are listed but the project declares ${opts.totalTowers}`
      );
    }
  }

  return problems;
}

/** Throw unless the inventory satisfies the invariant. */
export function assertInventoryValid(inventory, opts) {
  const problems = inventoryProblems(inventory, opts);
  if (problems.length) {
    throw new InventoryError(`Inventory does not add up: ${problems.join("; ")}`);
  }
}

/**
 * Apply a signed delta to one field and return the resulting inventory.
 *
 * Deltas rather than assignment, because "set available to 7" loses the reason
 * and races the booking engine; "+2 available, the builder released two units"
 * both states intent and composes correctly with a concurrent booking.
 *
 * EVERY DELTA HAS A COUNTERPART. The invariant is
 * `total = available + booked + blocked`, so no single field can move alone —
 * an isolated increment always unbalances the books. The counterpart is chosen
 * to match what the admin actually means:
 *
 *   totalUnits   +2  stock arrives     → availableUnits +2
 *   blockedUnits +1  hold one back     → availableUnits −1   (a transfer)
 *   bookedUnits  −1  correct a miscount→ availableUnits +1   (a transfer)
 *   availableUnits −3 sold elsewhere   → totalUnits −3       (stock leaves)
 *
 * So a move to totalUnits is stock entering or leaving, a move to available is
 * the same seen from the other side, and blocked/booked are transfers within
 * the stock that already exists.
 *
 * @returns {{ inventory: object, summary: string }}
 */
export function applyInventoryDelta(current = {}, { field, delta, totalTowers } = {}) {
  if (!ADJUSTABLE_FIELDS.includes(field)) {
    throw new InventoryError(
      `field must be one of: ${ADJUSTABLE_FIELDS.join(", ")}`, "INVENTORY_BAD_FIELD"
    );
  }
  if (!Number.isFinite(delta) || delta === 0) {
    throw new InventoryError("delta must be a non-zero number", "INVENTORY_BAD_DELTA");
  }

  const next = {
    totalUnits: current.totalUnits,
    availableUnits: current.availableUnits,
    bookedUnits: n(current.bookedUnits),
    blockedUnits: n(current.blockedUnits),
    towerAllocation: current.towerAllocation || [],
  };

  if (next.totalUnits == null && next.availableUnits == null) {
    throw new InventoryError(
      "This unit type has no inventory yet. Set it in the unit type form first.",
      "INVENTORY_UNSET"
    );
  }

  next[field] = n(next[field]) + delta;

  // The counterpart that keeps `total = available + booked + blocked` true.
  if (field === "totalUnits") {
    // Stock entering or leaving the project.
    next.availableUnits = n(next.availableUnits) + delta;
  } else if (field === "availableUnits") {
    // The same event described from the other side.
    next.totalUnits = n(next.totalUnits) + delta;
  } else {
    // blocked / booked are transfers WITHIN existing stock: holding a unit back
    // takes it off the market, it does not conjure an eleventh unit.
    next.availableUnits = n(next.availableUnits) - delta;
  }

  for (const key of ADJUSTABLE_FIELDS) {
    if (next[key] != null && next[key] < 0) {
      const isCounterpart = key !== field;
      throw new InventoryError(
        isCounterpart
          ? `That would leave ${key} at ${next[key]} — there are not enough units to move.`
          : `That would leave ${key} at ${next[key]}. Adjust by at most ${n(current[key])}.`,
        "INVENTORY_NEGATIVE"
      );
    }
  }

  assertInventoryValid(next, { totalTowers });

  const sign = delta > 0 ? `+${delta}` : `${delta}`;
  return { inventory: next, summary: `${field} ${sign} (now ${next[field]})` };
}
