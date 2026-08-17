import Category from "../models/Category.js";
import PropertyType from "../models/PropertyType.js";
import Property from "../models/Property.js";
import { isActiveCategoryName, isActivePropertyType } from "../config/taxonomy.js";

/**
 * What an admin may do to a taxonomy document.
 *
 * Phase 3B turned the taxonomy into a contract. `applyTaxonomy` resolves a
 * property's category and type against real documents by exact name, and the
 * active filters offer only names listed in CANONICAL_TAXONOMY. Both read the
 * same constant, so both assume the documents keep carrying exactly those
 * names.
 *
 * Four admin endpoints could change them, and none knew the contract existed.
 * Renaming `Residential` raises no error anywhere: the document is still valid
 * and still referenced by 37 listings. It just stops matching the allow-list,
 * so it disappears from every dropdown and every create against it starts
 * returning TAXONOMY_UNKNOWN_NAME. Nothing reports that, which makes it worse
 * than a crash. Deleting is faster: twenty requests empty the property type
 * taxonomy and strand every listing in the database.
 *
 * Two separate rules, because they protect different things:
 *
 *   PROTECTED  the document is part of the canonical contract. Immutable
 *              through the API. Changing it breaks resolution for every
 *              listing that names it.
 *
 *   IN_USE     the document is not canonical, but listings still point at it.
 *              Deleting it stands up a dangling reference, which is what the
 *              migration just spent a phase repairing.
 *
 * The guard is deliberately narrow. The additive migration left nineteen
 * obsolete rows behind and the destructive cleanup stage has to remove them, so
 * anything outside the canonical set stays editable and, when unreferenced,
 * deletable.
 */

export class TaxonomyGuardError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TaxonomyGuardError";
    this.code = code;
    this.status = 409;
  }
}

const protectedError = (kind, name) =>
  new TaxonomyGuardError(
    "TAXONOMY_PROTECTED",
    `"${name}" is part of the canonical taxonomy and cannot be renamed, moved or deleted. ` +
    `Change config/taxonomy.js and run a migration instead, so the data and the contract move together.`
  );

const inUseError = (kind, name, count) =>
  new TaxonomyGuardError(
    "TAXONOMY_IN_USE",
    `"${name}" is still referenced by ${count} ${count === 1 ? "listing" : "listings"}. ` +
    `Repoint them before deleting it.`
  );

/** True when this category document is part of the canonical contract. */
export function isProtectedCategory(doc) {
  return !!doc && isActiveCategoryName(doc.name);
}

/**
 * True when this property type is canonical FOR ITS PARENT.
 *
 * The parent matters. A row named `Villa` hanging off a legacy category is not
 * canonical, it is history that happens to share a string, and the cleanup
 * stage needs to be able to delete it.
 */
export async function isProtectedPropertyType(doc) {
  if (!doc) return false;
  const parent = await Category.findById(doc.category).lean();
  return isActivePropertyType(doc.name, parent?.name);
}

/**
 * Refuse an edit or delete of a canonical category.
 *
 * Applied to edits regardless of what the payload contains: there is no field
 * on a canonical category worth changing through this endpoint, and allowing
 * "harmless" edits means deciding which ones are harmless on every future
 * schema change.
 */
export async function assertCategoryMutable(id) {
  const doc = await Category.findById(id).lean();
  if (!doc) return null;
  if (isProtectedCategory(doc)) throw protectedError("category", doc.name);
  return doc;
}

/**
 * Refuse an edit or delete of a canonical property type.
 *
 * Reparenting is the case a name-only check misses. Moving `Villa` from
 * Residential to Commercial leaves the name untouched while recreating exactly
 * the parent mismatch the migration existed to fix, so the guard keys on the
 * document's current state rather than on what the payload touches.
 */
export async function assertPropertyTypeMutable(id) {
  const doc = await PropertyType.findById(id).lean();
  if (!doc) return null;
  if (await isProtectedPropertyType(doc)) throw protectedError("property type", doc.name);
  return doc;
}

/** Refuse to delete a taxonomy document that listings still reference. */
export async function assertNotReferenced(field, doc) {
  const count = await Property.countDocuments({ [field]: doc._id });
  if (count > 0) throw inUseError(field, doc.name, count);
}
