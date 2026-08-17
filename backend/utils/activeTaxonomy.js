import Category from "../models/Category.js";
import PropertyType from "../models/PropertyType.js";
import {
  CANONICAL_CATEGORIES,
  CANONICAL_PROPERTY_TYPES,
  isActivePropertyType,
} from "../config/taxonomy.js";

/**
 * The live taxonomy, as opposed to everything the collection happens to contain.
 *
 * The migration is deliberately additive: it seeded the canonical documents and
 * left the obsolete ones in place, because deleting them is a separate reviewed
 * stage. So `categories` currently holds Residential, Commercial and
 * Land & Plots alongside nineteen rows of history including `Buy`, `Rent`,
 * `Apartment` and `Office space`, and `propertytypes` holds the twenty canonical
 * types alongside `Residential`, `Commercial` and `Plot`.
 *
 * Every read path that offers a choice, and every write path that accepts one,
 * goes through here. Without it the Admin dropdown offers `Buy` as a category
 * and the create contract accepts `categoryName: "Apartment"`, because a legacy
 * row with that name genuinely exists and resolves.
 *
 * The criterion is membership in CANONICAL_TAXONOMY, not a list of names to
 * hide. An allow-list derived from the constant the migration seeds from cannot
 * fall out of step with it; a blacklist would need extending by hand every time
 * another piece of history surfaced.
 *
 * A property type must be canonical FOR ITS PARENT. Matching the name alone
 * would readmit exactly the inconsistency this phase removed: the right string
 * filed under the wrong category.
 */

/** Query fragment selecting active categories. */
export const activeCategoryQuery = () => ({ name: { $in: [...CANONICAL_CATEGORIES] } });

/** Active categories, ordered as the canonical definition lists them. */
export async function findActiveCategories() {
  const docs = await Category.find(activeCategoryQuery()).lean();
  return CANONICAL_CATEGORIES
    .map((name) => docs.find((d) => d.name === name))
    .filter(Boolean);
}

/**
 * Active property types. Each is checked against its own parent, so a canonical
 * name hanging off a legacy or wrong category is excluded.
 */
export async function findActivePropertyTypes() {
  const categories = await findActiveCategories();
  if (!categories.length) return [];

  const byId = new Map(categories.map((c) => [String(c._id), c.name]));
  const docs = await PropertyType.find({
    category: { $in: categories.map((c) => c._id) },
    name: { $in: [...CANONICAL_PROPERTY_TYPES] },
  }).lean();

  return docs.filter((d) => isActivePropertyType(d.name, byId.get(String(d.category))));
}

/** One active category by exact name, or null. */
export async function findActiveCategoryByName(name) {
  if (!CANONICAL_CATEGORIES.includes(name)) return null;
  return Category.findOne({ name }).lean();
}

/**
 * One active property type by exact name, or null.
 *
 * When a category is known the lookup is scoped to it, which is what makes
 * "same name under a different category" resolvable rather than ambiguous.
 */
export async function findActivePropertyTypeByName(name, categoryId = null) {
  if (!CANONICAL_PROPERTY_TYPES.includes(name)) return null;

  if (categoryId) {
    const doc = await PropertyType.findOne({ name, category: categoryId }).lean();
    if (!doc) return null;
    const category = await Category.findById(categoryId).lean();
    return isActivePropertyType(name, category?.name) ? doc : null;
  }

  const candidates = await PropertyType.find({ name }).lean();
  for (const doc of candidates) {
    const category = await Category.findById(doc.category).lean();
    if (category && isActivePropertyType(name, category.name)) return doc;
  }
  return null;
}
