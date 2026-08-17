import mongoose from "mongoose";
import Category from "../models/Category.js";
import PropertyType from "../models/PropertyType.js";
import {
  findActiveCategoryByName,
  findActivePropertyTypeByName,
} from "./activeTaxonomy.js";
import { isActiveCategoryName, isActivePropertyType } from "../config/taxonomy.js";

/**
 * Server-side taxonomy consistency contract.
 *
 * Every write path that accepts taxonomy runs through here. The rule is that a
 * request may not describe the same fact two ways and have the server pick one.
 *
 *   id + name, agreeing        -> accept
 *   id + name, disagreeing     -> REJECT
 *   id with no matching name   -> REJECT
 *   names only                 -> resolve exactly, server-side
 *   unknown name               -> REJECT
 *   type not under the category -> REJECT
 *
 * Why reject rather than reconcile: the corpus this replaces was corrupted by a
 * client that resolved names loosely and a server that stored whatever arrived.
 * Twenty-five of forty-seven listings ended up with references describing a
 * different property than the one they belong to, and no read path noticed
 * because the denormalised name columns still looked right. Silently preferring
 * the id, or silently preferring the name, would recreate exactly that: a
 * disagreement that resolves quietly and shows up months later as a filter
 * returning the wrong set.
 *
 * There is no fallback of any kind. No substring, no case folding, no nearest
 * match, no first-document default.
 */

export class TaxonomyError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'TaxonomyError';
    this.code = code;
    this.statusCode = 400;
  }
}

const isObjectId = (v) => mongoose.Types.ObjectId.isValid(String(v ?? ''));

/**
 * Resolve and validate the taxonomy on an inbound request body.
 *
 * Accepts the four fields as they arrive from JSON or multipart, which are the
 * same shape by the time they reach a controller.
 *
 * @returns {{category: ObjectId|null, propertyType: ObjectId|null,
 *            categoryName: string|null, propertyTypeName: string|null}}
 * @throws {TaxonomyError}
 */
export async function resolveTaxonomy(data = {}) {
  const categoryId = data.category ? String(data.category).trim() : null;
  const typeId = data.propertyType ? String(data.propertyType).trim() : null;
  const categoryName = typeof data.categoryName === 'string' ? data.categoryName.trim() : null;
  const typeName = typeof data.propertyTypeName === 'string' ? data.propertyTypeName.trim() : null;

  // Nothing supplied: not this function's business. Field-level validation
  // elsewhere decides whether taxonomy was required.
  if (!categoryId && !typeId && !categoryName && !typeName) {
    return { category: null, propertyType: null, categoryName: null, propertyTypeName: null };
  }

  const category = await resolveOne({
    id: categoryId, name: categoryName, model: Category, label: 'category',
  });

  const propertyType = await resolveOne({
    id: typeId, name: typeName, model: PropertyType, label: 'propertyType',
    categoryId: category ? category._id : null,
  });

  // The invariant that the other two cannot catch on their own: both halves can
  // resolve correctly while the type sits under a different category, which
  // yields a listing that answers correctly to a name filter and wrongly to a
  // category filter.
  if (category && propertyType) {
    if (!propertyType.category || String(propertyType.category) !== String(category._id)) {
      const parent = propertyType.category
        ? await Category.findById(propertyType.category).select('name').lean()
        : null;
      throw new TaxonomyError(
        `Property type "${propertyType.name}" belongs to ` +
        `${parent ? `"${parent.name}"` : 'no category'}, not "${category.name}".`,
        'TAXONOMY_PARENT_MISMATCH'
      );
    }
  }

  return {
    category: category ? category._id : null,
    propertyType: propertyType ? propertyType._id : null,
    categoryName: category ? category.name : null,
    propertyTypeName: propertyType ? propertyType.name : null,
  };
}

/**
 * Resolve one level. An id and a name must describe the same document.
 */
async function resolveOne({ id, name, model, label, categoryId = null }) {
  if (!id && !name) return null;

  const isCategory = label === 'category';

  if (id) {
    if (!isObjectId(id)) {
      throw new TaxonomyError(`"${label}" is not a valid identifier.`, 'TAXONOMY_INVALID_ID');
    }
    const doc = await model.findById(id).lean();
    if (!doc) {
      throw new TaxonomyError(`No ${label} exists with that identifier.`, 'TAXONOMY_UNKNOWN_ID');
    }
    // An id supplied with a name that does not match it is a contradiction, and
    // an id supplied with no name at all cannot be checked against anything.
    if (name === null) {
      throw new TaxonomyError(
        `"${label}" was supplied without the matching ${label}Name.`,
        'TAXONOMY_NAME_REQUIRED'
      );
    }
    if (doc.name !== name) {
      throw new TaxonomyError(
        `"${label}" identifies "${doc.name}" but ${label}Name says "${name}".`,
        'TAXONOMY_MISMATCH'
      );
    }
    // An id may point at a document that still exists but is no longer offered.
    // The migration left the obsolete rows in place, so "exists" and "is
    // selectable" are different questions and only the second one counts here.
    if (isCategory ? !isActiveCategoryName(doc.name) : !(await isActiveType(doc))) {
      throw new TaxonomyError(`"${doc.name}" is not an active ${label}.`, 'TAXONOMY_RETIRED');
    }
    return doc;
  }

  // Name only: exact, case-sensitive, active taxonomy only, no fallback.
  const doc = isCategory
    ? await findActiveCategoryByName(name)
    : await findActivePropertyTypeByName(name, categoryId);

  if (!doc) {
    // Scoping the type lookup to the category means "not under this category"
    // and "not a type at all" both come back empty, and they are different
    // errors. Telling an owner that "Office Space" is unrecognised when it
    // plainly exists is the kind of message that sends people to support, so
    // check the wider taxonomy before choosing what to say.
    if (!isCategory && categoryId) {
      const elsewhere = await findActivePropertyTypeByName(name, null);
      if (elsewhere) {
        const parent = await Category.findById(elsewhere.category).select('name').lean();
        const intended = await Category.findById(categoryId).select('name').lean();
        throw new TaxonomyError(
          `Property type "${name}" belongs to "${parent?.name}", not "${intended?.name}".`,
          'TAXONOMY_PARENT_MISMATCH'
        );
      }
    }
    throw new TaxonomyError(`"${name}" is not a recognised ${label}.`, 'TAXONOMY_UNKNOWN_NAME');
  }
  return doc;
}

/** Is this property type document canonical for its own parent category? */
async function isActiveType(doc) {
  if (!doc.category) return false;
  const parent = await Category.findById(doc.category).select('name').lean();
  return !!parent && isActivePropertyType(doc.name, parent.name);
}

/**
 * Apply the resolved taxonomy to a request payload in place.
 *
 * Writes the ids and normalises the name columns to the canonical spelling of
 * the documents they resolved to, so the stored row cannot disagree with itself.
 * `subcategory` is cleared: the level is retired (D9) and no new reference may
 * be created, whatever a client sends.
 */
export async function applyTaxonomy(data) {
  const resolved = await resolveTaxonomy(data);

  if (resolved.category) {
    data.category = resolved.category;
    data.categoryName = resolved.categoryName;
  }
  if (resolved.propertyType) {
    data.propertyType = resolved.propertyType;
    data.propertyTypeName = resolved.propertyTypeName;
  }

  delete data.subcategory;
  delete data.subcategoryName;

  return resolved;
}
