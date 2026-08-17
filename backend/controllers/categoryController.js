// controllers/categoryController.js
// SECURITY FIX: Sanitized error responses to prevent information disclosure
import Category from "../models/Category.js";
import { findActiveCategories } from "../utils/activeTaxonomy.js";
import {
  assertCategoryMutable, assertNotReferenced, TaxonomyGuardError,
} from "../utils/taxonomyGuard.js";

/** Guard failures are a 409 with a code; anything else is a real error. */
const handleGuard = (err, res, fallback) => {
  if (err instanceof TaxonomyGuardError) {
    return res.status(err.status).json({ success: false, message: err.message, code: err.code });
  }
  console.error(fallback.log, err.message);
  return res.status(500).json({ success: false, message: fallback.message });
};

export const createCategory = async (req, res) => {
  try {
    // Category is the top level and has no parent, so the name alone decides
    // uniqueness. This used to key on { name, propertyType }, which was the
    // inverted shape: a "category" was a child of a "property type".
    const exists = await Category.findOne({ name: req.body.name });

    if (exists)
      return res.status(400).json({ success: false, message: "Category already exists" });

    const category = await Category.create(req.body);
    res.status(201).json({ success: true, data: category });
  } catch (err) {
    console.error('[Category] Create error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to create category' });
  }
};

export const getCategories = async (req, res) => {
  try {
    // No populate: a category has no parent to populate. Leaving the old
    // populate("propertyType") in place threw a StrictPopulateError once the
    // path was removed from the schema, which took the endpoint to a 500 and
    // with it every taxonomy dropdown in the web and Admin forms.
    // Active taxonomy only. The migration was additive, so this collection
    // still holds nineteen obsolete rows including the listing intents Buy,
    // Rental and Rent; offering them as categories is how they got into the
    // data in the first place.
    const list = await findActiveCategories();
    res.json({ success: true, data: list });
  } catch (err) {
    console.error('[Category] Get all error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch categories' });
  }
};

export const deleteCategory = async (req, res) => {
  try {
    // Canonical first, then referenced. Both checks run before the delete
    // rather than after, because a taxonomy row is trivial to remove and
    // impossible to put back with the same _id, which is what the listings
    // point at.
    const category = await assertCategoryMutable(req.params.id);
    if (!category) return res.status(404).json({ success: false, message: "Category not found" });
    await assertNotReferenced('category', category);

    await Category.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Category deleted successfully" });
  } catch (err) {
    return handleGuard(err, res, {
      log: '[Category] Delete error:', message: 'Failed to delete category',
    });
  }
};

export const updateCategory = async (req, res) => {
  try {
    const existing = await assertCategoryMutable(req.params.id);
    if (!existing) return res.status(404).json({ success: false, message: "Category not found" });

    const updated = await Category.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    res.json({ success: true, data: updated });
  } catch (err) {
    return handleGuard(err, res, {
      log: '[Category] Update error:', message: 'Failed to update category',
    });
  }
};
