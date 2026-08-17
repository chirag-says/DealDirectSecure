// controllers/categoryController.js
// SECURITY FIX: Sanitized error responses to prevent information disclosure
import Category from "../models/Category.js";
import { findActiveCategories } from "../utils/activeTaxonomy.js";

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
    const category = await Category.findByIdAndDelete(req.params.id);
    if (!category) return res.status(404).json({ success: false, message: "Category not found" });
    res.json({ success: true, message: "Category deleted successfully" });
  } catch (err) {
    console.error('[Category] Delete error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to delete category' });
  }
};

export const updateCategory = async (req, res) => {
  try {
    const updated = await Category.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    if (!updated) return res.status(404).json({ success: false, message: "Category not found" });
    res.json({ success: true, data: updated });
  } catch (err) {
    console.error('[Category] Update error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to update category' });
  }
};
