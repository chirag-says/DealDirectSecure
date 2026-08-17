// controllers/propertyTypeController.js
// SECURITY FIX: Sanitized error responses to prevent information disclosure
import PropertyType from "../models/PropertyType.js";
import { findActivePropertyTypes } from "../utils/activeTaxonomy.js";
import {
  assertPropertyTypeMutable, assertNotReferenced, TaxonomyGuardError,
} from "../utils/taxonomyGuard.js";

/** Guard failures are a 409 with a code; anything else is a real error. */
const handleGuard = (err, res, fallback) => {
  if (err instanceof TaxonomyGuardError) {
    return res.status(err.status).json({ success: false, message: err.message, code: err.code });
  }
  console.error(fallback.log, err.message);
  return res.status(500).json({ success: false, message: fallback.message });
};

export const createPropertyType = async (req, res) => {
  try {
    const { name, category } = req.body;

    // A property type has a parent. The model requires it, so omitting it used
    // to surface as a ValidationError caught by the 500 branch, which reports a
    // client mistake as a server fault.
    if (!category) {
      return res.status(400).json({
        success: false, message: "A property type must belong to a category",
      });
    }

    // Scoped to the parent, matching the { category, name } unique index. The
    // global check that was here refused a legitimate same-name-under-a-
    // different-category create, so the index permitted something the endpoint
    // did not and the two disagreed about what the schema meant.
    const exists = await PropertyType.findOne({ name, category });
    if (exists) {
      return res.status(400).json({
        success: false, message: "That property type already exists in this category",
      });
    }

    const type = await PropertyType.create({ name, category });
    res.status(201).json({ success: true, data: type });
  } catch (err) {
    if (err.name === 'ValidationError' || err.name === 'CastError') {
      return res.status(400).json({ success: false, message: 'Invalid property type' });
    }
    console.error('[PropertyType] Create error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to create property type' });
  }
};

export const getPropertyTypes = async (req, res) => {
  try {
    // Active taxonomy only, and each one checked against its own parent, so a
    // canonical name hanging off a legacy category is excluded too.
    const list = await findActivePropertyTypes();
    res.json({ success: true, data: list });
  } catch (err) {
    console.error('[PropertyType] Get all error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch property types' });
  }
};

export const deletePropertyType = async (req, res) => {
  try {
    const propertyType = await assertPropertyTypeMutable(req.params.id);
    if (!propertyType) return res.status(404).json({ success: false, message: "Property type not found" });
    await assertNotReferenced('propertyType', propertyType);

    await PropertyType.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Property type deleted successfully" });
  } catch (err) {
    return handleGuard(err, res, {
      log: '[PropertyType] Delete error:', message: 'Failed to delete property type',
    });
  }
};

export const updatePropertyType = async (req, res) => {
  try {
    // Keyed on the document's current state, not on what the payload touches.
    // A rename and a reparent are both refused for a canonical type, and the
    // reparent is the one a name-only check would let through.
    const existing = await assertPropertyTypeMutable(req.params.id);
    if (!existing) return res.status(404).json({ success: false, message: "Property type not found" });

    const updated = await PropertyType.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    res.json({ success: true, data: updated });
  } catch (err) {
    return handleGuard(err, res, {
      log: '[PropertyType] Update error:', message: 'Failed to update property type',
    });
  }
};
