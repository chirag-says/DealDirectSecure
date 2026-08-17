import mongoose from "mongoose";

/**
 * Category: the top level of the property taxonomy.
 *
 *   Category  ->  PropertyType
 *
 * Residential, Commercial, Land & Plots. Nothing above it.
 *
 * This collection used to hold the CHILD level (Apartment, Villa, Office Space)
 * and carried a `propertyType` parent pointing the other way, so every name in
 * the codebase meant its opposite: `Property.category` resolved to a property
 * type, and the Admin "add category" screen asked for a property type as the
 * parent. The levels were consistently swapped rather than randomly wrong,
 * which is why nothing looked broken from inside any single file.
 *
 * The parent ref is gone rather than repointed. A category has no parent.
 */
const categorySchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true, trim: true },
  },
  { timestamps: true }
);

export default mongoose.model("Category", categorySchema);
