import mongoose from "mongoose";

/**
 * PropertyType: the second level of the property taxonomy.
 *
 *   Category  ->  PropertyType
 *
 * Apartment / Flat, Villa, Office Space, and the rest. Every property type
 * belongs to exactly one category.
 *
 * This collection used to hold the PARENT level (Residential, Commercial, Plot)
 * with no parent ref of its own. The two levels were swapped; see Category.js.
 *
 * `name` is unique per category rather than globally, because the same type
 * name could legitimately exist under two categories in future. The compound
 * index enforces that, and it is what stops the taxonomy reacquiring a
 * duplicate like the `Office Space` / `Office space` pair that made the old
 * data ambiguous to migrate.
 */
const propertyTypeSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },

    // Required for every document created from here on. The three legacy rows
    // that predate the redesign (Residential, Commercial, Plot) have no parent
    // and are deleted in the separate destructive cleanup stage, not here.
    // Mongoose validates on write, not on read, so they load without complaint.
    category: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Category",
      required: true,
      index: true,
    },
  },
  { timestamps: true }
);

propertyTypeSchema.index({ category: 1, name: 1 }, { unique: true });

export default mongoose.model("PropertyType", propertyTypeSchema);
