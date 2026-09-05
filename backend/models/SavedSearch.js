import mongoose from "mongoose";

const savedSearchSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    name: { type: String, required: true },
    filters: {
      search: { type: String, default: "" },
      city: { type: String, default: "" },
      propertyType: { type: String, default: "" },
      priceRange: { type: String, default: "" },
      availableFor: { type: String, default: "" },
    },
    notifyEmail: { type: Boolean, default: true },
    notifyInApp: { type: Boolean, default: true },
    /**
     * Push (Phase 1, F8). Defaults on: a saved search whose whole purpose is
     * to tell you when something appears should reach the phone that asked.
     * The three flags NARROW the channel policy, they never widen it.
     */
    notifyPush: { type: Boolean, default: true },
    isActive: { type: Boolean, default: true },

    /**
     * Match bookkeeping (Phase 1, F8). Written by `notifySavedSearchMatches`
     * so the Searches list can say "3 new since Tuesday" instead of showing a
     * row that looks inert. `matchCount` is lifetime, not unread.
     */
    lastMatchAt: { type: Date, default: null },
    matchCount: { type: Number, default: 0 },
  },
  { timestamps: true }
);

// The fan-out reads active searches by city on every listing creation.
savedSearchSchema.index({ isActive: 1, "filters.city": 1 });
savedSearchSchema.index({ user: 1, createdAt: -1 });

const SavedSearch = mongoose.model("SavedSearch", savedSearchSchema);
export default SavedSearch;
