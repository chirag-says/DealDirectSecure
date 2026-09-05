import mongoose from "mongoose";

/**
 * A privately saved property (Phase 1, engine E5).
 *
 * THE INVARIANT THAT DEFINES THIS COLLECTION: a shortlist entry notifies
 * nobody, creates no Lead, and is not capped. It is the buyer's own notebook.
 * The enquiry — `POST /properties/interested/:id`, capped at five, which
 * emails and WhatsApps the owner — is a different, deliberate act. Wiring a
 * shortlist control to the interest endpoint would silently disclose a
 * casual save to the owner, which is the exact behaviour the research
 * identified as the single most harmful thing the product did.
 *
 * The clients enforce this by construction too: the mobile shortlist module
 * imports no interest hook, and this controller imports neither `Lead` nor
 * the notification service.
 */
const shortlistSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    property: { type: mongoose.Schema.Types.ObjectId, ref: "Property", required: true },
    /** The buyer's own note. Never shown to the owner. */
    note: { type: String, maxlength: 300, default: "" },
    addedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

// One row per person per property; a repeat save is an update, not a duplicate.
shortlistSchema.index({ user: 1, property: 1 }, { unique: true });
shortlistSchema.index({ user: 1, addedAt: -1 });
// The price-drop scan reads this direction: who is watching this property.
shortlistSchema.index({ property: 1 });

const Shortlist = mongoose.model("Shortlist", shortlistSchema);
export default Shortlist;

/**
 * A read-only share of one person's shortlist (Phase 1, F7).
 *
 * The research is explicit that home buying is a group decision and that the
 * share is also the cheapest referral loop available. The token is the whole
 * authorisation: anyone holding it sees the list and nothing else — no email,
 * no phone, no other list, no ability to change anything. It expires, and the
 * owner can revoke it, because a link that lives forever is a link that ends
 * up somewhere its author did not intend.
 */
const shortlistShareSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    token: { type: String, required: true, unique: true },
    /** What the recipient is told to call this list. The owner's first name only. */
    label: { type: String, maxlength: 60, default: "" },
    expiresAt: { type: Date, required: true },
    revokedAt: { type: Date, default: null },
    views: { type: Number, default: 0 },
    lastViewedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

shortlistShareSchema.index({ user: 1, createdAt: -1 });
// Mongo removes the row once it is a week past its own expiry, so a dead
// link 404s rather than lingering as a revoked-but-present record.
shortlistShareSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 7 * 24 * 3600 });

export const ShortlistShare = mongoose.model("ShortlistShare", shortlistShareSchema);
