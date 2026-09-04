import mongoose from "mongoose";

/**
 * A verified-deal review (Phase 3, F16).
 *
 * Only the two parties of an admin-approved TransactionVerification can
 * write one, about each other, once. That is the whole anti-fake-review
 * mechanism: there is no way to review someone you did not verifiably
 * transact with.
 *
 * Simultaneous reveal: a review is written as `pending` and becomes
 * `published` only when the counterpart has submitted theirs too, or when
 * the 14-day window closes, whichever comes first. Nobody can read the other
 * side's review and then write a retaliation.
 *
 * Ratings are about the process, not the person: was the listing accurate,
 * did they respond, were they serious. Free text is short and moderated
 * after the fact (reports go through the existing Report model).
 */
const RATING = { type: Number, min: 1, max: 5, required: true };

const reviewSchema = new mongoose.Schema(
  {
    verification: { type: mongoose.Schema.Types.ObjectId, ref: "TransactionVerification", required: true },
    property: { type: mongoose.Schema.Types.ObjectId, ref: "Property", required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    subject: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    authorRole: { type: String, enum: ["owner", "buyer"], required: true },
    ratings: {
      accuracy: RATING,
      responsiveness: RATING,
      seriousness: RATING,
    },
    text: { type: String, maxlength: 600, default: "" },
    status: { type: String, enum: ["pending", "published", "hidden"], default: "pending" },
    submittedAt: { type: Date, default: Date.now },
    publishedAt: { type: Date, default: null },
    /** The other side's deadline: submit by this or the review publishes alone. */
    windowEndsAt: { type: Date, required: true },
  },
  { timestamps: true }
);

reviewSchema.index({ verification: 1, author: 1 }, { unique: true });
reviewSchema.index({ subject: 1, status: 1, publishedAt: -1 });
reviewSchema.index({ status: 1, windowEndsAt: 1 });

reviewSchema.virtual("overall").get(function overall() {
  const r = this.ratings || {};
  const values = [r.accuracy, r.responsiveness, r.seriousness].filter((v) => typeof v === "number");
  if (!values.length) return null;
  return Math.round((values.reduce((a, b) => a + b, 0) / values.length) * 10) / 10;
});

export const REVIEW_WINDOW_DAYS = 14;

const Review = mongoose.model("Review", reviewSchema);
export default Review;
