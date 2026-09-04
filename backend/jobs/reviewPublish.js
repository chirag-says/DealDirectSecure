import Review from "../models/Review.js";
import { notifyUser } from "../services/notificationService.js";

/**
 * Publish reviews whose reveal window closed with only one side written
 * (Phase 3, F16). The pair case is handled at submit time; this job is the
 * deadline. Idempotent: a published review is never touched again.
 */
export async function publishExpiredReviews({ now = new Date() } = {}) {
  const due = await Review.find({ status: "pending", windowEndsAt: { $lte: now } });
  let published = 0;
  for (const r of due) {
    r.status = "published";
    r.publishedAt = now;
    await r.save();
    published += 1;
    await notifyUser(r.subject, {
      title: "A review about you was published",
      message: "The review window on your verified deal has closed and the other side's review is now visible.",
      type: "review_published",
      data: { reviewId: r._id, verificationId: r.verification, actionUrl: "/profile", actionText: "See review" },
    });
  }
  return { published };
}
