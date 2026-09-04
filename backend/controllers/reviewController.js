import mongoose from "mongoose";
import Review, { REVIEW_WINDOW_DAYS } from "../models/Review.js";
import TransactionVerification from "../models/TransactionVerification.js";
import User from "../models/userModel.js";
import { notifyUser } from "../services/notificationService.js";

/**
 * Verified-deal reviews (Phase 3, F16). See models/Review.js for the rules.
 */

const isId = (v) => mongoose.Types.ObjectId.isValid(v);
const same = (a, b) => a && b && String(a) === String(b);

/** Who may review whom on this verification, or null. */
function partyOf(verification, userId) {
  if (same(verification.owner, userId)) return { role: "owner", subject: verification.buyer };
  if (same(verification.buyer, userId)) return { role: "buyer", subject: verification.owner };
  return null;
}

function publicReview(r) {
  return {
    id: r._id,
    authorRole: r.authorRole,
    ratings: r.ratings,
    overall: r.overall ?? overallOf(r.ratings),
    text: r.text,
    publishedAt: r.publishedAt,
    author: r.author && typeof r.author === "object" ? { name: r.author.name, profileImage: r.author.profileImage || null } : undefined,
  };
}

function overallOf(ratings) {
  const values = [ratings?.accuracy, ratings?.responsiveness, ratings?.seriousness].filter((v) => typeof v === "number");
  if (!values.length) return null;
  return Math.round((values.reduce((a, b) => a + b, 0) / values.length) * 10) / 10;
}

/** Publish both sides when both are in. Exported for the job and tests. */
export async function publishPair(verificationId, now = new Date()) {
  const pending = await Review.find({ verification: verificationId, status: "pending" });
  const total = await Review.countDocuments({ verification: verificationId, status: { $ne: "hidden" } });
  if (pending.length && total >= 2) {
    for (const r of pending) {
      r.status = "published";
      r.publishedAt = now;
      await r.save();
      await notifyUser(r.subject, {
        title: "A review about you was published",
        message: "Both sides of your verified deal have reviewed each other. See what they said.",
        type: "review_published",
        data: { reviewId: r._id, verificationId, actionUrl: "/profile", actionText: "See review" },
      });
    }
    return pending.length;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// GET /reviews/eligibility/:verificationId
// ---------------------------------------------------------------------------
export const getEligibility = async (req, res) => {
  try {
    const { verificationId } = req.params;
    if (!isId(verificationId)) return res.status(400).json({ success: false, code: "INVALID_ID", message: "Invalid id" });
    const verification = await TransactionVerification.findById(verificationId).select("owner buyer status property reviewedAt").lean();
    if (!verification) return res.status(404).json({ success: false, code: "NOT_FOUND", message: "Verification not found" });
    const party = partyOf(verification, req.user._id);
    if (!party) return res.status(403).json({ success: false, code: "NOT_A_PARTY", message: "You are not part of this deal" });

    const mine = await Review.findOne({ verification: verificationId, author: req.user._id }).lean();
    const theirs = await Review.findOne({ verification: verificationId, subject: req.user._id }).lean();
    res.status(200).json({
      success: true,
      data: {
        eligible: verification.status === "approved" && !mine,
        role: party.role,
        submitted: !!mine,
        mine: mine ? { status: mine.status, submittedAt: mine.submittedAt, windowEndsAt: mine.windowEndsAt } : null,
        counterpartSubmitted: !!theirs,
        counterpartPublished: theirs?.status === "published" ? publicReview(theirs) : null,
      },
    });
  } catch (error) {
    console.error("[reviews] eligibility failed:", error);
    res.status(500).json({ success: false, message: "Could not check review eligibility" });
  }
};

// ---------------------------------------------------------------------------
// POST /reviews   { verificationId, ratings: {accuracy, responsiveness, seriousness}, text? }
// ---------------------------------------------------------------------------
export const submitReview = async (req, res) => {
  try {
    const { verificationId, ratings, text } = req.body || {};
    if (!isId(verificationId)) return res.status(400).json({ success: false, code: "INVALID_ID", message: "verificationId is required" });

    const verification = await TransactionVerification.findById(verificationId).select("owner buyer status property reviewedAt").lean();
    if (!verification) return res.status(404).json({ success: false, code: "NOT_FOUND", message: "Verification not found" });
    if (verification.status !== "approved") {
      return res.status(409).json({ success: false, code: "NOT_VERIFIED", message: "Reviews open once DealDirect has verified the deal" });
    }
    const party = partyOf(verification, req.user._id);
    if (!party) return res.status(403).json({ success: false, code: "NOT_A_PARTY", message: "You are not part of this deal" });

    const r = ratings || {};
    for (const key of ["accuracy", "responsiveness", "seriousness"]) {
      const v = r[key];
      if (!Number.isInteger(v) || v < 1 || v > 5) {
        return res.status(400).json({ success: false, code: "INVALID_RATING", message: `${key} must be a whole number from 1 to 5` });
      }
    }
    const body = typeof text === "string" ? text.trim().slice(0, 600) : "";

    const now = new Date();
    const existingOther = await Review.findOne({ verification: verificationId, subject: req.user._id }).select("windowEndsAt").lean();
    const windowEndsAt = existingOther?.windowEndsAt || new Date(now.getTime() + REVIEW_WINDOW_DAYS * 86400 * 1000);

    let review;
    try {
      review = await Review.create({
        verification: verificationId,
        property: verification.property,
        author: req.user._id,
        subject: party.subject,
        authorRole: party.role,
        ratings: { accuracy: r.accuracy, responsiveness: r.responsiveness, seriousness: r.seriousness },
        text: body,
        submittedAt: now,
        windowEndsAt,
      });
    } catch (err) {
      if (err?.code === 11000) {
        return res.status(409).json({ success: false, code: "ALREADY_REVIEWED", message: "You have already reviewed this deal" });
      }
      throw err;
    }

    const published = await publishPair(verificationId, now);
    if (!published) {
      await notifyUser(party.subject, {
        title: "Your turn to review",
        message: `The other side of your verified deal has left a review. Yours publishes both at once; you have ${REVIEW_WINDOW_DAYS} days.`,
        type: "review_request",
        data: { verificationId, actionUrl: `/reviews/${verificationId}`, actionText: "Write your review" },
      });
    }

    res.status(201).json({
      success: true,
      data: { id: review._id, status: published ? "published" : "pending", windowEndsAt },
    });
  } catch (error) {
    console.error("[reviews] submit failed:", error);
    res.status(500).json({ success: false, message: "Could not submit the review" });
  }
};

// ---------------------------------------------------------------------------
// GET /reviews/user/:userId?page=&limit=      public, published only
// ---------------------------------------------------------------------------
export const getUserReviews = async (req, res) => {
  try {
    const { userId } = req.params;
    if (!isId(userId)) return res.status(400).json({ success: false, code: "INVALID_ID", message: "Invalid id" });
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 10));

    const filter = { subject: userId, status: "published" };
    const [rows, total, summary] = await Promise.all([
      Review.find(filter).populate("author", "name profileImage").sort({ publishedAt: -1 }).skip((page - 1) * limit).limit(limit),
      Review.countDocuments(filter),
      Review.aggregate([
        { $match: { subject: new mongoose.Types.ObjectId(userId), status: "published" } },
        {
          $group: {
            _id: null,
            count: { $sum: 1 },
            accuracy: { $avg: "$ratings.accuracy" },
            responsiveness: { $avg: "$ratings.responsiveness" },
            seriousness: { $avg: "$ratings.seriousness" },
          },
        },
      ]),
    ]);

    const s = summary[0];
    res.status(200).json({
      success: true,
      data: rows.map(publicReview),
      summary: s
        ? {
            count: s.count,
            accuracy: Math.round(s.accuracy * 10) / 10,
            responsiveness: Math.round(s.responsiveness * 10) / 10,
            seriousness: Math.round(s.seriousness * 10) / 10,
            overall: Math.round(((s.accuracy + s.responsiveness + s.seriousness) / 3) * 10) / 10,
          }
        : { count: 0 },
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (error) {
    console.error("[reviews] list failed:", error);
    res.status(500).json({ success: false, message: "Could not load reviews" });
  }
};

// ---------------------------------------------------------------------------
// GET /reviews/mine     the caller's own reviews, both directions
// ---------------------------------------------------------------------------
export const getMyReviews = async (req, res) => {
  try {
    const me = req.user._id;
    const [written, received] = await Promise.all([
      Review.find({ author: me }).sort({ submittedAt: -1 }).limit(50).lean(),
      Review.find({ subject: me, status: "published" }).populate("author", "name profileImage").sort({ publishedAt: -1 }).limit(50),
    ]);
    res.status(200).json({
      success: true,
      data: {
        written: written.map((r) => ({ ...publicReview(r), status: r.status, verification: r.verification, windowEndsAt: r.windowEndsAt })),
        received: received.map(publicReview),
      },
    });
  } catch (error) {
    console.error("[reviews] mine failed:", error);
    res.status(500).json({ success: false, message: "Could not load your reviews" });
  }
};

/** Summary for a user id, used by the public property payload. */
export async function reviewSummaryFor(userId) {
  const s = await Review.aggregate([
    { $match: { subject: new mongoose.Types.ObjectId(userId), status: "published" } },
    { $group: { _id: null, count: { $sum: 1 }, overall: { $avg: { $avg: ["$ratings.accuracy", "$ratings.responsiveness", "$ratings.seriousness"] } } } },
  ]);
  if (!s[0]) return { count: 0, overall: null };
  return { count: s[0].count, overall: Math.round(s[0].overall * 10) / 10 };
}

export { User };
