import TransactionVerification from "../models/TransactionVerification.js";
import { notifyUsers } from "../services/notificationService.js";

/**
 * The rental renewal clock (Phase 5, F21).
 *
 * Indian residential rent agreements run eleven months, near-universally, to
 * stay outside the Rent Control Acts. DealDirect knows the close date of
 * every verified rental, which no competitor does, so it can reach both
 * sides in month ten — the fortnight when the owner decides whether to renew
 * or relist, and the tenant decides whether to renew or start searching.
 *
 * This is the only true lifetime-value loop the product has. Sales are
 * episodic: a buyer returns in seven years or never. Rentals return every
 * eleven months, and the platform is the one holding the calendar.
 *
 * Fired once per verified rental, at `RENEWAL_NUDGE_MONTHS`, recorded on the
 * verification so a restart or a re-run cannot send it twice. Both parties
 * get their own message, because the action each should take is different.
 */

const RENEWAL_NUDGE_MONTHS = 10;
const AGREEMENT_MONTHS = 11;
const MAX_PER_RUN = 200;

/** `n` months before `date`, clamped for short months (31 Mar minus 1 month). */
function monthsBefore(date, months) {
  const d = new Date(date);
  const target = new Date(d);
  target.setUTCMonth(target.getUTCMonth() - months);
  return target;
}

export async function runRentalClock({ now = new Date() } = {}) {
  // Approved rentals whose verification is at least ten months old and that
  // have not been nudged. There is no upper bound on age: a rental verified
  // fourteen months ago that was never nudged (because this job did not
  // exist) still deserves the message once, and after that never again.
  const dueBefore = monthsBefore(now, RENEWAL_NUDGE_MONTHS);

  const due = await TransactionVerification.find({
    status: "approved",
    closingType: "rented",
    renewalNudgedAt: null,
    reviewedAt: { $ne: null, $lte: dueBefore },
  })
    .populate("property", "title city locality address")
    .limit(MAX_PER_RUN)
    .lean();

  if (!due.length) return { nudged: 0, verifications: 0 };

  const entries = [];
  const ids = [];

  for (const v of due) {
    const title = v.property?.title || "your rented home";
    const where = v.property?.locality || v.property?.city || v.property?.address?.city || "";
    const endsAt = new Date(v.reviewedAt);
    endsAt.setUTCMonth(endsAt.getUTCMonth() + AGREEMENT_MONTHS);
    const endsOn = endsAt.toLocaleDateString("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "long" });

    entries.push({
      user: v.owner,
      title: "Your rental agreement is ending",
      message: `The eleven months on ${title} run out around ${endsOn}. Renew with your tenant, or relist it now and line up the next one.`,
      type: "rental_renewal",
      data: { propertyId: v.property?._id, verificationId: v._id, role: "owner", actionUrl: "/my-properties", actionText: "Relist or renew" },
    });

    entries.push({
      user: v.buyer,
      title: "Your rent agreement is ending",
      message: `Your agreement for ${title}${where ? ` in ${where}` : ""} runs out around ${endsOn}. Renewing, or shall we find you the next one?`,
      type: "rental_renewal",
      data: { propertyId: v.property?._id, verificationId: v._id, role: "tenant", actionUrl: "/properties", actionText: "Start searching" },
    });

    ids.push(v._id);
  }

  // Marked BEFORE sending: a crash between the two costs one nudge, which is
  // the failure everyone prefers over a duplicate on a WhatsApp-billed
  // channel.
  await TransactionVerification.updateMany({ _id: { $in: ids } }, { $set: { renewalNudgedAt: now } });
  await notifyUsers(entries);

  return { nudged: entries.length, verifications: ids.length };
}
