import CampaignMember from "../models/CampaignMember.js";

/**
 * The narrow state contract for CampaignMember.
 *
 * Not a state machine, and deliberately not the beginning of one. It encodes
 * one invariant: a membership must never sit in a state that contradicts what
 * the money says. Everything else about campaign lifecycle is left alone.
 *
 * THE TWO STATES THAT WERE REACHABLE AND WRONG
 *
 * `active + paid → exited` by self-service. `exitCampaign` filtered on
 * `status: "active"` and never read `tokenStatus`, so a paid user could exit
 * their own campaign. `paidMemberCount` dropped, `tokenStatus` stayed `paid`,
 * and the response promised a manual refund while recording that obligation
 * nowhere. The surviving document — paid and exited together — was the only
 * evidence money was owed, and nothing surfaced it.
 *
 * `paid` surviving a cancelled booking. `syncBookingToCampaign` enrols a user
 * as a PAID member when their booking is verified or completed, and ran forward
 * only. Cancelling that booking restored inventory and wrote history but left
 * the member it had created counting toward `paidMemberCount` forever.
 *
 * WHAT `refunded` MEANS HERE
 *
 * Nothing yet. `tokenStatus: "refunded"` is reserved for a manual refund flow
 * that does not exist, and nothing in this file writes it. A reversal that
 * quietly claimed the money went back would be a lie in the one field anyone
 * would check, and there is no gateway that could make it true.
 *
 * WHY REVERSAL IS NOT A REFUND
 *
 * `ProjectBooking` is the authoritative payment record: it holds the amount,
 * the UTR, the screenshot and its own status history. The CampaignMember is a
 * projection created by the sync, carrying a copy of the reference and no
 * amount at all. Reversing it records that the membership is no longer valid
 * and stops it being counted. Whether money goes back is the booking's
 * business, and a human's.
 */

/**
 * Booking states from which a paid CampaignMember exists.
 *
 * Enrolment happens on `verifyPayment` (booking → `confirmed`) and on the
 * transition to `completed`. So cancelling out of these two invalidates a
 * membership that exists; cancelling out of `enquiry` or `payment_submitted`
 * invalidates nothing, because nobody was enrolled.
 *
 * This is the same set as STATUSES_HOLDING_INVENTORY, and not by coincidence:
 * the states that hold a unit are the states that made someone a paid member.
 * They are kept separate anyway, because they answer different questions and a
 * future change to one should not silently move the other.
 */
export const BOOKING_STATES_WITH_ENROLMENT = ["confirmed", "completed"];

export class CampaignMemberStateError extends Error {
  constructor(code, message, status = 409) {
    super(message);
    this.name = "CampaignMemberStateError";
    this.code = code;
    this.status = status;
  }
}

/**
 * Refuse a self-service exit once money has been taken.
 *
 * Current product policy is option C: the membership and its evidence are kept,
 * deletion stays refused, and a paid member is handled by support rather than
 * by a self-service button that cannot settle anything. When a refund workflow
 * exists this becomes the place that routes into it.
 */
export function assertSelfExitAllowed(member) {
  if (member.tokenStatus === "paid") {
    throw new CampaignMemberStateError(
      "CAMPAIGN_MEMBER_PAYMENT_PROTECTED",
      "You have already paid the token for this campaign, so it cannot be cancelled from here. " +
      "Please contact support and an admin will handle it, including any refund due."
    );
  }
}

/**
 * Reverse the membership a booking created, when that booking is cancelled.
 *
 * Records rather than deletes. `tokenStatus` is left as `paid` because it is
 * true and it is evidence; `status` moves to `exited` so the post-save hook
 * stops counting it. The reason names the booking and the transition, so the
 * membership can be traced back to the record that actually holds the money.
 *
 * Scoped to the booking's own user. One cancelled booking must not disturb
 * anybody else's membership in the same campaign.
 *
 * Returns the number of memberships reversed. Never throws into the caller:
 * a booking cancellation that already succeeded must not be reported as failed
 * because a derived record could not be updated, and the counters are
 * recalculated from the collection anyway.
 */
export async function reverseMembershipForCancelledBooking(booking, previousStatus) {
  if (!BOOKING_STATES_WITH_ENROLMENT.includes(previousStatus)) return 0;
  if (!booking.user) return 0;

  try {
    const members = await CampaignMember.find({
      user: booking.user._id || booking.user,
      status: "active",
      tokenStatus: "paid",
    }).populate("campaign", "project unitType");

    let reversed = 0;
    for (const member of members) {
      // Only the campaign this booking actually feeds. A user may hold paid
      // memberships in unrelated campaigns and those are none of this
      // booking's business.
      const campaign = member.campaign;
      if (!campaign) continue;
      const sameUnit = String(campaign.unitType) === String(booking.unitType._id || booking.unitType);
      const sameProject = String(campaign.project) === String(booking.project._id || booking.project);
      if (!sameUnit || !sameProject) continue;

      member.status = "exited";
      member.exitedAt = new Date();
      member.exitReason =
        `Booking ${booking._id} cancelled (${previousStatus} → cancelled). ` +
        `Token payment remains recorded; any refund is handled against the booking.`;

      await member.save(); // post-save hook recounts memberCount and paidMemberCount
      reversed += 1;
    }
    return reversed;
  } catch (err) {
    console.error("[CampaignMember] Reversal after booking cancellation failed:", err.message);
    return 0;
  }
}
