import GroupBuyCampaign from "../models/GroupBuyCampaign.js";
import CampaignMember from "../models/CampaignMember.js";
import ProjectBooking from "../models/ProjectBooking.js";

/**
 * Refusal guards for the builder chain.
 *
 * Refusal, not cascade. Deleting is irreversible and the documents below are
 * payment evidence, so a 409 someone can act on beats a cascade that quietly
 * destroys a receipt. Named per aggregate root rather than wired into Mongoose
 * middleware: a hook that fires on every delete everywhere is exactly the thing
 * nobody can reason about at the call site.
 *
 * Every check reads `countDocuments`. Never a denormalised counter.
 *
 * `UnitType.activeCampaignCount` is cached and counts only campaigns in state
 * `active`, which is how a completed campaign holding PAID members left the
 * counter at zero and let the unit type delete. A cached number is fine for
 * display and wrong for a gate: it can be stale in both directions, and stale
 * in the permissive direction destroys data.
 *
 * There is no payment gateway behind any of this. The UPI reference and the
 * uploaded screenshot on `CampaignMember` and `ProjectBooking` ARE the receipt,
 * so losing the document loses the only record that the money moved.
 */

const LIVE_BOOKING = { status: { $ne: "cancelled" } };

export class DeleteBlockedError extends Error {
  constructor(blockers) {
    super(
      `Cannot delete: ${blockers.join("; ")}. ` +
      `Resolve these first — deleting would destroy records that cannot be reconstructed.`
    );
    this.name = "DeleteBlockedError";
    this.code = "DELETE_BLOCKED_DEPENDENTS";
    this.status = 409;
    this.blockers = blockers;
  }
}

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

/**
 * Refuse deleting a unit type that still owns campaigns, paid members or live
 * bookings.
 *
 * Campaigns block in ANY state. A completed or cancelled campaign still owns
 * its members and their payment references, and "the campaign is over" is not
 * the same fact as "nobody paid".
 */
export async function assertUnitTypeDeletable(unitTypeId) {
  const blockers = [];

  const campaigns = await GroupBuyCampaign.find({ unitType: unitTypeId }, { _id: 1 }).lean();
  if (campaigns.length) {
    blockers.push(`${plural(campaigns.length, "campaign", "campaigns")} reference this unit type`);

    const paidMembers = await CampaignMember.countDocuments({
      campaign: { $in: campaigns.map((c) => c._id) },
      tokenStatus: "paid",
    });
    if (paidMembers) {
      // Named separately and first in the operator's mind: this is money.
      blockers.push(
        `${plural(paidMembers, "member has", "members have")} paid a token that would be stranded`
      );
    }
  }

  const bookings = await ProjectBooking.countDocuments({ unitType: unitTypeId, ...LIVE_BOOKING });
  if (bookings) {
    blockers.push(`${plural(bookings, "booking is", "bookings are")} still open against it`);
  }

  if (blockers.length) throw new DeleteBlockedError(blockers);
}

/**
 * Refuse deleting a project with live bookings.
 *
 * The existing unit-type check stays where it is, in the controller, and keeps
 * its 400. It predates this module, its message is already specific, and
 * changing a status code is a client-visible change that this task does not
 * need to make.
 */
export async function assertProjectDeletable(projectId) {
  const bookings = await ProjectBooking.countDocuments({ project: projectId, ...LIVE_BOOKING });
  if (bookings) {
    throw new DeleteBlockedError([
      `${plural(bookings, "booking is", "bookings are")} still open against this project`,
    ]);
  }
}

/** Guard failures are a typed 409; anything else is a real error. */
export const handleDeleteGuard = (err, res, fallback) => {
  if (err instanceof DeleteBlockedError) {
    return res.status(err.status).json({
      success: false, message: err.message, code: err.code, blockers: err.blockers,
    });
  }
  console.error(fallback.log, err.message);
  return res.status(500).json({ success: false, message: fallback.message });
};
