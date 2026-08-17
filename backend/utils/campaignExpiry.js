import GroupBuyCampaign from "../models/GroupBuyCampaign.js";

/**
 * Lazy campaign expiry.
 *
 * `expired` has been in the GroupBuyCampaign status enum since the model was
 * written and no code path has ever set it. A campaign whose end date passed
 * stayed `active` forever: it kept appearing in active listings, and the only
 * thing stopping someone joining was a date check inside `joinCampaign`. The
 * status field and the campaign's actual state disagreed, and the status is
 * what every read path shows.
 *
 * Resolved on read rather than by a scheduled job. There is no scheduler in
 * this deployment, adding one for a single field is disproportionate, and lazy
 * expiry cannot drift: a campaign is expired exactly when someone looks at it
 * after its end date, which is the only moment the answer matters.
 *
 * Only `active` campaigns expire. `paused`, `completed` and `cancelled` are
 * deliberate administrative states and an end date passing does not override a
 * decision someone made.
 *
 * Failure is swallowed. This runs inside read endpoints, and a campaign listing
 * must not 500 because a status could not be updated. The read still returns
 * the corrected value in that case; only the persisted write is lost, and the
 * next read retries it.
 */

const isExpired = (campaign, now) =>
  campaign?.status === "active" &&
  campaign?.duration?.endDate &&
  new Date(campaign.duration.endDate) < now;

/**
 * Expire one campaign document if its end date has passed.
 * Accepts a lean object or a hydrated document; returns it with `status`
 * corrected either way, so callers can use the result directly.
 */
export async function expireIfDue(campaign, now = new Date()) {
  if (!isExpired(campaign, now)) return campaign;

  try {
    await GroupBuyCampaign.updateOne(
      { _id: campaign._id, status: "active" },
      { $set: { status: "expired" } }
    );
  } catch (err) {
    console.error("[Campaign] Lazy expiry write failed:", err.message);
  }

  campaign.status = "expired";
  return campaign;
}

/** Expire any due campaigns in a list. One write per campaign that is due. */
export async function expireDueInList(campaigns, now = new Date()) {
  const due = campaigns.filter((c) => isExpired(c, now));
  if (!due.length) return campaigns;

  try {
    await GroupBuyCampaign.updateMany(
      { _id: { $in: due.map((c) => c._id) }, status: "active" },
      { $set: { status: "expired" } }
    );
  } catch (err) {
    console.error("[Campaign] Lazy expiry bulk write failed:", err.message);
  }

  for (const c of due) c.status = "expired";
  return campaigns;
}
