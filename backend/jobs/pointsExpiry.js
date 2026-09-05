import Reward from "../models/Reward.js";
import { notifyUsers } from "../services/notificationService.js";
import { getRewardPolicy } from "../config/rewardPolicy.js";
import { POINTS_TO_RUPEES } from "../services/rewardService.js";

/**
 * Points lapse on inactivity (Phase 5, F21).
 *
 * TWO DELIBERATE CHOICES, both from the research:
 *
 *   1. ACTIVITY-BASED, NOT A CALENDAR CLIFF. Points lapse after a stretch of
 *      doing nothing, not on a fixed date. A person who earned points in
 *      March and used the product in September has not abandoned anything,
 *      and taking their balance would be a punishment for a schedule they
 *      never agreed to. Any earn, any redemption, any adjustment resets the
 *      clock.
 *
 *   2. THE WARNING IS THE POINT. Expiry exists to bring people back, not to
 *      reclaim liability. The nudge goes out `NUDGE_DAYS` before, says the
 *      exact amount and date, and any activity in response cancels the
 *      expiry entirely.
 *
 * OFF BY DEFAULT. `POINTS_INACTIVITY_DAYS` is 0 unless set, and at 0 this
 * job does nothing at all: no nudges, no forfeits. Nobody's balance changes
 * until the client has agreed to the number.
 */

const NUDGE_DAYS = 14;
const MAX_PER_RUN = 500;

const rupees = (points) => Math.round(points * POINTS_TO_RUPEES);

export async function expirePoints({ now = new Date() } = {}) {
  const days = parseInt(process.env.POINTS_INACTIVITY_DAYS || "0", 10);
  if (!Number.isFinite(days) || days <= 0) {
    return { disabled: true, nudged: 0, expired: 0 };
  }

  const lapseBefore = new Date(now.getTime() - days * 86400 * 1000);
  const nudgeBefore = new Date(now.getTime() - (days - NUDGE_DAYS) * 86400 * 1000);

  // Activity is the wallet's own updatedAt: every earn, redemption and
  // adjustment saves it. A wallet with nothing to lose is not considered.
  const nudgeCandidates = await Reward.find({
    availablePoints: { $gt: 0 },
    updatedAt: { $lte: nudgeBefore, $gt: lapseBefore },
    $or: [{ expiryNudgedAt: null }, { expiryNudgedAt: { $lte: lapseBefore } }],
  })
    .select("user availablePoints updatedAt")
    .limit(MAX_PER_RUN)
    .lean();

  const entries = [];
  for (const wallet of nudgeCandidates) {
    const expiresOn = new Date(new Date(wallet.updatedAt).getTime() + days * 86400 * 1000);
    entries.push({
      user: wallet.user,
      title: "Your points are about to expire",
      message: `You have ${wallet.availablePoints} points (about ₹${rupees(wallet.availablePoints)}) that lapse on ${expiresOn.toLocaleDateString("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "long" })}. Using the app keeps them.`,
      type: "points_expiring",
      data: { points: wallet.availablePoints, expiresAt: expiresOn, actionUrl: "/rewards", actionText: "See your points" },
    });
  }

  if (entries.length) {
    // The nudge stamp is written even if delivery fails: the alternative is
    // nudging the same person every night until a send succeeds.
    await Reward.updateMany(
      { _id: { $in: nudgeCandidates.map((w) => w._id) } },
      { $set: { expiryNudgedAt: now } }
    );
    await notifyUsers(entries);
  }

  // The forfeits. A `forfeit` transaction rather than a silent decrement, so
  // the wallet history explains where a balance went and support can answer
  // "my points vanished" with a row and a date.
  const lapsed = await Reward.find({ availablePoints: { $gt: 0 }, updatedAt: { $lte: lapseBefore } })
    .limit(MAX_PER_RUN);

  let expired = 0;
  const expiryEntries = [];

  for (const wallet of lapsed) {
    const points = wallet.availablePoints;
    if (points <= 0) continue;
    wallet.addTransaction({
      type: "forfeit",
      action: "points_expired",
      points: -points,
      basePoints: points,
      multiplier: 1,
      description: `${points} points lapsed after ${days} days without activity`,
      metadata: { inactivityDays: days },
    });
    // addTransaction bumps updatedAt, which restarts the clock for whatever
    // is earned next. That is correct: the next balance gets its own life.
    await wallet.save();
    expired += 1;

    expiryEntries.push({
      user: wallet.user,
      title: "Your points have lapsed",
      message: `${points} points expired after ${days} days without activity. Anything you earn from here starts a fresh clock.`,
      type: "points_expiring",
      data: { points, actionUrl: "/rewards", actionText: "See your wallet" },
    });
  }

  if (expiryEntries.length) await notifyUsers(expiryEntries);

  return { disabled: false, nudged: entries.length, expired, inactivityDays: days };
}
