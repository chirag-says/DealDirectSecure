/**
 * Reward policy (Phase 3, F15), read from the environment.
 *
 * Every default here reproduces the behaviour the platform had before Phase
 * 3, so deploying this code changes nothing until the client has seen the
 * numbers and Chirag sets the variables. The table the client approves IS
 * this configuration.
 *
 *   MILESTONE_REWARDS_ENABLED   "true" turns on the two mid-journey rewards.
 *                               Milestone points are NON-CASHABLE: they count
 *                               toward tier progress and show in the wallet,
 *                               but never enter `availablePoints`, so nothing
 *                               liquid can be farmed before a verified close.
 *   MILESTONE_VISIT_POINTS      awarded to both parties when BOTH have marked a
 *                               visit done (default 100).
 *   MILESTONE_AGREEMENT_POINTS  awarded to both parties when an agreement is
 *                               fully signed (default 200).
 *   CLOSE_PAYOUT_FIXED_POINTS   > 0 makes the verified-close payout a fixed
 *                               base plus the existing shagun draw as a bonus.
 *                               0 keeps today's draw-only payout.
 *   PAYOUT_HOLD_DAYS            days between approval and claim for a clean
 *                               close (default 0: claim at once, as today).
 *   PAYOUT_HOLD_DAYS_FLAGGED    hold when the linkage check raised a flag
 *                               (default 60). Framed to users as registry
 *                               confirmation; admins see the flags.
 */

const int = (key, fallback) => {
  const raw = process.env[key];
  if (raw === undefined || raw === "") return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
};

export function getRewardPolicy() {
  return Object.freeze({
    milestonesEnabled: process.env.MILESTONE_REWARDS_ENABLED === "true",
    milestoneVisitPoints: int("MILESTONE_VISIT_POINTS", 100),
    milestoneAgreementPoints: int("MILESTONE_AGREEMENT_POINTS", 200),
    closePayoutFixedPoints: int("CLOSE_PAYOUT_FIXED_POINTS", 0),
    payoutHoldDays: int("PAYOUT_HOLD_DAYS", 0),
    payoutHoldDaysFlagged: int("PAYOUT_HOLD_DAYS_FLAGGED", 60),
  });
}

/** The public explainer the clients render. Numbers only, no promises. */
export function describeRewardPolicy() {
  const p = getRewardPolicy();
  return {
    milestones: p.milestonesEnabled
      ? [
          { key: "visit_completed", points: p.milestoneVisitPoints, cashable: false, when: "Both of you mark a visit as done" },
          { key: "agreement_completed", points: p.milestoneAgreementPoints, cashable: false, when: "An agreement is signed by both" },
        ]
      : [],
    close: {
      fixedPoints: p.closePayoutFixedPoints,
      drawBonus: true,
      holdDays: p.payoutHoldDays,
      holdDaysFlagged: p.payoutHoldDaysFlagged,
    },
    pointValueRupees: 0.05,
  };
}
