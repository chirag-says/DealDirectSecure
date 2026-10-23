/**
 * DealDirect Rewards: the programme as the backend runs it.
 *
 * A copy of backend services/rewardService.js (REWARD_TIERS, FIXED_POINTS,
 * the once-per-account listing reward, the five-a-day enquiry reward) and
 * models/Reward.js (tier thresholds and multipliers). The backend test
 * tests/rewards-website-contract.test.js imports this file and fails if any
 * number here differs from the engine, so the public page cannot promise a
 * prize, an odds figure or a bonus the engine does not pay.
 *
 * Draw tables are [points, weight] pairs: the chance of a prize is its weight
 * divided by the pool's total weight, exactly as getRandomReward picks it.
 */

export const POINT_VALUE_RUPEES = 0.05;

export const DRAW_POOLS = {
  property_posting: [
    [40, 150000], [100, 50000], [200, 20000], [400, 11000], [600, 2100], [800, 1100], [1000, 500],
    [2000, 200], [4000, 200], [5000, 200], [6000, 40], [7000, 40], [8000, 20], [10000, 10],
    [20000, 5], [30000, 5], [40000, 5], [60000, 3], [70000, 3], [80000, 2], [90000, 2], [100000, 2],
  ],
  property_sale: [
    [1000, 10000], [2000, 5000], [10000, 1200], [15000, 50], [18000, 50], [20000, 50], [22000, 50],
    [30000, 50], [42000, 40], [50000, 30], [62000, 20], [82000, 10], [102000, 5], [220000, 3],
    [300000, 2], [420000, 1], [500000, 1],
  ],
  property_enquiry: [
    [20, 500000], [40, 200000], [60, 30000], [80, 10000], [100, 6000], [120, 5000], [140, 4000],
    [160, 3000], [180, 3000], [200, 2000], [400, 900], [600, 800], [800, 700], [1000, 600],
    [1200, 500], [1400, 400], [1600, 300], [1800, 200], [2000, 110],
  ],
};

export const FIXED_POINTS = {
  referral_signup: 100,
  report_property: 100,
  upload_5_photos: 50,
  referral_first_action: 50,
  referral_deal_closure: 500,
};

export const LIMITS = {
  listingRewardOncePerAccount: true,
  enquiryRewardsPerDay: 5,
};

/** Lifetime-points thresholds and the multiplier each tier applies to every reward. */
export const TIERS = [
  { key: "bronze", name: "Bronze", min: 0, multiplier: 1.0 },
  { key: "silver", name: "Silver", min: 1000, multiplier: 1.1 },
  { key: "gold", name: "Gold", min: 5000, multiplier: 1.25 },
  { key: "diamond", name: "Diamond", min: 15000, multiplier: 1.5 },
];

// ---------------------------------------------------------------------------
// Derived figures for display
// ---------------------------------------------------------------------------

export const toRupees = (points) => points * POINT_VALUE_RUPEES;

/** Whole rupees as "₹5,000"; amounts with paise as "₹2.50", never "₹2.5". */
export const formatRupees = (amount) => {
  const paise = amount < 100 && !Number.isInteger(amount);
  return `₹${amount.toLocaleString("en-IN", { minimumFractionDigits: paise ? 2 : 0, maximumFractionDigits: paise ? 2 : 0 })}`;
};

/** Odds as people read them: "64%" for likely outcomes, "1 in 16,562" for rare ones. */
export function formatChance(probability) {
  if (probability >= 0.01) return `${(probability * 100).toFixed(probability >= 0.1 ? 0 : 1)}%`;
  return `1 in ${Math.round(1 / probability).toLocaleString("en-IN")}`;
}

export function poolSummary(pool) {
  const total = pool.reduce((sum, [, w]) => sum + w, 0);
  const rows = pool.map(([points, weight]) => ({ points, rupees: toRupees(points), probability: weight / total }));
  const average = rows.reduce((sum, r) => sum + r.rupees * r.probability, 0);
  const likely = rows.reduce((best, r) => (r.probability > best.probability ? r : best), rows[0]);
  const top = rows[rows.length - 1];
  return { rows, average, likely, top };
}
