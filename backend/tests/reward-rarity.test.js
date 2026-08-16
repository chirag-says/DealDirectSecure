/**
 * Reward reveal rarity (Phase 2.6)
 *
 * INVARIANT: every generated reward carries a rarity the reveal UI understands,
 * and a high-value draw is never presented as "Common".
 *
 * Equally important: this must change ONLY the rarity label. Probabilities,
 * point values, cash values, tier multipliers and earning rules are asserted
 * unchanged, including a deterministic check that the weighted selection picks
 * exactly the same entry it did before.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §17 F-R5 (rewardTier always
 * undefined, so the whole rarity dimension of the reveal was dead).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  REWARD_TIERS,
  getRandomReward,
  rarityForProbability,
  POINTS_TO_RUPEES,
} from '../services/rewardService.js';

const CLIENT = new URL('../../client-next/src/', import.meta.url);
const readClient = (rel) => readFileSync(new URL(rel, CLIENT), 'utf8');

const spinWheel = readClient('components/Rewards/SpinWheelOverlay.jsx');
const huntGame = readClient('components/PropertyHuntGame.jsx');
const rewardService = readFileSync(new URL('../services/rewardService.js', import.meta.url), 'utf8');

/** The vocabulary both reveal components key their presentation off. */
const UI_RARITIES = ['common', 'uncommon', 'rare', 'epic', 'legendary'];
const CATEGORIES = Object.keys(REWARD_TIERS);

describe('a generated reward carries a valid rarity', () => {
  test('getRandomReward returns a tier on every draw', () => {
    for (const category of CATEGORIES) {
      for (let i = 0; i < 200; i++) {
        const reward = getRandomReward(category);
        assert.ok(reward.tier, `${category} produced a reward with no tier`);
        assert.ok(
          UI_RARITIES.includes(reward.tier),
          `${category} produced "${reward.tier}", which no reveal component knows`
        );
      }
    }
  });

  test('an unknown category still returns a usable rarity', () => {
    const reward = getRandomReward('no_such_category');
    assert.equal(reward.points, 0);
    assert.ok(UI_RARITIES.includes(reward.tier));
  });

  test('every entry in every table maps to a known rarity', () => {
    for (const [category, tiers] of Object.entries(REWARD_TIERS)) {
      const total = tiers.reduce((s, t) => s + t.weight, 0);
      for (const t of tiers) {
        const rarity = rarityForProbability(t.weight / total);
        assert.ok(UI_RARITIES.includes(rarity), `${category} ${t.points}pts → "${rarity}"`);
      }
    }
  });

  test('rarity is ordered — a less likely outcome is never rarer-labelled downward', () => {
    for (const [category, tiers] of Object.entries(REWARD_TIERS)) {
      const total = tiers.reduce((s, t) => s + t.weight, 0);
      const ranked = tiers
        .map((t) => ({ points: t.points, rank: UI_RARITIES.indexOf(rarityForProbability(t.weight / total)) }))
        .sort((a, b) => a.points - b.points);
      for (let i = 1; i < ranked.length; i++) {
        assert.ok(
          ranked[i].rank >= ranked[i - 1].rank,
          `${category}: ${ranked[i].points}pts is rarer-labelled lower than ${ranked[i - 1].points}pts`
        );
      }
    }
  });
});

describe('a high-value reward is no longer forced into "common"', () => {
  test('the top prize in each category is not common', () => {
    for (const [category, tiers] of Object.entries(REWARD_TIERS)) {
      const total = tiers.reduce((s, t) => s + t.weight, 0);
      const top = tiers.reduce((a, b) => (b.points > a.points ? b : a));
      const rarity = rarityForProbability(top.weight / total);
      assert.notEqual(rarity, 'common', `${category}'s ${top.points}-point prize still reads as Common`);
    }
  });

  test('the 100,000-point property_posting jackpot is legendary', () => {
    const tiers = REWARD_TIERS.property_posting;
    const total = tiers.reduce((s, t) => s + t.weight, 0);
    const jackpot = tiers.find((t) => t.points === 100000);
    assert.ok(jackpot, 'the jackpot entry was removed');
    assert.equal(rarityForProbability(jackpot.weight / total), 'legendary');
  });

  test('the most likely outcome is still common', () => {
    // Guards against over-correcting into "everything is legendary".
    for (const [category, tiers] of Object.entries(REWARD_TIERS)) {
      const total = tiers.reduce((s, t) => s + t.weight, 0);
      const likeliest = tiers.reduce((a, b) => (b.weight > a.weight ? b : a));
      assert.equal(
        rarityForProbability(likeliest.weight / total),
        'common',
        `${category}'s most frequent outcome is not labelled common`
      );
    }
  });

  test('band boundaries behave', () => {
    assert.equal(rarityForProbability(1), 'common');
    assert.equal(rarityForProbability(0.25), 'common');
    assert.equal(rarityForProbability(0.2499), 'uncommon');
    assert.equal(rarityForProbability(0.05), 'uncommon');
    assert.equal(rarityForProbability(0.0499), 'rare');
    assert.equal(rarityForProbability(0.005), 'rare');
    assert.equal(rarityForProbability(0.0049), 'epic');
    assert.equal(rarityForProbability(0.0005), 'epic');
    assert.equal(rarityForProbability(0.0004), 'legendary');
    assert.equal(rarityForProbability(0), 'legendary');
  });
});

describe('the reveal receives the rarity', () => {
  test('awardPoints passes the drawn tier through as rewardTier', () => {
    assert.match(rewardService, /tierName = reward\.tier/);
    assert.match(rewardService, /rewardTier: tierName/);
  });

  test('fixed-point actions still default to common', () => {
    // referral_signup and report_property take the non-category branch.
    assert.match(rewardService, /let tierName = 'common'/);
  });

  test('both reveal components read reward.rewardTier', () => {
    assert.match(spinWheel, /reward\?\.rewardTier/);
    assert.match(huntGame, /reward\?\.rewardTier/);
  });
});

describe('the existing presentation can distinguish tiers', () => {
  test('SpinWheelOverlay defines every rarity the service can emit', () => {
    for (const rarity of UI_RARITIES) {
      assert.match(spinWheel, new RegExp(`\\b${rarity}:`), `SpinWheelOverlay has no "${rarity}" style`);
    }
  });

  test('PropertyHuntGame defines every rarity the service can emit', () => {
    for (const rarity of UI_RARITIES) {
      assert.match(huntGame, new RegExp(`\\b${rarity}:`), `PropertyHuntGame has no "${rarity}" style`);
    }
  });

  test('the rare-and-above presentation is now reachable', () => {
    // These branches existed but could never fire while rewardTier was undefined.
    assert.match(spinWheel, /explosive: true/);
    assert.match(huntGame, /\['rare', 'epic', 'legendary'\]\.includes\(reward\?\.rewardTier\)/);

    // Prove at least one real table entry lands in each of those bands.
    const reachable = new Set();
    for (const tiers of Object.values(REWARD_TIERS)) {
      const total = tiers.reduce((s, t) => s + t.weight, 0);
      for (const t of tiers) reachable.add(rarityForProbability(t.weight / total));
    }
    for (const rarity of ['rare', 'epic', 'legendary']) {
      assert.ok(reachable.has(rarity), `no reward anywhere is "${rarity}" — the styling stays dead`);
    }
  });
});

describe('the engine itself is unchanged', () => {
  test('the weighted selection picks exactly the entry it always did', () => {
    // Deterministic walk: stub Math.random to land on a known cumulative point.
    const tiers = REWARD_TIERS.property_posting;
    const total = tiers.reduce((s, t) => s + t.weight, 0);
    const realRandom = Math.random;

    try {
      // Just inside the first entry's weight → first entry.
      Math.random = () => 0;
      assert.equal(getRandomReward('property_posting').points, tiers[0].points);

      // Just past the first entry → second entry.
      Math.random = () => (tiers[0].weight + 1) / total;
      assert.equal(getRandomReward('property_posting').points, tiers[1].points);

      // Just past the first two → third entry.
      Math.random = () => (tiers[0].weight + tiers[1].weight + 1) / total;
      assert.equal(getRandomReward('property_posting').points, tiers[2].points);
    } finally {
      Math.random = realRandom;
    }
  });

  test('points and cash values still come from the table verbatim', () => {
    const realRandom = Math.random;
    try {
      const tiers = REWARD_TIERS.property_sale;
      const total = tiers.reduce((s, t) => s + t.weight, 0);
      let cumulative = 0;
      for (const entry of tiers) {
        Math.random = () => (cumulative + entry.weight / 2) / total;
        const reward = getRandomReward('property_sale');
        assert.equal(reward.points, entry.points);
        assert.equal(reward.cashValue, entry.cashValue);
        cumulative += entry.weight;
      }
    } finally {
      Math.random = realRandom;
    }
  });

  test('no weight, point or cash value was edited', () => {
    // Spot-check the anchors of each table against the audited figures.
    assert.deepEqual(REWARD_TIERS.property_posting[0], { points: 40, cashValue: 2, weight: 150000 });
    assert.deepEqual(REWARD_TIERS.property_enquiry[0], { points: 20, cashValue: 1, weight: 500000 });
    assert.deepEqual(REWARD_TIERS.property_sale[0], { points: 1000, cashValue: 50, weight: 10000 });
  });

  test('the conversion rate is untouched', () => {
    assert.equal(POINTS_TO_RUPEES, 0.05);
  });

  test('cashValue still matches points at the conversion rate', () => {
    for (const [category, tiers] of Object.entries(REWARD_TIERS)) {
      for (const t of tiers) {
        assert.equal(
          t.cashValue,
          Math.round(t.points * POINTS_TO_RUPEES),
          `${category} ${t.points}pts has a cashValue inconsistent with the rate`
        );
      }
    }
  });

  test('tier multipliers and the one-time listing cap are still in place', () => {
    assert.match(rewardService, /getTierMultiplier\(\)/);
    assert.match(rewardService, /action === "list_property"/);
    assert.match(rewardService, /todaysEnquiriesCount >= 5/);
  });
});
