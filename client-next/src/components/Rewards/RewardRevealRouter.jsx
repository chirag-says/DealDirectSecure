'use client';

import React from 'react';
import PropertyHuntGame from '../PropertyHuntGame';
import SpinWheelOverlay from './SpinWheelOverlay';

/**
 * RewardRevealRouter — Routes to the correct reward reveal component
 * based on the reward category returned by the backend.
 *
 *  - property_sale     → 3-Gate Door (PropertyHuntGame) — Shagun
 *  - property_posting  → Spin Wheel
 *  - property_enquiry  → Spin Wheel
 *  - fallback          → 3-Gate Door (safe default)
 *
 * Props (same as PropertyHuntGame):
 *   reward: { pointsAwarded, rewardTier, rewardCategory, action, cashValue, description }
 *   onClose: () => void
 */
export default function RewardRevealRouter({ reward, onClose }) {
  if (!reward) return null;

  // Determine which reveal to show based on reward category
  const category = reward.rewardCategory || '';

  if (category === 'property_posting' || category === 'property_enquiry') {
    return (
      <SpinWheelOverlay
        reward={reward}
        onClose={onClose}
        category={category}
      />
    );
  }

  // property_sale (Shagun) + any other/unknown → existing door game
  return <PropertyHuntGame reward={reward} onClose={onClose} />;
}
