/**
 * Rewards contract. Source: backend/controllers/rewardsController.js and
 * backend/services/rewardService.js.
 *
 * Two response bodies here spread a service result directly into the envelope
 * (`{ success: true, ...result }`), so their shape is defined by the service
 * rather than the controller. Those are typed loosely on purpose: tightening
 * them would mean guessing, and a wrong guess is worse than an honest gap.
 * They are pinned down in M7 against a live response.
 */

import type { IsoDate, ObjectId } from './common';

export interface RewardsWallet {
  balance?: number;
  lifetimeEarned?: number;
  lifetimeRedeemed?: number;
  [key: string]: unknown;
}

export interface RewardTransaction {
  _id?: ObjectId;
  type?: string;
  points?: number;
  description?: string;
  createdAt?: IsoDate;
  [key: string]: unknown;
}

export interface StoreReward {
  slug?: string;
  name?: string;
  points?: number;
  [key: string]: unknown;
}

/** `GET /rewards/wallet`. */
export interface WalletResponse {
  success: true;
  wallet: RewardsWallet;
}

/** `GET /rewards/transactions`. Service result is spread into the envelope. */
export interface TransactionsResponse {
  success: true;
  transactions?: RewardTransaction[];
  [key: string]: unknown;
}

/** `GET /rewards/referral-code`. */
export interface ReferralCodeResponse {
  success: true;
  referralCode: string | null;
  /** Built from the backend's CLIENT_URL, so it points at the WEBSITE. */
  referralLink: string | null;
  stats?: unknown;
}

/** `GET /rewards/referrals`. Service result is spread into the envelope. */
export interface ReferralsResponse {
  success: true;
  totalReferred?: number;
  totalPointsEarned?: number;
  [key: string]: unknown;
}

/** `GET /rewards/store`. Public. */
export interface RewardsStoreResponse {
  success: true;
  rewards: StoreReward[];
}

export interface RedeemRewardRequest {
  rewardSlug: string;
  bankDetails?: Record<string, unknown>;
}

export interface RedeemRewardResponse {
  success: true;
  message: string;
  redemption: unknown;
  newBalance: number;
}
