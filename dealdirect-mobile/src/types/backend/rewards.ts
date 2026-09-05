/**
 * Rewards contract. Source: backend/controllers/rewardsController.js,
 * backend/services/rewardService.js and backend/models/Reward.js.
 *
 * PINNED 2026-08-13 (defect F1). Several bodies here spread a service result
 * into the envelope (`{ success: true, ...result }`), so their shape comes
 * from the service, not the controller. They were previously typed loosely
 * with guessed key names; every key below was then read out of the service
 * function that produces it, so the guessing is over.
 *
 * The one that mattered: the wallet has NO `balance` key. Reading
 * `wallet.balance ?? 0` showed every user a balance of zero.
 */

import type { IsoDate, ObjectId } from './common';

export type RewardTier = 'bronze' | 'silver' | 'gold' | 'diamond';

/** `Reward.getNextTierProgress()`. `nextTier` is null only at diamond. */
export interface NextTierProgress {
  nextTier: RewardTier | null;
  /** 0-100. Always 100 at diamond. */
  progress: number;
  pointsNeeded: number;
}

/**
 * `rewardService.getWallet()` — the exact six keys it returns.
 *
 * `availablePoints` is the spendable balance and is what the website renders
 * (`RewardsDashboardContent.jsx:183`). `totalPoints` is lifetime-earned and
 * is what tier is computed from, so the two diverge once anything is spent.
 */
export interface RewardsWallet {
  totalPoints: number;
  availablePoints: number;
  /**
   * Phase 3. Milestone points (a visit done, an agreement signed). They count
   * toward tier and are never redeemable: `addTransaction` routes any earn
   * with `metadata.cashable === false` here instead of `availablePoints`.
   * Absent on a backend older than Phase 3.
   */
  lockedPoints?: number;
  tier: RewardTier;
  tierMultiplier: number;
  nextTierProgress: NextTierProgress;
  recentTransactions: RewardTransaction[];
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

/** Pagination block on `getTransactionHistory`. */
export interface RewardsPagination {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

/**
 * `GET /rewards/transactions`. Service result is spread into the envelope.
 * Key names confirmed against `rewardService.getTransactionHistory`.
 */
export interface TransactionsResponse {
  success: true;
  transactions: RewardTransaction[];
  pagination: RewardsPagination;
}

/** `GET /rewards/referral-code`. */
export interface ReferralCodeResponse {
  success: true;
  referralCode: string | null;
  /** Built from the backend's CLIENT_URL, so it points at the WEBSITE. */
  referralLink: string | null;
  stats?: unknown;
}

/** One row of `referrals[]`, from `rewardService.getReferralStats`. */
export interface ReferralEntry {
  id: ObjectId;
  /** Null when the referred user's account no longer exists. */
  referredUser: { name: string; joinedAt: IsoDate } | null;
  milestones: {
    signup?: boolean;
    firstAction?: boolean;
    dealClosure?: boolean;
  };
  createdAt: IsoDate;
}

/**
 * `GET /rewards/referrals`. Service result is spread into the envelope.
 * All six keys confirmed against `rewardService.getReferralStats`.
 *
 * `signups`, `firstActions` and `dealClosures` are the three referral
 * milestones, counted across `referrals[]`. Note only `signup` currently
 * contributes to `totalPointsEarned` — milestones 2 and 3 are awarded
 * elsewhere and are known-incomplete backend-side (KNOWN_BUGS B11).
 */
export interface ReferralsResponse {
  success: true;
  totalReferred: number;
  signups: number;
  firstActions: number;
  dealClosures: number;
  totalPointsEarned: number;
  referrals: ReferralEntry[];
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

/**
 * `GET /rewards/policy`. Public. The numbers behind the rewards explainer,
 * read from `config/rewardPolicy.js`, which is env-driven: `milestones` is
 * EMPTY when milestone rewards are switched off, and the screen must render
 * nothing for that section rather than a heading over an empty list.
 */
export interface RewardsPolicyResponse {
  success: true;
  data: {
    milestones: Array<{
      key: string;
      points: number;
      cashable: false;
      /** One line: when this is awarded. */
      when: string;
    }>;
    close: {
      /** Fixed points on a verified close, on top of the draw. 0 when unset. */
      fixedPoints: number;
      drawBonus: true;
      holdDays: number;
      holdDaysFlagged: number;
    };
    pointValueRupees: number;
  };
}

export interface RedeemRewardResponse {
  success: true;
  message: string;
  redemption: unknown;
  newBalance: number;
}

// --- Hubble gift-card SDK ---------------------------------------------------
//
// Redemption is not an API this app calls; it is a web SDK the app hosts. The
// two types below are the entire client-facing surface — the app fetches them,
// builds a URL, and hands the rest to Hubble. Everything else in that
// integration (`/sso`, `/balance`, `/debit`, `/reverse`) is Hubble calling the
// backend with a shared secret, which is why the wallet can be debited without
// this client ever being told a balance changed.

/** `GET /rewards/hubble/config`. 503 when the integration is unconfigured. */
export interface HubbleConfigResponse {
  success: true;
  config: {
    clientId: string;
    /**
     * A credential, and it travels in the SDK URL because that is the
     * integration Hubble documents. Treat it as write-only: never log it,
     * never persist it, never let it reach an error report.
     */
    appSecret: string;
    /** Environment-specific. Do not hardcode — dev and prod differ. */
    sdkBaseUrl: string;
    theme?: string;
  };
}

/** `GET /rewards/hubble/token`. Single-use, five-minute SSO token. */
export interface HubbleTokenResponse {
  success: true;
  token: string;
}
