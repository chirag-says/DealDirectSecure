/**
 * Rewards endpoints. Mounted at `/api/rewards`
 * (backend/routes/rewardsRoutes.js).
 *
 * The RewardPort catalogue routes and the Hubble gift-card SDK routes exist on
 * the backend but are not declared here. The catalogue is a legacy surface the
 * website keeps for compatibility, and Hubble is a web-SDK integration with no
 * native equivalent. Neither is in the approved mobile scope. They are
 * catalogued in docs/API_CONTRACT.md so the omission is a recorded decision
 * rather than an oversight.
 */

import type {
  ReferralCodeResponse,
  ReferralsResponse,
  RedeemRewardRequest,
  RedeemRewardResponse,
  RewardsStoreResponse,
  TransactionsResponse,
  WalletResponse,
} from '@/types/backend/rewards';
import type { PaginationParams } from '@/types/backend/common';
import { defineEndpoint } from './_contract';

export const rewardsEndpoints = {
  store: defineEndpoint<void, RewardsStoreResponse>({
    method: 'GET',
    path: '/rewards/store',
    auth: 'public',
    envelope: 'keyed',
  }),

  wallet: defineEndpoint<void, WalletResponse>({
    method: 'GET',
    path: '/rewards/wallet',
    auth: 'user',
    envelope: 'keyed',
  }),

  transactions: defineEndpoint<PaginationParams, TransactionsResponse>({
    method: 'GET',
    path: '/rewards/transactions',
    auth: 'user',
    envelope: 'keyed',
    note:
      'The controller spreads a service result into the envelope, so the exact keys are ' +
      'defined by rewardService rather than the controller. Typed loosely on purpose; pinned ' +
      'down in M7 against a live response.',
  }),

  referralCode: defineEndpoint<void, ReferralCodeResponse>({
    method: 'GET',
    path: '/rewards/referral-code',
    auth: 'user',
    envelope: 'keyed',
    note:
      '`referralLink` is built from the backend CLIENT_URL and therefore points at the ' +
      'WEBSITE, not the app. Share it as-is; rewriting it to a deep link would break ' +
      'attribution for recipients without the app installed.',
  }),

  referrals: defineEndpoint<void, ReferralsResponse>({
    method: 'GET',
    path: '/rewards/referrals',
    auth: 'user',
    envelope: 'keyed',
    note: 'Also spreads a service result into the envelope. See `transactions`.',
  }),

  redeem: defineEndpoint<RedeemRewardRequest, RedeemRewardResponse>({
    method: 'POST',
    path: '/rewards/redeem',
    auth: 'user',
    envelope: 'keyed',
    note:
      'A business-rule failure returns HTTP 400 with success:false, not a 200 with an error ' +
      'field. Treat 400 here as a normal outcome to display, not an exception.',
  }),
} as const;
