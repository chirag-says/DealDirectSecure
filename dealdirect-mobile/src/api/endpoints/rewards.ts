/**
 * Rewards endpoints. Mounted at `/api/rewards`
 * (backend/routes/rewardsRoutes.js), except the Hubble pair, which is mounted
 * one level deeper at `/api/rewards/hubble` (backend/routes/hubbleRoutes.js).
 *
 * The RewardPort catalogue routes are still not declared here: that is a legacy
 * surface the website keeps for compatibility and it is not in mobile scope.
 *
 * The Hubble SDK routes WERE excluded on the same grounds until 2026-08-22,
 * when redemption was brought into the app — see `app/rewards/redeem.tsx`. Only
 * the two routes a client is allowed to call are declared. The other four
 * (`/sso`, `/balance`, `/debit`, `/reverse`) are server-to-server, guarded by
 * the `X-Hubble-Secret` header, and are Hubble's to call, never ours.
 */

import type {
  HubbleConfigResponse,
  HubbleTokenResponse,
  ReferralCodeResponse,
  ReferralsResponse,
  RedeemRewardRequest,
  RedeemRewardResponse,
  RewardsPolicyResponse,
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
    note: 'Carries `lockedPoints` (non-cashable milestone points) since Phase 3.',
  }),

  policy: defineEndpoint<void, RewardsPolicyResponse>({
    method: 'GET',
    path: '/rewards/policy',
    auth: 'public',
    envelope: 'data',
    note:
      'The explainer numbers. `milestones` is empty when milestone rewards are off; render ' +
      'nothing for that section then. Numbers only, no promises.',
  }),

  hubbleConfig: defineEndpoint<void, HubbleConfigResponse>({
    method: 'GET',
    path: '/rewards/hubble/config',
    auth: 'user',
    envelope: 'keyed',
    note:
      'Returns `config: {clientId, appSecret, sdkBaseUrl, theme}`. 503 when the integration ' +
      'is unconfigured, which is a normal state in dev, not a fault. Carries a SECRET: never ' +
      'log it, never persist it, never put it in a query key that is cached to disk.',
  }),

  hubbleToken: defineEndpoint<void, HubbleTokenResponse>({
    method: 'GET',
    path: '/rewards/hubble/token',
    auth: 'user',
    envelope: 'keyed',
    note:
      'A SINGLE-USE SSO token, valid five minutes, held in an in-process Map on the server. ' +
      'Fetch one immediately before opening the SDK and throw it away afterwards — a cached ' +
      'token is either already spent or already expired, and both fail the same silent way.',
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
