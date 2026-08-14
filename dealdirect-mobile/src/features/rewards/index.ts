/**
 * `useRewardsStore` and `useRedeemReward` were removed 2026-08-13: the
 * in-house store/redeem endpoints are deleted backend-side and redemption is
 * a separate workstream (HANDOFF §9.1 D3). Do not re-add them here without
 * that decision.
 */
export { useWallet, useTransactions, useReferral, useClaimDealReward } from './hooks';
export { RewardReveal, type RewardRevealProps } from './components/RewardReveal';
