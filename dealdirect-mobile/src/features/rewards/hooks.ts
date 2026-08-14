/**
 * Rewards: wallet, transactions and referrals.
 *
 * Key names here are PINNED against the service functions that produce them
 * (see `src/types/backend/rewards.ts`), replacing the earlier defensive
 * multi-key guessing. The guess that mattered was `wallet.balance`, which
 * does not exist: the spendable balance is `availablePoints`, and reading the
 * wrong key showed every user zero points (defect F1).
 *
 * Redemption is deliberately absent. The in-house store/redeem endpoints are
 * deleted backend-side and the website's only redemption path is the Hubble
 * SDK iframe; mobile redemption is its own workstream (HANDOFF §9.1 D3).
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { call, propertiesEndpoints, qk, rewardsEndpoints } from '@/api';
import { useAuth } from '@/auth';
import type { ObjectId } from '@/types/backend/common';

export function useWallet() {
  const { status } = useAuth();
  const enabled = status === 'authenticated';

  const query = useQuery({
    queryKey: qk.rewardsWallet(),
    queryFn: async () => {
      const response = await call(rewardsEndpoints.wallet);
      return response.wallet;
    },
    enabled,
    staleTime: 30_000,
  });

  const wallet = query.data ?? null;

  return {
    wallet,
    /** Spendable points. `totalPoints` is lifetime-earned and drives tier. */
    balance: wallet?.availablePoints ?? 0,
    lifetimePoints: wallet?.totalPoints ?? 0,
    tier: wallet?.tier ?? null,
    tierMultiplier: wallet?.tierMultiplier ?? 1,
    nextTierProgress: wallet?.nextTierProgress ?? null,
    isLoading: enabled && query.isPending,
    error: query.error,
    refresh: () => void query.refetch(),
    requiresAuth: !enabled,
  };
}

export function useTransactions() {
  const { status } = useAuth();
  const enabled = status === 'authenticated';

  const query = useQuery({
    queryKey: qk.rewardsTransactions(),
    queryFn: () => call(rewardsEndpoints.transactions, { data: { limit: 50 } }),
    enabled,
    staleTime: 30_000,
  });

  return {
    transactions: query.data?.transactions ?? [],
    /** Total across all pages; the screen requests one page of 50. */
    totalTransactions: query.data?.pagination?.total ?? 0,
    isLoading: enabled && query.isPending,
    isRefreshing: query.isRefetching,
    error: query.error,
    refresh: () => void query.refetch(),
  };
}

export function useReferral() {
  const { status } = useAuth();
  const enabled = status === 'authenticated';

  const codeQuery = useQuery({
    queryKey: qk.rewardsReferralCode(),
    queryFn: () => call(rewardsEndpoints.referralCode),
    enabled,
    staleTime: 60_000,
  });

  const statsQuery = useQuery({
    queryKey: qk.rewardsReferrals(),
    queryFn: () => call(rewardsEndpoints.referrals),
    enabled,
    staleTime: 60_000,
  });

  return {
    referralCode: codeQuery.data?.referralCode ?? null,
    // Points at the WEBSITE (built from the backend's CLIENT_URL), not a deep
    // link. Share it as-is.
    referralLink: codeQuery.data?.referralLink ?? null,
    totalReferred: statsQuery.data?.totalReferred ?? 0,
    totalPointsEarned: statsQuery.data?.totalPointsEarned ?? 0,
    // The three milestones the website breaks out separately. Only `signups`
    // currently contributes points; milestones 2 and 3 are known-incomplete
    // backend-side, so a non-zero count there is informational, not earnings.
    signups: statsQuery.data?.signups ?? 0,
    firstActions: statsQuery.data?.firstActions ?? 0,
    dealClosures: statsQuery.data?.dealClosures ?? 0,
    referrals: statsQuery.data?.referrals ?? [],
    isLoading: enabled && (codeQuery.isPending || statsQuery.isPending),
    error: codeQuery.error ?? statsQuery.error,
  };
}

/**
 * Claims the reward for an approved close-deal verification — the other half
 * of `useCloseDeal` (`features/listings`). Reached from a `deal_reward`
 * notification (see `features/notifications/targets.ts`), never from a
 * standing list: there is no "my verifications" endpoint on this backend, so
 * the notification IS the only route to a claimable reward.
 */
export function useClaimDealReward() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (verificationId: ObjectId) =>
      call(propertiesEndpoints.claimDealReward, { params: { verificationId } }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.rewardsWallet() });
      void queryClient.invalidateQueries({ queryKey: qk.rewardsTransactions() });
    },
  });

  return {
    claim: mutation.mutateAsync,
    isPending: mutation.isPending,
    error: mutation.error,
  };
}
