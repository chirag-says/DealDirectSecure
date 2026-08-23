import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useRef, useState } from 'react';
import { View } from 'react-native';

import { ApiError } from '@/api';
import { RequireAuth, useAuth } from '@/auth';
import { useClaimDealReward } from '@/features/rewards';
import { useTheme } from '@/theme';
import type { ClaimDealRewardResponse } from '@/types/backend/property';
import { Button, ErrorState, Screen, ScreenHeader, Skeleton, Text } from '@/ui';

/**
 * Claim the reward for an approved close-deal verification.
 *
 * Reached only from a `deal_reward` notification tap
 * (`features/notifications/targets.ts`) — there is no "my verifications"
 * list on this backend to browse to this screen from any other way, so a
 * verification id with nothing behind it (already claimed by someone else's
 * tap, or never approved) is a real state to design for, not an edge case.
 *
 * Claims automatically on open rather than behind a second tap: the
 * notification itself was already the confirmation step, and
 * `claimDealReward` is safe to call more than once — a repeat returns
 * `alreadyClaimed: true` as a 200, not an error.
 */
export default function ClaimRewardRoute() {
  const { verificationId } = useLocalSearchParams<{ verificationId: string }>();

  return (
    <RequireAuth
      title="Deal reward"
      promptTitle="Sign in to claim this reward"
      // The copy no longer asks the user to go and find the notification
      // again: the claim is recorded as a pending intent, so signing in comes
      // straight back here and claims.
      promptDescription="This reward belongs to your account. Sign in and we will bring you straight back to it — nothing is lost in the meantime."
      icon="gift-outline"
      intent={{ kind: 'claimReward', verificationId }}
    >
      <ClaimRewardScreen />
    </RequireAuth>
  );
}

function ClaimRewardScreen() {
  const router = useRouter();
  const theme = useTheme();
  const { status } = useAuth();
  const { verificationId } = useLocalSearchParams<{ verificationId: string }>();
  const { claim, isPending, error } = useClaimDealReward();

  const [result, setResult] = useState<ClaimDealRewardResponse | null>(null);
  const attempted = useRef(false);

  useEffect(() => {
    // `RequireAuth` renders its children while the session is still restoring,
    // so claiming has to wait for a DECIDED session. Firing during the probe
    // sends a request that is guaranteed to 401, and `attempted` would then
    // block the real attempt a second later.
    if (status !== 'authenticated') return;
    if (!verificationId || attempted.current) return;
    attempted.current = true;
    claim(verificationId)
      .then(setResult)
      .catch(() => {
        // surfaced via `error` below
      });
  }, [status, verificationId, claim]);


  return (
    <Screen>
      <ScreenHeader title="Deal reward" />

      <View className="flex-1 items-center justify-center px-xl">
        {(isPending || status === 'restoring') && !result ? (
          <View className="w-full items-center">
            <Skeleton width={72} height={72} radius={36} />
            <Skeleton width={160} height={20} className="mt-lg" />
            <Skeleton width={220} height={16} className="mt-sm" />
          </View>
        ) : error && !result ? (
          <ErrorState
            title="Could not claim this reward"
            description={
              error instanceof ApiError
                ? error.message
                : 'Please check your connection and try again.'
            }
            onRetry={() => {
              attempted.current = false;
              claim(verificationId).then(setResult).catch(() => {});
            }}
          />
        ) : result ? (
          <>
            <View
              className="h-20 w-20 items-center justify-center rounded-full"
              style={{ backgroundColor: theme.colors.accentMuted }}
            >
              <Ionicons name="gift" size={36} color={theme.colors.accent} />
            </View>

            <Text variant="title2" className="mt-lg text-center">
              {result.alreadyClaimed ? 'Already claimed' : 'Reward claimed'}
            </Text>
            <Text variant="callout" tone="secondary" className="mt-xs text-center">
              {result.reward.description}
            </Text>

            <View className="mt-xl flex-row gap-xl">
              <View className="items-center">
                <Text variant="title1" tone="accent">
                  {result.reward.pointsAwarded.toLocaleString('en-IN')}
                </Text>
                <Text variant="footnote" tone="muted">
                  points
                </Text>
              </View>
              {result.reward.cashValue > 0 ? (
                <View className="items-center">
                  <Text variant="title1" tone="accent">
                    ₹{result.reward.cashValue.toLocaleString('en-IN')}
                  </Text>
                  <Text variant="footnote" tone="muted">
                    value
                  </Text>
                </View>
              ) : null}
            </View>

            <Button
              label="View rewards"
              className="mt-2xl"
              onPress={() => router.replace('/rewards')}
            />
          </>
        ) : null}
      </View>
    </Screen>
  );
}
