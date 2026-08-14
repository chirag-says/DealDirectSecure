import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useRef, useState } from 'react';
import { View } from 'react-native';

import { ApiError } from '@/api';
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
export default function ClaimRewardScreen() {
  const router = useRouter();
  const theme = useTheme();
  const { verificationId } = useLocalSearchParams<{ verificationId: string }>();
  const { claim, isPending, error } = useClaimDealReward();

  const [result, setResult] = useState<ClaimDealRewardResponse | null>(null);
  const attempted = useRef(false);

  useEffect(() => {
    if (!verificationId || attempted.current) return;
    attempted.current = true;
    claim(verificationId)
      .then(setResult)
      .catch(() => {
        // surfaced via `error` below
      });
  }, [verificationId, claim]);


  return (
    <Screen>
      <ScreenHeader title="Deal reward" />

      <View className="flex-1 items-center justify-center px-xl">
        {isPending && !result ? (
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
