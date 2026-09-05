import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useRef, useState } from 'react';
import { Pressable, Share, View } from 'react-native';

import { ApiError } from '@/api';
import { RequireAuth, useAuth } from '@/auth';
import { WEB_URL } from '@/config/env';
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

  /**
   * 409 `PAYOUT_ON_HOLD` is a STATE, not a fault. The close was approved and
   * the reward is the user's; the backend holds it for a set number of days
   * (`GET /rewards/policy` says how many, longer when the linkage check
   * flagged the deal) and refuses a claim until `holdUntil`. Rendered calmly,
   * with the date, and with the one thing the user CAN do meanwhile: review
   * the deal, which is what the review request notification asks for too.
   */
  const onHold = error instanceof ApiError && error.code === 'PAYOUT_ON_HOLD' ? error : null;
  const holdUntil = onHold?.details.holdUntil ? new Date(onHold.details.holdUntil) : null;
  const holdUntilLabel =
    holdUntil && !Number.isNaN(holdUntil.getTime())
      ? holdUntil.toLocaleDateString('en-IN', { day: 'numeric', month: 'long' })
      : null;

  const openReview = () => router.push(`/review/${verificationId}`);

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
        ) : onHold && !result ? (
          <>
            <View
              className="h-20 w-20 items-center justify-center rounded-full"
              style={{ backgroundColor: theme.colors.accentMuted }}
            >
              <Ionicons name="time-outline" size={36} color={theme.colors.accent} />
            </View>

            <Text variant="title2" className="mt-lg text-center">
              Reserved for you
            </Text>
            <Text variant="callout" tone="secondary" className="mt-xs text-center">
              {holdUntilLabel
                ? `Your reward is set aside and unlocks on ${holdUntilLabel}. Come back then to claim it.`
                : 'Your reward is set aside and unlocks once the hold on this deal ends. Come back then to claim it.'}
            </Text>

            <Button label="View rewards" className="mt-2xl" onPress={() => router.replace('/rewards')} />
            <Button
              label="Review this deal"
              variant="secondary"
              className="mt-md"
              onPress={openReview}
            />
          </>
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
            {/* The other party is asked for one too; both publish together. */}
            <Button
              label="Review this deal"
              variant="secondary"
              className="mt-md"
              onPress={openReview}
            />

            {result.referral ? <ReferralShareCard referral={result.referral} /> : null}
          </>
        ) : null}
      </View>
    </Screen>
  );
}

/**
 * The referral card, at the reward moment.
 *
 * ---------------------------------------------------------------------------
 * WHY HERE AND NOT ONLY ON THE REWARDS TAB
 *
 * The rewards screen already carries a referral card, and it is the right home
 * for it. This one exists because of WHEN it is on screen: the user has just
 * closed a deal without a broker and been paid for it. That is the single
 * second in the whole product where the sentence "this worked, tell someone"
 * is true rather than nagging, and a card the user has to go and find three
 * screens later is a card nobody finds.
 *
 * It is a share, not a prompt. No modal, no interstitial, no dismissal to
 * remember: it sits under the reward, below the two buttons that were already
 * there, and is ignorable.
 *
 * The link points at the website, exactly as `useReferral` does, because a
 * referral is read by somebody who does not have the app yet.
 */
function ReferralShareCard({ referral }: { referral: { code: string; message: string } }) {
  const theme = useTheme();

  const link = `${WEB_URL}/register?ref=${encodeURIComponent(referral.code)}`;

  const share = () => {
    void Share.share({
      // The server writes the sentence; the client only appends the link. A
      // second hand-written version here would drift from the one the website
      // and the email use.
      message: `${referral.message} ${link}`,
      url: link,
    });
  };

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`Share your referral code ${referral.code}`}
      onPress={share}
      className="mt-2xl w-full flex-row items-center rounded-xl active:opacity-80"
      style={{ padding: 16, backgroundColor: theme.colors.surface }}
    >
      <View
        className="items-center justify-center rounded-full"
        style={{ width: 42, height: 42, backgroundColor: theme.colors.accentMuted }}
      >
        <Ionicons name="share-social-outline" size={20} color={theme.colors.accent} />
      </View>

      <View className="ml-base flex-1">
        <Text variant="bodyEmphasis">Pass it on</Text>
        <Text variant="caption" tone="secondary" className="mt-xs">
          {referral.message}
        </Text>
        <Text variant="caption" tone="accent" className="mt-xs">
          {referral.code}
        </Text>
      </View>

      <Ionicons name="chevron-forward" size={18} color={theme.colors.textMuted} />
    </Pressable>
  );
}
