import Ionicons from '@expo/vector-icons/Ionicons';
import { Modal, Pressable, View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
import type { ActionReward } from '@/types/backend/property';
import { Button, Text } from '@/ui';

/**
 * "You earned points" — shown after an action that awarded them.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS AND WHY IT IS NOT A SPIN WHEEL
 *
 * Several write endpoints return a `reward` object, and mobile discarded it
 * until 2026-08-13: users earned points for enquiring and posting and were
 * never told. The website reveals it through `RewardRevealRouter`, which
 * routes by `rewardCategory` to a spin wheel or a door-reveal animation.
 *
 * This is the same information without the animation. The points are already
 * decided server-side by the time the response arrives — the wheel is
 * theatre over a settled number, and porting two reveal animations to carry a
 * value the user could equally just read was not worth the surface. If the
 * gamification is later judged to be doing real work on the website, this is
 * the one place that has to change.
 *
 * Shown only for a positive award. A zero is not a reward, and the backend
 * returns null past the daily cap anyway.
 */

export interface RewardRevealProps {
  reward: ActionReward | null;
  onDismiss: () => void;
}

export function RewardReveal({ reward, onDismiss }: RewardRevealProps) {
  const theme = useTheme();

  if (!reward || reward.pointsAwarded <= 0) return null;

  return (
    <Modal visible transparent animationType="fade" onRequestClose={onDismiss}>
      <Pressable
        accessibilityRole="button"
        accessibilityLabel="Dismiss"
        onPress={onDismiss}
        style={{
          flex: 1,
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: 'rgba(0,0,0,0.45)',
          padding: spacing.xl,
        }}
      >
        {/* Swallows taps so pressing the card does not dismiss through it. */}
        <Pressable
          onPress={() => {}}
          style={{
            width: '100%',
            alignItems: 'center',
            padding: spacing.xl,
            borderRadius: radius.xl,
            backgroundColor: theme.colors.surface,
          }}
        >
          <View
            style={{
              width: 64,
              height: 64,
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: radius.full,
              backgroundColor: theme.colors.successMuted,
            }}
          >
            <Ionicons name="gift" size={30} color={theme.colors.success} />
          </View>

          <Text variant="title2" className="mt-base text-center">
            +{reward.pointsAwarded.toLocaleString('en-IN')} points
          </Text>

          <Text variant="callout" tone="secondary" className="mt-xs text-center">
            {reward.description ?? 'Added to your rewards balance.'}
          </Text>

          {/* Only shown when the tier actually multiplied the award, so it
              reads as an explanation of a bigger number rather than as a
              decorative badge on every reveal. */}
          {reward.rewardTier && reward.cashValue ? (
            <Text variant="footnote" tone="muted" className="mt-sm text-center">
              {reward.rewardTier} tier · worth ₹{reward.cashValue.toLocaleString('en-IN')}
            </Text>
          ) : null}

          {typeof reward.newBalance === 'number' ? (
            <Text variant="footnote" tone="secondary" className="mt-base text-center">
              Balance: {reward.newBalance.toLocaleString('en-IN')} points
            </Text>
          ) : null}

          <Button label="Nice" fullWidth className="mt-lg" onPress={onDismiss} />
        </Pressable>
      </Pressable>
    </Modal>
  );
}
