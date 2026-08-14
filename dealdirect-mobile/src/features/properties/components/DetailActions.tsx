import Ionicons from '@expo/vector-icons/Ionicons';
import { useCallback } from 'react';
import { Alert, Linking, StyleSheet, View, type LayoutChangeEvent } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { screenPadding, spacing, useTheme } from '@/theme';
import { Button, PressableScale, Text } from '@/ui';
import type { InterestState } from '../interest';
import type { PropertyDetail } from '../types';

/**
 * The action bar, pinned to the bottom of the detail screen.
 *
 * Pinned rather than placed inline because it is the only thing on this screen
 * the user is meant to DO, and the screen is long enough that an inline button
 * would sit several scrolls below where the decision is actually made.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS NOT IN HERE ANY MORE
 *
 * Share and Report were. Both are rare, neither is what the screen is for, and
 * a bar of four equal-weight icons next to the primary action reads as a
 * toolbar of options rather than as one decision. Share belongs in the nav bar,
 * which is where a user reaches for it; Report belongs at the foot of the page,
 * after the thing being reported. What survives here is the primary action and
 * the two ways to reach a human about it.
 *
 * ---------------------------------------------------------------------------
 * WHY THE PRIMARY ACTION IS A LABELLED BUTTON AND NOT A HEART
 *
 * Marking interest notifies the owner, creates a lead against the user's name,
 * email and phone, and counts against a cap of five. A heart icon communicates
 * the opposite of every one of those: private, free, unlimited, undoable
 * without consequence. So the control is labelled, and the consequence line
 * under it says what happens before the press rather than after.
 *
 * Reversing it is offered — `DELETE /interested/:id` works — but the line does
 * not promise that undoing unsends the notification, because it does not. The
 * lead survives.
 *
 * ---------------------------------------------------------------------------
 * Calling is offered only to signed-in users. Worth being honest about what
 * that is and is not: `GET /properties/:id` is a PUBLIC endpoint and populates
 * the owner's phone and email into its response, so the number is already
 * readable by anyone who calls the API directly. The gate here is a product
 * decision about what the app encourages, not a control that protects the
 * data. Protecting it means changing what the endpoint returns.
 */

export interface DetailActionsProps {
  property: PropertyDetail;
  interest: InterestState;
  /**
   * Reports the painted height, so the scroll view above can end its content
   * clear of the bar. A hard-coded constant here would be wrong on the first
   * device with a different bottom inset, and wrong again the moment the
   * consequence line wraps to two lines at a large text size.
   */
  onHeightChange?: (height: number) => void;
}

export function DetailActions({ property, interest, onHeightChange }: DetailActionsProps) {
  const insets = useSafeAreaInsets();
  const theme = useTheme();

  const phone = property.owner?.phone?.replace(/[^\d+]/g, '');
  const canCall = !!phone && !interest.requiresAuth;

  const handleCall = useCallback(async () => {
    if (!phone) return;

    const url = `tel:${phone}`;
    const supported = await Linking.canOpenURL(url);

    // A simulator and some tablets have no dialler. Failing with an
    // explanation beats a press that does nothing at all.
    //
    // Stays an `Alert` rather than becoming a toast, unlike the other passive
    // errors in this pass: it carries the number the user now has to dial by
    // hand, and a toast that vanishes after 2.6 seconds is not long enough to
    // read and transcribe ten digits.
    if (!supported) {
      Alert.alert('Cannot place calls', `Owner's number: ${phone}`);
      return;
    }

    await Linking.openURL(url);
  }, [phone]);

  const handleLayout = useCallback(
    (event: LayoutChangeEvent) => onHeightChange?.(event.nativeEvent.layout.height),
    [onHeightChange]
  );

  return (
    <View
      onLayout={handleLayout}
      className="bg-surface"
      style={{
        paddingHorizontal: screenPadding,
        paddingTop: spacing.md,
        paddingBottom: insets.bottom + spacing.md,
        borderTopWidth: StyleSheet.hairlineWidth,
        borderTopColor: theme.colors.border,
        // An UPWARD shadow. This bar is chrome floating over content that
        // keeps scrolling beneath it, and a hairline alone does not say that —
        // it says "the page ends here". The shadow is what makes the last row
        // of the attribute table read as passing under the bar rather than
        // being cut off by it.
        shadowColor: '#000',
        shadowOpacity: 0.1,
        shadowRadius: 16,
        shadowOffset: { width: 0, height: -4 },
        elevation: 16,
      }}
    >
      {interest.error ? (
        <Text variant="footnote" tone="danger" className="mb-sm">
          {interest.error}
        </Text>
      ) : (
        <Text variant="caption" tone="muted" className="mb-sm">
          {interest.isInterested
            ? 'The owner has your contact details and can reach you.'
            : 'The owner will be notified and can contact you directly.'}
        </Text>
      )}

      <View className="flex-row items-center">
        <View className="flex-1">
          <Button
            label={interest.isInterested ? "You're interested" : "I'm interested"}
            variant={interest.isInterested ? 'secondary' : 'primary'}
            loading={interest.isPending || interest.isLoading}
            onPress={interest.toggle}
            fullWidth
            leading={
              interest.isInterested ? (
                <Ionicons name="checkmark" size={17} color={theme.colors.textPrimary} />
              ) : undefined
            }
          />
        </View>

        {canCall ? (
          <IconAction icon="call-outline" label="Call owner" onPress={handleCall} />
        ) : null}
      </View>
    </View>
  );
}

/**
 * A secondary action beside the primary one.
 *
 * Filled rather than outlined, so it sits in the same visual family as the
 * button it stands next to instead of being an empty box beside a solid one,
 * and pressed with `PressableScale` rather than an opacity fade — dimming a
 * control on touch is the same signal as disabling it.
 *
 * The fill paints at 48pt, which is the primary button's height at the default
 * size (12pt padding either side of a 24pt line box) and is above the 44pt
 * minimum on both axes, so there is nothing to make up with hit slop.
 */
function IconAction({
  icon,
  label,
  onPress,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  onPress: () => void;
}) {
  const theme = useTheme();

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={label}
      onPress={onPress}
      style={{ marginLeft: 8 }}
    >
      <View className="h-12 w-12 items-center justify-center rounded-lg bg-surface-muted">
        <Ionicons name={icon} size={22} color={theme.colors.textPrimary} />
      </View>
    </PressableScale>
  );
}
