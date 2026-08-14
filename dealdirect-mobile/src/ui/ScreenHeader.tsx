import Ionicons from '@expo/vector-icons/Ionicons';
import { router } from 'expo-router';
import React from 'react';
import { View } from 'react-native';

import { gesture, screenPadding, spacing, touchTarget, useTheme } from '@/theme';
import { PressableScale } from './PressableScale';
import { Text } from './Text';

/**
 * The nav bar. One implementation, used by every screen that has a title.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS
 *
 * Twenty screens hand-rolled the same four lines — a row, a back Pressable, a
 * chevron, a title — and no two agreed. Padding varied between `px-lg pt-md
 * pb-sm` and `px-base pt-sm`, the title was `title2` on some screens and
 * `title3` on others, some had a trailing action and some had a gap where one
 * used to be, and the back button's fallback destination was invented
 * separately each time. That is not twenty decisions; it is one decision made
 * badly twenty times.
 *
 * ---------------------------------------------------------------------------
 * TITLE ALIGNMENT
 *
 * Leading-aligned, not centred. A centred title has to be absolutely
 * positioned to stay centred against unequal left and right accessory widths,
 * and it truncates far sooner because it can only use the space between them.
 * Leading alignment gives a long screen title the whole width, which matters
 * for the real ones here ("Payment verification", "Group buy campaign").
 *
 * ---------------------------------------------------------------------------
 * THE BACK BUTTON'S FALLBACK IS NOT OPTIONAL
 *
 * `router.back()` on a screen entered by deep link has nowhere to go and
 * leaves the user stranded. Every call site therefore either passes `backTo`
 * or accepts the default of the home tab. The old hand-rolled headers each
 * chose their own, and several chose nothing.
 */

export interface ScreenHeaderProps {
  title?: string;
  /** Sits under the title, for context that is not part of the name. */
  subtitle?: string;
  /**
   * Where back goes when there is no history — a deep link or a cold start
   * into this screen. Defaults to the home tab.
   */
  backTo?: string;
  /** Hides the back affordance. For root tab screens, which have nowhere back. */
  showBack?: boolean;
  /** Trailing controls. Keep to two; three is a toolbar and belongs elsewhere. */
  actions?: React.ReactNode;
  /** Removes the bottom padding, for a header sitting directly on its content. */
  tight?: boolean;
}

export function ScreenHeader({
  title,
  subtitle,
  backTo,
  showBack = true,
  actions,
  tight = false,
}: ScreenHeaderProps) {
  const theme = useTheme();

  const goBack = () => {
    if (router.canGoBack()) {
      router.back();
      return;
    }
    // `replace`, not `push`: the user arrived here without history, so pushing
    // would build a stack whose back button leads to this same screen.
    router.replace((backTo ?? '/(tabs)') as never);
  };

  return (
    <View
      className="flex-row items-center"
      style={{
        // The same margin the content below uses. See `screenPadding` for why
        // this was the app's most widespread alignment bug.
        paddingHorizontal: screenPadding,
        paddingTop: spacing.sm,
        paddingBottom: tight ? 0 : spacing.md,
        minHeight: touchTarget.min + spacing.sm,
      }}
    >
      {showBack ? (
        <PressableScale
          accessibilityRole="button"
          accessibilityLabel="Go back"
          onPress={goBack}
          hitSlop={gesture.hitSlop}
          // Pulled left by the optical difference between the glyph's bounding
          // box and its ink, so the chevron aligns with the content below it
          // rather than sitting a few points inside.
          style={{
            width: touchTarget.min,
            height: touchTarget.min,
            marginLeft: -spacing.md,
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <Ionicons name="chevron-back" size={26} color={theme.colors.textPrimary} />
        </PressableScale>
      ) : null}

      <View className="flex-1">
        {title ? (
          <Text variant="title2" numberOfLines={1}>
            {title}
          </Text>
        ) : null}
        {subtitle ? (
          <Text variant="footnote" tone="secondary" numberOfLines={1}>
            {subtitle}
          </Text>
        ) : null}
      </View>

      {actions ? <View className="flex-row items-center gap-xs">{actions}</View> : null}
    </View>
  );
}

/**
 * A single icon control for `ScreenHeader`'s `actions`.
 *
 * Painted at 44×44 rather than at the glyph's size, because these sit within a
 * few points of each other and of the screen corner, where a mis-tap navigates
 * somewhere entirely unrelated to what the user wanted.
 */
export function HeaderAction({
  icon,
  label,
  onPress,
  tone = 'primary',
}: {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  onPress: () => void;
  tone?: 'primary' | 'accent' | 'danger';
}) {
  const theme = useTheme();
  const color =
    tone === 'accent'
      ? theme.colors.accent
      : tone === 'danger'
        ? theme.colors.danger
        : theme.colors.textPrimary;

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={label}
      onPress={onPress}
      hitSlop={gesture.hitSlop}
      style={{
        width: touchTarget.min,
        height: touchTarget.min,
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <Ionicons name={icon} size={22} color={color} />
    </PressableScale>
  );
}
