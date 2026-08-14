import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
import { Button, Text } from '@/ui';

/**
 * The signed-out state of a screen that needs an account.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NOT JUST AN `EmptyState`
 *
 * Six screens rendered one — Saved, Saved searches, Profile, Notifications,
 * Rewards, Messages — and every one of them had the same two problems.
 *
 * They offered exactly one way forward: "Sign in". A brand-new user, who is
 * the single most likely person to be looking at a signed-out screen, had no
 * route to an account from any of them. They had to find the sign-in screen,
 * read it, and notice the "create an account" link at the bottom. That is a
 * dead end wearing a button.
 *
 * And they were undifferentiated: a bare title over a bare button, identical
 * on all six, which reads as a wall rather than an invitation. The icon says
 * WHICH thing is behind the gate, so the screen is still communicating
 * something even before you act on it.
 *
 * ---------------------------------------------------------------------------
 * THE ICON WELL IS TINTED, NOT FILLED
 *
 * A large solid-accent circle on an otherwise empty screen reads as an alert.
 * The muted tint carries the same shape at a fraction of the weight, which is
 * the difference between "you are locked out" and "there is something here
 * for you".
 */

export interface SignInPromptProps {
  /** What is behind the gate. Names the thing, not the act of signing in. */
  title: string;
  description: string;
  icon?: keyof typeof Ionicons.glyphMap;
  /**
   * Sits at the top of a scroll instead of filling and centring the screen.
   *
   * The default is right for the five screens where EVERYTHING needs an
   * account — Saved, Saved searches, Notifications, Rewards, Messages have
   * literally nothing to show a guest, so the prompt is the screen.
   *
   * Profile is the exception, and it is not a styling preference. Half of what
   * that screen indexes needs no account at all: browsing listings, builder
   * projects, the blog, the calculators and the help page all work signed out.
   * A full-height prompt there hides working destinations behind a wall, which
   * is the same dead end this component was built to stop — just one level up.
   */
  compact?: boolean;
}

export function SignInPrompt({
  title,
  description,
  icon = 'lock-closed-outline',
  compact = false,
}: SignInPromptProps) {
  const router = useRouter();
  const theme = useTheme();

  return (
    <View
      className={
        compact ? 'items-center px-xl py-xl' : 'flex-1 items-center justify-center px-xl'
      }
    >
      <View
        style={{
          width: 72,
          height: 72,
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: radius.full,
          backgroundColor: theme.colors.accentMuted,
          marginBottom: spacing.lg,
        }}
      >
        <Ionicons name={icon} size={30} color={theme.colors.accent} />
      </View>

      <Text variant="title3" className="text-center">
        {title}
      </Text>
      <Text variant="callout" tone="secondary" className="mt-sm text-center">
        {description}
      </Text>

      <Button
        label="Sign in"
        align="center"
        className="mt-xl"
        onPress={() => router.push('/(auth)/login')}
      />

      {/* The path a new user actually needs, and the one all six of these
          screens were missing. Secondary, because returning users outnumber
          new ones on a screen you reach by tapping a tab. */}
      <Button
        label="Create an account"
        variant="ghost"
        align="center"
        className="mt-xs"
        onPress={() => router.push('/(auth)/register')}
      />
    </View>
  );
}
