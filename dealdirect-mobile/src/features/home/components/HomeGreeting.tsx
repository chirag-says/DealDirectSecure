import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { gesture, useTheme } from '@/theme';
import { Avatar, PressableScale, Text } from '@/ui';

/**
 * The line at the top of Home, and the way to the account.
 *
 * ---------------------------------------------------------------------------
 * A GREETING, NOT A HEADLINE
 *
 * What used to sit here was "Buy, Rent & Sell Properties Directly from Owners
 * / No middleman. No commission fees." — the website's pitch, addressed to a
 * stranger, on a screen only reachable by someone who has already installed
 * the app. This says the time of day and, if it knows it, the user's first
 * name. That is the entire content, and the point: Home opens by acknowledging
 * who is there rather than by arguing.
 *
 * Signed out it is just the time of day. No "Sign in to unlock" strapline, no
 * account benefits list — a guest can search, browse, shortlist and use the
 * calculators, and being told to log in before they have wanted anything is
 * how an app teaches people to ignore its first screen. The prompts appear
 * where an account is actually required.
 *
 * ---------------------------------------------------------------------------
 * THE AVATAR IS THE ROUTE TO PROFILE
 *
 * Profile is also a tab, so this is a second door to one destination rather
 * than the only one — which is the pattern nearly every app uses, because the
 * top-right of a home screen is where a hand expects its own account to be.
 * It carries a real image when there is one and initials when there is not;
 * for a guest it is a neutral glyph rather than an empty circle.
 */

export interface HomeGreetingProps {
  /** Full name; only the first word is used. Absent for a guest. */
  name?: string;
  avatarUri?: string;
  onOpenProfile: () => void;
}

export function HomeGreeting({ name, avatarUri, onOpenProfile }: HomeGreetingProps) {
  const theme = useTheme();
  const firstName = name?.trim().split(/\s+/)[0];

  return (
    <View className="flex-row items-center justify-between">
      <View className="flex-1 pr-base">
        <Text variant="title2" numberOfLines={1}>
          {firstName ? `${timeOfDay()}, ${firstName}` : timeOfDay()}
        </Text>
      </View>

      <PressableScale
        accessibilityRole="button"
        accessibilityLabel="Your account"
        hitSlop={gesture.hitSlop}
        onPress={onOpenProfile}
        activeScale={0.94}
      >
        {name ? (
          <Avatar uri={avatarUri} name={name} size="md" />
        ) : (
          <Ionicons name="person-circle-outline" size={34} color={theme.colors.textSecondary} />
        )}
      </PressableScale>
    </View>
  );
}

/**
 * Local device time, deliberately.
 *
 * The alternative is not greeting by time at all, because the server has no
 * notion of the user's clock. Device time is what the user's phone says it is,
 * which is the only definition that matters for the word "morning".
 */
function timeOfDay(): string {
  const hour = new Date().getHours();
  if (hour < 12) return 'Good morning';
  if (hour < 17) return 'Good afternoon';
  return 'Good evening';
}
