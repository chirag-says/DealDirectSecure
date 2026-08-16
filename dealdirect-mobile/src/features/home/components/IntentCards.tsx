import Ionicons from '@expo/vector-icons/Ionicons';
import { Pressable, View } from 'react-native';

import type { ListingIntent } from '@/features/properties';
import { radius, useTheme } from '@/theme';
import { Text } from '@/ui';

/**
 * The rent / sale split, as the first decision on the screen.
 *
 * This is the fork every property search starts from, so it gets the largest
 * targets on Home and sits above everything except the search field. Each card
 * navigates to the browse screen with `listingType` already applied — it is a
 * shortcut into the one canonical results screen, never a separate feed.
 *
 * The two cards are tinted rather than filled: a full-strength accent on a
 * half-width block would spend the primary colour on navigation, and the
 * primary is reserved for actions. The tint carries the distinction, the icon
 * and the label carry the meaning, so neither depends on colour alone.
 */

export interface IntentCardsProps {
  onSelect: (intent: ListingIntent) => void;
}

interface IntentSpec {
  intent: ListingIntent;
  eyebrow: string;
  title: string;
  icon: string;
}

const INTENTS: readonly IntentSpec[] = [
  { intent: 'rent', eyebrow: 'Find a place', title: 'For Rent', icon: 'key-outline' },
  { intent: 'sale', eyebrow: 'Find a place', title: 'For Sale', icon: 'home-outline' },
];

export function IntentCards({ onSelect }: IntentCardsProps) {
  const theme = useTheme();

  return (
    <View className="flex-row gap-md px-base">
      {INTENTS.map((spec) => {
        const isRent = spec.intent === 'rent';
        const tint = isRent ? theme.colors.dangerMuted : theme.colors.accentMuted;
        const ink = isRent ? theme.colors.danger : theme.colors.accent;

        return (
          <Pressable
            key={spec.intent}
            accessibilityRole="button"
            accessibilityLabel={`Find a place ${spec.title}`}
            onPress={() => onSelect(spec.intent)}
            // Object, not a function — see `ui/Chip.tsx`. As a function this
            // was discarded by NativeWind's interop, which is why these two
            // cards painted with no tint and square corners.
            style={{ backgroundColor: tint, borderRadius: radius.lg }}
            className="flex-1 justify-between p-base active:opacity-85"
          >
            <View className="mb-2xl">
              <Text variant="footnote" tone="secondary">
                {spec.eyebrow}
              </Text>
              <Text variant="title3" className="mt-xs">
                {spec.title}
              </Text>
            </View>

            <View className="self-end">
              <Ionicons name={spec.icon as never} size={30} color={ink} />
            </View>
          </Pressable>
        );
      })}
    </View>
  );
}
