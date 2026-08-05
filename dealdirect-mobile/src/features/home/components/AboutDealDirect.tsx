import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
import { Text } from '@/ui';

/**
 * What DealDirect is, in about fifteen seconds of reading.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS THREE LINES AND NOT THE WEBSITE'S THREE SECTIONS
 *
 * The website carries "Why Choose DealDirect", "How DealDirect Works" and a
 * publications strip, and that is right there: a visitor arrives cold from a
 * search engine and has to be told what this is and why to trust it.
 *
 * A person holding the app already installed it. Re-arguing the pitch on every
 * launch spends the most valuable screen in the product on a case they have
 * already accepted. So this is not that pitch reformatted; it is the single
 * claim that distinguishes DealDirect, stated once, low on the page where
 * someone who is browsing rather than searching will pass it.
 *
 * Three points because there are genuinely three, not because three is a
 * pleasing number. No brokerage is the offer, direct contact is the mechanism,
 * verified listings is the reassurance. Each is a fact about how the product
 * works rather than an adjective about how good it is.
 *
 * NO NUMBERS. Not "10,000 happy families", not "₹50 Cr saved". The version of
 * this screen ported from the production app carried both, against a live
 * corpus of 36 listings. Copy that makes no quantitative claim cannot go stale
 * and cannot be disproved by the rail above it.
 */

interface Point {
  icon: keyof typeof Ionicons.glyphMap;
  title: string;
  body: string;
}

const POINTS: readonly Point[] = [
  {
    icon: 'pricetag-outline',
    title: 'No brokerage',
    body: 'You deal with the owner, so there is no commission in the middle.',
  },
  {
    icon: 'chatbubbles-outline',
    title: 'Talk to the owner',
    body: 'Message and negotiate directly. No agent relaying answers.',
  },
  {
    icon: 'shield-checkmark-outline',
    title: 'Checked before listing',
    body: 'Every listing is reviewed by our team before it appears here.',
  },
];

export function AboutDealDirect() {
  const theme = useTheme();

  return (
    <View
      style={{
        marginHorizontal: spacing.base,
        padding: spacing.lg,
        borderRadius: radius.xl,
        // The one recessed surface on Home. Everything above is a card sitting
        // above the page; this sits INTO it, which is what marks it as
        // editorial rather than as another thing to tap.
        backgroundColor: theme.colors.surfaceMuted,
      }}
    >
      <Text variant="title3">Why DealDirect</Text>
      <Text variant="footnote" tone="secondary" className="mt-xs">
        Property, straight from the people who own it.
      </Text>

      <View className="mt-lg" style={{ gap: spacing.base }}>
        {POINTS.map((point) => (
          <View key={point.title} className="flex-row" style={{ gap: spacing.md }}>
            <View
              className="items-center justify-center"
              style={{
                width: 38,
                height: 38,
                borderRadius: radius.md,
                backgroundColor: theme.colors.surface,
              }}
            >
              <Ionicons name={point.icon} size={19} color={theme.colors.brand} />
            </View>

            <View className="flex-1">
              <Text variant="subhead" style={{ fontWeight: '600' }}>
                {point.title}
              </Text>
              <Text variant="footnote" tone="secondary" className="mt-xs">
                {point.body}
              </Text>
            </View>
          </View>
        ))}
      </View>
    </View>
  );
}
