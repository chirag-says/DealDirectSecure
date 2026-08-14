import { View } from 'react-native';

import { spacing, useTheme } from '@/theme';
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
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NUMBERED PROSE AND NOT A GREY CARD OF ICON ROWS
 *
 * The previous version sat inside a `surfaceMuted` rounded rectangle — a
 * single grey box holding three icon-and-text rows. It read as a settings
 * panel, which is exactly backwards for the one section on Home that is pure
 * persuasion rather than navigation. Dropping the container and setting each
 * point as a numbered line lets typography and whitespace carry the
 * hierarchy instead of a background fill, which is the editorial register the
 * rest of the redesign is built in.
 */

interface Point {
  number: string;
  title: string;
  body: string;
}

const POINTS: readonly Point[] = [
  {
    number: '01',
    title: 'No brokerage',
    body: 'You deal with the owner, so there is no commission in the middle.',
  },
  {
    number: '02',
    title: 'Talk to the owner',
    body: 'Message and negotiate directly. No agent relaying answers.',
  },
  {
    number: '03',
    title: 'Verified listings',
    body: 'Every listing is reviewed by our team before it appears here.',
  },
];

export function AboutDealDirect() {
  const theme = useTheme();

  return (
    <View className="px-lg">
      <Text variant="title2">Why DealDirect</Text>
      <Text variant="callout" tone="secondary" className="mt-xs">
        Property, straight from the people who own it.
      </Text>

      <View className="mt-xl" style={{ gap: spacing.xl }}>
        {POINTS.map((point, index) => (
          <View key={point.title}>
            <View className="flex-row items-baseline" style={{ gap: spacing.md }}>
              <Text
                variant="title2"
                style={{ color: theme.colors.brand, fontVariant: ['tabular-nums'] }}
              >
                {point.number}
              </Text>
              <Text variant="title3" className="flex-1">
                {point.title}
              </Text>
            </View>

            <Text variant="callout" tone="secondary" className="mt-xs" style={{ marginLeft: 44 }}>
              {point.body}
            </Text>

            {index < POINTS.length - 1 ? (
              <View
                className="mt-lg"
                style={{ height: 1, backgroundColor: theme.colors.border, marginLeft: 44 }}
              />
            ) : null}
          </View>
        ))}
      </View>
    </View>
  );
}
