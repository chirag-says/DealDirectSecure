import Ionicons from '@expo/vector-icons/Ionicons';

import { palette, radius, spacing } from '@/theme';
import { Gradient, PressableScale, Text } from '@/ui';

/**
 * The closing call to action.
 *
 * Ported from the original screen and kept, against the general rule that
 * marketing blocks belong on the website, because of where it sits. This is the
 * last thing on Home. A scroll that ends by simply running out reads as the app
 * having nothing more; ending on a deliberate full-width statement reads as
 * arrival. People weight the end of an experience out of all proportion to its
 * middle, so the final screenful is worth spending on.
 *
 * What it does NOT do is claim anything. The original said "thousands of
 * verified properties" above a corpus of 36. The copy here is an invitation
 * with no number in it, which needs no maintenance and cannot go stale.
 */

const CTA_GRADIENT = [palette.red600, palette.red700] as const;

export interface CtaBannerProps {
  onPress: () => void;
}

export function CtaBanner({ onPress }: CtaBannerProps) {
  return (
    <Gradient
      colors={CTA_GRADIENT}
      // Diagonal rather than vertical. On a short wide block a vertical fade
      // reads as a printing error; across the diagonal it reads as light.
      angle={135}
      style={{
        margin: spacing.base,
        padding: spacing.xl,
        borderRadius: radius.xl,
        alignItems: 'center',
      }}
    >
      <Text variant="title2" className="text-center" style={{ color: palette.neutral0 }}>
        Ready to find your home?
      </Text>

      <Text
        variant="callout"
        className="mt-sm text-center"
        style={{ color: 'rgba(255,255,255,0.86)' }}
      >
        Browse every listing, straight from the owner.
      </Text>

      <PressableScale
        accessibilityLabel="Explore properties"
        onPress={onPress}
        style={{
          marginTop: spacing.lg,
          flexDirection: 'row',
          alignItems: 'center',
          gap: spacing.sm,
          height: 48,
          paddingHorizontal: spacing.xl,
          borderRadius: radius.full,
          backgroundColor: palette.neutral0,
        }}
      >
        <Text variant="bodyEmphasis" style={{ color: palette.red600 }}>
          Explore Properties
        </Text>
        <Ionicons name="arrow-forward" size={18} color={palette.red600} />
      </PressableScale>
    </Gradient>
  );
}
