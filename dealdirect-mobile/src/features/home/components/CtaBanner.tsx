import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { palette, radius, spacing } from '@/theme';
import { PressableScale, Text } from '@/ui';

/**
 * The closing call to action.
 *
 * Kept, against the general rule that marketing blocks belong on the website,
 * because of where it sits. This is the last thing on Home. A scroll that ends
 * by simply running out reads as the app having nothing more; ending on a
 * deliberate statement reads as arrival. People weight the end of an
 * experience out of all proportion to its middle, so the final screenful is
 * worth spending on.
 *
 * Trimmed from the original's full gradient slab. The brief for this redesign
 * asks for restraint everywhere, including here: a shorter block, a single
 * flat red rather than a gradient, and copy set left rather than centred so it
 * reads as one more editorial section instead of a banner interrupting them.
 *
 * What it does NOT do is claim anything. The original said "thousands of
 * verified properties" above a corpus of 36. The copy here is an invitation
 * with no number in it, which needs no maintenance and cannot go stale.
 */

export interface CtaBannerProps {
  onPress: () => void;
}

export function CtaBanner({ onPress }: CtaBannerProps) {
  return (
    <View
      className="mx-lg"
      style={{
        padding: spacing.lg,
        borderRadius: radius.xl,
        backgroundColor: palette.red600,
      }}
    >
      <Text variant="title3" style={{ color: palette.neutral0 }}>
        Ready to find your home?
      </Text>
      <Text variant="footnote" className="mt-xs" style={{ color: 'rgba(255,255,255,0.82)' }}>
        Browse properties directly from owners.
      </Text>

      <PressableScale
        accessibilityLabel="Browse properties"
        onPress={onPress}
        style={{
          marginTop: spacing.base,
          alignSelf: 'flex-start',
          flexDirection: 'row',
          alignItems: 'center',
          gap: spacing.xs,
          height: 40,
          paddingHorizontal: spacing.base,
          borderRadius: radius.full,
          backgroundColor: palette.neutral0,
        }}
      >
        <Text variant="subhead" style={{ color: palette.red600, fontWeight: '600' }}>
          Browse Properties
        </Text>
        <Ionicons name="arrow-forward" size={15} color={palette.red600} />
      </PressableScale>
    </View>
  );
}
