import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import type { RailProperty } from '@/features/properties';
import { radius, touchTarget, useTheme } from '@/theme';
import { selection } from '@/native';
import { PressableScale, Text, useToast } from '@/ui';
import { toggleShortlist, useIsShortlisted } from '../store';

/**
 * The shortlist control, beside the enquiry button on the detail screen.
 *
 * ---------------------------------------------------------------------------
 * WHY THERE ARE NOW TWO CONTROLS IN A BAR THAT DELIBERATELY HELD ONE
 *
 * `DetailActions` records that a `tel:` shortcut was removed from this bar on
 * instruction, leaving one action, "which is what a sticky action bar is for".
 * That reasoning stands and this does not reopen it. The call button was a
 * SECOND ROUTE TO THE SAME OUTCOME — reach the owner — competing with the
 * enquiry beside it. This is the opposite: it is the low-commitment answer to
 * the question the screen actually asks, and its whole purpose is to give
 * someone who is not ready to contact an owner something to do other than
 * press the button that contacts one.
 *
 * A bookmark, not a heart. The heart on a browse card already means "enquire"
 * in this app, with a consequence sheet behind it, and two hearts meaning two
 * different things is worse than either. A bookmark also happens to be the
 * honest glyph: this saves a listing for you, privately.
 *
 * ---------------------------------------------------------------------------
 * IT SAYS WHAT IT IS
 *
 * The toast on the first add names the limitation — the list is on this device
 * — because a user who assumes it syncs will lose work and blame the app.
 * Removal is silent: there is nothing to disclose about forgetting something.
 */

export interface ShortlistButtonProps {
  property: RailProperty;
}

export function ShortlistButton({ property }: ShortlistButtonProps) {
  const theme = useTheme();
  const toast = useToast();
  const shortlisted = useIsShortlisted(property.id);

  const handlePress = () => {
    const added = toggleShortlist(property);
    // A light tick either way — the state changed under the thumb.
    selection();
    if (added) {
      toast.show('Shortlisted. Kept on this device, and the owner is not told.', 'success');
    }
  };

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={
        shortlisted ? `Remove ${property.title} from your shortlist` : `Shortlist ${property.title}`
      }
      accessibilityState={{ selected: shortlisted }}
      onPress={handlePress}
      activeScale={0.94}
      style={{
        minWidth: touchTarget.min,
        height: touchTarget.min,
        paddingHorizontal: 14,
        borderRadius: radius.md,
        borderWidth: 1,
        borderColor: shortlisted ? theme.colors.accent : theme.colors.border,
        backgroundColor: shortlisted ? theme.colors.accentMuted : theme.colors.surface,
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <View className="flex-row items-center" style={{ gap: 6 }}>
        <Ionicons
          name={shortlisted ? 'bookmark' : 'bookmark-outline'}
          size={18}
          color={shortlisted ? theme.colors.accent : theme.colors.textSecondary}
        />
        <Text
          variant="footnote"
          tone={shortlisted ? 'accent' : 'secondary'}
          style={{ fontWeight: '600' }}
        >
          {shortlisted ? 'Saved' : 'Save'}
        </Text>
      </View>
    </PressableScale>
  );
}
