import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { track } from '@/analytics';
import { useAuth } from '@/auth';
import type { RailProperty } from '@/features/properties';
import { registerPushTokenIfPermitted, requestNotificationPermissionOnce } from '@/notifications';
import { radius, touchTarget, useTheme } from '@/theme';
import { selection } from '@/native';
import { PressableScale, Text, useToast } from '@/ui';
import { useIsShortlisted, useShortlistSync, useToggleShortlist } from '../hooks';

/**
 * The shortlist control, beside the enquiry button on the detail screen.
 *
 * ---------------------------------------------------------------------------
 * WHY THERE ARE TWO CONTROLS IN A BAR THAT DELIBERATELY HELD ONE
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
 * different things is worse than either.
 *
 * ---------------------------------------------------------------------------
 * WHAT CHANGED IN PHASE 1, AND WHAT DID NOT
 *
 * The shortlist has a server now (`/api/shortlist`), so this button issues a
 * request when there is a session: the list follows the user to a second
 * phone. What has NOT changed is the invariant the feature exists for — a
 * shortlist entry still creates no Lead, notifies no owner, awards no points
 * and counts against no cap. The toast still says the owner is not told,
 * because that is the fact a user needs before they tap it twenty times.
 *
 * A SIGNED-OUT tap still saves locally and says so. Those saves are handed to
 * the server once, at the first authenticated launch (`useShortlistSync`), so
 * a guest who browses for a week and then registers keeps everything.
 *
 * ---------------------------------------------------------------------------
 * THE PERMISSION MOMENT (Phase 0, unchanged)
 *
 * An add is one of the two places the OS notification prompt is asked (the
 * other is saving a search), and it is asked here rather than at launch
 * because this is the first moment the user has shown they want to hear about
 * something. `requestNotificationPermissionOnce` asks at most once ever;
 * `registerPushTokenIfPermitted` then posts the device token if the answer was
 * yes and there is a signed-in account to post it for.
 */

export interface ShortlistButtonProps {
  property: RailProperty;
}

export function ShortlistButton({ property }: ShortlistButtonProps) {
  const theme = useTheme();
  const toast = useToast();
  const { status } = useAuth();
  const shortlisted = useIsShortlisted(property.id);
  const { toggle } = useToggleShortlist();

  // The handover, if this account has not had one. Mounted here because the
  // detail screen is where a returning guest most often signs in, and because
  // it costs nothing when there is nothing to hand over.
  useShortlistSync();

  const handlePress = () => {
    const added = toggle(property);
    // A light tick either way — the state changed under the thumb.
    selection();
    if (added) {
      toast.show(
        status === 'authenticated'
          ? 'Shortlisted. The owner is not told, and there is no limit.'
          : 'Saved on this device. Sign in and it moves to your account.',
        'success'
      );
      track('shortlist_add', { propertyId: property.id });
      void requestNotificationPermissionOnce().then(registerPushTokenIfPermitted);
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
