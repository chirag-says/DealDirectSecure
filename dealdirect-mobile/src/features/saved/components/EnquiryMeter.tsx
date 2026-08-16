import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { spacing, useTheme } from '@/theme';
import { CARD_RADIUS } from '@/features/properties';
import { ProgressBar, Text } from '@/ui';
import { INTEREST_LIMIT } from '../hooks';

/**
 * How many of the five enquiries are spent.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A COMPONENT AND NOT A SENTENCE
 *
 * The backend refuses a sixth enquiry anywhere in the app, so this screen is
 * where a user comes to make room. That makes the count a functional part of
 * the screen rather than a statistic: it is the reason the next tap on another
 * screen will fail, and the thing the user has to act on here.
 *
 * ---------------------------------------------------------------------------
 * WHAT WAS WRONG WITH THE VERSION THIS REPLACES
 *
 * The three parts — "4 of 5 enquiries used", the bar, "1 left" — were laid
 * loose on the page background at full screen width, above a stack of white
 * cards. A 2pt line running edge to edge with a label floating over it does
 * not read as a component; it reads as a progress indicator for the screen
 * itself, which is a thing several apps genuinely do. So the first thing a user
 * had to work out was that the page was not loading.
 *
 * It sits on a surface now, inset with the cards below it, with the bar inside
 * that surface's padding. Same three facts, grouped into one object that
 * belongs to the list it describes.
 *
 * ---------------------------------------------------------------------------
 * IT CHANGES CHARACTER AT THE CAP
 *
 * At 5 of 5 the meter has stopped being information and started being the
 * reason the next tap will fail, so it turns brand-toned and grows a line
 * saying what to do about it. That line is the only instruction on the screen
 * and it appears only when it is actionable — an always-present "you can save
 * up to five" is noise for the four states where it is not yet true.
 */
export function EnquiryMeter({ used }: { used: number }) {
  const theme = useTheme();
  const remaining = Math.max(0, INTEREST_LIMIT - used);
  const full = remaining === 0;

  return (
    <View
      className="bg-surface"
      // The card radius, not the generic one: this sits directly above a
      // column of property cards at the same width, and a surface with a
      // tighter corner than the thing under it reads as a different system.
      style={{ borderRadius: CARD_RADIUS, padding: spacing.base }}
    >
      <View className="flex-row items-center justify-between">
        <Text variant="subhead">
          {used} of {INTEREST_LIMIT} enquiries used
        </Text>
        <Text variant="footnote" tone={full ? 'danger' : 'muted'}>
          {full ? 'Limit reached' : `${remaining} left`}
        </Text>
      </View>

      <View className="mt-sm">
        <ProgressBar
          value={used / INTEREST_LIMIT}
          tone={full ? 'brand' : 'accent'}
          size="sm"
          label={`${used} of ${INTEREST_LIMIT} enquiries used`}
        />
      </View>

      {full ? (
        <View className="mt-sm flex-row items-start">
          <Ionicons
            name="information-circle-outline"
            size={14}
            color={theme.colors.textMuted}
            style={{ marginTop: 2 }}
          />
          <Text variant="caption" tone="muted" className="ml-xs flex-1">
            Tap the heart on a listing below to free a slot.
          </Text>
        </View>
      ) : null}
    </View>
  );
}
