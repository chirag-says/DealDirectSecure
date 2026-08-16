import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { gesture, radius, spacing, touchTarget, useTheme } from '@/theme';
import { PressableScale, Text } from '@/ui';

/**
 * The results toolbar: how many, and the three controls that act on the whole
 * set.
 *
 * ---------------------------------------------------------------------------
 * WHERE IT SITS, AND WHY IT SCROLLS
 *
 * Inside the list as its header, not pinned above it. The screen's fixed chrome
 * is already a search field and a filter rail; pinning a third row would spend
 * about a fifth of the viewport on how to look before showing anything to look
 * at. The count and these controls describe the ANSWER, and an answer belongs
 * with the results — the question (field, filters) is what stays put, because
 * that is what a user reaches for while looking at a result they want to
 * change.
 *
 * ---------------------------------------------------------------------------
 * IT IS A TOOLBAR NOW RATHER THAN TWO ICONS AFTER A SENTENCE
 *
 * The row is exactly `touchTarget.min` tall and the controls are square at that
 * height, so the count's baseline is centred against a real bar instead of
 * floating above two 36pt circles that left a band of dead space under it. The
 * previous version also carried its own bottom padding on top of the list's
 * `gap`, which stacked into roughly 45pt between the last filter pill and the
 * first card.
 *
 * ---------------------------------------------------------------------------
 * THE COMPARE TOGGLE IS A MODE, AND MODES HAVE TO BE UNMISSABLE
 *
 * Compare selection used to be a permanent unlabelled circle on every card —
 * the corner where every user looks for the save control, occupied by a control
 * whose meaning could not be guessed. It is a mode now, which is a real cost,
 * so it is paid for properly: the toggle fills with the accent while it is on,
 * the cards swap their heart for a checkbox, and the compare bar appears at the
 * bottom of the screen. Three simultaneous signals for a state the user opted
 * into deliberately.
 */

export interface ResultsToolbarProps {
  total: number;
  density: 'card' | 'row';
  onToggleDensity: () => void;
  comparing: boolean;
  /** Shown on the toggle while comparing, so the count is legible without
   *  reading the bar at the far end of the screen. */
  compareCount: number;
  onToggleCompare: () => void;
  onSaveSearch: () => void;
  /** Hidden while comparing: the selection lives on the card, so switching to
   *  the compact row would strand it on a view that cannot show it. */
  showDensity?: boolean;
}

export function ResultsToolbar({
  total,
  density,
  onToggleDensity,
  comparing,
  compareCount,
  onToggleCompare,
  onSaveSearch,
  showDensity = true,
}: ResultsToolbarProps) {
  return (
    <View
      className="flex-row items-center justify-between"
      style={{ height: touchTarget.min }}
    >
      <Text variant="subhead" tone="secondary">
        {total.toLocaleString('en-IN')} {total === 1 ? 'property' : 'properties'}
      </Text>

      <View className="flex-row items-center">
        {/*
          Saving is offered only once there are results — the caller gates on
          that — because a saved search that matched nothing produces an alert
          the user cannot interpret.
        */}
        <ToolbarButton
          icon="bookmark-outline"
          label="Save this search"
          onPress={onSaveSearch}
        />

        <ToolbarButton
          icon="git-compare-outline"
          label={
            comparing ? 'Exit compare mode, ' + compareCount + ' selected' : 'Compare properties'
          }
          active={comparing}
          badge={comparing ? compareCount : undefined}
          onPress={onToggleCompare}
        />

        {/*
          Density. Not decoration: the compact row fits about three times as
          many results per screen, which matters most to users on large
          accessibility text who see fewest. The icon shows the view you will
          GET, which is the convention every gallery app uses — showing the
          current view instead is the classic mode-signifier inversion.
        */}
        {showDensity ? (
          <ToolbarButton
            icon={density === 'card' ? 'list-outline' : 'grid-outline'}
            label={density === 'card' ? 'Switch to compact list' : 'Switch to large cards'}
            onPress={onToggleDensity}
          />
        ) : null}
      </View>
    </View>
  );
}

/**
 * One toolbar control.
 *
 * Square at the full touch target, with no visible chrome until it is active.
 * A row of three outlined buttons beside a line of grey text would out-shout
 * the count they belong to; a bare glyph at a proper size is the quieter and
 * larger option, which is rarely a trade you get to make.
 */
function ToolbarButton({
  icon,
  label,
  active = false,
  badge,
  onPress,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  active?: boolean;
  /** Rendered beside the glyph when active. Widens the control; the 44pt
   *  height and the 19pt icon do not change, so the row stays one system. */
  badge?: number;
  onPress: () => void;
}) {
  const theme = useTheme();
  const showBadge = active && badge !== undefined;

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={label}
      accessibilityState={{ selected: active }}
      hitSlop={gesture.hitSlop}
      onPress={onPress}
      activeScale={0.9}
      style={{
        height: touchTarget.min,
        minWidth: touchTarget.min,
        alignItems: 'center',
        justifyContent: 'center',
        marginLeft: spacing.xs,
      }}
    >
      <View
        className="flex-row items-center justify-center"
        style={{
          height: 34,
          minWidth: 34,
          paddingHorizontal: showBadge ? spacing.sm : 0,
          borderRadius: radius.sm,
          backgroundColor: active ? theme.colors.accentMuted : 'transparent',
        }}
      >
        <Ionicons
          name={icon}
          size={19}
          color={active ? theme.colors.accent : theme.colors.textSecondary}
        />
        {showBadge ? (
          <Text
            variant="footnote"
            style={{ marginLeft: spacing.xs, color: theme.colors.accent, fontWeight: '600' }}
          >
            {badge}
          </Text>
        ) : null}
      </View>
    </PressableScale>
  );
}
