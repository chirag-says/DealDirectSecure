import Ionicons from '@expo/vector-icons/Ionicons';
import { Pressable, ScrollView, StyleSheet, View } from 'react-native';

import { spacing, useTheme } from '@/theme';
import { Sheet, Text } from '@/ui';

/**
 * One facet, one sheet, applied on tap.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NOT `FilterSheet` WITH ONE GROUP
 *
 * `FilterSheet` edits a draft and commits on Apply, and that is right for it:
 * it holds seven groups, a user setting five of them wants one search fired at
 * the end rather than five, and Reset has to be able to undo the lot.
 *
 * A single facet has none of those problems. Tapping "2 BHK" in a sheet whose
 * only content is BHK has exactly one meaning, so making the user then find and
 * press Apply is the kind of ceremony that turns a one-second decision into a
 * three-tap one. Every portal we looked at applies these immediately and closes.
 *
 * The cost is one search per tap against a 20-per-minute limiter, and it is
 * worth naming rather than hiding: these sheets carry between two and six
 * options, so a user cannot spend the budget by browsing them the way they
 * could with seven groups of chips.
 *
 * ---------------------------------------------------------------------------
 * A LIST, NOT CHIPS
 *
 * `FilterSheet` uses wrapped chips because it shows seven groups at once and
 * chips are the only shape that fits that much in a scroll. Here there is one
 * group and the full sheet width to spend, so full-width rows are better: the
 * tap target is the whole row rather than a word, the options read top to
 * bottom in one column instead of reflowing, and the current value can carry a
 * checkmark at a fixed position the eye can scan straight down.
 *
 * Height is derived from the option count rather than fixed. A three-option
 * sheet at `FilterSheet`'s 0.85 would be a screen of empty space under three
 * rows, which reads as a loading failure.
 */

export interface FacetOption {
  label: string;
  value: string;
}

export interface FacetSheetProps {
  visible: boolean;
  title: string;
  options: readonly FacetOption[];
  /** The selected value, or undefined when the facet is unset. */
  value: string | undefined;
  /**
   * Called with the tapped value, or `undefined` when the user picks the
   * clear-all row or re-taps the current selection. The caller closes the
   * sheet; this component does not, so a caller can keep it open on failure.
   */
  onSelect: (value: string | undefined) => void;
  onClose: () => void;
  /**
   * Label for the row that clears the facet. Omitted for facets that always
   * hold a value — sort, for instance, has no "no sort" state.
   */
  clearLabel?: string;
}

/** Row height plus the sheet's own handle, title and padding. */
const ROW_HEIGHT = 52;
const SHEET_CHROME = 120;

export function FacetSheet({
  visible,
  title,
  options,
  value,
  onSelect,
  onClose,
  clearLabel,
}: FacetSheetProps) {
  const rows = options.length + (clearLabel ? 1 : 0);
  // Capped at half the screen so a long facet (city) scrolls rather than
  // becoming a full-height sheet the user has to dismiss twice.
  const heightRatio = Math.min(0.55, (rows * ROW_HEIGHT + SHEET_CHROME) / 812);

  return (
    <Sheet visible={visible} onClose={onClose} title={title} heightRatio={heightRatio}>
      <ScrollView showsVerticalScrollIndicator={false}>
        {clearLabel ? (
          <FacetRow
            label={clearLabel}
            selected={value === undefined}
            onPress={() => onSelect(undefined)}
          />
        ) : null}

        {options.map((option) => (
          <FacetRow
            key={option.value}
            label={option.label}
            selected={value === option.value}
            // Re-tapping the current value clears it rather than doing
            // nothing, which is the same affordance the chips in
            // `FilterSheet` give. Facets without a clear row are the ones
            // that must always hold a value, so there it is a no-op instead.
            onPress={() => onSelect(value === option.value && clearLabel ? undefined : option.value)}
          />
        ))}
      </ScrollView>
    </Sheet>
  );
}

function FacetRow({
  label,
  selected,
  onPress,
}: {
  label: string;
  selected: boolean;
  onPress: () => void;
}) {
  const theme = useTheme();

  return (
    <Pressable
      accessibilityRole="radio"
      accessibilityState={{ selected }}
      accessibilityLabel={label}
      onPress={onPress}
      // A plain object, NOT a `({ pressed }) => …` function: NativeWind's JSX
      // pragma spreads a function-valued `style` into `{}` and assigns that
      // over the prop, so the function is never called and the row renders
      // with no layout at all. `active:` carries the press instead.
      className="active:opacity-60"
      style={{
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        minHeight: ROW_HEIGHT,
        paddingVertical: spacing.md,
        borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: theme.colors.border,
      }}
    >
      <Text
        variant={selected ? 'bodyEmphasis' : 'body'}
        tone={selected ? 'accent' : 'primary'}
        className="flex-1"
      >
        {label}
      </Text>

      {/* A checkmark rather than a radio circle: an unselected radio draws an
          empty ring on every row, which is eleven pieces of chrome saying
          nothing. The absent checkmark says the same thing with no ink. */}
      {selected ? (
        <View className="ml-md">
          <Ionicons name="checkmark" size={20} color={theme.colors.accent} />
        </View>
      ) : null}
    </Pressable>
  );
}
