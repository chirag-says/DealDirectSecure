import Ionicons from '@expo/vector-icons/Ionicons';
import { useCallback, useState } from 'react';
import { Pressable, ScrollView, View } from 'react-native';

import type { ListingIntent } from '@/features/properties';
import { gesture, radius, spacing, useTheme } from '@/theme';
import { Segmented, Text, type SegmentedOption } from '@/ui';
import {
  BHK_OPTIONS,
  CATEGORY_OPTIONS,
  CONSTRUCTION_STATUS_OPTIONS,
  FURNISHING_OPTIONS,
  LISTING_TYPE_OPTIONS,
  PRICE_BANDS,
  SORT_OPTIONS,
  countActiveFilters,
  type SearchFilters,
} from '../filters';
import { FacetSheet, type FacetOption } from './FacetSheet';

/**
 * The quick-filter rail.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS REPLACES, AND WHY
 *
 * The results screen previously offered exactly two controls above the list: a
 * Filters button and three rent/sale chips. Everything else — price,
 * configuration, city, furnishing, possession, sort — lived behind the Filters
 * button, four taps deep (open, scroll, choose, apply) for a value most buyers
 * change several times in a single session.
 *
 * Every large Indian portal solves this the same way and it is worth being
 * explicit that this is copied rather than invented. 99acres' results page runs
 * a sticky horizontal pill rail reading Sort · Owner · Budget · BHK · Property
 * Type · Verified · Ready To Move; Square Yards runs a narrower Filters · Sort
 * strip pinned under its search field; Housing pins a search bar and a bottom
 * nav and puts the facets in a sheet behind a single control. The first is the
 * right model for us because our corpus is small enough that most searches need
 * narrowing rather than expanding.
 *
 * ---------------------------------------------------------------------------
 * THE THREE KINDS OF CONTROL ON ONE RAIL, AND WHY THEY LOOK DIFFERENT
 *
 * 1. **Filters** opens a different surface rather than setting a value. It
 *    leads the rail and is separated by a hairline, the same treatment it had
 *    before, because it is a different KIND of control from everything after it.
 *
 * 2. **Listing type** is one value with three spellings, so it is a segmented
 *    control rather than three chips — see `ui/Segmented.tsx`. It stays inline
 *    and one tap deep, rather than becoming a facet pill like the rest, because
 *    it is the primary axis of a property search: a user who arrived from
 *    Home's "For Rent" card must be able to see and change it without opening
 *    anything to find out why the results look the way they do.
 *
 * 3. **Facet pills** each open a small sheet. A pill shows its FACET NAME when
 *    unset ("Budget") and its VALUE when set ("₹25 Lakh – ₹1 Crore"), which is
 *    the property that makes the rail readable at a glance: the state of the
 *    search is spelled out along the strip instead of being summarised as a
 *    number on a funnel icon.
 *
 * Possession is the one exception — a direct toggle, no sheet. "Ready to move"
 * is the option nearly everyone who touches that facet wants, so it gets the
 * single tap and the full sheet keeps "Under construction". If the user does
 * pick the other one from the full sheet, this pill shows THAT value rather
 * than lying about the state, and tapping clears it.
 */

export interface QuickFilterBarProps {
  filters: SearchFilters;
  onChange: (filters: SearchFilters) => void;
  onOpenAllFilters: () => void;
}

/** Which facet sheet is up, or null. */
type FacetKey = 'sort' | 'priceBand' | 'bhk' | 'categoryName' | 'furnishing';

/**
 * `SearchFilters.listingType` uses `undefined` for "either", and `Segmented`
 * takes a string union — a control where exactly one option is always chosen
 * has no use for an absent value, and loosening its generic so one caller can
 * pass `undefined` would weaken it for every other. So "either" is spelled
 * `'all'` across this boundary and converted back in `setIntent`.
 *
 * The labels come from `LISTING_TYPE_OPTIONS` rather than being retyped, so the
 * rail and the rest of the search feature cannot drift on what to call them.
 */
type IntentSegment = ListingIntent | 'all';

const INTENT_SEGMENTS: readonly SegmentedOption<IntentSegment>[] = LISTING_TYPE_OPTIONS.map(
  (option) => ({ label: option.label, value: option.value ?? 'all' })
);

interface FacetSpec {
  key: FacetKey;
  /** Shown on the pill and as the sheet title when nothing is chosen. */
  label: string;
  options: readonly FacetOption[];
  /** Absent for facets that must always hold a value. */
  clearLabel?: string;
}

const FACETS: readonly FacetSpec[] = [
  {
    key: 'sort',
    label: 'Sort',
    options: SORT_OPTIONS.map((option) => ({ label: option.label, value: option.value })),
  },
  {
    key: 'priceBand',
    label: 'Budget',
    options: PRICE_BANDS.map((band) => ({ label: band.label, value: band.id })),
    clearLabel: 'Any budget',
  },
  {
    key: 'bhk',
    label: 'Rooms',
    options: BHK_OPTIONS,
    clearLabel: 'Any configuration',
  },
  {
    key: 'categoryName',
    label: 'Type',
    options: CATEGORY_OPTIONS,
    clearLabel: 'Any type',
  },
  {
    key: 'furnishing',
    label: 'Furnishing',
    options: FURNISHING_OPTIONS,
    clearLabel: 'Any furnishing',
  },
];

/**
 * The pill's text.
 *
 * Sort is the special case: it always holds a value, so showing it would mean
 * the pill permanently reads "Newest first" and permanently looks selected.
 * The facet name is shown while the value is the default, and the value only
 * once the user has actually chosen something.
 */
function pillLabel(spec: FacetSpec, filters: SearchFilters): { text: string; active: boolean } {
  const value = filters[spec.key];

  if (spec.key === 'sort') {
    if (!value || value === 'newest') return { text: spec.label, active: false };
    const match = spec.options.find((option) => option.value === value);
    return { text: match?.label ?? spec.label, active: true };
  }

  if (!value) return { text: spec.label, active: false };

  const match = spec.options.find((option) => option.value === value);
  return { text: match?.label ?? spec.label, active: true };
}

export function QuickFilterBar({ filters, onChange, onOpenAllFilters }: QuickFilterBarProps) {
  const theme = useTheme();
  const [openFacet, setOpenFacet] = useState<FacetKey | null>(null);
  const activeCount = countActiveFilters(filters);

  const setIntent = useCallback(
    (value: IntentSegment) =>
      onChange({ ...filters, listingType: value === 'all' ? undefined : value }),
    [filters, onChange]
  );

  const setFacet = useCallback(
    (key: FacetKey, value: string | undefined) => {
      // Sort has no cleared state — dismissing without a pick leaves it alone.
      if (key === 'sort') {
        if (value) onChange({ ...filters, sort: value as SearchFilters['sort'] });
      } else {
        onChange({ ...filters, [key]: value });
      }
      setOpenFacet(null);
    },
    [filters, onChange]
  );

  const possession = filters.constructionStatus;
  const possessionLabel =
    CONSTRUCTION_STATUS_OPTIONS.find((option) => option.value === possession)?.label ??
    'Ready to move';

  const togglePossession = useCallback(() => {
    onChange({
      ...filters,
      constructionStatus: filters.constructionStatus ? undefined : 'ready',
    });
  }, [filters, onChange]);

  const activeSpec = FACETS.find((spec) => spec.key === openFacet);

  return (
    <>
      <ScrollView
        horizontal
        showsHorizontalScrollIndicator={false}
        contentContainerStyle={RAIL_STYLE}
        // Without this a tap on a pill while the search field has focus is
        // swallowed by the keyboard dismissal and has to be repeated.
        keyboardShouldPersistTaps="handled"
      >
        <Pill
          icon="options-outline"
          label={activeCount > 0 ? `Filters · ${activeCount}` : 'Filters'}
          active={activeCount > 0}
          accessibilityLabel={activeCount > 0 ? `Filters, ${activeCount} applied` : 'Filters'}
          onPress={onOpenAllFilters}
        />

        <View
          style={{
            width: 1,
            alignSelf: 'stretch',
            marginVertical: spacing.xs,
            backgroundColor: theme.colors.border,
          }}
        />

        <Segmented
          compact
          options={INTENT_SEGMENTS}
          value={filters.listingType ?? 'all'}
          onChange={setIntent}
          accessibilityLabel="Listing type"
        />

        {FACETS.map((spec) => {
          const { text, active } = pillLabel(spec, filters);
          return (
            <Pill
              key={spec.key}
              label={text}
              active={active}
              chevron
              accessibilityLabel={active ? `${spec.label}, ${text}` : spec.label}
              onPress={() => setOpenFacet(spec.key)}
            />
          );
        })}

        <Pill
          label={possessionLabel}
          active={Boolean(possession)}
          accessibilityLabel={possessionLabel}
          onPress={togglePossession}
        />
      </ScrollView>

      {activeSpec ? (
        <FacetSheet
          visible
          title={activeSpec.label}
          options={activeSpec.options}
          value={filters[activeSpec.key]}
          clearLabel={activeSpec.clearLabel}
          onSelect={(value) => setFacet(activeSpec.key, value)}
          onClose={() => setOpenFacet(null)}
        />
      ) : null}
    </>
  );
}

const RAIL_STYLE = {
  gap: spacing.sm,
  alignItems: 'center',
  paddingHorizontal: spacing.base,
} as const;

/**
 * One rail pill.
 *
 * A local component rather than `ui/Chip` because the two states differ: a
 * `Chip` is on or off, and a pill here is unset-showing-its-name or
 * set-showing-its-value, which needs a chevron on the first and none on the
 * second kind of control at all. Reusing `Chip` would mean adding an icon slot
 * and a chevron slot to a primitive that has neither use anywhere else.
 */
function Pill({
  label,
  active,
  icon,
  chevron = false,
  accessibilityLabel,
  onPress,
}: {
  label: string;
  active: boolean;
  icon?: keyof typeof Ionicons.glyphMap;
  chevron?: boolean;
  accessibilityLabel: string;
  onPress: () => void;
}) {
  const theme = useTheme();
  const tint = active ? theme.colors.accent : theme.colors.textSecondary;

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ selected: active }}
      accessibilityLabel={accessibilityLabel}
      hitSlop={gesture.hitSlop}
      onPress={onPress}
      style={({ pressed }) => [
        {
          flexDirection: 'row',
          alignItems: 'center',
          borderRadius: radius.full,
          borderWidth: 1,
          paddingHorizontal: spacing.md,
          paddingVertical: spacing.sm,
          borderColor: active ? theme.colors.accent : theme.colors.border,
          backgroundColor: active ? theme.colors.accentMuted : theme.colors.surface,
        },
        pressed ? { opacity: 0.7 } : undefined,
      ]}
    >
      {icon ? (
        <Ionicons name={icon} size={16} color={tint} style={{ marginRight: spacing.xs }} />
      ) : null}

      <Text variant={active ? 'subhead' : 'footnote'} tone={active ? 'accent' : 'secondary'}>
        {label}
      </Text>

      {chevron ? (
        <Ionicons
          name="chevron-down"
          size={13}
          color={tint}
          style={{ marginLeft: spacing.xs, marginTop: 1 }}
        />
      ) : null}
    </Pressable>
  );
}
