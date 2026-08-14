import React, { useEffect, useState } from 'react';
import { ScrollView, View } from 'react-native';

import { Button, Chip, Sheet, Text } from '@/ui';
import {
  CATEGORY_OPTIONS,
  CITY_OPTIONS,
  CONSTRUCTION_STATUS_OPTIONS,
  DEFAULT_FILTERS,
  FURNISHING_OPTIONS,
  PRICE_BANDS,
  SORT_OPTIONS,
  countActiveFilters,
  type SearchFilters,
} from '../filters';

/**
 * Filter sheet.
 *
 * Edits a DRAFT copy and commits on Apply. Live-applying each tap would fire a
 * search per change against a 20-per-minute limiter shared across everyone
 * behind the same carrier NAT, and would also mean a user experimenting with
 * filters cannot back out without undoing every step. The draft re-seeds
 * whenever the sheet opens, so an abandoned edit leaves nothing behind.
 *
 * Chips rather than dropdowns: every option is visible at once, so choosing is
 * recognition instead of recall, and a tap is one gesture rather than
 * open-scroll-pick-close.
 *
 * Six groups. Price and Sort go straight to `/properties/search` params. City,
 * Category, Furnishing and Construction Status do not — they switch the
 * results screen into a bounded fetch-and-filter mode instead of infinite
 * scroll. `../filters.ts` explains why that split exists and why each of
 * these four is safe to offer now when it wasn't before. Read it before
 * adding a seventh group; some filters (property size, buildingType) are
 * still absent on purpose because the schema field they'd need doesn't exist.
 */

export interface FilterSheetProps {
  visible: boolean;
  filters: SearchFilters;
  onClose: () => void;
  onApply: (filters: SearchFilters) => void;
}

export function FilterSheet({ visible, filters, onClose, onApply }: FilterSheetProps) {
  const [draft, setDraft] = useState<SearchFilters>(filters);

  // Re-seed on open, not on every `filters` change: a commit from elsewhere
  // while the sheet is open should not yank the user's in-progress edit.
  useEffect(() => {
    if (visible) setDraft(filters);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible]);

  const activeCount = countActiveFilters(draft);
  const isDefault = activeCount === 0 && draft.sort === DEFAULT_FILTERS.sort;

  return (
    <Sheet visible={visible} onClose={onClose} title="Filters" heightRatio={0.85}>
      <ScrollView showsVerticalScrollIndicator={false}>
        <FilterGroup title="Price">
          {PRICE_BANDS.map((band) => (
            <Chip
              key={band.id}
              label={band.label}
              selected={draft.priceBand === band.id}
              onPress={() =>
                setDraft((current) => ({
                  ...current,
                  priceBand: current.priceBand === band.id ? undefined : band.id,
                }))
              }
            />
          ))}
        </FilterGroup>

        <FilterGroup title="City">
          {CITY_OPTIONS.map((option) => (
            <Chip
              key={option.value}
              label={option.label}
              selected={draft.city === option.value}
              onPress={() =>
                setDraft((current) => ({
                  ...current,
                  city: current.city === option.value ? undefined : option.value,
                }))
              }
            />
          ))}
        </FilterGroup>

        <FilterGroup title="Property type">
          {CATEGORY_OPTIONS.map((option) => (
            <Chip
              key={option.value}
              label={option.label}
              selected={draft.categoryName === option.value}
              onPress={() =>
                setDraft((current) => ({
                  ...current,
                  categoryName: current.categoryName === option.value ? undefined : option.value,
                }))
              }
            />
          ))}
        </FilterGroup>

        <FilterGroup title="Furnishing">
          {FURNISHING_OPTIONS.map((option) => (
            <Chip
              key={option.value}
              label={option.label}
              selected={draft.furnishing === option.value}
              onPress={() =>
                setDraft((current) => ({
                  ...current,
                  furnishing: current.furnishing === option.value ? undefined : option.value,
                }))
              }
            />
          ))}
        </FilterGroup>

        <FilterGroup title="Possession">
          {CONSTRUCTION_STATUS_OPTIONS.map((option) => (
            <Chip
              key={option.value}
              label={option.label}
              selected={draft.constructionStatus === option.value}
              onPress={() =>
                setDraft((current) => ({
                  ...current,
                  constructionStatus:
                    current.constructionStatus === option.value ? undefined : option.value,
                }))
              }
            />
          ))}
        </FilterGroup>

        <FilterGroup title="Sort by">
          {SORT_OPTIONS.map((option) => (
            <Chip
              key={option.value}
              label={option.label}
              selected={draft.sort === option.value}
              onPress={() => setDraft((current) => ({ ...current, sort: option.value }))}
            />
          ))}
        </FilterGroup>

        <View className="h-2xl" />
      </ScrollView>

      <View className="flex-row gap-md border-t border-border py-md">
        <Button
          label="Reset"
          variant="secondary"
          className="flex-1"
          disabled={isDefault}
          onPress={() =>
            setDraft((current) => ({ ...DEFAULT_FILTERS, query: current.query }))
          }
        />
        <Button
          label={activeCount > 0 ? `Apply (${activeCount})` : 'Apply'}
          className="flex-1"
          onPress={() => onApply(draft)}
        />
      </View>
    </Sheet>
  );
}

function FilterGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View className="pb-lg">
      <Text variant="subhead" tone="secondary" className="pb-sm">
        {title}
      </Text>
      <View className="flex-row flex-wrap gap-sm">{children}</View>
    </View>
  );
}
