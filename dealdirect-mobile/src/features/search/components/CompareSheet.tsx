import { ScrollView, View } from 'react-native';

import type { PropertySummary } from '@/features/properties';
import { Image, PriceLabel, Sheet, Text } from '@/ui';
import { COMPARE_ROWS } from '../compare';

/**
 * Side-by-side comparison table. Ported from `PropertyListContent.jsx`'s
 * compare modal (~L2276–2521), laid out as columns (one per property) rather
 * than the website's CSS grid, since a synced two-axis grid has no cheap
 * equivalent in React Native's layout system and a column-per-property reads
 * just as well on a screen this narrow.
 *
 * Row set is `COMPARE_ROWS` — see `../compare.ts` for why it is shorter than
 * the website's (this compares `PropertySummary`, deliberately never fetches
 * `PropertyDetail` for it).
 */
export interface CompareSheetProps {
  visible: boolean;
  items: readonly PropertySummary[];
  onClose: () => void;
}

const COLUMN_WIDTH = 180;

export function CompareSheet({ visible, items, onClose }: CompareSheetProps) {
  return (
    <Sheet visible={visible} onClose={onClose} title="Compare properties" heightRatio={0.85}>
      <ScrollView horizontal showsHorizontalScrollIndicator={false}>
        <View>
          <View className="flex-row gap-md pb-md">
            {items.map((item) => (
              <View key={item.id} style={{ width: COLUMN_WIDTH }}>
                {item.coverImage ? (
                  <Image uri={item.coverImage} size="thumb" style={COVER_STYLE} />
                ) : (
                  <View className="items-center justify-center rounded-lg bg-surface-muted" style={COVER_STYLE} />
                )}
                <Text variant="footnote" numberOfLines={2} className="mt-sm">
                  {item.title}
                </Text>
                <Text variant="caption" tone="muted" numberOfLines={1} className="mt-xs">
                  {item.locationLabel || '—'}
                </Text>
                <PriceLabel
                  price={item.priceRupees}
                  variant="bodyEmphasis"
                  suffix={item.intent === 'rent' ? '/month' : undefined}
                  className="mt-xs"
                />
              </View>
            ))}
          </View>

          {COMPARE_ROWS.map((row) => (
            <View key={row.label} className="flex-row gap-md border-t border-border py-sm">
              {items.map((item) => (
                <View key={item.id} style={{ width: COLUMN_WIDTH }}>
                  <Text variant="caption" tone="muted">
                    {row.label}
                  </Text>
                  <Text variant="footnote" className="mt-xs">
                    {row.value(item)}
                  </Text>
                </View>
              ))}
            </View>
          ))}
        </View>
      </ScrollView>
    </Sheet>
  );
}

const COVER_STYLE = { width: COLUMN_WIDTH, height: 110, borderRadius: 12 } as const;
