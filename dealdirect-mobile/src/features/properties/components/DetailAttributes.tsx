import { useMemo } from 'react';
import { View } from 'react-native';

import { Text } from '@/ui';
import { resolveFieldSections } from '../fieldMap';
import type { PropertyDetail } from '../types';

/**
 * The full attribute table.
 *
 * One renderer for every section the field map produces. It knows nothing
 * about bedrooms or loading docks — which fields exist, what they are called
 * and how they read is entirely in `fieldMap.ts`, so adding a backend field is
 * a line of data rather than a component change.
 *
 * Two-column rows with the label muted and the value primary. A label column
 * fixed at 45% rather than sized to content: ragged label edges across four
 * sections read as four unrelated tables, and a value that wraps is easier to
 * scan than a label that does.
 *
 * The whole block renders nothing when a listing carries no attributes at all,
 * which happens on minimally-filled listings. A heading over an empty table is
 * worse than silence.
 */

export interface DetailAttributesProps {
  property: PropertyDetail;
}

export function DetailAttributes({ property }: DetailAttributesProps) {
  // Recomputed only when the listing changes: this walks roughly eighty
  // specs, and the screen re-renders on every carousel page turn.
  const sections = useMemo(() => resolveFieldSections(property.raw), [property.raw]);

  if (sections.length === 0) return null;

  return (
    <View>
      {sections.map((section) => (
        <View key={section.id} className="mt-xl">
          <Text variant="title3" className="mb-sm">
            {section.title}
          </Text>

          <View className="overflow-hidden rounded-xl border border-border bg-surface">
            {section.rows.map((row, index) => (
              <View
                key={row.label}
                className={`flex-row px-md py-sm ${index > 0 ? 'border-t border-border' : ''}`}
              >
                <Text
                  variant="footnote"
                  tone="muted"
                  style={{ width: '45%' }}
                  numberOfLines={2}
                >
                  {row.label}
                </Text>
                <Text variant="footnote" className="flex-1">
                  {row.value}
                </Text>
              </View>
            ))}
          </View>
        </View>
      ))}
    </View>
  );
}
