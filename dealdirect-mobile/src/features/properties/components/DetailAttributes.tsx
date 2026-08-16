import { useMemo } from 'react';
import { StyleSheet, View } from 'react-native';

import { useTheme } from '@/theme';
import { Card, Text } from '@/ui';
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
  const theme = useTheme();

  // Recomputed only when the listing changes: this walks roughly eighty
  // specs, and the screen re-renders on every carousel page turn.
  const sections = useMemo(() => resolveFieldSections(property.raw), [property.raw]);

  if (sections.length === 0) return null;

  return (
    <View>
      {sections.map((section) => (
        <View key={section.id} className="mt-2xl">
          <Text variant="title3" className="mb-md">
            {section.title}
          </Text>

          {/*
            `padded={false}`, and it is load-bearing. Every row below supplies
            its own `px-base py-md`, so the card must contribute none — with
            `Card`'s default padding the rows sat 32pt in from the card edge,
            and the separator's `marginLeft: 16` inset (which assumes the row's
            own 16 is the only one) stopped landing under the label it is meant
            to be inset to. Regression from the 2026-08-15 `Card` default;
            fixed 2026-08-16.
          */}
          <Card bordered={false} radius="xl" padded={false} className="overflow-hidden">
            {section.rows.map((row, index) => (
              <View
                key={row.label}
                className="flex-row px-base py-md"
                // Inset from the leading edge rather than run full-bleed, so
                // the rule reads as separating two rows of one list instead of
                // ruling a table. The inset matches the row's own padding.
                style={
                  index > 0
                    ? {
                        borderTopWidth: StyleSheet.hairlineWidth,
                        borderTopColor: theme.colors.border,
                        marginLeft: 16,
                        paddingLeft: 0,
                      }
                    : undefined
                }
              >
                <Text
                  variant="subhead"
                  tone="muted"
                  style={{ width: '45%' }}
                  numberOfLines={2}
                >
                  {row.label}
                </Text>
                <Text variant="subhead" className="flex-1">
                  {row.value}
                </Text>
              </View>
            ))}
          </Card>
        </View>
      ))}
    </View>
  );
}
