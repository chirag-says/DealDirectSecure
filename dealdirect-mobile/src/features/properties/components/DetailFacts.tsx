import Ionicons from '@expo/vector-icons/Ionicons';
import { StyleSheet, View } from 'react-native';

import { useTheme } from '@/theme';
import { Card, Text } from '@/ui';
import type { PropertyDetail } from '../types';

/**
 * The three or four numbers a buyer checks before reading anything else.
 *
 * A strip of icon-over-value cells, not a label/value table. The full
 * attribute table is a separate surface further down the screen; this is the
 * summary that has to survive being glanced at, so it holds only facts that
 * are meaningful without a heading and that most listings actually carry.
 *
 * Cells are dropped rather than blanked. An empty cell reading "—" tells the
 * user the data is missing, which is true but not useful, and it costs the
 * same horizontal space as a real one. With three fields present the row
 * divides in three; with two, in two.
 *
 * Deliberately NOT here: price (it is the focal point above and must not be
 * repeated at this weight), and anything commercial-only. `bathrooms` is
 * residential in practice — commercial listings use `washrooms`, a different
 * field — so the commercial equivalent comes from the field map in the full
 * attribute table rather than being special-cased into this row.
 */

interface Fact {
  icon: keyof typeof Ionicons.glyphMap;
  value: string;
  label: string;
}

/**
 * `bhk` arrives pre-suffixed on real data ("2 BHK", "5+ BHK"), so the suffix
 * is added only when genuinely missing. Same rule as `PropertyCard.specLine`.
 */
function bedroomFact(property: PropertyDetail): Fact | null {
  if (property.bhk) {
    return {
      icon: 'bed-outline',
      value: /bhk/i.test(property.bhk) ? property.bhk : `${property.bhk} BHK`,
      label: 'Configuration',
    };
  }

  if (property.bedrooms) {
    return {
      icon: 'bed-outline',
      value: `${property.bedrooms}`,
      label: property.bedrooms === 1 ? 'Bedroom' : 'Bedrooms',
    };
  }

  return null;
}

function buildFacts(property: PropertyDetail): Fact[] {
  const facts: Fact[] = [];

  const bedrooms = bedroomFact(property);
  if (bedrooms) facts.push(bedrooms);

  if (property.bathrooms) {
    facts.push({
      icon: 'water-outline',
      value: `${property.bathrooms}`,
      label: property.bathrooms === 1 ? 'Bathroom' : 'Bathrooms',
    });
  }

  if (property.areaSqft) {
    facts.push({
      icon: 'resize-outline',
      value: property.areaSqft.toLocaleString('en-IN'),
      label: 'sqft',
    });
  }

  const type = property.propertyTypeName ?? property.subcategoryName ?? property.categoryName;
  if (type) {
    facts.push({ icon: 'home-outline', value: type, label: 'Type' });
  }

  return facts;
}

export interface DetailFactsProps {
  property: PropertyDetail;
}

export function DetailFacts({ property }: DetailFactsProps) {
  const theme = useTheme();
  const facts = buildFacts(property);

  if (facts.length === 0) return null;

  return (
    <Card bordered={false} radius="xl" padded={false} className="flex-row px-sm py-base">
      {facts.map((fact, index) => (
        <View
          key={fact.label}
          className="flex-1 items-center px-xs"
          // A hairline, not a 1px border. A device-pixel rule reads as a
          // division; a full point reads as a table.
          style={
            index > 0
              ? { borderLeftWidth: StyleSheet.hairlineWidth, borderLeftColor: theme.colors.border }
              : undefined
          }
        >
          <Ionicons name={fact.icon} size={18} color={theme.colors.textMuted} />
          <Text variant="bodyEmphasis" className="mt-sm text-center" numberOfLines={1}>
            {fact.value}
          </Text>
          <Text variant="caption" tone="muted" className="mt-xs" numberOfLines={1}>
            {fact.label}
          </Text>
        </View>
      ))}
    </Card>
  );
}
