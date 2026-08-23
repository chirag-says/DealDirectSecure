import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { gesture, radius, spacing, useTheme } from '@/theme';
import { Image, PressableScale, PriceLabel, Text } from '@/ui';
import type { ShortlistedProperty } from '../store';

/**
 * One shortlisted listing.
 *
 * A compact row rather than a full card, and that follows from what the list is
 * for. A shortlist is read as a SET — the point is comparing eight things and
 * removing the four that no longer belong — so the useful density is the one
 * that puts several on screen at once. The browse feed already owns the large
 * card, where the job is selling one listing at a time.
 *
 * It draws from a disk snapshot (`RailProperty`), so it cannot show anything
 * the snapshot did not capture: no view count, no posted date, no live price.
 * See `store.ts` for why refetching to fill those in would corrupt the view
 * counter.
 *
 * Removal is immediate and unconfirmed. Nothing on the server changes, no
 * notification is unsent, and the way back is one tap on the listing — a
 * dialog here would be ceremony that teaches users to dismiss the ones that
 * matter.
 */

export interface ShortlistRowProps {
  entry: ShortlistedProperty;
  onPress: (id: string) => void;
  onRemove: (id: string) => void;
}

const THUMB = 92;

export function ShortlistRow({ entry, onPress, onRemove }: ShortlistRowProps) {
  const theme = useTheme();
  const { property } = entry;

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={property.title}
      onPress={() => onPress(property.id)}
      activeScale={0.985}
      style={{
        flexDirection: 'row',
        borderRadius: radius.lg,
        borderWidth: 1,
        borderColor: theme.colors.border,
        backgroundColor: theme.colors.surface,
        overflow: 'hidden',
      }}
    >
      <Image
        uri={property.coverImage}
        size="thumb"
        style={{ width: THUMB, height: THUMB, backgroundColor: theme.colors.surfaceMuted }}
      />

      <View className="flex-1 justify-center" style={{ padding: spacing.md }}>
        <PriceLabel
          price={property.priceRupees}
          variant="bodyEmphasis"
          suffix={property.intent === 'rent' ? '/month' : undefined}
          numberOfLines={1}
        />

        <Text variant="footnote" tone="secondary" numberOfLines={1} className="mt-xs">
          {typeLine(property) ?? property.title}
        </Text>

        <Text variant="caption" tone="muted" numberOfLines={1} className="mt-xs">
          {property.locationLabel}
        </Text>
      </View>

      <View style={{ padding: spacing.sm }}>
        <PressableScale
          accessibilityRole="button"
          accessibilityLabel={`Remove ${property.title} from your shortlist`}
          hitSlop={gesture.hitSlop}
          onPress={() => onRemove(property.id)}
        >
          <Ionicons name="close" size={18} color={theme.colors.textMuted} />
        </PressableScale>
      </View>
    </PressableScale>
  );
}

/** "3 BHK Apartment", when the snapshot captured enough to say it. */
function typeLine(property: ShortlistedProperty['property']): string | undefined {
  const bhk = property.bhk
    ? /bhk/i.test(property.bhk)
      ? property.bhk
      : `${property.bhk} BHK`
    : property.bedrooms
      ? `${property.bedrooms} BHK`
      : undefined;

  const type = property.propertyTypeName ?? property.subcategoryName;

  if (bhk && type) return `${bhk} ${type}`;
  return bhk ?? type;
}
