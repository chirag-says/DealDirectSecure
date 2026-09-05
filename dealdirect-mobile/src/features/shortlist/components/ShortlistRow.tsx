import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { gesture, radius, spacing, useTheme } from '@/theme';
import { Badge, Image, PressableScale, PriceLabel, Text } from '@/ui';
import { UNAVAILABLE_LABELS, type ShortlistItem } from '../types';

/**
 * One shortlisted listing.
 *
 * A compact row rather than a full card, and that follows from what the list is
 * for. A shortlist is read as a SET — the point is comparing eight things and
 * removing the four that no longer belong — so the useful density is the one
 * that puts several on screen at once. The browse feed already owns the large
 * card, where the job is selling one listing at a time.
 *
 * ---------------------------------------------------------------------------
 * A SOLD LISTING STAYS, AND SAYS SO
 *
 * The server reports `available` and `unavailableReason` per row. A listing
 * that goes off the market is marked and dimmed rather than deleted: it
 * disappearing overnight reads as the app losing the user's work, and the user
 * is the one who decides when it stops being useful to them. The row is still
 * tappable, because the detail screen is where "no longer available" is
 * explained properly.
 *
 * ---------------------------------------------------------------------------
 * ONE ROW, THREE CONTEXTS
 *
 * The same row draws the user's own list, the compare selection, and somebody
 * else's shared list. The controls are props rather than variants: a shared
 * list passes none of them and therefore renders none, which is what makes the
 * public screen read-only by construction instead of by discipline.
 *
 * Removal is immediate and unconfirmed. Nothing on the server changes that a
 * user cannot redo in one tap on the listing, and a dialog here would be
 * ceremony that teaches people to dismiss the ones that matter.
 */

export interface ShortlistRowProps {
  entry: ShortlistItem;
  onPress: (id: string) => void;
  /** Omitted on a shared list, which has nothing to remove. */
  onRemove?: (id: string) => void;
  /** Opens the note sheet. Omitted for a guest: there is nowhere to store it. */
  onEditNote?: (entry: ShortlistItem) => void;
  /** Compare mode: the row becomes a checkbox and the tap selects. */
  selectable?: boolean;
  selected?: boolean;
  onToggleSelect?: (id: string) => void;
}

const THUMB = 92;

export function ShortlistRow({
  entry,
  onPress,
  onRemove,
  onEditNote,
  selectable = false,
  selected = false,
  onToggleSelect,
}: ShortlistRowProps) {
  const theme = useTheme();
  const { property } = entry;
  const unavailable = !entry.available;

  const handlePress = () => {
    if (selectable) onToggleSelect?.(property.id);
    else onPress(property.id);
  };

  return (
    <PressableScale
      accessibilityRole={selectable ? 'checkbox' : 'button'}
      accessibilityLabel={property.title}
      accessibilityState={selectable ? { checked: selected } : undefined}
      onPress={handlePress}
      activeScale={0.985}
      style={{
        borderRadius: radius.lg,
        borderWidth: 1,
        borderColor: selected ? theme.colors.accent : theme.colors.border,
        backgroundColor: theme.colors.surface,
        overflow: 'hidden',
      }}
    >
      <View className="flex-row">
        <View>
          <Image
            uri={property.coverImage}
            size="thumb"
            style={{
              width: THUMB,
              height: THUMB,
              backgroundColor: theme.colors.surfaceMuted,
              // Dimmed rather than greyscaled: there is no cheap desaturation
              // in RN, and half opacity says "past tense" well enough.
              opacity: unavailable ? 0.45 : 1,
            }}
          />
          {selectable ? (
            <View
              className="absolute items-center justify-center rounded-full"
              style={{
                top: spacing.xs,
                left: spacing.xs,
                width: 24,
                height: 24,
                backgroundColor: selected ? theme.colors.accent : 'rgba(0,0,0,0.45)',
              }}
            >
              <Ionicons
                name={selected ? 'checkmark' : 'ellipse-outline'}
                size={15}
                color="#fff"
              />
            </View>
          ) : null}
        </View>

        <View className="flex-1 justify-center" style={{ padding: spacing.md }}>
          <View className="flex-row items-center">
            <PriceLabel
              price={property.priceRupees}
              variant="bodyEmphasis"
              suffix={property.intent === 'rent' ? '/month' : undefined}
              numberOfLines={1}
            />
            {unavailable && entry.unavailableReason ? (
              <Badge
                label={UNAVAILABLE_LABELS[entry.unavailableReason]}
                tone="neutral"
                className="ml-sm"
              />
            ) : null}
          </View>

          <Text variant="footnote" tone="secondary" numberOfLines={1} className="mt-xs">
            {typeLine(property) ?? property.title}
          </Text>

          <Text variant="caption" tone="muted" numberOfLines={1} className="mt-xs">
            {property.locationLabel}
          </Text>

          {entry.note ? (
            <View className="mt-xs flex-row items-start">
              <Ionicons
                name="create-outline"
                size={12}
                color={theme.colors.textMuted}
                style={{ marginTop: 2 }}
              />
              <Text variant="caption" tone="muted" numberOfLines={2} className="ml-xs flex-1">
                {entry.note}
              </Text>
            </View>
          ) : null}
        </View>

        {onRemove || onEditNote ? (
          <View style={{ padding: spacing.sm, gap: spacing.md }}>
            {onRemove ? (
              <PressableScale
                accessibilityRole="button"
                accessibilityLabel={`Remove ${property.title} from your shortlist`}
                hitSlop={gesture.hitSlop}
                onPress={() => onRemove(property.id)}
              >
                <Ionicons name="close" size={18} color={theme.colors.textMuted} />
              </PressableScale>
            ) : null}

            {onEditNote ? (
              <PressableScale
                accessibilityRole="button"
                accessibilityLabel={
                  entry.note ? `Edit your note on ${property.title}` : `Add a note to ${property.title}`
                }
                hitSlop={gesture.hitSlop}
                onPress={() => onEditNote(entry)}
              >
                <Ionicons
                  name={entry.note ? 'create' : 'create-outline'}
                  size={17}
                  color={entry.note ? theme.colors.accent : theme.colors.textMuted}
                />
              </PressableScale>
            ) : null}
          </View>
        ) : null}
      </View>
    </PressableScale>
  );
}

/** "3 BHK Apartment", when the row captured enough to say it. */
function typeLine(property: ShortlistItem['property']): string | undefined {
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
