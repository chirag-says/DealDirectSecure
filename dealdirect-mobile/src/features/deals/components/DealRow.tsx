import Ionicons from '@expo/vector-icons/Ionicons';
import { memo } from 'react';
import { Pressable, View } from 'react-native';

import { gesture, radius, spacing, useTheme } from '@/theme';
import type { DealListRow } from '@/types/backend/deal';
import { Badge, Image, PressableScale, PriceLabel, Text } from '@/ui';
import { stageLabel, stageTone } from '../stage';

/**
 * One deal in the Activity list.
 *
 * What the row answers, in order: which listing, where it stands, what is
 * next. The stage badge is the ONE badge; role, when shown, is a small
 * muted word rather than a second pill, because a user who is both buying
 * and selling needs to tell the two apart but does not need it shouted.
 *
 * Unread is a dot at the edge plus a heavier title, the mail-client
 * convention, never a count: the count lives inside the deal where it means
 * something. "Waiting on you" is text, not colour, because it is the one
 * thing on the row that asks for an action.
 */

const THUMB = 64;

export interface DealRowProps {
  deal: DealListRow;
  /** Whether to name the role. True when the list mixes buying and selling. */
  showRole: boolean;
  onPress: (leadId: string) => void;
  /** Buyer-side rows only: withdraw the enquiry behind this deal. */
  onOverflow?: (deal: DealListRow) => void;
}

function nextLine(deal: DealListRow): { text: string; emphasis: boolean } | null {
  if (deal.role === 'owner' && deal.awaitingOwner) {
    return { text: 'Waiting on you', emphasis: true };
  }
  const visit = deal.nextVisit;
  if (visit) {
    const date = new Date(visit.scheduledAt);
    const when = Number.isNaN(date.getTime())
      ? null
      : `${date.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' })}, ${date.toLocaleTimeString('en-IN', { hour: 'numeric', minute: '2-digit' })}`;
    if (when) {
      return {
        text: visit.status === 'proposed' ? `Visit proposed for ${when}` : `Visit on ${when}`,
        emphasis: false,
      };
    }
  }
  return null;
}

function DealRowComponent({ deal, showRole, onPress, onOverflow }: DealRowProps) {
  const theme = useTheme();
  const property = deal.property;
  const title = property?.title ?? 'Listing no longer available';
  const place = [property?.locality, property?.city].filter(Boolean).join(', ');
  const unread = deal.unread > 0;
  const next = nextLine(deal);

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={[
        unread ? `${deal.unread} unread` : null,
        showRole ? (deal.role === 'buyer' ? 'Buying' : 'Selling') : null,
        title,
        stageLabel(deal.stage),
        next?.text ?? null,
      ]
        .filter(Boolean)
        .join(', ')}
      onPress={() => onPress(deal.id)}
      activeScale={0.99}
      style={{
        flexDirection: 'row',
        borderRadius: radius.lg,
        backgroundColor: theme.colors.surface,
        overflow: 'hidden',
        padding: spacing.md,
      }}
    >
      <View
        style={{
          width: THUMB,
          height: THUMB,
          borderRadius: radius.md,
          overflow: 'hidden',
          backgroundColor: theme.colors.surfaceMuted,
        }}
      >
        {property?.image ? (
          <Image uri={property.image} size="thumb" style={{ width: THUMB, height: THUMB }} />
        ) : (
          <View className="flex-1 items-center justify-center">
            <Ionicons name="home-outline" size={22} color={theme.colors.textMuted} />
          </View>
        )}
      </View>

      <View className="ml-md flex-1">
        <View className="flex-row items-start">
          <View className="flex-1 pr-sm">
            {showRole || deal.counterpartName ? (
              <Text variant="caption" tone="muted" numberOfLines={1}>
                {[
                  showRole ? (deal.role === 'buyer' ? 'Buying' : 'Selling') : null,
                  deal.counterpartName ? `with ${deal.counterpartName}` : null,
                ]
                  .filter(Boolean)
                  .join(' ')}
              </Text>
            ) : null}
            <Text variant={unread ? 'bodyEmphasis' : 'body'} numberOfLines={2}>
              {title}
            </Text>
          </View>
          <View style={{ flexShrink: 0, alignItems: 'flex-end' }}>
            <Badge label={stageLabel(deal.stage)} tone={stageTone(deal.stage)} />
            {unread ? (
              <View
                accessible={false}
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: 4,
                  marginTop: spacing.xs,
                  backgroundColor: theme.colors.accent,
                }}
              />
            ) : null}
          </View>
        </View>

        <View className="mt-xs flex-row items-center">
          {property?.price ? (
            <PriceLabel price={property.price} variant="subhead" numberOfLines={1} />
          ) : null}
          {place ? (
            <Text
              variant="caption"
              tone="muted"
              numberOfLines={1}
              className={property?.price ? 'ml-sm flex-1' : 'flex-1'}
            >
              {place}
            </Text>
          ) : null}
        </View>

        {next || onOverflow ? (
          <View className="mt-sm flex-row items-center">
            {next ? (
              <>
                <Ionicons
                  name={next.emphasis ? 'alert-circle-outline' : 'calendar-outline'}
                  size={13}
                  color={next.emphasis ? theme.colors.accent : theme.colors.textMuted}
                />
                <Text
                  variant="caption"
                  tone={next.emphasis ? 'accent' : 'muted'}
                  numberOfLines={1}
                  className="ml-xs flex-1"
                >
                  {next.text}
                </Text>
              </>
            ) : (
              <View className="flex-1" />
            )}
            {onOverflow ? (
              <Pressable
                accessibilityRole="button"
                accessibilityLabel="More options for this deal"
                hitSlop={gesture.hitSlop}
                onPress={() => onOverflow(deal)}
                className="active:opacity-60"
              >
                <Ionicons name="ellipsis-horizontal" size={18} color={theme.colors.textMuted} />
              </Pressable>
            ) : null}
          </View>
        ) : null}
      </View>
    </PressableScale>
  );
}

export const DealRow = memo(DealRowComponent);
