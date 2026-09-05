import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { gesture, useTheme } from '@/theme';
import type { OwnerStats } from '@/types/backend/property';
import { Avatar, Card, PressableScale, Text } from '@/ui';
import type { PropertyOwnerContact } from '../types';

/**
 * Who posted the listing, and what the server can vouch for about them.
 *
 * The whole premise of this marketplace is that the person on the other end is
 * the owner rather than an agent, so naming them is not decoration.
 *
 * The phone number and email are populated by `GET /properties/:id` but are
 * deliberately not rendered. Printing a private contact detail on a public
 * screen makes every listing a scrapeable directory; the action buttons dial
 * or open a thread without ever displaying the value.
 *
 * ---------------------------------------------------------------------------
 * THE TRUST LINES (Phase 3)
 *
 * `ownerStats` is three facts the backend computes and this component only
 * repeats: an admin marked the identity verified; the owner's median time to
 * a first reply, present only once three leads have been answered; and the
 * count and mean of reviews written by the other party to a verified close.
 * Each line renders only when its fact is present, so an owner with none has
 * the same card as before Phase 3 rather than three rows of "not yet".
 *
 * The reviews line is the ONE control: the page owns the sheet that lists
 * them, because the list is a different feature (`features/reviews`) fetched
 * only when asked for. This component says the number; it does not fetch.
 *
 * `owner` is null on listings whose owner account was deleted, and on every
 * endpoint other than the detail one, which returns a bare id instead of a
 * document. Nothing renders in that case rather than an "Unknown" row.
 */

export interface DetailOwnerProps {
  owner: PropertyOwnerContact | null;
  /** Absent on a backend older than Phase 3. */
  ownerStats?: OwnerStats | null;
  /** Opens the owner's published reviews. Wired only when there is at least one. */
  onShowReviews?: () => void;
}

/** "~2h" under a day, "~2d" past it; the tilde says the figure is a median. */
export function formatResponseHours(hours: number): string {
  if (hours < 1) return 'under an hour';
  if (hours < 24) return `~${Math.round(hours)}h`;
  return `~${Math.round(hours / 24)}d`;
}

function reviewsLine(overall: number, count: number): string {
  return `${overall.toFixed(1)} out of 5, ${count} verified ${count === 1 ? 'review' : 'reviews'}`;
}

function ReviewsLine({ overall, count }: { overall: number; count: number }) {
  const theme = useTheme();
  return (
    <>
      <Ionicons name="star" size={14} color={theme.colors.warning} />
      <Text variant="footnote" className="ml-xs">
        {overall.toFixed(1)}
      </Text>
      <Text variant="footnote" tone="secondary">
        {' '}
        · {count} verified {count === 1 ? 'review' : 'reviews'}
      </Text>
    </>
  );
}

export function DetailOwner({ owner, ownerStats, onShowReviews }: DetailOwnerProps) {
  const theme = useTheme();
  if (!owner) return null;

  const stats = ownerStats ?? null;
  const reviewCount = stats?.reviews.count ?? 0;
  const overall = stats?.reviews.overall ?? null;
  const showReviews = !!stats && reviewCount > 0 && overall !== null;
  const showReply = !!stats && stats.responseHours !== null;

  return (
    <Card bordered={false} radius="xl">
      <View className="flex-row items-center">
        <Avatar uri={owner.profileImage} name={owner.name} size="md" />

        <View className="ml-base flex-1">
          <Text variant="caption" tone="muted">
            Posted by
          </Text>
          <Text variant="bodyEmphasis" numberOfLines={1}>
            {owner.name ?? 'Owner'}
          </Text>
        </View>

        {stats?.verified ? (
          <View
            className="flex-row items-center rounded-full px-sm py-xs"
            style={{ backgroundColor: theme.colors.successMuted }}
            accessible
            accessibilityLabel="Verified owner"
          >
            <Ionicons name="shield-checkmark" size={14} color={theme.colors.success} />
            <Text variant="caption" tone="success" className="ml-xs">
              Verified owner
            </Text>
          </View>
        ) : null}
      </View>

      {showReply || showReviews ? (
        <View className="mt-md" style={{ gap: 6 }}>
          {showReply ? (
            <View className="flex-row items-center">
              <Ionicons name="time-outline" size={14} color={theme.colors.textMuted} />
              <Text variant="footnote" tone="secondary" className="ml-xs">
                Usually replies within {formatResponseHours(stats.responseHours as number)}
              </Text>
            </View>
          ) : null}

          {showReviews ? (
            onShowReviews ? (
              <PressableScale
                accessibilityRole="button"
                accessibilityLabel={`${reviewsLine(overall, reviewCount)}. Read them`}
                hitSlop={gesture.hitSlop}
                onPress={onShowReviews}
                activeScale={0.98}
                style={{ flexDirection: 'row', alignItems: 'center', alignSelf: 'flex-start' }}
              >
                <ReviewsLine overall={overall} count={reviewCount} />
                <Ionicons
                  name="chevron-forward"
                  size={14}
                  color={theme.colors.textMuted}
                  style={{ marginLeft: 2 }}
                />
              </PressableScale>
            ) : (
              <View className="flex-row items-center">
                <ReviewsLine overall={overall} count={reviewCount} />
              </View>
            )
          ) : null}
        </View>
      ) : null}
    </Card>
  );
}
