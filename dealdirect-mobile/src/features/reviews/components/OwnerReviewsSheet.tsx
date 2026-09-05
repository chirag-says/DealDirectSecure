import { ActivityIndicator, ScrollView, View } from 'react-native';

import { spacing, useTheme } from '@/theme';
import type { ObjectId } from '@/types/backend/common';
import { Button, EmptyState, ErrorState, Sheet, Text } from '@/ui';
import { useUserReviews } from '../hooks';
import { ReviewCard } from './ReviewCard';
import { StarRating } from './StarRating';

/**
 * An owner's published reviews, from the property detail screen.
 *
 * Public data (`GET /reviews/user/:id`), fetched only once the sheet is
 * opened: the detail screen already shows the count and the mean from
 * `ownerStats`, so nobody pays for the list until they ask for it. Ten at a
 * time with a "Show more" button, matching the server's page size.
 */

export interface OwnerReviewsSheetProps {
  ownerId: ObjectId;
  ownerName: string;
  visible: boolean;
  onClose: () => void;
}

export function OwnerReviewsSheet({ ownerId, ownerName, visible, onClose }: OwnerReviewsSheetProps) {
  const theme = useTheme();
  const { reviews, summary, isLoading, isFetchingMore, hasMore, error, refresh, loadMore } =
    useUserReviews(ownerId, visible);

  return (
    <Sheet visible={visible} onClose={onClose} title={`Reviews of ${ownerName}`} heightRatio={0.8}>
      {isLoading ? (
        <View className="flex-1 items-center justify-center">
          <ActivityIndicator color={theme.colors.textMuted} />
        </View>
      ) : error ? (
        <ErrorState title="Could not load reviews" onRetry={refresh} />
      ) : reviews.length === 0 ? (
        <EmptyState
          title="No published reviews yet"
          description="Reviews come from verified deals and publish once both sides have written one."
        />
      ) : (
        <ScrollView showsVerticalScrollIndicator={false}>
          {summary && summary.count > 0 && summary.overall !== undefined ? (
            <View className="mb-base flex-row items-center">
              <StarRating value={summary.overall} size={18} />
              <Text variant="bodyEmphasis" className="ml-sm">
                {summary.overall.toFixed(1)}
              </Text>
              <Text variant="footnote" tone="secondary" className="ml-xs">
                · {summary.count} verified {summary.count === 1 ? 'review' : 'reviews'}
              </Text>
            </View>
          ) : null}

          <View style={{ gap: spacing.md, paddingBottom: spacing.xl }}>
            {reviews.map((review) => (
              <ReviewCard key={review.id} review={review} />
            ))}
            {hasMore ? (
              <Button
                label="Show more"
                variant="secondary"
                size="sm"
                loading={isFetchingMore}
                onPress={loadMore}
                align="center"
              />
            ) : null}
          </View>
        </ScrollView>
      )}
    </Sheet>
  );
}
