import { View } from 'react-native';

import { relativeDay } from '@/lib';
import type { Review } from '@/types/backend/review';
import { Avatar, Card, Text } from '@/ui';
import { StarRating } from './StarRating';

/**
 * One published review. The overall mean leads; the three ratings are
 * listed under it in words with their number, so a reader who wants to know
 * WHAT was rated highly can see it without decoding three rows of stars.
 */

export interface ReviewCardProps {
  review: Review;
}

const RATING_LABEL: Record<keyof Review['ratings'], string> = {
  accuracy: 'Accuracy',
  responsiveness: 'Responsiveness',
  seriousness: 'Seriousness',
};

export function ReviewCard({ review }: ReviewCardProps) {
  const when = review.publishedAt ? relativeDay(review.publishedAt) : null;

  return (
    <Card>
      <View className="flex-row items-center">
        <Avatar uri={review.author.profileImage ?? undefined} name={review.author.name} size="sm" />
        <View className="ml-sm flex-1">
          <Text variant="subhead" numberOfLines={1}>
            {review.author.name}
          </Text>
          <Text variant="caption" tone="muted">
            {review.authorRole === 'buyer' ? 'Bought from' : 'Sold to'} this person
            {when ? ` · ${when}` : ''}
          </Text>
        </View>
        <View className="items-end">
          <StarRating value={review.overall} />
          <Text variant="caption" tone="muted" className="mt-xs">
            {review.overall.toFixed(1)}
          </Text>
        </View>
      </View>

      <View className="mt-sm flex-row flex-wrap">
        {(Object.keys(RATING_LABEL) as Array<keyof Review['ratings']>).map((key) => (
          <Text key={key} variant="caption" tone="secondary" className="mr-md">
            {RATING_LABEL[key]} {review.ratings[key]}/5
          </Text>
        ))}
      </View>

      {review.text?.trim() ? (
        <Text variant="body" className="mt-sm">
          {review.text.trim()}
        </Text>
      ) : null}
    </Card>
  );
}
