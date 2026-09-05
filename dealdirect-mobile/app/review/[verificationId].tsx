import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useState } from 'react';
import { View } from 'react-native';

import { track } from '@/analytics';
import { ApiError } from '@/api';
import { RequireAuth } from '@/auth';
import { ReviewCard, StarRating, useReviewEligibility, useSubmitReview } from '@/features/reviews';
import { radius, screenPadding, scrollBottomPadding, spacing, useTheme } from '@/theme';
import type { ReviewRatings } from '@/types/backend/review';
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  Input,
  KeyboardAvoider,
  Refreshable,
  Screen,
  ScreenHeader,
  Skeleton,
  Text,
  useToast,
} from '@/ui';

/**
 * Review the other party to a verified close.
 *
 * Keyed by the VERIFICATION, because that is what makes a review possible:
 * only the two parties to an approved close-deal verification can write
 * one, once each. The server says which state the caller is in
 * (`GET /reviews/eligibility/:id`) and this screen renders that state; it
 * never guesses from a deal it might not have loaded.
 *
 * Both sides publish together, so a submitted review sits `pending` until
 * the other side writes theirs or fourteen days pass. The status view says
 * which, with the date, and shows the other side's review once it is out.
 *
 * Reached from a `review` push, from the deal's close card, and from the
 * claim screen. A lapsed session comes back here through the `review`
 * intent; nothing is pre-filled or auto-submitted on arrival.
 */
export default function ReviewRoute() {
  const { verificationId } = useLocalSearchParams<{ verificationId: string }>();

  return (
    <RequireAuth
      title="Review"
      promptTitle="Sign in to review this deal"
      promptDescription="Only the two people on a verified deal can review it. Sign in and we will bring you straight back."
      icon="star-outline"
      intent={verificationId ? { kind: 'review', verificationId } : undefined}
    >
      <ReviewScreen />
    </RequireAuth>
  );
}

const TEXT_MAX = 600;

const RATING_FIELDS: Array<{ key: keyof ReviewRatings; label: string; hint: string }> = [
  { key: 'accuracy', label: 'Accuracy', hint: 'Was the listing, or the enquiry, what it said?' },
  { key: 'responsiveness', label: 'Responsiveness', hint: 'Did they reply and turn up?' },
  { key: 'seriousness', label: 'Seriousness', hint: 'Were they there to make a deal?' },
];

function formatDate(iso: string): string | null {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' });
}

function ReviewScreen() {
  const router = useRouter();
  const toast = useToast();
  const { verificationId } = useLocalSearchParams<{ verificationId: string }>();
  const { eligibility, isLoading, error, refresh } = useReviewEligibility(verificationId);
  const { submit, isPending } = useSubmitReview();

  const [ratings, setRatings] = useState<Partial<ReviewRatings>>({});
  const [text, setText] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  const complete =
    ratings.accuracy !== undefined &&
    ratings.responsiveness !== undefined &&
    ratings.seriousness !== undefined;

  const handleSubmit = async () => {
    if (!verificationId || !complete) return;
    setFormError(null);
    try {
      await submit({
        verificationId,
        ratings: ratings as ReviewRatings,
        text: text.trim() || undefined,
      });
      track('review_submitted', { verificationId });
      toast.show('Review sent. It publishes when both sides are in.', 'success');
      // The eligibility query is invalidated by the mutation; the status
      // view takes over when it lands.
    } catch (caught) {
      if (caught instanceof ApiError) {
        setFormError(
          caught.code === 'NOT_VERIFIED'
            ? 'This deal has not been verified yet, so it cannot be reviewed.'
            : caught.code === 'ALREADY_REVIEWED'
              ? 'You have already reviewed this deal.'
              : caught.code === 'INVALID_RATING'
                ? 'Each rating needs to be between 1 and 5 stars.'
                : caught.message
        );
        if (caught.code === 'ALREADY_REVIEWED') refresh();
      } else {
        setFormError('Could not send your review. Please try again.');
      }
    }
  };

  if (isLoading) {
    return (
      <Screen>
        <ScreenHeader title="Review" />
        <View style={{ padding: screenPadding }}>
          <Skeleton height={64} radius={radius.lg} />
          <Skeleton height={220} radius={radius.lg} className="mt-base" />
        </View>
      </Screen>
    );
  }

  if (error || !eligibility) {
    const notFound = error instanceof ApiError && error.kind === 'notFound';
    return (
      <Screen>
        <ScreenHeader title="Review" />
        <ErrorState
          title={notFound ? 'We could not find this deal' : 'Could not load this review'}
          description={
            notFound
              ? 'It may have been removed, or the link is out of date.'
              : error instanceof ApiError
                ? error.message
                : undefined
          }
          onRetry={notFound ? undefined : refresh}
        />
      </Screen>
    );
  }

  const other = eligibility.role === 'buyer' ? 'the owner' : 'the buyer';

  // --- Already written: the status view ---------------------------------------
  if (eligibility.submitted || eligibility.mine) {
    const mine = eligibility.mine;
    const published = mine?.status === 'published';
    const windowEnds = mine?.windowEndsAt ? formatDate(mine.windowEndsAt) : null;

    return (
      <Screen>
        <ScreenHeader title="Review" />
        <Refreshable
          contentContainerStyle={{ padding: screenPadding, paddingBottom: scrollBottomPadding }}
          onRefresh={refresh}
        >
          <StatusCard
            published={published}
            body={
              published
                ? 'Your review is published.'
                : `Publishes when ${other} reviews too${windowEnds ? `, or on ${windowEnds}` : ''}.`
            }
          />

          {eligibility.counterpartPublished ? (
            <View className="mt-xl">
              <Text variant="subhead" tone="secondary" className="mb-sm">
                What {other} said about you
              </Text>
              <ReviewCard review={eligibility.counterpartPublished} />
            </View>
          ) : eligibility.counterpartSubmitted ? (
            <Text variant="footnote" tone="muted" className="mt-base">
              {other[0]!.toUpperCase() + other.slice(1)} has written a review. Both publish together.
            </Text>
          ) : null}

          <View className="mt-xl">
            <Button
              label="Back to rewards"
              variant="secondary"
              onPress={() => router.replace('/rewards')}
            />
          </View>
        </Refreshable>
      </Screen>
    );
  }

  // --- Not eligible, not written: say why in one line --------------------------
  if (!eligibility.eligible) {
    return (
      <Screen>
        <ScreenHeader title="Review" />
        <EmptyState
          title="Nothing to review yet"
          description="Reviews open once DealDirect has verified the close. You will be told when it is ready."
        />
      </Screen>
    );
  }

  // --- The form -----------------------------------------------------------------
  return (
    <Screen>
      <ScreenHeader title="Review" subtitle={`How was ${other}?`} />
      <KeyboardAvoider>
        <Refreshable
          contentContainerStyle={{ padding: screenPadding, paddingBottom: scrollBottomPadding }}
          keyboardShouldPersistTaps="handled"
        >
          <Text variant="footnote" tone="secondary" className="mb-base">
            Three ratings and, if you like, a few words. {other[0]!.toUpperCase() + other.slice(1)}{' '}
            sees it only once both of you have reviewed, or after 14 days.
          </Text>

          <Card>
            <View style={{ gap: spacing.lg }}>
              {RATING_FIELDS.map((field) => (
                <View key={field.key}>
                  <StarRating
                    label={field.label}
                    value={ratings[field.key] ?? 0}
                    onChange={(value) => {
                      setRatings((current) => ({ ...current, [field.key]: value }));
                      setFormError(null);
                    }}
                    disabled={isPending}
                  />
                  <Text variant="caption" tone="muted">
                    {field.hint}
                  </Text>
                </View>
              ))}
            </View>
          </Card>

          <View className="mt-base">
            <Input
              label="In your own words (optional)"
              placeholder="What would you tell someone about dealing with them?"
              value={text}
              onChangeText={(next) => setText(next.slice(0, TEXT_MAX))}
              maxLength={TEXT_MAX}
              multiline
              hint={`${text.length} / ${TEXT_MAX}`}
              editable={!isPending}
            />
          </View>

          {formError ? (
            <Text variant="footnote" tone="danger" className="mb-sm">
              {formError}
            </Text>
          ) : null}

          <Button
            label="Send review"
            loading={isPending}
            disabled={!complete}
            fullWidth
            onPress={() => void handleSubmit()}
          />
          {!complete ? (
            <Text variant="caption" tone="muted" className="mt-sm text-center">
              Rate all three to send.
            </Text>
          ) : null}
        </Refreshable>
      </KeyboardAvoider>
    </Screen>
  );
}

function StatusCard({ published, body }: { published: boolean; body: string }) {
  const theme = useTheme();
  return (
    <Card className="flex-row items-center">
      <View
        className="items-center justify-center rounded-full"
        style={{
          width: 44,
          height: 44,
          backgroundColor: published ? theme.colors.successMuted : theme.colors.accentMuted,
        }}
      >
        <Ionicons
          name={published ? 'checkmark-circle' : 'time-outline'}
          size={22}
          color={published ? theme.colors.success : theme.colors.accent}
        />
      </View>
      <View className="ml-base flex-1">
        <Text variant="bodyEmphasis">{published ? 'Published' : 'Review sent'}</Text>
        <Text variant="footnote" tone="secondary" className="mt-xs">
          {body}
        </Text>
      </View>
    </Card>
  );
}
