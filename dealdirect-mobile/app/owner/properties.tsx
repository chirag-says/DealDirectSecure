import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useState } from 'react';
import { Alert, Pressable, View } from 'react-native';

import { OwnerOnly } from '@/auth';
import { CloseDealSheet, useDeleteListing, useMyProperties } from '@/features/listings';
import { adaptProperty } from '@/features/properties';
import { gesture, screenPadding, spacing, scrollBottomPadding, useTheme } from '@/theme';
import type { Property } from '@/types/backend/property';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  HeaderAction,
  Image,
  PriceLabel,
  Refreshable,
  Screen,
  ScreenHeader,
  Skeleton,
  Text,
  useToast,
} from '@/ui';

/**
 * My listing(s).
 *
 * An owner account is capped at ONE property server-side — see
 * `useMyProperties`'s doc comment — so in practice this renders zero or one
 * card, plural naming aside. Written against the list response anyway, so a
 * future relaxation of that cap needs no change here.
 */
function MyPropertiesScreenContent() {
  const router = useRouter();
  const theme = useTheme();
  const { properties, isLoading, isRefreshing, error, refresh } = useMyProperties();
  const { remove, isPending: isDeleting } = useDeleteListing();
  const toast = useToast();
  const [closingDeal, setClosingDeal] = useState<Property | null>(null);

  /**
   * Stays an `Alert`. This is a QUESTION about an irreversible action, and a
   * question needs a deliberate answer — that is exactly what a modal is for.
   * The confirmation that follows is a toast, because that is an answer.
   */
  const handleDelete = (id: string, title: string) => {
    Alert.alert('Delete listing', `Remove "${title}" permanently? This cannot be undone.`, [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Delete',
        style: 'destructive',
        onPress: async () => {
          await remove(id);
          toast.show('Listing deleted.');
        },
      },
    ]);
  };

  return (
    <Screen>
      {/* The add action is offered only when there is nothing to add TO — an
          owner account is capped at one listing server-side, so the control
          would 400 if shown beside an existing one. */}
      <ScreenHeader
        title="My listing"
        backTo="/(tabs)/profile"
        actions={
          properties.length === 0 && !isLoading ? (
            <HeaderAction
              icon="add"
              label="Add a listing"
              tone="accent"
              onPress={() => router.push('/owner/property/new')}
            />
          ) : null
        }
      />

      {isLoading ? (
        <View className="px-base">
          <Skeleton height={220} radius={16} />
        </View>
      ) : error ? (
        <ErrorState title="Could not load your listing" onRetry={refresh} />
      ) : properties.length === 0 ? (
        <EmptyState
          title="You have no listing yet"
          description="Owner accounts can post one property. Add yours to start receiving leads."
          actionLabel="Add a listing"
          onAction={() => router.push('/owner/property/new')}
        />
      ) : (
        <Refreshable
          contentContainerStyle={{ padding: screenPadding, paddingBottom: scrollBottomPadding }}
          refreshing={isRefreshing}
          onRefresh={refresh}
        >
          {properties.map((property) => {
            const summary = adaptProperty(property);
            return (
              <Card key={property._id} padded={false} className="mb-base overflow-hidden">
                <Pressable
                  accessibilityRole="button"
                  onPress={() => router.push(`/property/${property._id}`)}
                >
                  {summary.coverImage ? (
                    <Image uri={summary.coverImage} size="medium" style={{ height: 180, width: '100%' }} />
                  ) : (
                    <View className="h-[180px] w-full items-center justify-center bg-surface-muted">
                      <Ionicons name="home-outline" size={32} color={theme.colors.textMuted} />
                    </View>
                  )}
                </Pressable>

                <View className="p-base">
                  <Badge
                    label={property.status ?? 'active'}
                    tone={
                      property.status === 'sold' || property.status === 'rented'
                        ? 'success'
                        : property.status === 'pending_verification'
                          ? 'warning'
                          : 'accent'
                    }
                  />

                  <Text variant="bodyEmphasis" numberOfLines={1} className="mt-sm">
                    {summary.headline ?? summary.title}
                  </Text>
                  <PriceLabel
                    price={summary.priceRupees}
                    suffix={summary.intent === 'rent' ? '/month' : undefined}
                    className="mt-xs"
                  />

                  {/*
                    THE TWO NUMBERS AN OWNER OPENS THIS SCREEN FOR.

                    Views was a grey footnote sharing a row with the status
                    badge — the same weight as the word "active", which is not
                    what it is worth. An owner checks this screen to find out
                    whether the listing is working, and views plus enquiries is
                    that answer. Enquiries leads, because a view is attention
                    and an enquiry is a person.
                  */}
                  <View
                    className="mt-base flex-row"
                    style={{
                      gap: spacing.xl,
                      paddingTop: spacing.md,
                      borderTopWidth: 1,
                      borderTopColor: theme.colors.border,
                    }}
                  >
                    <OwnerStat
                      label={interestedCount(property) === 1 ? 'Enquiry' : 'Enquiries'}
                      value={interestedCount(property)}
                    />
                    <OwnerStat label="Views" value={property.views ?? 0} />
                  </View>

                  {/*
                    Edit leads and is the only filled control. Delete moved out
                    of the primary row: it sat as an equal-width danger button
                    beside Edit, which gave a destructive, irreversible action
                    the same visual claim as the routine one and put the two a
                    thumb-width apart.
                  */}
                  <View className="mt-base flex-row" style={{ gap: spacing.sm }}>
                    <Button
                      label="Edit listing"
                      size="sm"
                      className="flex-1"
                      onPress={() => router.push(`/owner/property/${property._id}/edit`)}
                    />

                    {/* Matches the backend's own gate in `closeDeal`
                        (propertyController.js:2267) exactly, so this button
                        never offers an action the server would 400. */}
                    {!CLOSE_DEAL_BLOCKED_STATUSES.has(property.status ?? 'active') ? (
                      <Button
                        label="Close deal"
                        variant="secondary"
                        size="sm"
                        className="flex-1"
                        onPress={() => setClosingDeal(property)}
                      />
                    ) : null}
                  </View>

                  <Pressable
                    accessibilityRole="button"
                    accessibilityLabel={`Delete ${property.title}`}
                    hitSlop={gesture.hitSlop}
                    disabled={isDeleting}
                    onPress={() => handleDelete(property._id, property.title)}
                    className="mt-md flex-row items-center self-center active:opacity-60"
                  >
                    <Ionicons name="trash-outline" size={14} color={theme.colors.danger} />
                    <Text variant="footnote" tone="danger" className="ml-xs">
                      Delete listing
                    </Text>
                  </Pressable>
                </View>
              </Card>
            );
          })}
        </Refreshable>
      )}

      {closingDeal ? (
        <CloseDealSheet
          visible
          property={closingDeal}
          onClose={() => setClosingDeal(null)}
          onSuccess={() => {
            setClosingDeal(null);
            // An answer, not a question — the user asked to close the deal and
            // it went through. A modal here would make them dismiss a result
            // they already expected.
            toast.show('Submitted for verification. We will notify you once approved.', 'success');
            refresh();
          }}
        />
      ) : null}
    </Screen>
  );
}

const CLOSE_DEAL_BLOCKED_STATUSES = new Set(['pending_verification', 'sold', 'rented']);

/**
 * How many people have enquired.
 *
 * `interestedUsers` is the same array `markInterested` pushes to and
 * `getSavedProperties` reads back — see `features/properties/interest.ts`. Its
 * length is the enquiry count, and `getMyProperties` populates it, so this
 * needs no extra request.
 */
function interestedCount(property: Property): number {
  return property.interestedUsers?.length ?? 0;
}

/** One measurement on the listing card. Tabular figures so a row of them lines up. */
function OwnerStat({ label, value }: { label: string; value: number }) {
  return (
    <View>
      <Text variant="title3" style={{ fontVariant: ['tabular-nums'] }}>
        {value.toLocaleString('en-IN')}
      </Text>
      <Text variant="caption" tone="muted">
        {label}
      </Text>
    </View>
  );
}

/**
 * Owner-gated. See `auth/components/OwnerOnly.tsx` for why a role the
 * server already enforces still needs a client-side refusal: without it a
 * buyer who reaches this route is shown an error state for something that
 * is not an error.
 */
export default function MyPropertiesScreen() {
  return (
    <OwnerOnly title="My listing">
      <MyPropertiesScreenContent />
    </OwnerOnly>
  );
}
