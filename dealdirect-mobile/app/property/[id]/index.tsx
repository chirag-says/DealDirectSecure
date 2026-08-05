import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useState } from 'react';
import { ScrollView, View } from 'react-native';

import {
  DetailActions,
  DetailAttributes,
  DetailFacts,
  DetailHero,
  DetailOwner,
  HERO_HEIGHT,
  ReportSheet,
  useInterest,
  useRecordPropertyView,
  usePropertyDetail,
} from '@/features/properties';
import { Badge, Chip, EmptyState, ErrorState, PriceLabel, Screen, Skeleton, Text } from '@/ui';

/**
 * Property detail.
 *
 * The conversion screen, and the hub every other buyer surface routes through:
 * chat and agreements both start here, and it is where a view is recorded for
 * both the backend counter and local history.
 *
 * Layout is one column of grouped blocks rather than a card stack. The photo
 * runs full-bleed under the status bar, so the screen takes no top inset and
 * `DetailHero` insets its own controls instead.
 *
 * Reading order is deliberate: the price first, because it decides whether the
 * rest is worth reading; then where it is; then the facts strip; then the
 * owner's own words; then amenities. Nothing above the fold repeats itself.
 *
 * STILL TO COME IN M4: the photo carousel and full-screen gallery, the
 * declarative attribute table for the eighty-field residential/commercial
 * split, the Leaflet locator map, and the interest and contact actions. Each
 * has a marked seam below.
 */
export default function PropertyDetailScreen() {
  const router = useRouter();
  const { id } = useLocalSearchParams<{ id: string }>();

  const { property, isLoading, isMissing, error, refresh } = usePropertyDetail(id);

  const [reporting, setReporting] = useState(false);

  // Declared before the early returns: hooks cannot be called conditionally,
  // and the loading and 404 branches below both return before the action bar.
  const interest = useInterest(id, {
    onRequiresAuth: () => router.push('/(auth)/login'),
  });

  // Local view history, written once per listing. The backend counts its own
  // view inside the same request that produced this data, so the two agree on
  // what a view is.
  useRecordPropertyView(property);

  const handleBack = useCallback(() => {
    // `back()` alone strands a user who arrived from a deep link with nothing
    // to go back to. Falling through to the feed gives that case a destination
    // instead of a dead control.
    if (router.canGoBack()) router.back();
    else router.replace('/(tabs)');
  }, [router]);

  // Opens the viewer on the photo the carousel is currently showing, rather
  // than always on the first one.
  const openGallery = useCallback(
    (index: number) => router.push(`/property/${id}/gallery?index=${index}`),
    [router, id]
  );

  if (isLoading) {
    return <PropertyDetailSkeleton />;
  }

  // 404 covers deleted, unapproved, banned and suspended alike: the controller
  // deliberately does not distinguish them, so that a hidden listing cannot be
  // told apart from one that never existed. "No longer available" is true for
  // every one of those, which is why it is not phrased as an error.
  if (isMissing) {
    return (
      <Screen>
        <EmptyState
          title="Listing no longer available"
          description="It may have been sold, rented, or taken down by its owner."
          actionLabel="Back to search"
          onAction={() => router.replace('/(tabs)/search')}
        />
      </Screen>
    );
  }

  if (error || !property) {
    return (
      <Screen>
        <ErrorState
          title="Could not load this listing"
          onRetry={refresh}
        />
      </Screen>
    );
  }

  const { owner } = property;

  return (
    <Screen unsafe>
      <ScrollView
        className="flex-1"
        contentContainerStyle={{ paddingBottom: 32 }}
        showsVerticalScrollIndicator={false}
      >
        <DetailHero
          images={property.gallery}
          fallbackUri={property.coverImage}
          onBack={handleBack}
          onOpenGallery={openGallery}
        />

        <View className="px-lg pt-lg">
          {/* The number the screen is scanned by. Nothing else comes near it. */}
          <View className="flex-row items-center">
            <PriceLabel
              price={property.priceRupees}
              variant="title1"
              suffix={property.intent === 'rent' ? '/month' : undefined}
            />
            {property.negotiable ? (
              <Badge label="Negotiable" tone="neutral" className="ml-sm" />
            ) : null}
          </View>

          {property.locationLabel ? (
            <Text variant="callout" className="mt-xs" numberOfLines={2}>
              {property.locationLabel}
            </Text>
          ) : null}

          {/*
            The street line, only when it adds something. `address.line` on
            real listings is frequently the locality and city over again, and
            printing it under an identical line reads as a rendering fault.
          */}
          {property.addressLine && property.addressLine !== property.locationLabel ? (
            <Text variant="footnote" tone="muted" className="mt-xs" numberOfLines={2}>
              {property.addressLine}
            </Text>
          ) : null}

          <View className="mt-lg">
            <DetailFacts property={property} />
          </View>

          {/* Only listings whose owner wrote a real title reach this. */}
          {property.headline ? (
            <Section title="About this property">
              <Text variant="body">{property.headline}</Text>
            </Section>
          ) : null}

          {property.description ? (
            <Section title={property.headline ? 'Description' : 'About this property'}>
              <Text variant="body" tone="secondary">
                {property.description}
              </Text>
            </Section>
          ) : null}

          {property.amenities.length > 0 ? (
            <Section title="Amenities">
              <View className="flex-row flex-wrap gap-sm">
                {property.amenities.map((amenity) => (
                  <Chip key={amenity} label={amenity} />
                ))}
              </View>
            </Section>
          ) : null}

          {/*
            Every remaining attribute the listing carries, arranged by the
            field map. Sections it cannot fill do not appear, so this is where
            a residential and a commercial listing visibly diverge without the
            screen ever asking which it is looking at.
          */}
          <DetailAttributes property={property} />

          {/* M4, remaining phase: the locator map, then the actions. */}

          {owner ? (
            <Section title="Owner">
              <DetailOwner owner={owner} />
            </Section>
          ) : null}
        </View>
      </ScrollView>

      {/*
        Outside the ScrollView, so it stays put. This is the only thing on the
        screen the user is meant to do, and the page is long enough that an
        inline button would sit several scrolls below where the decision gets
        made.
      */}
      <DetailActions
        property={property}
        interest={interest}
        onReport={() => setReporting(true)}
      />

      <ReportSheet
        propertyId={property.id}
        visible={reporting}
        onClose={() => setReporting(false)}
      />
    </Screen>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View className="mt-xl">
      <Text variant="title3" className="mb-sm">
        {title}
      </Text>
      {children}
    </View>
  );
}

/**
 * Matches the loaded layout's geometry, so nothing shifts when data arrives.
 * The hero height is the real constant rather than a guess.
 */
function PropertyDetailSkeleton() {
  return (
    <Screen unsafe>
      <Skeleton height={HERO_HEIGHT} radius={0} />
      <View className="px-lg pt-lg">
        <Skeleton width={180} height={34} />
        <Skeleton width={220} height={18} className="mt-md" />
        <Skeleton height={84} className="mt-lg" radius={12} />
        <Skeleton height={16} className="mt-xl" />
        <Skeleton height={16} className="mt-sm" />
        <Skeleton width="60%" height={16} className="mt-sm" />
      </View>
    </Screen>
  );
}
