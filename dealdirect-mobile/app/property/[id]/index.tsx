import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useState } from 'react';
import { Pressable, Share, View } from 'react-native';
import Animated, { useAnimatedScrollHandler, useSharedValue } from 'react-native-reanimated';

import { WEB_URL } from '@/config/env';
import {
  DetailActions,
  DetailAttributes,
  DetailFacts,
  DetailHeader,
  DetailHero,
  DetailOwner,
  EmiCalculator,
  ExpandableText,
  HERO_HEIGHT,
  NearbyPlaces,
  ReportSheet,
  VideoWalkthrough,
  useInterest,
  useRecordPropertyView,
  usePropertyDetail,
} from '@/features/properties';
import { RewardReveal } from '@/features/rewards';
import { screenPadding, spacing, useTheme } from '@/theme';
import {
  Badge,
  EmptyState,
  ErrorState,
  formatPrice,
  PriceLabel,
  Screen,
  Skeleton,
  Tag,
  Text,
} from '@/ui';

/**
 * Property detail.
 *
 * The conversion screen, and the hub every other buyer surface routes through:
 * chat and agreements both start here, and it is where a view is recorded for
 * both the backend counter and local history.
 *
 * ---------------------------------------------------------------------------
 * THE SHAPE
 *
 * A photograph, then one column of grouped blocks over the page colour. Not a
 * stack of cards: cards are for things that are separately actionable, and
 * nothing between the price and the owner is. What the surfaces here are doing
 * is grouping — the facts strip is one object, each attribute table is one
 * object — so they sit on the page by being brighter than it, with a hairline
 * between their rows and no outline at all. The page background is a step down
 * the neutral ramp from `surface` specifically to make that work; see the note
 * in `theme/colors.ts`.
 *
 * Reading order is deliberate: the price first, because it decides whether the
 * rest is worth reading; then where it is; then the facts strip; then the
 * owner's own words; then everything a specific listing happens to carry.
 * Nothing above the fold repeats itself.
 *
 * ---------------------------------------------------------------------------
 * DEPTH
 *
 * Three layers and no more. The photograph is furthest back and moves slowest.
 * The content sheet slides over it. The nav bar and the action bar are chrome
 * that does not move at all. Everything else is flat within the sheet, which is
 * why the surfaces take a Level 1 shadow and nothing takes a bigger one.
 *
 * `scrollY` is the one value the layers share. It is a shared value rather than
 * state because it is read on every frame by the header's cross-fade and the
 * hero's parallax; routing it through React would re-render this screen — with
 * its eighty-field attribute table — sixty times a second.
 *
 * ---------------------------------------------------------------------------
 * STILL TO COME IN M4: the Leaflet locator map, held with the rest of the map
 * phase pending a dev-client rebuild for its native dependencies. Everything
 * else in the plan — gallery, attribute table, interest, contact, message,
 * share, report — is built.
 */
export default function PropertyDetailScreen() {
  const router = useRouter();
  const theme = useTheme();
  const { id } = useLocalSearchParams<{ id: string }>();

  const { property, isLoading, isMissing, error, refresh } = usePropertyDetail(id);

  const [reporting, setReporting] = useState(false);

  // Measured rather than assumed: the bar's height depends on the bottom safe
  // area, on whether the call and message actions are offered, and on whether
  // the consequence line wraps at the user's text size.
  const [actionBarHeight, setActionBarHeight] = useState(120);

  const scrollY = useSharedValue(0);
  const onScroll = useAnimatedScrollHandler((event) => {
    scrollY.value = event.contentOffset.y;
  });

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

  /*
   * "Message owner" was removed 2026-08-13. Messaging is unmounted
   * product-wide (HANDOFF §9.1 D2) and this was its last entry point outside
   * Home. `useStartConversation` and the thread screen remain on disk.
   *
   * Contacting an owner from here is now Call plus the interest action, which
   * is what the website offers — it mounts no chat UI at all.
   */

  /**
   * Lives here rather than in the action bar now that the control is in the
   * nav bar. The link is included only when a web origin is configured: a
   * share carrying a guessed domain produces a dead link, which is worse than
   * one carrying only the facts.
   */
  const handleShare = useCallback(() => {
    if (!property) return;

    const parts = [property.title, formatPrice(property.priceRupees), property.locationLabel].filter(
      Boolean
    );

    const link = WEB_URL ? `${WEB_URL}/properties/${property.id}` : undefined;
    const message = link ? `${parts.join(' — ')}\n${link}` : parts.join(' — ');

    void Share.share({ message, ...(link ? { url: link } : {}) });
  }, [property]);

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
          onAction={() => router.replace('/(tabs)/properties')}
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
      <DetailHeader
        title={property.locationLabel || property.title}
        scrollY={scrollY}
        onBack={handleBack}
        onShare={handleShare}
      />

      <Animated.ScrollView
        // A plain style rather than a class: NativeWind's `className` needs a
        // component registered through `cssInterop`, and Reanimated's wrapped
        // ScrollView is not one of them.
        style={{ flex: 1 }}
        contentContainerStyle={{ paddingBottom: actionBarHeight + 24 }}
        showsVerticalScrollIndicator={false}
        onScroll={onScroll}
        scrollEventThrottle={16}
      >
        <DetailHero
          images={property.gallery}
          fallbackUri={property.coverImage}
          onOpenGallery={openGallery}
          scrollY={scrollY}
        />

        {/*
          Opaque and painted after the photo, which is what lets the photo grow
          under it on overscroll without a clipping container. The rounded top
          is the sheet edge: it says the content is a layer over the image
          rather than the next thing down the page.
        */}
        <View
          className="rounded-t-2xl bg-background"
          style={{ marginTop: -20, paddingHorizontal: screenPadding, paddingTop: spacing.lg }}
        >
          {/*
            THE HEADER BLOCK.

            Intent leads as a small chip above the price, rather than sitting
            beside it. "For rent" and "₹45,000" on one line makes the eye
            choose between them at the same height; stacked, the chip is read
            first and instantly — which is what tells you whether the number
            below it is a monthly figure or a purchase price. That distinction
            is the difference between a 45,000 rupee flat and a 45,000 rupee
            mistake.
          */}
          {property.intent ? (
            <Badge
              label={property.intent === 'rent' ? 'For rent' : 'For sale'}
              tone="accent"
              className="mb-sm self-start"
            />
          ) : null}

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
            <View className="mt-sm flex-row items-start">
              <Ionicons
                name="location-outline"
                size={15}
                color={theme.colors.brand}
                style={{ marginTop: 2 }}
              />
              <Text variant="callout" tone="secondary" numberOfLines={2} className="ml-xs flex-1">
                {property.locationLabel}
              </Text>
            </View>
          ) : null}

          {/*
            The street line, only when it adds something. `address.line` on
            real listings is frequently the locality and city over again, and
            printing it under an identical line reads as a rendering fault.
          */}
          {property.addressLine && property.addressLine !== property.locationLabel ? (
            <Text
              variant="footnote"
              tone="muted"
              numberOfLines={2}
              style={{ marginTop: spacing.xs, marginLeft: 19 }}
            >
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
              <ExpandableText text={property.description} />
            </Section>
          ) : null}

          {property.amenities.length > 0 ? (
            <Section title="Amenities">
              <View className="flex-row flex-wrap gap-sm">
                {property.amenities.map((amenity) => (
                  <Tag key={amenity} label={amenity} />
                ))}
              </View>
            </Section>
          ) : null}

          {property.nearby.length > 0 ? (
            <Section title="Nearby">
              <NearbyPlaces places={property.nearby} />
            </Section>
          ) : null}

          {property.videoUrl ? (
            <Section title="Video">
              <VideoWalkthrough videoUrl={property.videoUrl} />
            </Section>
          ) : null}

          {/*
            Every remaining attribute the listing carries, arranged by the
            field map. Sections it cannot fill do not appear, so this is where
            a residential and a commercial listing visibly diverge without the
            screen ever asking which it is looking at.
          */}
          <DetailAttributes property={property} />

          {/* Rent has no purchase to finance against. */}
          {property.intent !== 'rent' && property.priceRupees > 0 ? (
            <Section title="EMI calculator">
              <EmiCalculator priceRupees={property.priceRupees} />
            </Section>
          ) : null}

          {/* M4, remaining phase: the locator map. */}

          {owner ? (
            <Section title="Owner">
              <DetailOwner owner={owner} />
            </Section>
          ) : null}

          {/*
            Last, quiet, and after the thing it refers to. Reporting is rare and
            consequential, which argues for being reachable rather than for
            being prominent — it held a quarter of the action bar and competed
            with the one action the screen exists for.
          */}
          <Pressable
            accessibilityRole="button"
            accessibilityLabel="Report this listing"
            onPress={() => setReporting(true)}
            hitSlop={12}
            className="mt-3xl flex-row items-center justify-center"
            style={({ pressed }) => (pressed ? { opacity: 0.6 } : undefined)}
          >
            <Ionicons name="flag-outline" size={15} color={theme.colors.textMuted} />
            <Text variant="footnote" tone="muted" className="ml-xs">
              Report this listing
            </Text>
          </Pressable>
        </View>
      </Animated.ScrollView>

      {/*
        Outside the ScrollView, so it stays put. This is the only thing on the
        screen the user is meant to do, and the page is long enough that an
        inline button would sit several scrolls below where the decision gets
        made.
      */}
      <DetailActions
        property={property}
        interest={interest}
        onHeightChange={setActionBarHeight}
      />

      <ReportSheet
        propertyId={property.id}
        visible={reporting}
        onClose={() => setReporting(false)}
      />

      {/* Marking interest earns points. The response says how many, and until
          2026-08-13 that was discarded — see `interest.ts`. */}
      <RewardReveal reward={interest.lastReward} onDismiss={interest.clearReward} />
    </Screen>
  );
}

/**
 * A titled block.
 *
 * 32 above the heading and 12 under it, which is the ratio that makes a heading
 * belong to what follows rather than floating between two blocks. Both come
 * off the spacing scale; neither is optically corrected, because at this size
 * the grid is already right.
 */
/**
 * A block heading on the detail page.
 *
 * This page is several thousand pixels long and every block is the same
 * neutral colour, so the headings are the only structure the eye has to work
 * with. `title3` alone was doing that job at the same weight as a card title
 * three lines above it; a rule above the heading gives each block a top edge
 * without adding a container around it.
 */
function Section({ title, children }: { title: string; children: React.ReactNode }) {
  const theme = useTheme();

  return (
    <View style={{ marginTop: spacing['2xl'] }}>
      <View
        style={{
          height: 1,
          backgroundColor: theme.colors.border,
          marginBottom: spacing.lg,
        }}
      />
      <Text variant="title3" className="mb-md">
        {title}
      </Text>
      {children}
    </View>
  );
}

/**
 * Matches the loaded layout's geometry, so nothing shifts when data arrives:
 * the hero height, the sheet's overlap and radius, and the price block's own
 * rhythm are the real constants rather than guesses.
 */
function PropertyDetailSkeleton() {
  return (
    <Screen unsafe>
      <Skeleton height={HERO_HEIGHT} radius={0} />
      <View
        className="rounded-t-2xl bg-background px-lg pt-lg"
        style={{ marginTop: -20 }}
      >
        <Skeleton width={180} height={33} />
        <Skeleton width={220} height={22} className="mt-xs" />
        <Skeleton height={92} className="mt-lg" radius={20} />
        <Skeleton width={140} height={23} className="mt-2xl" />
        <Skeleton height={16} className="mt-md" />
        <Skeleton height={16} className="mt-sm" />
        <Skeleton width="60%" height={16} className="mt-sm" />
      </View>
    </Screen>
  );
}
