import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { Pressable, Share, useWindowDimensions, View, type LayoutChangeEvent } from 'react-native';
import Animated, {
  runOnUI,
  scrollTo,
  useAnimatedRef,
  useAnimatedScrollHandler,
  useSharedValue,
} from 'react-native-reanimated';

import { WEB_URL } from '@/config/env';
import {
  DetailActions,
  DetailAttributes,
  DetailFacts,
  DetailHeader,
  DetailHero,
  DetailOwner,
  DetailSectionNav,
  EmiCalculator,
  ExpandableText,
  heroHeight,
  NearbyPlaces,
  PropertyRail,
  ReportSheet,
  VideoWalkthrough,
  useInterest,
  useRecordPropertyView,
  usePropertyDetail,
  useSectionRegistry,
} from '@/features/properties';
import { EnquirySheet, useSavedProperties } from '@/features/saved';
import { RewardReveal } from '@/features/rewards';
import { useSimilarProperties } from '@/features/search';
import { relativeDay } from '@/lib';
import { screenPadding, spacing, useTheme } from '@/theme';
import {
  Badge,
  EmptyState,
  ErrorState,
  formatPrice,
  formatRatePerSqft,
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
 * owner's own words; then everything a specific listing happens to carry, and
 * finally somewhere else to go. Nothing above the fold repeats itself.
 *
 * ---------------------------------------------------------------------------
 * GETTING AROUND IT
 *
 * The page is long enough that reading it top to bottom is not how anyone uses
 * it, so `DetailSectionNav` pins a strip of jump links under the nav bar once
 * the photo has scrolled past. Sections MEASURE themselves into it through
 * `SectionRegistryContext` rather than being listed anywhere, because which
 * sections a listing has depends on the listing; see that component for why a
 * declared list would be worse than no nav at all.
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
/**
 * Below this the view count is suppressed. Same threshold and same reasoning as
 * `PropertyCard`'s — under ten the figure is as likely to be the owner
 * reloading their own listing as it is to be demand.
 */
const MEANINGFUL_VIEW_COUNT = 10;

export default function PropertyDetailScreen() {
  const router = useRouter();
  const theme = useTheme();
  const { id } = useLocalSearchParams<{ id: string }>();

  const { property, isLoading, isMissing, error, refresh } = usePropertyDetail(id);

  const [reporting, setReporting] = useState(false);

  const [enquiring, setEnquiring] = useState(false);

  /**
   * Enquiry slots left, or null when unknown.
   *
   * The same `useSavedProperties` query the Saved tab and the feed's hearts
   * already run, deduplicated by TanStack — this screen adds no request. It is
   * needed here to say the true number in the confirmation sheet and to explain
   * a dead button rather than letting the user press it and be refused.
   *
   * Null while signed out or unresolved. The server remains the authority on
   * the cap; this only lets the UI stop being surprised by it.
   */
  const savedList = useSavedProperties();
  const enquiriesLeft =
    savedList.requiresAuth || savedList.isLoading ? null : savedList.remaining;

  // Measured rather than assumed: the bar's height depends on the bottom safe
  // area and on whether the supporting line wraps at the user's text size.
  const [actionBarHeight, setActionBarHeight] = useState(120);

  const scrollY = useSharedValue(0);
  const onScroll = useAnimatedScrollHandler((event) => {
    scrollY.value = event.contentOffset.y;
  });

  /**
   * The section nav's plumbing.
   *
   * `useAnimatedRef` rather than a plain ref because the jump goes through
   * Reanimated's `scrollTo`, which runs the scroll on the UI thread. A
   * `ref.current.scrollTo` would work too and would compete with the scroll
   * handler above for the same frames.
   *
   * `sheetTop` exists because `onLayout` reports a child's offset within its
   * PARENT, and every section's parent is the content sheet — which itself
   * starts one hero-height down the scroll content. Measuring the sheet once
   * and adding it is exact; assuming `HERO_HEIGHT - 20` would be a duplicate of
   * a constant two files away that nothing would catch when it changed.
   */
  const scrollRef = useAnimatedRef<Animated.ScrollView>();
  const registry = useSectionRegistry();
  const [sheetTop, setSheetTop] = useState(0);

  const onSheetLayout = useCallback((event: LayoutChangeEvent) => {
    setSheetTop(event.nativeEvent.layout.y);
  }, []);

  // `scrollTo` is a worklet and has to run on the UI thread; called from JS it
  // is a no-op with a warning. `runOnUI` is the documented way across.
  const jumpTo = useCallback(
    (y: number) => {
      runOnUI(() => {
        'worklet';
        scrollTo(scrollRef, 0, y, true);
      })();
    },
    [scrollRef]
  );

  const sectionContext = useMemo(
    () => ({ register: registry.register, offset: sheetTop }),
    [registry.register, sheetTop]
  );

  // Declared before the early returns: hooks cannot be called conditionally,
  // and the loading and 404 branches below both return before the action bar.
  const interest = useInterest(id, {
    onRequiresAuth: () => router.push('/(auth)/login'),
  });

  // Local view history, written once per listing. The backend counts its own
  // view inside the same request that produced this data, so the two agree on
  // what a view is.
  useRecordPropertyView(property);

  /**
   * The rail at the foot of the page.
   *
   * Every portal we measured ends its detail page this way — 99acres runs two
   * of them ("Compare with Similar Homes", "Owner Properties"), Square Yards
   * one ("How does this compare with other top projects?") — because the page
   * has exactly two useful endings: the user contacts this owner, or they go
   * look at something else. Without the rail the second ending is the back
   * button, which loses the search they arrived from.
   *
   * Declared here rather than beside the rail because hooks cannot be called
   * after the early returns below. It self-disables while `property` is
   * undefined, so the loading and 404 branches cost nothing.
   */
  const similar = useSimilarProperties(property);

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

  /**
   * `push`, not `replace`, even though it stacks this route on itself.
   *
   * Replacing would be tidier for the stack and wrong for the user: someone
   * three listings deep in a comparison expects back to walk them out the way
   * they came, and replace collapses that into a single jump to the search they
   * left twenty minutes ago. Every portal behaves the way `push` does here.
   */
  const openSimilar = useCallback(
    (similarId: string) => router.push(`/property/${similarId}`),
    [router]
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

  const rate =
    property.intent === 'rent' ? null : formatRatePerSqft(property.priceRupees, property.areaSqft);
  const posted = relativeDay(property.createdAt);

  return (
    <Screen unsafe>
      <DetailHeader
        title={property.locationLabel || property.title}
        scrollY={scrollY}
        onBack={handleBack}
        onShare={handleShare}
      />

      {/* Rendered after the header so it stacks under it, and before the scroll
          view in reading order because that is where it sits on screen. */}
      <DetailSectionNav sections={registry.sections} scrollY={scrollY} onJump={jumpTo} />

      <Animated.ScrollView
        ref={scrollRef}
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
          onLayout={onSheetLayout}
        >
         <SectionRegistryContext.Provider value={sectionContext}>
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

          {/*
            The unit rate, directly under the price and subordinate to it.

            This is the figure that makes the price above mean something: ₹1.18
            crore is a number, ₹6,800 per sqft is a judgement about whether the
            number is fair. 99acres prints it inside its key-facts row and
            Square Yards inside its attribute grid; here it goes under the price
            because it is a restatement OF the price, not a separate fact.

            Sale only, and `formatRatePerSqft` returns null far more often than
            it returns a string — see its note in `ui/PriceLabel.tsx` for both
            reasons.
          */}
          {rate ? (
            <Text variant="footnote" tone="muted" className="mt-xs">
              {rate}
            </Text>
          ) : null}

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

          {/*
            PROVENANCE, and why it sits below the facts rather than above them.

            "Posted 3 days ago · 142 views" answers two questions a listing page
            otherwise leaves open: is this still real, and is anyone else
            looking. 99acres runs both on its detail page — a "Posted today by
            owner" line above the price and a "3 people viewed this property in
            last 24 hours" line below the facts.

            We put ours in one place, under the facts, because the reading order
            this screen is built around is price → place → what it is → who
            else. Age and interest are the last thing that changes a decision,
            not the first; a listing nobody has viewed is still worth reading if
            the price and the size are right.

            The view count is suppressed under `MEANINGFUL_VIEW_COUNT` for the
            same reason as on the card, with one addition specific to here: the
            reader's own arrival has ALREADY been counted by the request that
            produced this page, so a listing showing "1 view" would be showing
            them themselves.
          */}
          {posted || property.views >= MEANINGFUL_VIEW_COUNT ? (
            <View className="mt-md flex-row items-center">
              <Ionicons name="time-outline" size={13} color={theme.colors.textMuted} />
              <Text variant="caption" tone="muted" className="ml-xs">
                {[
                  posted ? `Posted ${posted}` : null,
                  property.views >= MEANINGFUL_VIEW_COUNT
                    ? `${property.views.toLocaleString('en-IN')} views`
                    : null,
                ]
                  .filter(Boolean)
                  .join('  ·  ')}
              </Text>
            </View>
          ) : null}

          {/*
            Only listings whose owner wrote a real title reach this. It shares
            "About" in the nav with the description below, because whichever of
            the two exists is the first prose on the page and the user jumping
            to "About" wants the top of it — registering the same label twice
            would put two identical chips on the strip. `useSectionRegistry`
            keys on the label, so the second registration overwrites the first;
            they are adjacent, so the offset difference is a few points.
          */}
          {property.headline ? (
            <Section title="About this property" navLabel="About">
              <Text variant="body">{property.headline}</Text>
            </Section>
          ) : null}

          {property.description && !property.headline ? (
            <Section title="About this property" navLabel="About">
              <ExpandableText text={property.description} />
            </Section>
          ) : property.description ? (
            <Section title="Description">
              <ExpandableText text={property.description} />
            </Section>
          ) : null}

          {property.amenities.length > 0 ? (
            <Section title="Amenities" navLabel="Amenities">
              <View className="flex-row flex-wrap gap-sm">
                {property.amenities.map((amenity) => (
                  <Tag key={amenity} label={amenity} />
                ))}
              </View>
            </Section>
          ) : null}

          {property.nearby.length > 0 ? (
            <Section title="Nearby" navLabel="Nearby">
              <NearbyPlaces places={property.nearby} />
            </Section>
          ) : null}

          {property.videoUrl ? (
            <Section title="Video" navLabel="Video">
              <VideoWalkthrough videoUrl={property.videoUrl} />
            </Section>
          ) : null}

          {/*
            Every remaining attribute the listing carries, arranged by the
            field map. Sections it cannot fill do not appear, so this is where
            a residential and a commercial listing visibly diverge without the
            screen ever asking which it is looking at.

            One nav entry for the whole block rather than one per table. It
            renders between two and six tables depending on the listing, and
            six more chips would push everything after them off the strip for
            destinations a user cannot tell apart from the chip alone.
          */}
          <NavAnchor label="Details">
            <DetailAttributes property={property} />
          </NavAnchor>

          {/* Rent has no purchase to finance against. */}
          {property.intent !== 'rent' && property.priceRupees > 0 ? (
            <Section title="EMI calculator" navLabel="EMI">
              <EmiCalculator priceRupees={property.priceRupees} />
            </Section>
          ) : null}

          {/* M4, remaining phase: the locator map. */}

          {owner ? (
            <Section title="Owner" navLabel="Owner">
              <DetailOwner owner={owner} />
            </Section>
          ) : null}

          {/*
            The rail breaks the page's one-column grid on purpose: it is the
            only thing here that scrolls sideways, and it has to reach the
            screen edge for the next card to peek in and say so. The negative
            margin undoes this container's `screenPadding`; `PropertyRail`
            re-applies it as content inset, so the first card still lines up
            with everything above it.
          */}
          {similar.items.length > 0 ? (
            <NavAnchor label="Similar">
              <View style={{ marginTop: spacing['2xl'], marginHorizontal: -screenPadding }}>
                <View
                  style={{
                    height: 1,
                    backgroundColor: theme.colors.border,
                    marginBottom: spacing.lg,
                    marginHorizontal: screenPadding,
                  }}
                />
                <Text
                  variant="title3"
                  className="mb-md"
                  style={{ marginHorizontal: screenPadding }}
                >
                  Similar properties
                </Text>
                <PropertyRail
                  items={similar.items}
                  onSelect={openSimilar}
                  accessibilityLabel="Similar properties"
                />
              </View>
            </NavAnchor>
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
            className="mt-3xl flex-row items-center justify-center active:opacity-60"
          >
            <Ionicons name="flag-outline" size={15} color={theme.colors.textMuted} />
            <Text variant="footnote" tone="muted" className="ml-xs">
              Report this listing
            </Text>
          </Pressable>
         </SectionRegistryContext.Provider>
        </View>
      </Animated.ScrollView>

      {/*
        Outside the ScrollView, so it stays put. This is the only thing on the
        screen the user is meant to do, and the page is long enough that an
        inline button would sit several scrolls below where the decision gets
        made.
      */}
      {/*
        One action. The `tel:` shortcut that sat beside it is gone — see
        `DetailActions` for what it did and why removing the button does not
        remove the exposure.
      */}
      <DetailActions
        interest={interest}
        remaining={enquiriesLeft}
        onRequestEnquire={() => setEnquiring(true)}
        onHeightChange={setActionBarHeight}
      />

      {/*
        THE CONSEQUENCE IS STATED BEFORE THE SIDE EFFECT, NOT AFTER IT.

        `interest.toggle` posts to `/properties/interested/:id`, which creates a
        `Lead` holding this user's name, email and phone, notifies the owner in
        the app, and sends them those details over WhatsApp. None of that is
        reversible: withdrawing pulls the user from `interestedUsers` and frees
        the slot, and leaves the lead, the notification and the message where
        they are. So the sheet runs first and there is no Undo afterwards.
      */}
      <EnquirySheet
        visible={enquiring}
        subtitle={property.locationLabel || property.title}
        remaining={enquiriesLeft}
        onCancel={() => setEnquiring(false)}
        onConfirm={() => {
          setEnquiring(false);
          interest.toggle();
        }}
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
function Section({
  title,
  navLabel,
  children,
}: {
  title: string;
  /**
   * The chip's text in the section nav. Absent means the section is not
   * navigable — the strip has room for perhaps six labels before it stops being
   * scannable, so short blocks that a user would never jump TO are left out
   * rather than shortened until they fit.
   *
   * Often shorter than the heading: "About this property" is right above the
   * paragraph and wrong on a chip beside five others.
   */
  navLabel?: string;
  children: React.ReactNode;
}) {
  const theme = useTheme();
  const { register, offset } = useContext(SectionRegistryContext);

  const handleLayout = useCallback(
    (event: LayoutChangeEvent) => {
      if (navLabel) register(navLabel, navLabel, offset + event.nativeEvent.layout.y);
    },
    [navLabel, register, offset]
  );

  return (
    <View style={{ marginTop: spacing['2xl'] }} onLayout={handleLayout}>
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
 * How a `Section` reaches the registry without every call site passing it.
 *
 * `Section` is used seven times on this screen and the two values it needs —
 * the register function and the sheet's own offset — are the same for all of
 * them. Threading both through every call would put two props on each that say
 * nothing about that section, and a missed one would silently drop it from the
 * nav rather than failing.
 *
 * The default is a no-op, so `Section` still renders correctly outside a
 * provider. Nothing renders it outside one today; the default exists so that
 * moving it into a modal or a preview later cannot crash.
 */
const SectionRegistryContext = createContext<{
  register: (id: string, label: string, y: number) => void;
  offset: number;
}>({ register: () => undefined, offset: 0 });

/**
 * A nav destination that is not a `Section`.
 *
 * Two blocks on this page own their own heading and layout — the attribute
 * tables, which render several headings of their own, and the similar-properties
 * rail, which breaks the column grid to reach the screen edge. Neither can be
 * wrapped in `Section` without changing how it looks, so this wraps them in a
 * bare measuring `View` instead: it registers an offset and adds nothing else.
 *
 * `View` with only `onLayout` does not affect layout, so this is invisible in
 * every sense except the strip.
 */
function NavAnchor({ label, children }: { label: string; children: React.ReactNode }) {
  const { register, offset } = useContext(SectionRegistryContext);

  const handleLayout = useCallback(
    (event: LayoutChangeEvent) => register(label, label, offset + event.nativeEvent.layout.y),
    [label, register, offset]
  );

  return <View onLayout={handleLayout}>{children}</View>;
}

/**
 * Matches the loaded layout's geometry, so nothing shifts when data arrives:
 * the hero height, the sheet's overlap and radius, and the price block's own
 * rhythm are the real constants rather than guesses.
 */
function PropertyDetailSkeleton() {
  // Same derivation as the real hero, so the photo does not change height at
  // the moment the data lands.
  const { width } = useWindowDimensions();

  return (
    <Screen unsafe>
      <Skeleton height={heroHeight(width)} radius={0} />
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
