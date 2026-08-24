import Ionicons from '@expo/vector-icons/Ionicons';
import { Image as ExpoImage } from 'expo-image';
import { useCallback, useEffect, useState } from 'react';
import { ScrollView, StyleSheet, View, type LayoutChangeEvent } from 'react-native';
import Animated, {
  Extrapolation,
  interpolate,
  useAnimatedStyle,
  type SharedValue,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import type { ListingIntent } from '@/features/properties';
import { radius, screenPadding, spacing, touchTarget, useTheme, withAlpha } from '@/theme';
import { Gradient, PressableScale, Text } from '@/ui';
import type { City } from '../cities';
import { HOME_HEADER_ROW, SEARCH_PIN_WINDOW } from './HomeHeader';
import { HomeSearchField } from './HomeSearchField';

/**
 * The hero: a brand-coloured block carrying everything a session starts with.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT IS FOR
 *
 * Three controls, in the order the question gets asked: where am I looking,
 * what am I looking for, and the field to say it in.
 *
 * Identity, listing and notifications used to sit in a row at the top of this
 * block. They moved to `HomeHeader` on 2026-08-24, because they are the frame
 * the screen lives in rather than content, and a frame must not scroll away.
 * What is left here is everything that legitimately belongs to the first
 * screenful and is allowed to leave with it.
 *
 * The city selector is the piece the app never had. Every large Indian portal
 * scopes a session to a city and remembers it; DealDirect's search always
 * accepted the filter but nothing persisted the answer, so a user picked a city
 * on the results screen and was back to the whole country next launch. The chip
 * reads from `city.ts` and drives the intent chips and the search field beneath
 * it, so the block is one connected control rather than four decorations.
 *
 * ---------------------------------------------------------------------------
 * THE HEADLINE IS ONE LINE, AND IT IS THE ONLY CLAIM ON THE SCREEN
 *
 * A brand line in the hero is what every portal in this market opens with, and
 * it is the one place a claim earns its space: it sits above the search field
 * rather than in front of it, so it is read while the thumb is already moving.
 * What is NOT here is the page that used to follow it — the "why choose us"
 * block, the three-benefit strip and the closing "Ready to find your home?"
 * slab. One line, then the tools.
 *
 * ---------------------------------------------------------------------------
 * THE BACKGROUND IS A PHOTOGRAPH, NOT A FLAT FILL
 *
 * A brand-red image of a modern building against a city skyline sits behind
 * the content — already in the brand colour, so it reads as the hero's own
 * surface rather than a picture pasted onto it. A vertical brand scrim over it
 * keeps the white headline legible at the top and grounds the search field at
 * the bottom, while letting the building show through the middle. The base fill
 * stays `brand` underneath, so a slow image load or a decode failure degrades
 * to exactly the flat panel this replaced rather than to a blank gap.
 *
 * The asset is WebP, not PNG and not AVIF. PNG is a lossless container for a
 * photograph and cost 1508 KB for what WebP carries in 74 KB at 39.5 dB PSNR —
 * a 95% saving no user could see, especially under the scrim above. AVIF would
 * save perhaps another 30 KB and was rejected: `expo-image` decodes it only on
 * Android 12+ and iOS 16+, and this app's market runs a lot of older Android.
 * Trading the hero on those devices for 30 KB is the wrong side of that deal.
 */

export interface HomeHeroProps {
  /** The city the session is scoped to, or null for everywhere. */
  city: City | null;
  onOpenCityPicker: () => void;
  /** Run a search from the hero field. Empty term means browse everything. */
  onSubmitSearch: (term: string) => void;
  /** Open a previewed listing straight from the hero's search dropdown. */
  onOpenProperty: (id: string) => void;
  onIntent: (intent: ListingIntent | 'projects') => void;
  /** Live scroll offset, for the handover to the pinned header. */
  scrollY: SharedValue<number>;
  /** Shared with the header's copy — they are one field. */
  searchValue: string;
  onSearchValueChange: (value: string) => void;
  /**
   * Reports the scroll offset at which this field reaches the header, so the
   * header knows exactly when to take over. See the handover note there.
   */
  onPinOffsetChange: (offset: number) => void;
}

const INTENTS: readonly {
  id: ListingIntent | 'projects';
  label: string;
  icon: keyof typeof Ionicons.glyphMap;
}[] = [
  { id: 'sale', label: 'Buy', icon: 'home-outline' },
  { id: 'rent', label: 'Rent', icon: 'pricetag-outline' },
  { id: 'projects', label: 'Projects', icon: 'business-outline' },
];

export function HomeHero({
  city,
  onOpenCityPicker,
  onSubmitSearch,
  onOpenProperty,
  onIntent,
  scrollY,
  searchValue,
  onSearchValueChange,
  onPinOffsetChange,
}: HomeHeroProps) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();

  /**
   * Where this field sits, and therefore when the header takes over.
   *
   * Measured rather than derived from the hero's height: the block grows with
   * the user's text size and with the selected city's name, and a computed
   * guess would hand over at the wrong pixel on any device that is not the one
   * it was tuned on. The field's own `y` is exactly the number both sides need.
   */
  const [fieldY, setFieldY] = useState(0);
  const [searchFocused, setSearchFocused] = useState(false);

  const pinOffset = fieldY > 0 ? Math.max(fieldY - insets.top - HOME_HEADER_ROW, 0) : 0;

  useEffect(() => onPinOffsetChange(pinOffset), [pinOffset, onPinOffsetChange]);

  const onFieldLayout = useCallback(
    (event: LayoutChangeEvent) => setFieldY(event.nativeEvent.layout.y),
    []
  );

  /**
   * The hero's half of the handover.
   *
   * Across the pin window this copy is held STILL — translated down by exactly
   * as much as the scroll moves it up — while it fades out and the header's
   * copy fades in at the same pixels. Without the counter-translate the two
   * would drift apart during the crossfade and the handover would read as two
   * fields briefly, which is the thing being fixed.
   *
   * Skipped entirely while focused: the panel hangs off this field, and fading
   * out what someone is typing into would be worse than any seam.
   */
  const fieldStyle = useAnimatedStyle(() => {
    if (searchFocused || pinOffset <= 0) {
      return { opacity: 1, transform: [{ translateY: 0 }] };
    }

    const progress = interpolate(
      scrollY.value,
      [pinOffset, pinOffset + SEARCH_PIN_WINDOW],
      [0, 1],
      Extrapolation.CLAMP
    );

    return {
      opacity: 1 - progress,
      transform: [{ translateY: SEARCH_PIN_WINDOW * progress }],
    };
  }, [pinOffset, searchFocused]);

  /**
   * Text on the brand fill, not the page's text colours.
   *
   * `textOnAccent` is the token for exactly this — anything placed on an
   * accent, brand or danger fill — and using `textPrimary` here would be the
   * usual mistake: it inverts correctly in dark mode and is then unreadable on
   * a red panel in both.
   */
  const onBrand = theme.colors.textOnAccent;
  const onBrandMuted = withAlpha(theme.colors.textOnAccent, 0.82);

  return (
    <View
      style={{
        backgroundColor: theme.colors.brand,
        overflow: 'hidden',
        paddingHorizontal: screenPadding,
        /*
          Padded clear of the pinned header, which sits above this block and
          never scrolls.

          `Screen` no longer insets the top — the header has to be able to sit
          UNDER the status bar, and an inset screen would leave a strip of page
          colour above a bar whose entire job is to be the top of the screen.
          So the hero pays the inset AND the header's height.

          `HOME_HEADER_ROW` is imported rather than repeated: these two files
          have to agree on the number exactly, and two constants that must
          match are one edit away from not matching.
        */
        paddingTop: insets.top + HOME_HEADER_ROW + spacing.md,
        paddingBottom: spacing.lg,
        // Rounded only at the bottom: the block continues the header's fill
        // upward and ends in a curve, so the content below reads as sliding
        // out from beneath it rather than butting against a rectangle.
        borderBottomLeftRadius: radius.xl,
        borderBottomRightRadius: radius.xl,
      }}
    >
      {/* Behind the content, respecting the rounded corners via the container's
          `overflow: hidden`. `top right` features the building the image places
          there; the plain sky falls to the left, under the headline. */}
      <ExpoImage
        source={require('../../../../assets/home/brand/hero-city.webp')}
        /*
          Nudged up and to the left. The portrait image fills the hero by
          WIDTH under `cover`, so there is no horizontal crop room to shift
          into — the small `scale` creates it (and a little top overflow the
          upward translate needs), then the translate does the move. The two
          numbers to retune the framing are here: more-negative translateX
          moves it further left, more-negative translateY further up.
        */
        style={[
          StyleSheet.absoluteFill,
          { transform: [{ scale: 1.15 }, { translateX: -20 }, { translateY: -22 }] },
        ]}
        contentFit="cover"
        contentPosition="top"
        // The image is baked into the bundle, so caching it is pointless work;
        // memory-only avoids a disk round trip on every Home mount.
        cachePolicy="memory"
      />
      {/* The scrim, and the seam.

          The whole top-and-text zone is HELD fully opaque brand — the same
          fill the pinned header carries — not just the very top edge. The
          header covers roughly the first third of this block, the headline,
          subtitle and city chip the next; a scrim that started fading inside
          that zone let the dark photo tint the hero a shade below the flat
          header and reopened the seam the user saw. So the first two stops are
          both solid brand: the header, the headline and everything down to the
          intent chips sit on one identical red. Only past the halfway line does
          it clear, so the building emerges under the chips and search field —
          which reads as a photograph, not as a second background colour. */}
      <Gradient
        colors={[
          withAlpha(theme.colors.brand, 1),
          withAlpha(theme.colors.brand, 1),
          withAlpha(theme.colors.brand, 0.18),
        ]}
        locations={[0, 0.5, 1]}
        style={StyleSheet.absoluteFillObject}
      />

      <Text variant="title2" style={{ color: onBrand }}>
        Property, direct from owners
      </Text>
      <Text variant="callout" className="mt-xs" style={{ color: onBrandMuted }}>
        No brokerage, no middleman.
      </Text>

      {/* Where. Reads as a sentence rather than a form field, which is how the
          portals put it and why it does not need a label. */}
      <PressableScale
        accessibilityRole="button"
        accessibilityLabel={
          city ? `Searching in ${city.label}. Change city` : 'Choose a city to search in'
        }
        onPress={onOpenCityPicker}
        activeScale={0.98}
        style={{
          alignSelf: 'flex-start',
          flexDirection: 'row',
          alignItems: 'center',
          gap: 6,
          marginTop: spacing.base,
          height: 36,
          paddingHorizontal: spacing.base,
          borderRadius: radius.full,
          backgroundColor: withAlpha(theme.colors.textOnAccent, 0.16),
        }}
      >
        <Ionicons name="location-outline" size={15} color={onBrand} />
        <Text variant="footnote" style={{ color: onBrand }}>
          {city ? 'You are searching in ' : 'Searching '}
          <Text variant="footnote" style={{ color: onBrand, fontWeight: '700' }}>
            {city ? city.label : 'all cities'}
          </Text>
        </Text>
        <Ionicons name="chevron-down" size={14} color={onBrand} />
      </PressableScale>

      {/* What. Edge to edge so the last chip slides off the side rather than
          stopping in mid-air — the same rule the results rail follows. */}
      <ScrollView
        horizontal
        showsHorizontalScrollIndicator={false}
        style={{ marginHorizontal: -screenPadding, marginTop: spacing.base }}
        contentContainerStyle={{ paddingHorizontal: screenPadding, gap: spacing.sm }}
      >
        {INTENTS.map((intent) => (
          <PressableScale
            key={intent.id}
            accessibilityRole="button"
            accessibilityLabel={intent.label}
            onPress={() => onIntent(intent.id)}
            activeScale={0.96}
            style={{
              flexDirection: 'row',
              alignItems: 'center',
              gap: 6,
              height: touchTarget.min,
              paddingHorizontal: spacing.base,
              borderRadius: radius.full,
              backgroundColor: withAlpha(theme.colors.textOnAccent, 0.16),
              borderWidth: 1,
              borderColor: withAlpha(theme.colors.textOnAccent, 0.28),
            }}
          >
            <Ionicons name={intent.icon} size={16} color={onBrand} />
            <Text variant="callout" style={{ color: onBrand, fontWeight: '600' }}>
              {intent.label}
            </Text>
          </PressableScale>
        ))}
      </ScrollView>

      {/* How. A real field now: it answers with autocomplete in place and only
          leaves Home on a deliberate search — the submit button, the keyboard's
          search key, or a suggestion tap. See `HomeSearchField`. */}
      <Animated.View onLayout={onFieldLayout} style={fieldStyle}>
        <HomeSearchField
          city={city}
          value={searchValue}
          onChangeText={onSearchValueChange}
          onSubmit={onSubmitSearch}
          onOpenProperty={onOpenProperty}
          onFocusChange={setSearchFocused}
        />
      </Animated.View>
    </View>
  );
}
