import Ionicons from '@expo/vector-icons/Ionicons';
import { Image as ExpoImage } from 'expo-image';
import { ScrollView, StyleSheet, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import type { ListingIntent } from '@/features/properties';
import { radius, screenPadding, spacing, touchTarget, useTheme, withAlpha } from '@/theme';
import { Gradient, PressableScale, Text } from '@/ui';
import type { City } from '../cities';
import { HOME_HEADER_ROW } from './HomeHeader';

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
 */

export interface HomeHeroProps {
  /** The city the session is scoped to, or null for everywhere. */
  city: City | null;
  onOpenCityPicker: () => void;
  onSearch: () => void;
  onIntent: (intent: ListingIntent | 'projects') => void;
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
  onSearch,
  onIntent,
}: HomeHeroProps) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();

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
        source={require('../../../../assets/home/brand/hero-city.png')}
        style={StyleSheet.absoluteFill}
        contentFit="cover"
        contentPosition="top right"
        // The image is baked into the bundle, so caching it is pointless work;
        // memory-only avoids a disk round trip on every Home mount.
        cachePolicy="memory"
      />
      {/* The scrim: stronger at the top behind the white headline, near-clear
          through the middle so the building reads, lightly grounded at the
          bottom under the search field. */}
      <Gradient
        colors={[
          withAlpha(theme.colors.brand, 0.55),
          withAlpha(theme.colors.brand, 0.08),
          withAlpha(theme.colors.brand, 0.32),
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

      {/* How. A trigger, not a field: typing belongs on Search, which owns the
          suggestion panel and the history. Two editable search inputs would be
          two places for the query to live. */}
      <PressableScale
        accessibilityRole="search"
        accessibilityLabel="Search properties, localities or projects"
        onPress={onSearch}
        activeScale={0.99}
        style={{
          flexDirection: 'row',
          alignItems: 'center',
          gap: spacing.md,
          marginTop: spacing.base,
          height: 52,
          paddingHorizontal: spacing.base,
          borderRadius: radius.full,
          backgroundColor: theme.colors.surface,
        }}
      >
        <Ionicons name="search" size={20} color={theme.colors.textSecondary} />
        <Text variant="body" tone="secondary" numberOfLines={1} className="flex-1">
          {city ? `Search in ${city.label}` : 'Search locality, project or city'}
        </Text>
      </PressableScale>
    </View>
  );
}
