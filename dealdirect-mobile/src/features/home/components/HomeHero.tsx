import Ionicons from '@expo/vector-icons/Ionicons';
import { Image as ExpoImage } from 'expo-image';
import { useCallback, useEffect, useState } from 'react';
import { StyleSheet, View, type LayoutChangeEvent } from 'react-native';
import Animated, {
  Extrapolation,
  interpolate,
  useAnimatedStyle,
  type SharedValue,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import type { ListingIntent } from '@/features/properties';
import { radius, screenPadding, spacing, useTheme } from '@/theme';
import { Gradient, PressableScale, Text } from '@/ui';
import type { City } from '../cities';
import {
  HERO_BG,
  HERO_GLASS,
  HERO_GLASS_BORDER,
  HERO_TEXT,
  HERO_TEXT_MUTED,
} from '../heroTheme';
import { HOME_HEADER_ROW, SEARCH_PIN_WINDOW } from './HomeHeader';
import { HomeSearchField } from './HomeSearchField';

/**
 * The hero (redesigned 2026-09-05 to the reference mockup).
 *
 * A dusk photograph fills the whole top of Home, under the header too: glass
 * houses lit from inside at the top right, a dark slab rising from the
 * bottom left. The headline sits on the slab, the search field sits where
 * the slab meets the page. The city chip that used to live here moved up
 * into the header, where the reference puts it.
 *
 * WHAT DID NOT CHANGE, deliberately: `HomeSearchField` and everything behind
 * it. The field is the same component with the same handlers, the pin
 * handover to the header is the same measurement, and the "which offset does
 * the field reach the bar at" arithmetic is untouched. This file changed what
 * the top of Home looks like, not what it does.
 */

export interface HomeHeroProps {
  city: City | null;
  onSubmitSearch: (term: string) => void;
  onOpenProperty: (id: string) => void;
  onIntent: (intent: ListingIntent | 'projects') => void;
  scrollY: SharedValue<number>;
  searchValue: string;
  onSearchValueChange: (value: string) => void;
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

const CHIP_HEIGHT = 56;

export function HomeHero({
  city,
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

  const [fieldY, setFieldY] = useState(0);
  const [searchFocused, setSearchFocused] = useState(false);

  const pinOffset = fieldY > 0 ? Math.max(fieldY - insets.top - HOME_HEADER_ROW, 0) : 0;

  useEffect(() => onPinOffsetChange(pinOffset), [pinOffset, onPinOffsetChange]);

  const onFieldLayout = useCallback(
    (event: LayoutChangeEvent) => setFieldY(event.nativeEvent.layout.y),
    []
  );

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

  return (
    <View
      style={{
        backgroundColor: HERO_BG,
        overflow: 'hidden',
        paddingHorizontal: screenPadding,
        // Clear of the pinned header, which sits above this block and never
        // scrolls. The hero pays the status inset AND the header's height so
        // the photograph runs up under both — the header is transparent while
        // the page is at the top. `HOME_HEADER_ROW` is imported rather than
        // repeated; the two files must agree on it exactly.
        paddingTop: insets.top + HOME_HEADER_ROW + spacing.xl,
        paddingBottom: spacing.xl,
        borderBottomLeftRadius: radius.xl,
        borderBottomRightRadius: radius.xl,
      }}
    >
      {/* The photograph. Landscape, so under `cover` it fills by height and
          crops horizontally; anchoring top-right keeps the lit houses in the
          corner and lets the dark slab fall under the headline. */}
      <ExpoImage
        source={require('../../../../assets/home/brand/hero-dusk.webp')}
        style={StyleSheet.absoluteFill}
        contentFit="cover"
        contentPosition="top right"
        cachePolicy="memory"
      />
      {/* Two settles. A faint one at the top so the status bar and the header
          read on the sky, and a firm one at the bottom so the search field and
          the block's curved edge sit on the same near-black the page uses. */}
      <Gradient
        colors={['rgba(11, 13, 18, 0.55)', 'rgba(11, 13, 18, 0)']}
        locations={[0, 0.35]}
        style={StyleSheet.absoluteFillObject}
      />
      <Gradient
        colors={['rgba(11, 13, 18, 0)', 'rgba(11, 13, 18, 0.6)', HERO_BG]}
        locations={[0.45, 0.75, 1]}
        style={StyleSheet.absoluteFillObject}
      />

      <Text
        variant="title1"
        style={{ color: HERO_TEXT, fontWeight: '700', lineHeight: 38 }}
        accessibilityRole="header"
      >
        {'Property,\ndirect from owners'}
      </Text>
      <Text variant="body" className="mt-xs" style={{ color: HERO_TEXT_MUTED }}>
        No brokerage, no middleman.
      </Text>

      {/* What. Three intents in one row: Buy carries the brand, the other two
          are glass on the photo. */}
      <View style={{ flexDirection: 'row', gap: spacing.sm, marginTop: spacing.xl }}>
        {INTENTS.map((intent) => {
          const primary = intent.id === 'sale';
          return (
            <PressableScale
              key={intent.id}
              accessibilityRole="button"
              accessibilityLabel={intent.label}
              onPress={() => onIntent(intent.id)}
              activeScale={0.96}
              style={{
                flexDirection: 'row',
                alignItems: 'center',
                justifyContent: 'center',
                gap: spacing.sm,
                height: CHIP_HEIGHT,
                paddingHorizontal: spacing.lg,
                borderRadius: radius.full,
                backgroundColor: primary ? theme.colors.brand : HERO_GLASS,
                borderWidth: primary ? 0 : 1,
                borderColor: HERO_GLASS_BORDER,
              }}
            >
              <Ionicons name={intent.icon} size={22} color={HERO_TEXT} />
              <Text variant="bodyEmphasis" style={{ color: HERO_TEXT }}>
                {intent.label}
              </Text>
            </PressableScale>
          );
        })}
      </View>

      {/* How. The same field as before, with the same autocomplete and the
          same handover to the header; only its dress changed. See
          `HomeSearchField`. */}
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
