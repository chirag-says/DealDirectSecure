import Ionicons from '@expo/vector-icons/Ionicons';
import { Image as ExpoImage } from 'expo-image';
import { useCallback, useEffect, useState } from 'react';
import { View, useWindowDimensions, type LayoutChangeEvent } from 'react-native';
import Animated, {
  Extrapolation,
  interpolate,
  useAnimatedStyle,
  type SharedValue,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import type { ListingIntent } from '@/features/properties';
import { radius, useTheme } from '@/theme';
import { PressableScale, Text } from '@/ui';
import type { City } from '../cities';
import {
  HEADER_ROW_PX,
  HEADER_TOP_PX,
  HERO_BG,
  HERO_GLASS,
  HERO_GLASS_BORDER,
  HERO_HEADLINE_TOP_PX,
  HERO_INSET_PX,
  HERO_TEXT,
  HERO_TEXT_MUTED,
  useMockScale,
} from '../heroTheme';
import { SEARCH_PIN_WINDOW } from './HomeHeader';
import { HomeSearchField } from './HomeSearchField';

/**
 * The hero, drawn to the reference mockup (measured pass, 2026-09-05).
 *
 * Every number below is a reference pixel through `mockPx`; see
 * `heroTheme.ts`. Measured from the mockup, all from the status bar's bottom:
 *
 *   photograph      full width, top-anchored, 3:2, so it ends above the pill
 *   headline        top 204, 43 px bold, 47 px line pitch, two lines
 *   subtitle        28 px regular, grey, 8 below the headline's line box
 *   chips           top 429 (27 below the subtitle), 68 tall, 22 apart
 *                   Buy is red with 52 of side padding; the others glass, 35
 *   search pill     top 528 (31 below the chips), 86 tall
 *   next section    34 below the pill — supplied by the page, not by this block
 *
 * WHAT DID NOT CHANGE, deliberately: `HomeSearchField` and everything behind
 * it. Same component, same handlers, same autocomplete, same handover to the
 * header; the pin arithmetic reads the same layout event it always did.
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
  /** Reference side padding. Buy is the wide one. */
  padPx: number;
}[] = [
  { id: 'sale', label: 'Buy', icon: 'home-outline', padPx: 52 },
  { id: 'rent', label: 'Rent', icon: 'pricetag-outline', padPx: 35 },
  { id: 'projects', label: 'Projects', icon: 'business-outline', padPx: 35 },
];

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
  const mockPx = useMockScale();
  const { width } = useWindowDimensions();

  const [fieldY, setFieldY] = useState(0);
  const [searchFocused, setSearchFocused] = useState(false);

  // The header's bottom edge, in the hero's coordinates: the field reaches
  // the bar when it has scrolled up by its own offset minus that.
  const headerBottom = insets.top + mockPx(HEADER_TOP_PX + HEADER_ROW_PX);
  const pinOffset = fieldY > 0 ? Math.max(fieldY - headerBottom, 0) : 0;

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
        paddingHorizontal: mockPx(HERO_INSET_PX),
        // The photograph runs up under the transparent header, so this block
        // pays the status inset AND the header, then the measured gap to the
        // headline. All three are the header's own constants.
        paddingTop: insets.top + mockPx(HERO_HEADLINE_TOP_PX),
        // The page supplies the gap to the next section; the reference has
        // nothing of this block below the pill but its colour.
        paddingBottom: 0,
        borderBottomLeftRadius: radius.xl,
        borderBottomRightRadius: radius.xl,
      }}
    >
      {/* The photograph: full width, top-anchored, its native 3:2. It ends
          above the search pill; below it the block is the slab's own colour,
          which is also the colour of the photograph's last rows, so there is
          no edge to see. */}
      <ExpoImage
        source={require('../../../../assets/home/brand/hero-dusk.webp')}
        style={{ position: 'absolute', top: 0, left: 0, width, height: (width * 1024) / 1536 }}
        contentFit="cover"
        cachePolicy="memory"
      />

      <Text
        variant="title1"
        accessibilityRole="header"
        style={{ color: HERO_TEXT, fontSize: mockPx(43), lineHeight: mockPx(47) }}
      >
        {'Property,\ndirect from owners'}
      </Text>
      <Text
        variant="body"
        style={{
          color: HERO_TEXT_MUTED,
          fontSize: mockPx(28),
          lineHeight: mockPx(34),
          marginTop: mockPx(8),
        }}
      >
        No brokerage, no middleman.
      </Text>

      {/* Buy, Rent, Projects. One row, reference widths by padding. */}
      <View style={{ flexDirection: 'row', gap: mockPx(22), marginTop: mockPx(27) }}>
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
                gap: mockPx(12),
                height: mockPx(68),
                paddingHorizontal: mockPx(intent.padPx),
                borderRadius: mockPx(34),
                backgroundColor: primary ? theme.colors.brand : HERO_GLASS,
                borderWidth: primary ? 0 : 1,
                borderColor: HERO_GLASS_BORDER,
              }}
            >
              <Ionicons name={intent.icon} size={mockPx(28)} color={HERO_TEXT} />
              <Text
                variant="bodyEmphasis"
                style={{ color: HERO_TEXT, fontSize: mockPx(26), lineHeight: mockPx(32) }}
              >
                {intent.label}
              </Text>
            </PressableScale>
          );
        })}
      </View>

      {/* The search field: same component, same autocomplete, same handover.
          Only its dress changed; see `HomeSearchField`. */}
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
