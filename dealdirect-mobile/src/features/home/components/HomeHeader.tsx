import Ionicons from '@expo/vector-icons/Ionicons';
import { Image as ExpoImage } from 'expo-image';
import { StatusBar } from 'expo-status-bar';
import { useState } from 'react';
import { Dimensions, StyleSheet, View } from 'react-native';
import Animated, {
  Extrapolation,
  interpolate,
  useAnimatedStyle,
  type SharedValue,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { gesture } from '@/theme';
import { Avatar, PressableScale, Text } from '@/ui';
import type { City } from '../cities';
import {
  HEADER_ROW_PX,
  HEADER_TOP_PX,
  HERO_BG,
  HERO_HEADER_GLASS,
  HERO_HEADER_INK,
  HERO_TEXT,
  HERO_TEXT_FAINT,
  useMockScale,
} from '../heroTheme';
import { HomeSearchField } from './HomeSearchField';

/**
 * The sticky header, drawn to the reference mockup (measured pass, 2026-09-05).
 *
 * Every number below is a reference pixel through `mockPx`; see
 * `heroTheme.ts` for why. Measured from the mockup:
 *
 *   wordmark        x 40, y 95 (25 below the status bar), 250 wide
 *   tagline 1       "Zero Brokerage Property Deals", white, 24 px semibold
 *   tagline 2       "Buy · Rent · Sell directly from owners", grey, 19 px
 *   city chip       right-aligned group, 60 tall, pale glass, dark text
 *   bell            60 circle, pale glass, dark glyph
 *   avatar          60 circle, white, dark glyph; 30 from the right edge
 *   controls        centred on the wordmark's line, 18–20 apart
 *
 * ---------------------------------------------------------------------------
 * TRANSPARENT AT REST, SOLID ONCE SCROLLED
 *
 * At the top of the page the bar has no fill: the photograph runs up under
 * it and the sky is what the wordmark sits on. As the page scrolls the fill
 * fades in to the hero's own near-black over the window in which the search
 * field arrives, so the moment the bar has content to separate from, it has
 * a colour to do it with.
 *
 * THE SEARCH HANDOVER IS UNCHANGED: the pinned copy of the hero's field, its
 * measurement and the crossfade window are the same code they were.
 */

export interface HomeHeaderProps {
  /** Live scroll offset, from the reveal host. */
  scrollY: SharedValue<number>;
  /**
   * Scroll offset at which the hero's search field reaches this bar, measured
   * by the hero. 0 while unmeasured, which keeps this copy hidden.
   */
  pinOffset: number;
  name?: string;
  avatarUri?: string;
  hasUnread: boolean;
  city: City | null;
  /** Shared with the hero's copy — they are one field. See `HomeSearchField`. */
  searchValue: string;
  onSearchValueChange: (value: string) => void;
  onSubmitSearch: (term: string) => void;
  onOpenProperty: (id: string) => void;
  onOpenProfile: () => void;
  onOpenUpdates: () => void;
  onOpenCityPicker: () => void;
}

/** How many scrolled pixels the crossfade between the two field copies takes. */
export const SEARCH_PIN_WINDOW = 10;

/** The search pill's reference height plus the breathing room under it. */
const SEARCH_ROW_PX = 86 + 16;

const FOCUSED_HEIGHT = Dimensions.get('window').height;

/** The wordmark asset is 308×82; the reference renders it 258 wide. */
const LOGO_WIDTH_PX = 258;
const LOGO_HEIGHT_PX = (LOGO_WIDTH_PX * 82) / 308;

export function HomeHeader({
  scrollY,
  pinOffset,
  name,
  avatarUri,
  hasUnread,
  city,
  searchValue,
  onSearchValueChange,
  onSubmitSearch,
  onOpenProperty,
  onOpenProfile,
  onOpenUpdates,
  onOpenCityPicker,
}: HomeHeaderProps) {
  const insets = useSafeAreaInsets();
  const mockPx = useMockScale();

  const [searchFocused, setSearchFocused] = useState(false);

  // Nothing until the hero has reported where its field actually is. A
  // guessed pin would hand over at the wrong pixel, which is the one failure
  // this whole arrangement exists to avoid.
  const armed = pinOffset > 0;

  const fillStyle = useAnimatedStyle(() => {
    if (searchFocused) return { opacity: 1 };
    if (!armed) return { opacity: 0 };
    return {
      opacity: interpolate(scrollY.value, [0, Math.max(pinOffset, 1)], [0, 1], Extrapolation.CLAMP),
    };
  }, [pinOffset, armed, searchFocused]);

  const searchRow = mockPx(SEARCH_ROW_PX);

  const searchRowStyle = useAnimatedStyle(() => {
    if (searchFocused) return { height: FOCUSED_HEIGHT, opacity: 1 };
    if (!armed) return { height: 0, opacity: 0 };

    const progress = interpolate(
      scrollY.value,
      [pinOffset, pinOffset + SEARCH_PIN_WINDOW],
      [0, 1],
      Extrapolation.CLAMP
    );

    // Full height the instant the pin is crossed, rather than growing with
    // the fade: a growing box would clip the field and reveal it top-down.
    return {
      height: progress > 0 ? searchRow : 0,
      opacity: progress,
    };
  }, [pinOffset, armed, searchFocused, searchRow]);

  const control = {
    width: mockPx(60),
    height: mockPx(60),
    borderRadius: mockPx(30),
    alignItems: 'center' as const,
    justifyContent: 'center' as const,
    backgroundColor: HERO_HEADER_GLASS,
  };

  return (
    <View style={[styles.host, { paddingTop: insets.top + mockPx(HEADER_TOP_PX) }]}>
      {/* The hero is a photograph in every scheme, so the status bar is light
          on Home regardless of the theme. */}
      <StatusBar style="light" />

      <Animated.View
        pointerEvents="none"
        style={[StyleSheet.absoluteFillObject, { backgroundColor: HERO_BG }, fillStyle]}
      />

      <View
        style={{
          flexDirection: 'row',
          alignItems: 'flex-start',
          height: mockPx(HEADER_ROW_PX),
          paddingLeft: mockPx(40),
          paddingRight: mockPx(30),
        }}
      >
        {/* Identity: the website's wordmark, and what it stands for. */}
        <View style={{ flex: 1 }}>
          <ExpoImage
            source={require('../../../../assets/home/brand/logo.png')}
            style={{ width: mockPx(LOGO_WIDTH_PX), height: mockPx(LOGO_HEIGHT_PX) }}
            contentFit="contain"
            contentPosition="left"
            accessibilityLabel="DealDirect"
            cachePolicy="memory"
          />
          <Text
            variant="bodyEmphasis"
            numberOfLines={1}
            style={{
              color: HERO_TEXT,
              fontSize: mockPx(24),
              lineHeight: mockPx(30),
              marginTop: mockPx(4),
            }}
          >
            Zero Brokerage Property Deals
          </Text>
          <Text
            variant="body"
            numberOfLines={1}
            style={{ color: HERO_TEXT_FAINT, fontSize: mockPx(19), lineHeight: mockPx(24) }}
          >
            Buy · Rent · Sell directly from owners
          </Text>
        </View>

        {/* The controls sit on the wordmark's line, not the block's centre. */}
        <View
          style={{
            flexDirection: 'row',
            alignItems: 'center',
            height: mockPx(LOGO_HEIGHT_PX),
            marginTop: mockPx(-8),
            gap: mockPx(18),
          }}
        >
          <PressableScale
            accessibilityRole="button"
            accessibilityLabel={
              city ? `Searching in ${city.label}. Change city` : 'Choose a city to search in'
            }
            onPress={onOpenCityPicker}
            activeScale={0.96}
            style={{
              flexDirection: 'row',
              alignItems: 'center',
              gap: mockPx(10),
              height: mockPx(60),
              maxWidth: mockPx(230),
              paddingHorizontal: mockPx(22),
              borderRadius: mockPx(30),
              backgroundColor: HERO_HEADER_GLASS,
            }}
          >
            <Ionicons name="location-outline" size={mockPx(28)} color={HERO_HEADER_INK} />
            <Text
              variant="bodyEmphasis"
              numberOfLines={1}
              style={{ color: HERO_HEADER_INK, fontSize: mockPx(26), lineHeight: mockPx(32), flexShrink: 1 }}
            >
              {city ? city.label : 'All cities'}
            </Text>
            <Ionicons name="chevron-down" size={mockPx(24)} color={HERO_HEADER_INK} />
          </PressableScale>

          <PressableScale
            accessibilityRole="button"
            accessibilityLabel={hasUnread ? 'Updates, you have unread items' : 'Updates'}
            hitSlop={gesture.hitSlop}
            onPress={onOpenUpdates}
            activeScale={0.94}
            style={control}
          >
            <Ionicons name="notifications-outline" size={mockPx(32)} color={HERO_HEADER_INK} />
            {hasUnread ? (
              <View
                style={{
                  position: 'absolute',
                  top: mockPx(12),
                  right: mockPx(14),
                  width: mockPx(12),
                  height: mockPx(12),
                  borderRadius: mockPx(6),
                  backgroundColor: '#F33F40',
                }}
              />
            ) : null}
          </PressableScale>

          <PressableScale
            accessibilityRole="button"
            accessibilityLabel="Your account"
            hitSlop={gesture.hitSlop}
            onPress={onOpenProfile}
            activeScale={0.94}
            style={{ ...control, backgroundColor: HERO_TEXT }}
          >
            {name ? (
              <Avatar uri={avatarUri} name={name} size="sm" />
            ) : (
              <Ionicons name="person" size={mockPx(34)} color={HERO_HEADER_INK} />
            )}
          </PressableScale>
        </View>
      </View>

      {/* The pinned copy of the hero's field. Same component, same geometry.
          `overflow: 'hidden'` keeps it clipped to zero before the pin, which
          is also what stops the not-yet-pinned copy from taking taps meant for
          the hero underneath. */}
      <Animated.View style={[styles.searchRow, { paddingHorizontal: mockPx(34) }, searchRowStyle]}>
        <HomeSearchField
          city={city}
          value={searchValue}
          onChangeText={onSearchValueChange}
          onSubmit={onSubmitSearch}
          onOpenProperty={onOpenProperty}
          onFocusChange={setSearchFocused}
          flush
        />
      </Animated.View>
    </View>
  );
}

const styles = StyleSheet.create({
  host: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    zIndex: 10,
  },
  searchRow: {
    overflow: 'hidden',
  },
});
