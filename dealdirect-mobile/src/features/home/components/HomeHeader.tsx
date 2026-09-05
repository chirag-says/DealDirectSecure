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

import { gesture, radius, screenPadding, spacing, useTheme } from '@/theme';
import { Avatar, PressableScale, Text } from '@/ui';
import type { City } from '../cities';
import { HERO_BG, HERO_GLASS, HERO_GLASS_BORDER, HERO_TEXT, HERO_TEXT_FAINT } from '../heroTheme';
import { HomeSearchField } from './HomeSearchField';

/**
 * The sticky header (redesigned 2026-09-05 to the reference mockup).
 *
 * Identity on the left — the wordmark and its two tag lines — and on the
 * right the city the person is shopping in, the bell, and their avatar.
 * "List property" left this bar: the reference has no room for it, and the
 * listing card further down Home carries that action with more context than
 * a pill ever did.
 *
 * ---------------------------------------------------------------------------
 * TRANSPARENT AT REST, SOLID ONCE SCROLLED
 *
 * At the top of the page the bar has no fill: the hero's photograph runs up
 * under it and the sky is what the logo sits on. As the page scrolls, the
 * fill fades in to the hero's own near-black over the same window in which
 * the search field arrives, so the moment the bar has content to separate
 * from, it has a colour to do it with. Because the fill is the exact colour
 * of the slab it covers, there is no seam to see at the handover.
 *
 * ---------------------------------------------------------------------------
 * THE SEARCH HANDOVER IS UNCHANGED
 *
 * The pinned copy of the hero's field, its measurement, and the crossfade
 * window are exactly what they were. This file changed the bar's look and
 * what sits in it; the field and the pin arithmetic are the same code.
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

/**
 * The bar's own height, below the status inset. Taller than a plain icon row
 * because the wordmark carries two lines of tagline under it. The hero pads
 * by this exact number, which is why it is exported.
 */
export const HOME_HEADER_ROW = 80;

const SEARCH_FIELD = 60;

const SEARCH_ROW = SEARCH_FIELD + spacing.sm;

/** How many scrolled pixels the crossfade between the two field copies takes. */
export const SEARCH_PIN_WINDOW = 10;

const FOCUSED_HEIGHT = Dimensions.get('window').height;

/** The wordmark asset is 308×82; rendered at this width it keeps that ratio. */
const LOGO_WIDTH = 150;
const LOGO_HEIGHT = Math.round((LOGO_WIDTH * 82) / 308);

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
  const theme = useTheme();
  const insets = useSafeAreaInsets();

  const [searchFocused, setSearchFocused] = useState(false);

  // Nothing until the hero has reported where its field actually is. A
  // guessed pin would hand over at the wrong pixel, which is the one failure
  // this whole arrangement exists to avoid.
  const armed = pinOffset > 0;

  const fillStyle = useAnimatedStyle(() => {
    if (searchFocused) return { opacity: 1 };
    if (!armed) return { opacity: 0 };
    return {
      opacity: interpolate(
        scrollY.value,
        [0, Math.max(pinOffset, 1)],
        [0, 1],
        Extrapolation.CLAMP
      ),
    };
  }, [pinOffset, armed, searchFocused]);

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
    // Snapping is invisible because the bar's fill and the slab behind it are
    // the same colour, so nothing arrives except the field, which crossfades.
    return {
      height: progress > 0 ? SEARCH_ROW : 0,
      opacity: progress,
    };
  }, [pinOffset, armed, searchFocused]);

  return (
    <View style={[styles.host, { paddingTop: insets.top }]}>
      {/* The hero is a photograph in every scheme, so the status bar is light
          on Home regardless of the theme. */}
      <StatusBar style="light" />

      <Animated.View
        pointerEvents="none"
        style={[StyleSheet.absoluteFillObject, { backgroundColor: HERO_BG }, fillStyle]}
      />

      <View style={styles.row}>
        {/* Identity. The wordmark and what it stands for, on two lines. */}
        <View style={{ flex: 1 }}>
          <ExpoImage
            source={require('../../../../assets/home/brand/logo.png')}
            style={{ width: LOGO_WIDTH, height: LOGO_HEIGHT }}
            contentFit="contain"
            accessibilityLabel="DealDirect"
            cachePolicy="memory"
          />
          <Text
            variant="footnote"
            style={{ color: HERO_TEXT, fontWeight: '600', marginTop: 2 }}
            numberOfLines={1}
          >
            Zero Brokerage Property Deals
          </Text>
          <Text variant="caption" style={{ color: HERO_TEXT_FAINT }} numberOfLines={1}>
            Buy · Rent · Sell directly from owners
          </Text>
        </View>

        {/* Where. The city chip lives here now, as the reference has it. */}
        <PressableScale
          accessibilityRole="button"
          accessibilityLabel={
            city ? `Searching in ${city.label}. Change city` : 'Choose a city to search in'
          }
          onPress={onOpenCityPicker}
          activeScale={0.96}
          style={styles.cityChip}
        >
          <Ionicons name="location-outline" size={15} color={HERO_TEXT} />
          <Text variant="footnote" style={{ color: HERO_TEXT, fontWeight: '600' }} numberOfLines={1}>
            {city ? city.label : 'All cities'}
          </Text>
          <Ionicons name="chevron-down" size={14} color={HERO_TEXT} />
        </PressableScale>

        <PressableScale
          accessibilityRole="button"
          accessibilityLabel={hasUnread ? 'Updates, you have unread items' : 'Updates'}
          hitSlop={gesture.hitSlop}
          onPress={onOpenUpdates}
          activeScale={0.94}
          style={styles.glassCircle}
        >
          <Ionicons name="notifications-outline" size={20} color={HERO_TEXT} />
          {hasUnread ? <View style={[styles.dot, { backgroundColor: theme.colors.brand }]} /> : null}
        </PressableScale>

        <PressableScale
          accessibilityRole="button"
          accessibilityLabel="Your account"
          hitSlop={gesture.hitSlop}
          onPress={onOpenProfile}
          activeScale={0.94}
          style={{ ...styles.glassCircle, backgroundColor: HERO_TEXT, borderWidth: 0 }}
        >
          {name ? (
            <Avatar uri={avatarUri} name={name} size="sm" />
          ) : (
            <Ionicons name="person" size={22} color={HERO_BG} />
          )}
        </PressableScale>
      </View>

      {/* The pinned copy of the hero's field. Same component, same geometry.
          `overflow: 'hidden'` keeps it clipped to zero before the pin, which
          is also what stops the not-yet-pinned copy from taking taps meant for
          the hero underneath. */}
      <Animated.View style={[styles.searchRow, searchRowStyle]}>
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
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    height: HOME_HEADER_ROW,
    paddingHorizontal: screenPadding,
  },
  cityChip: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    height: 40,
    maxWidth: 150,
    paddingHorizontal: spacing.md,
    borderRadius: radius.full,
    backgroundColor: HERO_GLASS,
    borderWidth: 1,
    borderColor: HERO_GLASS_BORDER,
  },
  glassCircle: {
    width: 44,
    height: 44,
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: radius.full,
    backgroundColor: HERO_GLASS,
    borderWidth: 1,
    borderColor: HERO_GLASS_BORDER,
  },
  searchRow: {
    overflow: 'hidden',
    paddingHorizontal: screenPadding,
  },
  dot: {
    position: 'absolute',
    top: 9,
    right: 10,
    width: 8,
    height: 8,
    borderRadius: radius.full,
  },
});
