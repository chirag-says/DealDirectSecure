import Ionicons from '@expo/vector-icons/Ionicons';
import { Image as ExpoImage } from 'expo-image';
import { Image as RNImage, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import type { ListingIntent } from '@/features/properties';
import { radius, spacing, useTheme, type Theme } from '@/theme';
import { PressableScale, Text } from '@/ui';

import { HeroSearchField } from './HeroSearchField';

/**
 * The hero.
 *
 *   header      wordmark, messages, notifications, profile
 *   headline    "Find your / dream home"
 *   artwork     the house cutout, full width
 *   search card white, elevated, OVERLAPPING the artwork
 *     └ search row + Buy/Rent segment + Post Property
 *
 * ---------------------------------------------------------------------------
 * WHY THE ARTWORK IS A FULL-WIDTH BAND AND NOT A RIGHT-HAND PANEL
 *
 * The design this is built from puts a rectangular photograph on the right of
 * the headline, bleeding off the screen edge with its left corners rounded.
 * That composition needs a photo with a background — you crop it and whatever
 * is left still reads as a picture.
 *
 * The supplied artwork is a Photoroom cutout: a house on an oval of lawn, on
 * TRANSPARENCY, 1672x941. It has a silhouette rather than edges. Cropping it
 * into a tall right-hand panel would cut the house in half and leave the lawn
 * hanging in space, and a cutout cannot "bleed off" an edge it does not have.
 *
 * So the artwork is set narrower than the screen and pushed to the right, on
 * white, which is what a background-free cutout is FOR. It sits opposite the
 * headline rather than under it, the search card rides up over its lower edge,
 * and the house is shown whole.
 *
 * `contentFit="contain"` rather than `cover`, for the same reason: the
 * transparent margin around the house is part of the composition, and cropping
 * to fill would clip the roof.
 */

/** 1672x941 as supplied. Declared so the band reserves the right height
 *  before the image decodes and nothing below it jumps on first paint. */
const ARTWORK_RATIO = 1672 / 941;

/**
 * Narrower than the screen and anchored right, which is as close to the
 * reference's right-hand placement as a cutout can honestly get: the artwork
 * sits opposite the headline rather than under the middle of it, and the empty
 * left margin becomes deliberate white space instead of dead centre padding.
 */
const ARTWORK_WIDTH = '95%';

/**
 * Bleeds the artwork past the right gutter so it reads as anchored to the
 * screen edge rather than floating just inside it. Pushed further than the
 * first pass — the cutout's right edge is mostly tree canopy and fence rail,
 * which crops gracefully, unlike the roofline on the left.
 */
const ARTWORK_BLEED = spacing.lg;

/**
 * Closes the transparent margin above the house.
 *
 * The PNG carries roughly a fifth of its height as empty space over the roof.
 * `contain` honours that, so without this the headline and the artwork are
 * separated by a gap nobody chose and which is invisible in the source file.
 */
const ARTWORK_RISE = spacing['4xl'] + spacing.sm;

/** How far the search card rides up over the artwork. */
const CARD_OVERLAP = spacing['4xl'];

export interface HeroProps {
  /** Fires with the committed search term. Empty means "browse everything". */
  onSearch: (term: string) => void;
  onOpenFilters: () => void;
  onIntent: (intent: ListingIntent) => void;
  onPostProperty: () => void;
  onNotifications: () => void;
  onProfile: () => void;
  /** Unread notifications. Only presence is drawn, as a dot. */
  notificationBadge?: string | null;
}

export function Hero({
  onSearch,
  onOpenFilters,
  onIntent,
  onPostProperty,
  onNotifications,
  onProfile,
  notificationBadge,
}: HeroProps) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();

  return (
    <View style={{ paddingTop: insets.top + spacing.sm }}>
      {/* Identity left, the user's own controls right. */}
      <View className="flex-row items-center justify-between px-lg">
        <RNImage
          source={require('../../../../assets/home/brand/logo.png')}
          style={{ width: 118, height: 29 }}
          resizeMode="contain"
          accessibilityLabel="DealDirect"
        />

        <View className="flex-row items-center">
          {/*
            No Messages icon. Chat is built but unmounted product-wide
            (HANDOFF §9.1 D2), matching the website, which mounts no chat UI
            either. The feature code is still on disk; this was its last entry
            point on Home.
          */}
          <HeaderIcon
            icon="notifications-outline"
            label={notificationBadge ? `Notifications, ${notificationBadge} unread` : 'Notifications'}
            onPress={onNotifications}
            dot={!!notificationBadge}
            theme={theme}
          />
          <HeaderIcon
            icon="person-circle-outline"
            label="Profile"
            onPress={onProfile}
            theme={theme}
          />
        </View>
      </View>

      {/*
        `title1` (28pt), not `display` (34pt), and the headline text is why.

        "Buy, Rent & Sell Properties" is 27 characters against roughly 350pt of
        usable width once the screen gutters are taken out. At 34pt it measures
        near 500pt and wraps to two lines, and the accent line wraps to two
        more — a four-line headline that pushes the artwork and the search
        field most of a screen further down, which is the opposite of what this
        hero is for. At 28pt the same copy settles in three lines and the
        search card stays in the first viewport.

        The break before the accent line is explicit rather than left to the
        wrap. Where the colour changes is a meaning boundary — what you can do,
        then who you do it with — and letting the line box decide would put
        "Properties Directly" on one line and split the phrase across colours.
      */}
      <View className="px-lg" style={{ marginTop: spacing.xl }}>
        <Text variant="title1" style={{ color: theme.colors.textPrimary }}>
          Buy, Rent & Sell Properties{'\n'}
          {/*
            Red, not the blue this copy uses on the website.

            Blue is already spoken for on this screen: it is the tint behind
            "Direct Owners" in the trust strip, and it is the app's `accent`
            everywhere outside Home. Putting it in the headline would give the
            first viewport two competing accents, with red on the Post button,
            the active tab, "View all" and every price. One accent per screen.
          */}
          <Text variant="title1" style={{ color: theme.colors.brand }}>
            Directly from Owners
          </Text>
        </Text>

        <Text variant="callout" tone="secondary" className="mt-md">
          No middleman. No commission fees.{'\n'}Deal directly with property owners
        </Text>
      </View>

      <ExpoImage
        source={require('../../../../assets/home/brand/hero-house.png')}
        style={{
          width: ARTWORK_WIDTH,
          aspectRatio: ARTWORK_RATIO,
          alignSelf: 'flex-end',
          marginTop: -ARTWORK_RISE,
          marginRight: -ARTWORK_BLEED,
        }}
        contentFit="contain"
        // Local and already decoded; a fade would flash white on every mount
        // of the tab.
        transition={0}
        // Decorative. The headline above it carries the meaning.
        accessible={false}
      />

      {/*
        The one elevated surface on the screen, and it earns the shadow: it is
        physically in front of the artwork, which is the only place on Home
        where two layers actually overlap.
      */}
      <View
        className="mx-lg"
        style={{
          marginTop: -CARD_OVERLAP,
          padding: spacing.md,
          borderRadius: radius.xl,
          backgroundColor: theme.colors.surface,
          shadowColor: '#000',
          shadowOpacity: 0.08,
          shadowRadius: 20,
          shadowOffset: { width: 0, height: 6 },
          elevation: 6,
        }}
      >
        {/*
          A real field. It was a button dressed as one until 2026-08-13, which
          opened a full-screen modal — see `HeroSearchField` for why that was
          replaced rather than restyled.
        */}
        <HeroSearchField onSubmit={onSearch} onOpenFilters={onOpenFilters} />

        <View className="mt-md flex-row items-center" style={{ gap: spacing.sm }}>
          {/*
            Buy and Rent only.

            The reference design carries a third segment, "PG/Co-living". There
            is nothing behind it: `ListingIntent` is `'rent' | 'sale'`, the
            taxonomy has no PG or co-living member, and no probed search term
            matches one (see `home/catalog.ts`, where every shortcut was tested
            against live data and the ones returning zero were removed). A third
            pill would be a control that always lands on an empty list, which
            teaches the user the app is empty rather than that the shortcut is
            broken. It goes in the day the inventory does.
          */}
          <View
            className="flex-1 flex-row items-center"
            style={{
              borderRadius: radius.full,
              borderWidth: 1,
              borderColor: theme.colors.border,
              padding: spacing.xs,
            }}
          >
            <IntentSegment label="Buy" active onPress={() => onIntent('sale')} theme={theme} />
            <View style={{ width: 1, height: 20, backgroundColor: theme.colors.border }} />
            <IntentSegment label="Rent" onPress={() => onIntent('rent')} theme={theme} />
          </View>

          <PressableScale
            accessibilityLabel="Post a property, free"
            onPress={onPostProperty}
            style={{
              flexDirection: 'row',
              alignItems: 'center',
              gap: spacing.sm,
              height: 48,
              paddingHorizontal: spacing.base,
              borderRadius: radius.full,
              backgroundColor: theme.colors.brand,
            }}
          >
            <Ionicons name="add-circle-outline" size={20} color={theme.colors.textOnAccent} />
            <View>
              <Text variant="subhead" style={{ color: theme.colors.textOnAccent, fontWeight: '600' }}>
                Post Property
              </Text>
              <Text variant="caption" style={{ color: 'rgba(255,255,255,0.85)' }}>
                It&apos;s free
              </Text>
            </View>
          </PressableScale>
        </View>
      </View>
    </View>
  );
}

/**
 * 44x44, enforced by the painted size rather than by hit slop. These sit within
 * a few points of each other and of the screen corner, where a mis-tap sends
 * the user somewhere entirely unrelated to what they wanted.
 *
 * The badge is a DOT, not a count. At this size a two-digit number is unreadable
 * and the exact figure changes nothing about what the user does next — the
 * screen behind it shows the real count. The accessible name still carries it.
 */
function HeaderIcon({
  icon,
  label,
  onPress,
  dot = false,
  theme,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  onPress: () => void;
  dot?: boolean;
  theme: Theme;
}) {
  return (
    <PressableScale
      accessibilityLabel={label}
      onPress={onPress}
      style={{ width: 44, height: 44, alignItems: 'center', justifyContent: 'center' }}
    >
      <Ionicons name={icon} size={24} color={theme.colors.textPrimary} />

      {dot ? (
        <View
          pointerEvents="none"
          style={{
            position: 'absolute',
            top: 9,
            right: 8,
            width: 9,
            height: 9,
            borderRadius: radius.full,
            backgroundColor: theme.colors.brand,
            // Separates the dot from the glyph it sits on rather than letting
            // the two merge into one smudge at a glance.
            borderWidth: 1.5,
            borderColor: theme.colors.surface,
          }}
        />
      ) : null}
    </PressableScale>
  );
}

/**
 * `active` is presentational only.
 *
 * Both segments navigate to the one canonical results screen with
 * `listingType` prefilled — neither filters anything in place, so there is no
 * selection state on Home to track. "Buy" reads as active because it is the
 * default a property search starts from, not because tapping it changed
 * anything here.
 */
function IntentSegment({
  label,
  active = false,
  onPress,
  theme,
}: {
  label: string;
  active?: boolean;
  onPress: () => void;
  theme: Theme;
}) {
  return (
    <PressableScale
      accessibilityLabel={`Browse properties to ${label.toLowerCase()}`}
      onPress={onPress}
      style={{
        flex: 1,
        height: 38,
        alignItems: 'center',
        justifyContent: 'center',
        borderRadius: radius.full,
        backgroundColor: active ? theme.colors.dangerMuted : 'transparent',
      }}
    >
      <Text
        variant="subhead"
        style={{
          color: active ? theme.colors.brand : theme.colors.textSecondary,
          fontWeight: '600',
        }}
      >
        {label}
      </Text>
    </PressableScale>
  );
}
