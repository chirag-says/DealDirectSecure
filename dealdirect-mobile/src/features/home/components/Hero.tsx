import Ionicons from '@expo/vector-icons/Ionicons';
import { Image as ExpoImage } from 'expo-image';
import { Image as RNImage, StyleSheet, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import type { ListingIntent } from '@/features/properties';
import { palette, radius, spacing } from '@/theme';
import { Gradient, PressableScale, Text } from '@/ui';

/**
 * The hero.
 *
 * Ported from the production app's `HomeScreen.js` and rebuilt. The shape is
 * the same on purpose — dark slab, logo, headline, search, intent row — because
 * that shape is already familiar to existing users and it works. What changed
 * is everything underneath it.
 *
 * ---------------------------------------------------------------------------
 * WHAT CHANGED FROM THE ORIGINAL, AND WHY
 *
 * **The stats strip is gone.** It read "₹50Cr+ Brokerage Saved", "10k+ Happy
 * Families", "12+ Cities" against a live corpus of 36 listings. A number that
 * the product disproves two taps later is worse than no number, and this one
 * sat directly above a rail showing the real inventory. It comes back the day
 * there is a real figure to put in it.
 *
 * **Buy and Rent are navigation, not tabs.** In the original they were a
 * segmented control that filtered a list further down the same screen. That
 * makes Home a second browsing surface, competing with the screen built for
 * browsing, and the two drift: one gets the new filter sheet, the other keeps
 * the old sort. Here each one pushes to the canonical results screen with
 * `listingType` preselected. Same two taps to the same place, one
 * implementation.
 *
 * **The colours are literal, and that is deliberate.** A hero is brand chrome:
 * it is the same dark slab in light and dark mode, the same way a scrim over a
 * photograph is. Routing it through the semantic scheme would produce a hero
 * that inverts to near-white in light mode, and white text on it would vanish.
 * These are the only literal colours in the component.
 */

/**
 * The scrim laid over the photograph.
 *
 * The first version ran 0.72 / 0.46 / 0.90 and buried the image. That is the
 * standard mistake with a scrim: it is tuned until the text is comfortable,
 * and by then the photograph is a dark rectangle with a building faintly
 * visible in it. If the picture is not worth seeing there is no reason to load
 * it, and a flat dark slab would be cheaper and sharper.
 *
 * So the scrim now does the minimum: enough to stop white text dissolving into
 * a bright patch, and no more. The heavy lifting for legibility moved to
 * `TEXT_SHADOW` below, which darkens only the few pixels immediately behind
 * each glyph instead of the entire image.
 *
 * The shape still matters. Darkest at the very bottom, where the search field
 * and the action row sit and where a photograph is usually busiest; lightest
 * around 38% height, which is the gap between the headline and the subtitle,
 * so the image reads most clearly exactly where nothing covers it.
 */
/**
 * A colour-graded scrim, not a neutral one.
 *
 * Every previous version used `rgba(10,10,10,x)` — flat black at varying
 * opacity. Flat black is the safe choice and it is also why the hero looked
 * washed out: black over a colour does not darken it, it DESATURATES it. Put
 * 50% neutral black over a blue sky and you get grey, because you have pulled
 * every channel toward zero equally and thrown the hue away with the
 * brightness. The photograph ends up dimmer AND duller, and only one of those
 * was wanted.
 *
 * Tinting the scrim instead keeps the light down while pushing the hue up. Deep
 * navy over a blue sky deepens the blue rather than cancelling it. The four
 * stops run navy into indigo into violet into a near-black plum, which is a
 * dusk grade: the same trick film uses to make a daylight plate read as
 * evening without losing colour.
 *
 * Four stops rather than three because a long vertical fade across three shows
 * visible banding on an OLED panel, and the extra stop breaks the ramp up.
 *
 * The bottom is the darkest and the most saturated. That is where the search
 * field and the action row sit, and where the photograph is busiest.
 */
const HERO_SCRIM = [
  'rgba(9,18,48,0.78)',
  'rgba(13,32,74,0.34)',
  'rgba(26,16,48,0.62)',
  'rgba(12,8,22,0.90)',
] as const;
const HERO_SCRIM_STOPS = [0, 0.34, 0.72, 1] as const;

/*
 * TUNED FOR A BRIGHT PHOTOGRAPH, and that is a real coupling worth naming.
 *
 * These numbers are not a house style; they are a response to the specific
 * artwork in `assets/home/brand/hero-bg.jpg`. The current image is a sunlit
 * villa under an open blue sky, and white text needs roughly 50% black over
 * something that bright before it stops floating. The upper half is almost
 * entirely sky, which is the worst case on the screen and the reason the top
 * stop is as heavy as it is.
 *
 * An earlier image was a dusk skyline, already dark, and it looked buried under
 * these values — 0.40 / 0.12 / 0.64 was right for it.
 *
 * So: swapping the hero image means re-checking this. Darker photo, lower
 * numbers. There is no single setting that flatters both, which is the honest
 * argument for the photo-band layout instead, where the text never sits on the
 * image at all and the artwork can be anything.
 */

/**
 * Per-glyph legibility, so the scrim does not have to provide it.
 *
 * A soft shadow tight to the letterforms buys roughly as much contrast as
 * another 25% of flat black over the whole surface, while costing the image
 * nothing: it only darkens what the text already covers. This is what makes a
 * light scrim safe on an image nobody art-directed, including a bright sky
 * directly behind the headline.
 *
 * Offset stays at 1px. Anything more reads as a drop shadow, which is a 2003
 * effect; at 1px with a 6px blur it is invisible as a treatment and simply
 * makes the text look solid.
 */
const TEXT_SHADOW = {
  textShadowColor: 'rgba(0,0,0,0.6)',
  textShadowOffset: { width: 0, height: 1 },
  textShadowRadius: 6,
} as const;

/**
 * Ink for text sitting on the scrim.
 *
 * The secondary tone is a cool tint rather than `neutral300`. Grey text on a
 * navy field reads as dirty — the eye compares it against the surrounding hue
 * and sees the missing blue as a stain. Carrying a little of the background's
 * colour into the type is what makes the two look like one surface instead of
 * text pasted onto a picture.
 *
 * Primary stays pure white. It is the headline; it should be the brightest
 * thing on the screen and it is the one element that must not pick up a cast.
 */
const ON_HERO = palette.neutral0;
const ON_HERO_MUTED = '#C3D0EA';

/**
 * The accent word in the headline.
 *
 * `red500` rather than the brand `red600`, and the reason is the background it
 * now sits on. Against a deep navy-to-violet grade, `red600` is close enough in
 * value to the scrim that it reads as muddy brown; `red500` is lighter and more
 * saturated, so it separates cleanly and stays unmistakably the brand red. The
 * mark elsewhere in the app is unchanged — this is one word on one photograph.
 */
const HERO_ACCENT = palette.red500;

export interface HeroProps {
  onSearch: () => void;
  onIntent: (intent: ListingIntent) => void;
  onPostProperty: () => void;
  onNotifications: () => void;
  onProfile: () => void;
}

export function Hero({
  onSearch,
  onIntent,
  onPostProperty,
  onNotifications,
  onProfile,
}: HeroProps) {
  const insets = useSafeAreaInsets();

  return (
    <View
      style={{
        // The status bar sits ON the hero rather than above it, so it reads as
        // full-bleed. Padding comes from the measured inset, not a guessed
        // constant, because notch heights vary by 20pt across devices and a
        // fixed value clips the logo on some and floats it on others.
        paddingTop: insets.top + spacing.base,
        /*
          Height is a deliberate trade, made in favour of presence.
          `cover` fills the height and discards the sides, so a taller hero
          zooms further into the panorama and shows less of it. The spacing
          here was previously squeezed to claw that back, which won a few
          percent of image and left the content looking cramped against the
          edges — a poor bargain, since nobody reads a hero for its
          photographic completeness.
          So it is generous again. The room goes to the headline, which is the
          thing anyone actually looks at.
        */
        paddingBottom: spacing['2xl'],
        borderBottomLeftRadius: radius['2xl'],
        borderBottomRightRadius: radius['2xl'],
        // Required: the photograph and the scrim are absolutely positioned
        // children, and without this they paint past the rounded corners as
        // square ones.
        overflow: 'hidden',
        // Sits under the photograph. If the image fails to decode the hero is
        // still dark and the text still readable — and it matches the scrim's
        // navy rather than a neutral grey, so the failure state looks like a
        // design choice instead of a missing asset.
        backgroundColor: '#0B1533',
      }}
    >
      {/*
        `expo-image` rather than RN's `Image`, for `contentPosition` alone.
        React Native's `Image` has no equivalent: `resizeMode="cover"` always
        crops from the centre outward, with no way to say which part of the
        photograph matters.

        The hero is roughly 390x430pt (portrait) and the artwork is 1200x628
        (landscape), so `cover` has to scale until the HEIGHT fills and then
        discard the sides. Anchoring to the top keeps the sky and the skyline —
        which is what the picture is of, and the calm area the headline sits on
        — and throws away the dense foreground rooftops at the bottom, which
        are the busiest part of the frame and the worst thing to put behind
        text.
      */}
      <ExpoImage
        source={require('../../../../assets/home/brand/hero-bg.jpg')}
        style={StyleSheet.absoluteFillObject}
        contentFit="cover"
        /*
          The artwork is the website's own hero (`client-next/src/assets/
          herokaback.png`), so both clients open on the same picture.

          It is a 2752x1085 panorama — ratio 2.54 against a hero of roughly
          1.01 — which is the most extreme mismatch of anything tried here.
          `cover` fills the height and discards the sides, leaving about 40% of
          the frame visible. Centred, that 40% lands on the modern villa in the
          middle of the composition, which is the subject. The Burj Khalifa at
          the far left and the second villa at the far right are both outside
          the crop.

          Worth knowing rather than rediscovering: a panorama this wide can
          only be shown properly in a short, wide band. At full height the
          layout is choosing one third of the photograph for you.
        */
        contentPosition="center"
        // A local asset is already decoded; a fade would show the background
        // colour flashing through on every mount of the tab.
        transition={0}
        // Decorative. The headline over it carries the meaning, and announcing
        // "photo of a city" before it would just delay that.
        accessible={false}
      />

      <Gradient
        colors={HERO_SCRIM}
        locations={HERO_SCRIM_STOPS}
        pointerEvents="none"
        style={StyleSheet.absoluteFillObject}
      />

      <View className="px-base">
        {/* Row 1: identity left, the user's own controls right. */}
        <View className="flex-row items-center justify-between">
          <RNImage
            source={require('../../../../assets/home/brand/logo.png')}
            style={{ width: 132, height: 34 }}
            resizeMode="contain"
            accessibilityLabel="DealDirect"
          />

          <View className="flex-row items-center gap-sm">
            <HeroIconButton
              icon="notifications-outline"
              label="Notifications"
              onPress={onNotifications}
            />
            <HeroIconButton icon="person-circle-outline" label="Profile" onPress={onProfile} />
          </View>
        </View>

        {/*
          The greeting is the one genuinely personal line on the screen, so it
          leads. Signed out it degrades to the time of day alone rather than to
          "Hello, Guest", which is worse than saying nothing.
        */}
        {/*
          The headline now carries the top of the hero on its own. It takes the
          gap the greeting used to occupy rather than sitting where the greeting
          left it, so the space above it still reads as deliberate rather than
          as something having been deleted.
        */}
        <Text variant="display" style={{ color: ON_HERO, ...TEXT_SHADOW }} className="mt-3xl">
          Find Your{'\n'}
          {/* Red is the one colour here that can genuinely fail against a
              photograph, so it carries the same shadow as everything else and
              is doing more work on this line than any other. */}
          <Text variant="display" style={{ color: HERO_ACCENT, ...TEXT_SHADOW }}>
            Dream Home
          </Text>
        </Text>

        <Text variant="callout" style={{ color: ON_HERO_MUTED, ...TEXT_SHADOW }} className="mt-md">
          Connect directly with property owners. Zero brokerage.
        </Text>

        {/*
          A button that LOOKS like a text field, not a text field.

          Tapping it opens the search screen, where the real input lives with
          its suggestions, its recent searches and its filters. An actual
          `TextInput` here would raise the keyboard over the hero, offer no
          suggestions, and then navigate away on submit — the user types into
          one context and lands in another. This is the pattern every mature
          search app converged on for the same reason.
        */}
        <PressableScale
          accessibilityLabel="Search properties"
          accessibilityHint="Opens search"
          onPress={onSearch}
          activeScale={0.985}
          style={{
            marginTop: spacing.xl,
            flexDirection: 'row',
            alignItems: 'center',
            gap: spacing.md,
            height: 54,
            paddingHorizontal: spacing.base,
            borderRadius: radius.lg,
            /*
              Dark and NAVY-TINTED, not neutral black and not translucent
              white. White washes out wherever the photograph is bright, which
              on a property shot is the sky. Neutral black works but punches a
              grey hole in a colour-graded surface. Tinting the fill toward the
              scrim's own navy keeps the field reading as part of the hero.

              The border carries the same tint in reverse — a cool near-white
              rather than pure white — for the same reason the secondary text
              does.
            */
            backgroundColor: 'rgba(6,12,32,0.46)',
            borderWidth: 1,
            borderColor: 'rgba(190,210,255,0.26)',
          }}
        >
          <Ionicons name="search" size={20} color={ON_HERO_MUTED} />
          <Text variant="callout" style={{ color: ON_HERO_MUTED }} className="flex-1">
            Search by location, property…
          </Text>
          <View
            className="items-center justify-center"
            style={{
              width: 34,
              height: 34,
              borderRadius: radius.md,
              backgroundColor: palette.red600,
            }}
          >
            <Ionicons name="arrow-forward" size={18} color={ON_HERO} />
          </View>
        </PressableScale>

        {/* Row 3: the fork every property search starts from, plus supply. */}
        <View className="mt-md flex-row gap-sm">
          <HeroAction icon="home-outline" label="Buy" onPress={() => onIntent('sale')} primary />
          <HeroAction icon="key-outline" label="Rent" onPress={() => onIntent('rent')} primary />
          <HeroAction icon="add-circle-outline" label="Post Free" onPress={onPostProperty} />
        </View>
      </View>
    </View>
  );
}

/**
 * 44x44 minimum, enforced by the painted size rather than by hit slop.
 *
 * These sit within a few points of the screen corner, where a mis-tap on the
 * bell instead of the avatar is easy and both destinations are wrong for the
 * other's intent.
 */
function HeroIconButton({
  icon,
  label,
  onPress,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  onPress: () => void;
}) {
  return (
    <PressableScale
      accessibilityLabel={label}
      onPress={onPress}
      style={{ width: 44, height: 44, alignItems: 'center', justifyContent: 'center' }}
    >
      <Ionicons name={icon} size={26} color={ON_HERO} />
    </PressableScale>
  );
}

/**
 * `primary` marks the two intent actions so "Post Free" reads as the third,
 * different thing that it is: the other two consume inventory, this one adds
 * it. Distinguished by fill weight rather than by colour alone.
 */
function HeroAction({
  icon,
  label,
  onPress,
  primary = false,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  onPress: () => void;
  primary?: boolean;
}) {
  return (
    <PressableScale
      accessibilityLabel={label}
      onPress={onPress}
      style={{
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: spacing.xs + 2,
        height: 46,
        borderRadius: radius.md,
        // Same navy-tinted treatment as the search field. `primary` still reads
        // as the heavier pair through fill weight and border strength, not
        // through a second colour.
        backgroundColor: primary ? 'rgba(6,12,32,0.48)' : 'rgba(6,12,32,0.28)',
        borderWidth: 1,
        borderColor: primary ? 'rgba(190,210,255,0.30)' : 'rgba(190,210,255,0.15)',
      }}
    >
      <Ionicons name={icon} size={18} color={primary ? ON_HERO : ON_HERO_MUTED} />
      <Text variant="subhead" style={{ color: primary ? ON_HERO : ON_HERO_MUTED, fontWeight: '600' }}>
        {label}
      </Text>
    </PressableScale>
  );
}
