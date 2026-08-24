import Ionicons from '@expo/vector-icons/Ionicons';
import { ScrollView, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import type { ListingIntent } from '@/features/properties';
import { gesture, radius, screenPadding, spacing, touchTarget, useTheme, withAlpha } from '@/theme';
import { Avatar, PressableScale, Text } from '@/ui';
import type { City } from '../cities';

/**
 * The hero: a brand-coloured block carrying everything a session starts with.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT IS FOR
 *
 * Five controls, in the order the question gets asked: who am I signed in as,
 * where am I looking, what am I looking for, and the field to say it in. The
 * "List property" pill is the fifth, and it is here rather than in the tab bar
 * because it belongs to the small share of sessions that are selling.
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
 * THE BELL, NOT A TAB
 *
 * Notifications live here rather than in the dock, which is what the portals
 * this is modelled on do and what freed the dock's fifth slot for the Post
 * action. The dot is drawn from rows the app already holds; there is no
 * server-side unread count, so there is no number on it. See `updates.tsx`.
 */

export interface HomeHeroProps {
  /** Signed-in user's name, for the avatar. Absent for a guest. */
  name?: string;
  avatarUri?: string;
  city: City | null;
  /** True when at least one notification in the loaded set is unread. */
  hasUnread: boolean;
  onOpenProfile: () => void;
  onOpenUpdates: () => void;
  onOpenCityPicker: () => void;
  onSearch: () => void;
  onIntent: (intent: ListingIntent | 'projects') => void;
  onListProperty: () => void;
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
  name,
  avatarUri,
  city,
  hasUnread,
  onOpenProfile,
  onOpenUpdates,
  onOpenCityPicker,
  onSearch,
  onIntent,
  onListProperty,
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
        paddingHorizontal: screenPadding,
        /*
          The hero owns its safe area, because the screen no longer does.

          `Screen` used to inset the top, but the sticky header has to be able
          to sit UNDER the status bar — an inset screen would leave a strip of
          page colour above a bar whose entire job is to be the top of the
          screen. So the inset moved here, to the block that is actually at the
          top when nothing is scrolled.
        */
        paddingTop: insets.top + spacing.sm,
        paddingBottom: spacing.lg,
        // Rounded only at the bottom: the block runs under the status bar and
        // ends in a curve, so the content below reads as sliding out from
        // beneath it rather than butting against a coloured rectangle.
        borderBottomLeftRadius: radius.xl,
        borderBottomRightRadius: radius.xl,
      }}
    >
      {/* Row one: identity, the selling action, notifications. */}
      <View className="flex-row items-center" style={{ gap: spacing.sm }}>
        <PressableScale
          accessibilityRole="button"
          accessibilityLabel="Your account"
          hitSlop={gesture.hitSlop}
          onPress={onOpenProfile}
          activeScale={0.94}
        >
          {name ? (
            <Avatar uri={avatarUri} name={name} size="sm" />
          ) : (
            <Ionicons name="person-circle-outline" size={30} color={onBrand} />
          )}
        </PressableScale>

        <View className="flex-1" />

        <PressableScale
          accessibilityRole="button"
          accessibilityLabel="List your property"
          onPress={onListProperty}
          activeScale={0.96}
          style={{
            flexDirection: 'row',
            alignItems: 'center',
            gap: 6,
            height: 36,
            paddingHorizontal: spacing.base,
            borderRadius: radius.full,
            // The page surface on the brand fill, so the pill reads as a raised
            // object rather than a tint of the panel. Inverts with the theme
            // like everything else; a hardcoded dark would be wrong in one mode
            // and unreadable in the other.
            backgroundColor: theme.colors.surface,
          }}
        >
          <Ionicons name="add" size={16} color={theme.colors.brand} />
          <Text variant="footnote" style={{ color: theme.colors.brand, fontWeight: '700' }}>
            List property
          </Text>
        </PressableScale>

        <PressableScale
          accessibilityRole="button"
          accessibilityLabel={hasUnread ? 'Updates, you have unread items' : 'Updates'}
          hitSlop={gesture.hitSlop}
          onPress={onOpenUpdates}
          activeScale={0.94}
          style={{
            width: 36,
            height: 36,
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: radius.full,
            borderWidth: 1,
            borderColor: withAlpha(theme.colors.textOnAccent, 0.35),
          }}
        >
          <Ionicons name="notifications-outline" size={18} color={onBrand} />
          {hasUnread ? (
            <View
              style={{
                position: 'absolute',
                top: 7,
                right: 8,
                width: 8,
                height: 8,
                borderRadius: radius.full,
                backgroundColor: theme.colors.textOnAccent,
              }}
            />
          ) : null}
        </PressableScale>
      </View>

      <Text variant="title2" className="mt-lg" style={{ color: onBrand }}>
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
