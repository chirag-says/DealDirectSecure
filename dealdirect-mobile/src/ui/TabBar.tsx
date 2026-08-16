import Ionicons from '@expo/vector-icons/Ionicons';
import type { BottomTabBarProps } from '@react-navigation/bottom-tabs';
import { View } from 'react-native';
import Animated, { LinearTransition, useReducedMotion } from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { radius, spacing, useTheme } from '@/theme';
import { PressableScale } from './PressableScale';
import { Text } from './Text';

/**
 * The bottom dock.
 *
 * ---------------------------------------------------------------------------
 * A FLOATING PILL, NOT AN EDGE-TO-EDGE BAR — rebuilt 2026-08-14
 *
 * The previous bar spanned the full width, sat on a hairline border, and drew
 * four icons with four labels and a 2pt rule under the active one. Everything
 * about it was legible and none of it was memorable: it read as chrome the app
 * was obliged to have rather than as part of the product.
 *
 * This detaches from the screen edges and floats. Two things follow from that
 * and both are the point: the content scrolls visibly beneath it, so the app
 * feels layered rather than boxed; and the dock becomes an object with a
 * shape, which is what lets it carry a shadow and read as premium rather than
 * as a divider with icons on it.
 *
 * ---------------------------------------------------------------------------
 * THE ACTIVE TAB EXPANDS; THE OTHERS ARE ICON-ONLY
 *
 * Four labels shown permanently is four pieces of text competing at 11pt, and
 * on a 360pt screen "Properties" either truncates or forces every other label
 * to shrink with it. Showing the label only for the tab you are ON solves the
 * width problem and produces the strongest possible active state — the
 * selected tab is a different SHAPE, not just a different colour, which
 * survives both low contrast and colour blindness.
 *
 * The trade is real and worth naming: an inactive tab is an icon with no
 * caption. That is acceptable here and nowhere near universally — the four
 * glyphs are home, magnifier, heart and person, which are the four most
 * conventional icons in mobile software. It would NOT be acceptable for a
 * domain-specific icon, and a fifth destination should bring its label back
 * rather than push this pattern further.
 *
 * Every tab keeps its `accessibilityLabel` regardless, so a screen reader
 * always announces the destination whether or not it is painted.
 *
 * ---------------------------------------------------------------------------
 * POST IS AN ACTION IN A NAVIGATION BAR, DELIBERATELY
 *
 * The standing guidance is that a tab bar holds destinations only. This holds
 * one action, because posting a property is the single thing an owner opens
 * this app to do and burying it inside Profile would cost more than the rule
 * is worth. It is marked as an action rather than a destination by being the
 * only filled, circular, brand-coloured element here, and it never takes the
 * selected state.
 *
 * ---------------------------------------------------------------------------
 * THE ACTION IS RED; THE SELECTED TAB IS NOT — changed 2026-08-15
 *
 * That claim above — "the only brand-coloured element here" — stopped being
 * true when the selected tab was given a `brandMuted` pill and brand-red icon
 * and label. The dock then held two red objects side by side, one a
 * destination and one an action, and the reported symptom was that the post
 * button "competes with the navigation". It was not the button. It was that
 * nothing distinguished it.
 *
 * `colors.ts` already says which is which: brand is "the brand mark colour.
 * Not an action colour", accent is "the primary action colour". The selected
 * tab now takes the accent, and red means exactly one thing in this bar.
 *
 * The separator before the action is the second half. Four destinations, a
 * hairline, one action — the grouping is stated rather than inferred from the
 * fact that the last item happens to look different.
 */

/** Drawn in this order. A registered route absent from this map is skipped. */
const TABS: Record<string, { label: string; icon: keyof typeof Ionicons.glyphMap }> = {
  index: { label: 'Home', icon: 'home' },
  properties: { label: 'Properties', icon: 'search' },
  saved: { label: 'Saved', icon: 'heart' },
  profile: { label: 'Profile', icon: 'person' },
};

const DOCK_HEIGHT = 58;
const ITEM_HEIGHT = 42;

export interface TabBarProps extends BottomTabBarProps {
  onPost: () => void;
}

export function TabBar({ state, navigation, onPost }: TabBarProps) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();
  const reduceMotion = useReducedMotion();

  const visible = state.routes.filter((route) => TABS[route.name]);

  return (
    <View
      pointerEvents="box-none"
      style={{
        paddingHorizontal: spacing.base,
        // Clears the home indicator when there is one, and still floats off
        // the bottom edge on a device without one.
        paddingBottom: insets.bottom > 0 ? insets.bottom : spacing.base,
      }}
    >
      <View
        style={{
          flexDirection: 'row',
          alignItems: 'center',
          height: DOCK_HEIGHT,
          paddingHorizontal: spacing.xs,
          borderRadius: radius.full,
          backgroundColor: theme.colors.surface,
          // A hairline as well as a shadow. On a light page the shadow alone
          // is nearly invisible at the top edge of the pill, and the outline
          // is what keeps the shape crisp there.
          borderWidth: 1,
          borderColor: theme.colors.border,
          shadowColor: '#000',
          shadowOpacity: 0.14,
          shadowRadius: 20,
          shadowOffset: { width: 0, height: 8 },
          elevation: 12,
        }}
      >
        {visible.map((route) => {
          const spec = TABS[route.name];
          if (!spec) return null;

          const focused = state.routes[state.index]?.key === route.key;

          return (
            <Animated.View
              key={route.key}
              // The width change is the animation. `LinearTransition` measures
              // it rather than requiring a hard-coded expanded width, which
              // would be wrong the moment a label is translated.
              layout={reduceMotion ? undefined : LinearTransition.springify().damping(20)}
              style={focused ? { flex: 1 } : undefined}
            >
              <PressableScale
                accessibilityRole="button"
                accessibilityLabel={spec.label}
                accessibilityState={{ selected: focused }}
                activeScale={0.94}
                onPress={() => {
                  // `navigate`, not a raw dispatch: tapping the active tab pops
                  // its stack to the root rather than pushing a duplicate.
                  if (!focused) navigation.navigate(route.name);
                }}
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  justifyContent: 'center',
                  height: ITEM_HEIGHT,
                  paddingHorizontal: focused ? spacing.base : spacing.md,
                  borderRadius: radius.full,
                  backgroundColor: focused ? theme.colors.accentMuted : 'transparent',
                }}
              >
                <Ionicons
                  name={focused ? spec.icon : (`${spec.icon}-outline` as keyof typeof Ionicons.glyphMap)}
                  size={21}
                  color={focused ? theme.colors.accent : theme.colors.textSecondary}
                />

                {focused ? (
                  <Text
                    variant="footnote"
                    numberOfLines={1}
                    style={{
                      marginLeft: spacing.sm,
                      color: theme.colors.accent,
                      fontWeight: '600',
                    }}
                  >
                    {spec.label}
                  </Text>
                ) : null}
              </PressableScale>
            </Animated.View>
          );
        })}

        {/* Destinations end here. */}
        <View
          style={{
            width: 1,
            alignSelf: 'stretch',
            marginLeft: spacing.xs,
            marginVertical: spacing.md,
            backgroundColor: theme.colors.border,
          }}
        />

        {/* The one action. Circular, filled, and now the only red thing in the
            dock — see the module doc. */}
        <PressableScale
          accessibilityRole="button"
          accessibilityLabel="Post a property"
          onPress={onPost}
          activeScale={0.9}
          style={{
            width: ITEM_HEIGHT,
            height: ITEM_HEIGHT,
            marginLeft: spacing.xs,
            borderRadius: radius.full,
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: theme.colors.brand,
            // Raised off the dock rather than sitting flush in it. A filled
            // disc with no depth on a white pill reads as a swatch; a small
            // shadow is what makes it read as a button on top of a surface.
            shadowColor: theme.colors.brand,
            shadowOpacity: 0.35,
            shadowRadius: 8,
            shadowOffset: { width: 0, height: 3 },
            elevation: 4,
          }}
        >
          <Ionicons name="add" size={24} color={theme.colors.textOnAccent} />
        </PressableScale>
      </View>
    </View>
  );
}
