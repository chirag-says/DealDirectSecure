import { Tabs } from 'expo-router';

import { TabBar } from '@/ui';

/**
 * Tab shell.
 *
 * The bar itself is `ui/TabBar` — a floating pill holding five destinations,
 * no action. See that file for the width budget that keeps them from
 * colliding.
 *
 * ---------------------------------------------------------------------------
 * FIVE DESTINATIONS, NAMED FOR THE QUESTION THEY ANSWER — 2026-08-24
 *
 *   Home      what matters to me, and where a session starts
 *   Search    what can I find
 *   Activity  what have I done
 *   Updates   what changed
 *   Profile   who am I, and how do I manage this account
 *
 * The set before this was Home · Properties · Saved · Profile, which was the
 * website's: a landing page, a listings section, a bucket, an account. It was
 * replaced by Search · Activity · Updates · Profile, which fixed the naming
 * but went one step too far — it folded Home INTO Search, so the first screen
 * was a workspace and nothing in the app answered "what should I do next".
 *
 * Home is back as its own surface, and the two are deliberately different
 * jobs. Home is personal, short and adaptive: a greeting, a way into search,
 * what you have in flight, what changed, what you were looking at. Search is
 * the corpus — field, filters, sort, compare, results — and carries nothing
 * personal at all. If a section is tempted onto Search, it belongs on Home.
 *
 * ---------------------------------------------------------------------------
 * POSTING IS NOT A TAB
 *
 * The dock holds destinations only. Listing a property is reached from Home —
 * the "List property" pill in the hero and the card further down, both of
 * which adapt to whether the viewer is a guest, a buyer, an owner with no
 * listing or an owner with one. An owner account is capped at a single listing
 * server-side, so a permanent button in the bar would be unusable for every
 * buyer and for every owner who already has theirs. Full reasoning in
 * `ui/TabBar.tsx`.
 *
 * Updates is a destination again, and Home's hero also carries a bell for it.
 * Two doors to one place, on the screen where a user looks for it — the same
 * pattern as the hero's avatar and the Profile tab.
 *
 * The owner surface (listings, leads, analytics) is likewise not a tab: it
 * applies only to accounts with the `owner` role, and a permanently disabled
 * tab would be worse than no tab. It is reached from Home and from Profile.
 *
 * ---------------------------------------------------------------------------
 * `properties`, `saved` and the stack's `/notifications` remain on disk as
 * redirects so existing `dealdirect://` links keep resolving, and `chat` stays
 * registered and dark (HANDOFF §9.1 D2). All four are declared `href: null`:
 * Expo Router builds its tree from the filesystem, so a file that exists is a
 * route whether or not it is declared, and declaring it is the only way to
 * keep it out of the bar.
 */
export default function TabsLayout() {
  return (
    <Tabs screenOptions={{ headerShown: false }} tabBar={(props) => <TabBar {...props} />}>
      <Tabs.Screen name="index" options={{ title: 'Home' }} />
      <Tabs.Screen name="search" options={{ title: 'Search' }} />
      <Tabs.Screen name="activity" options={{ title: 'Activity' }} />
      <Tabs.Screen name="updates" options={{ title: 'Updates' }} />
      <Tabs.Screen name="profile" options={{ title: 'Profile' }} />

      {/* Redirect-only and dark routes. Registered so they stay out of the
          bar; see the module doc. */}
      <Tabs.Screen name="properties" options={{ href: null }} />
      <Tabs.Screen name="saved" options={{ href: null }} />
      <Tabs.Screen name="chat" options={{ href: null }} />
    </Tabs>
  );
}
