import { Tabs, useRouter } from 'expo-router';

import { useAuth } from '@/auth';
import { TabBar } from '@/ui';

/**
 * Tab shell.
 *
 * The bar itself is `ui/TabBar` — an edge-to-edge bar with four destinations
 * either side of a raised action. See that file for why nothing in it animates
 * its width any more.
 *
 * ---------------------------------------------------------------------------
 * FOUR DESTINATIONS, NAMED FOR THE QUESTION THEY ANSWER — 2026-08-24
 *
 *   Home      what matters to me, and where a session starts
 *   Search    what can I find
 *   Activity  what have I done
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
 * FOUR DESTINATIONS AND ONE ACTION
 *
 * Listing a property is the raised button in the middle of the bar, not a
 * destination — it never takes the selected state. Guests go to login; the
 * form itself handles the buyer-to-owner upgrade prompt, which is a role
 * decision rather than a session one. Home carries the same action as a card
 * that adapts to who is looking, so it is offered twice on purpose: once where
 * a seller looks for it, once where a seller is told what it involves.
 *
 * Notifications are NOT a destination either. They are the bell in Home's
 * hero, which is where the portals this is modelled on put them.
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
  const router = useRouter();
  const { status } = useAuth();

  /**
   * The centre action. Guests go to login rather than into a multi-step form
   * they would hit a wall inside; the form itself handles the buyer-to-owner
   * upgrade, which is a role decision rather than a session one.
   */
  const handleAction = () => {
    if (status !== 'authenticated') {
      router.push('/(auth)/login');
      return;
    }
    router.push('/owner/property/new');
  };

  return (
    <Tabs
      screenOptions={{ headerShown: false }}
      tabBar={(props) => <TabBar {...props} onAction={handleAction} />}
    >
      <Tabs.Screen name="index" options={{ title: 'Home' }} />
      <Tabs.Screen name="search" options={{ title: 'Search' }} />
      <Tabs.Screen name="activity" options={{ title: 'Activity' }} />
      <Tabs.Screen name="profile" options={{ title: 'Profile' }} />

      {/* Reached from Home's bell rather than the bar; still a real route. */}
      <Tabs.Screen name="updates" options={{ href: null }} />

      {/* Redirect-only and dark routes. Registered so they stay out of the
          bar; see the module doc. */}
      <Tabs.Screen name="properties" options={{ href: null }} />
      <Tabs.Screen name="saved" options={{ href: null }} />
      <Tabs.Screen name="chat" options={{ href: null }} />
    </Tabs>
  );
}
