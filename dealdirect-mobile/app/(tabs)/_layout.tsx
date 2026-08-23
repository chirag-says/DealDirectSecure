import { Tabs, useRouter } from 'expo-router';

import { useAuth } from '@/auth';
import { TabBar } from '@/ui';

/**
 * Tab shell.
 *
 * The bar itself is `ui/TabBar` — four destinations either side of a raised
 * Post action. See that file for why posting is not a tab.
 *
 * ---------------------------------------------------------------------------
 * FOUR DESTINATIONS, NAMED FOR WHAT THE USER IS DOING — 2026-08-24
 *
 * Search · Activity · Updates · Profile.
 *
 * The set they replace was Home · Properties · Saved · Profile, and the
 * difference is not cosmetic. That set was the website's: a landing page, a
 * listings section, a bucket, an account. This one is the four states of
 * hunting for or managing a property — look for something, track what you are
 * already dealing with, see what changed, manage yourself.
 *
 * What moved:
 *
 *   Home + Properties   ──►  Search    one tab. Discovery was a page that
 *                                      routed to the search engine; now the
 *                                      search engine IS the tab and discovery
 *                                      is what it shows before you have asked
 *                                      it anything.
 *   Saved               ──►  Activity  widened past its one list.
 *   notifications       ──►  Updates   promoted out of a bell inside a hero.
 *
 * `saved`, `properties` and the stack's `/notifications` remain as redirects
 * so existing `dealdirect://` links keep resolving. They are registered here
 * with `href: null` for the same reason `chat` is: Expo Router builds its tree
 * from the filesystem, so a file that exists is a route whether or not it is
 * declared, and declaring it is the only way to keep it out of the bar.
 *
 * `chat` stays registered and dark (HANDOFF §9.1 D2). The screen and the whole
 * chat feature remain on disk, dormant, matching how the website carries its
 * own unmounted chat implementation.
 *
 * The owner surface (listings, leads) is NOT a tab. It is reached from
 * Profile, because it applies only to accounts with the `owner` role and a
 * permanently disabled tab would be worse than no tab.
 */
export default function TabsLayout() {
  const router = useRouter();
  const { status } = useAuth();

  /**
   * The Post action used to push straight to the owner form for anyone,
   * including guests, who would then hit a wall inside a multi-step form.
   * Guests go to login; the form itself handles the buyer-to-owner upgrade
   * prompt, which is a role decision rather than a session one.
   */
  const handlePost = () => {
    if (status !== 'authenticated') {
      router.push('/(auth)/login');
      return;
    }
    router.push('/owner/property/new');
  };

  return (
    <Tabs
      screenOptions={{ headerShown: false }}
      tabBar={(props) => <TabBar {...props} onPost={handlePost} />}
    >
      <Tabs.Screen name="index" options={{ title: 'Search' }} />
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
