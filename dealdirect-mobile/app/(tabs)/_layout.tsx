import { Tabs, useRouter } from 'expo-router';

import { useAuth } from '@/auth';
import { TabBar } from '@/ui';

/**
 * Tab shell.
 *
 * The bar itself is `ui/TabBar` — four destinations either side of a raised
 * Post action. See that file for why posting is not a tab.
 *
 * `chat` stays REGISTERED here, with `href: null`, even though messaging is
 * unmounted product-wide (HANDOFF §9.1 D2). Expo Router builds its route tree
 * from the filesystem, so `app/(tabs)/chat.tsx` existing means the route
 * exists whether or not it is declared; declaring it with `href: null` is what
 * keeps it out of the bar. Deleting the declaration would put Messages back in
 * the tab bar, which is the opposite of what is wanted.
 *
 * Nothing in the app navigates to it. The screen and the whole chat feature
 * remain on disk, dormant, matching how the website carries its own unmounted
 * chat implementation.
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
      <Tabs.Screen name="index" options={{ title: 'Home' }} />
      <Tabs.Screen name="properties" options={{ title: 'Properties' }} />
      <Tabs.Screen name="saved" options={{ title: 'Saved' }} />
      <Tabs.Screen name="profile" options={{ title: 'Profile' }} />
      <Tabs.Screen name="chat" options={{ href: null }} />
    </Tabs>
  );
}
