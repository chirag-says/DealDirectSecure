import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { Alert, ScrollView, View } from 'react-native';

import { useAuth, SignInPrompt } from '@/auth';
import { useWallet } from '@/features/rewards';
import {
  screenPadding,
  spacing,
  tabBarClearance,
  useTheme,
  useThemePreference,
  type ThemePreference,
} from '@/theme';
import {
  Avatar,
  Badge,
  Button,
  Card,
  ListGroup,
  ListRow,
  Refreshable,
  Screen,
  ScreenHeader,
  Segmented,
  Skeleton,
  Text,
} from '@/ui';

/**
 * Profile tab.
 *
 * The account hub: identity, the rewards summary, the owner surface (either
 * an entry point if already an owner, or the upgrade CTA if not), and settings.
 *
 * ---------------------------------------------------------------------------
 * THE SIGNED-OUT STATE IS NOT A WALL — changed 2026-08-14
 *
 * It used to be a full-height sign-in prompt and nothing else, on the grounds
 * that "nothing here has a public reading". That was wrong, and checkably so:
 * builder projects, both calculators and the help page all work signed out.
 *
 * So a guest gets the prompt at the top and then the half of the screen that
 * works for them, rather than a dead end covering destinations that were
 * available the whole time. `PublicSections` is the shared half; both branches
 * render the same component, so a route added there cannot appear for one kind
 * of user and not the other.
 *
 * ---------------------------------------------------------------------------
 * IT IS NO LONGER THE APP'S INDEX — 2026-08-24
 *
 * Profile used to carry a link to every destination in the product, because it
 * was the only screen that could. Search, Activity and Updates now carry their
 * own, so the rows that repeated them are gone; see `PublicSections` for what
 * was kept and the reachability check behind each one.
 */
export default function ProfileScreen() {
  const router = useRouter();
  const theme = useTheme();
  const { status, user, logout } = useAuth();

  if (status !== 'authenticated' || !user) {
    return (
      <Screen edges={['top']}>
        {/* `tight`, matching the signed-in header below. Without it the title
            sits 12pt lower here than it does one render later, so signing in
            visibly shifts the whole screen. */}
        <ScreenHeader title="Profile" showBack={false} tight />

        <ScrollView
          contentContainerStyle={{
            padding: screenPadding,
            paddingBottom: tabBarClearance,
          }}
          showsVerticalScrollIndicator={false}
        >
          <SignInPrompt
            compact
            icon="person-circle-outline"
            title="Your account"
            description="Your profile, rewards and listings live here once you are signed in."
          />

          <PublicSections />
        </ScrollView>
      </Screen>
    );
  }

  const isOwner = user.role === 'owner';

  const handleLogout = () => {
    Alert.alert('Log out', 'You will need to sign in again to access your account.', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Log out', style: 'destructive', onPress: () => void logout() },
    ]);
  };

  return (
    <Screen edges={['top']}>
      <ScreenHeader title="Profile" showBack={false} tight />

      <Refreshable
        contentContainerStyle={{
          padding: screenPadding,
          paddingBottom: tabBarClearance,
        }}
      >
        {/*
          THE ACCOUNT HEADER.

          A surface rather than bare rows, because this is the one block on the
          screen that is ABOUT the user rather than a link to somewhere else —
          and it earns the distinction by being tappable straight through to
          editing. It reads as premium now for one unglamorous reason: it has
          padding. `Card` supplied none until 2026-08-15, so the avatar sat
          flush against the card's top and left edges and the rewards card
          below it touched this one with no gap at all. See `ui/Card.tsx`.
        */}
        <Card onPress={() => router.push('/settings')} className="flex-row items-center">
          <Avatar uri={user.profileImage} name={user.name} size="lg" />
          <View className="ml-base flex-1">
            <Text variant="title3" numberOfLines={1}>
              {user.name}
            </Text>
            <Text variant="footnote" tone="secondary" numberOfLines={1}>
              {user.email}
            </Text>
            <View className="mt-sm flex-row items-center">
              <Badge
                label={isOwner ? 'Owner' : user.isVerified ? 'Verified' : 'Unverified'}
                tone={isOwner ? 'accent' : user.isVerified ? 'success' : 'warning'}
              />
              {user.phone ? (
                <Text variant="caption" tone="muted" className="ml-sm">
                  {user.phone}
                </Text>
              ) : null}
            </View>
          </View>
          <Ionicons name="chevron-forward" size={20} color={theme.colors.textMuted} />
        </Card>

        {/* 12, not 24: the wallet is part of "about you", so it sits closer to
            the identity card than the navigation groups sit to each other. */}
        <View className="mt-md">
          <RewardsSummaryCard />
        </View>

        {isOwner ? <OwnerCard /> : <UpgradeCard />}

        <PublicSections />

        <ListGroup title="Account" className="mt-xl">
          <ListRow
            icon="gift-outline"
            label="Rewards"
            detail="Points, tier and referrals"
            onPress={() => router.push('/rewards')}
          />
          <ListRow
            icon="settings-outline"
            label="Settings"
            detail="Profile, password and devices"
            onPress={() => router.push('/settings')}
          />
        </ListGroup>

        {/* Its own group, and last. Log out sitting inside the navigation list
            is one mis-tap away from every other row. */}
        <ListGroup className="mt-xl">
          <ListRow
            icon="log-out-outline"
            label="Log out"
            destructive
            chevron={false}
            onPress={handleLogout}
          />
        </ListGroup>
      </Refreshable>
    </Screen>
  );

}

/**
 * The destinations that work without an account.
 *
 * Rendered by BOTH branches, and that is the point rather than a convenience:
 * an earlier version listed these only for signed-in users, so a guest was
 * shown a wall in front of destinations that were open the whole time. Sharing
 * one component means a route added here cannot go missing for one kind of user.
 *
 * ---------------------------------------------------------------------------
 * THIS USED TO BE THE APP'S SITEMAP — cut back 2026-08-24
 *
 * It carried three groups and a comment declaring that "the test for this list
 * is coverage, not brevity", because Profile was the only complete index of the
 * app. That is a website's footer, and it was the right structure for a screen
 * whose siblings were a landing page and a listings section.
 *
 * With Search, Activity and Updates as tabs, most of it was duplication:
 * "Browse properties" is the first tab, "Notifications" is the fourth,
 * "Interested listings" and "My bookings" are two segments of Activity. Those
 * rows are gone. A row that repeats a tab is not navigation, it is noise that
 * makes the account screen longer.
 *
 * What stays is what is genuinely reachable from nowhere else. Every one was
 * checked before the deletion rather than after:
 *
 *   Builder projects   only entry point in the app; the rail that used to
 *                      carry it went with Home.
 *   The calculators    inline EMI exists on a listing, but affordability is a
 *                      pre-search question with no home of its own.
 *   Help & support     nothing else links to it.
 *   Appearance         a device preference, and the one setting a guest can
 *                      reach.
 *
 * Blog is deliberately NOT here any more — see `support.tsx` and the content
 * decision it records. The routes stay on disk for deep links.
 */
function PublicSections() {
  const router = useRouter();

  return (
    <>
      <ListGroup title="Explore" className="mt-xl">
        <ListRow
          icon="business-outline"
          label="Builder projects"
          detail="New developments, direct from the builder"
          onPress={() => router.push('/projects')}
        />
      </ListGroup>

      {/*
        The calculators get their own group rather than folding into "Explore".
        Browsing listings and working out a budget are different activities, and
        a row reading "What can I afford?" under a heading that otherwise means
        "look at things" is a category error the reader has to see past.
      */}
      <ListGroup title="Plan your purchase" className="mt-xl">
        <ListRow
          icon="wallet-outline"
          label="What can I afford?"
          detail="Turn your income and savings into a budget"
          onPress={() => router.push('/tools/affordability')}
        />
        <ListRow
          icon="calculator-outline"
          label="EMI calculator"
          onPress={() => router.push('/tools/emi')}
        />
      </ListGroup>

      <ListGroup title="Help" className="mt-xl">
        <ListRow
          icon="help-circle-outline"
          label="Help & support"
          onPress={() => router.push('/support')}
        />
      </ListGroup>

      <AppearanceGroup />
    </>
  );
}

const THEME_OPTIONS: readonly { label: string; value: ThemePreference }[] = [
  { label: 'System', value: 'system' },
  { label: 'Light', value: 'light' },
  { label: 'Dark', value: 'dark' },
];

/**
 * The light/dark switch.
 *
 * It lives in `PublicSections`, so a signed-out user gets it too. A colour
 * scheme is a device preference, not account data — `ThemeProvider` already
 * persists it outside the session for the same reason — and hiding it behind a
 * sign-in wall would be the one setting in the app a guest cannot reach.
 *
 * Three options rather than a two-state switch, because "follow the phone" has
 * to be expressible. A toggle can only ever say light or dark, so choosing
 * either would silently opt the user out of their phone's own schedule with no
 * way back short of reinstalling.
 *
 * Inside a `ListGroup` rather than bare on the page: the segmented control
 * draws its track in `surfaceMuted`, which separates from a card but is within
 * two percent of the page background in light mode, where it would vanish.
 */
function AppearanceGroup() {
  return (
    <ListGroup
      title="Appearance"
      className="mt-xl"
      footer="System follows your phone's light or dark setting."
    >
      <ThemeSegments />
    </ListGroup>
  );
}

/** Its own component so `ListGroup`'s `isLast` clone has a props bag to land
 *  in — a bare `View` would forward the unknown prop to the host component. */
function ThemeSegments() {
  const { preference, setPreference } = useThemePreference();

  return (
    <View style={{ padding: spacing.md }}>
      <Segmented
        options={THEME_OPTIONS}
        value={preference}
        onChange={setPreference}
        accessibilityLabel="App theme"
      />
    </View>
  );
}

function RewardsSummaryCard() {
  const router = useRouter();
  const theme = useTheme();
  const { balance, tier, isLoading, error } = useWallet();

  return (
    <Card onPress={() => router.push('/rewards')} className="flex-row items-center justify-between">
      <View>
        <Text variant="footnote" tone="secondary">
          Reward points
        </Text>
        {/* `balance` is 0 whenever the wallet is null, and null covers every
            error — so an unguarded read told a user with points that they had
            none. Tapping through still reaches the Rewards screen, which now
            offers a real retry. */}
        {isLoading ? (
          <Skeleton width={80} height={26} className="mt-xs" />
        ) : error ? (
          <Text variant="title2" tone="muted" className="mt-xs">
            —
          </Text>
        ) : (
          <Text variant="title2" className="mt-xs">
            {balance.toLocaleString('en-IN')}
          </Text>
        )}
      </View>

      <View className="flex-row items-center">
        {tier ? <Badge label={tier} tone="accent" className="mr-sm" /> : null}
        <Ionicons name="chevron-forward" size={20} color={theme.colors.textMuted} />
      </View>
    </Card>
  );
}

function OwnerCard() {
  const router = useRouter();

  return (
    <ListGroup title="Your property" className="mt-xl">
      <ListRow
        icon="home-outline"
        label="My listing"
        onPress={() => router.push('/owner/properties')}
      />
      <ListRow icon="people-outline" label="Leads" onPress={() => router.push('/owner/leads')} />
      <ListRow
        icon="bar-chart-outline"
        label="Analytics"
        onPress={() => router.push('/owner/analytics')}
      />
    </ListGroup>
  );
}

/**
 * Buyer/user role: the route into listing.
 *
 * This used to be a "Become an owner" card that ran a second OTP flow of its
 * own. Two things killed it. The role is no longer something you apply for —
 * `ensureOwnerRole` grants it server-side the moment an account first posts a
 * listing — so the card offered a parallel path to a destination the listing
 * form already reaches. And it was actively broken for the accounts this
 * release creates: it texted `user.phone`, which a Google account does not have
 * yet, while its own enablement check read `isVerified`, which has never meant
 * what its name says.
 *
 * So it points at the listing form. The phone check happens inside that flow,
 * once, at the moment it is justified.
 */
function UpgradeCard() {
  const router = useRouter();

  return (
    <Card className="mt-xl">
      <Text variant="bodyEmphasis">List your property on DealDirect</Text>
      <Text variant="footnote" tone="secondary" className="mt-xs mb-base">
        Post a listing and manage leads directly. We will ask you to verify your mobile number
        once, as part of posting.
      </Text>
      <Button
        label="List a property"
        variant="secondary"
        onPress={() => router.push('/owner/property/new')}
      />
    </Card>
  );
}
