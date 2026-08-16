import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useState } from 'react';
import { Alert, ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import { useAuth, SignInPrompt } from '@/auth';
import { useOwnerUpgrade } from '@/features/profile';
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
  Input,
  ListGroup,
  ListRow,
  Refreshable,
  Screen,
  ScreenHeader,
  Segmented,
  Sheet,
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
 * of the eight destinations this screen indexes, five need no account at all.
 * Browsing listings, builder projects, the blog, both calculators and the help
 * page all work signed out.
 *
 * So a guest gets the prompt at the top and then the half of the index that
 * works for them, rather than a dead end covering destinations that were
 * available the whole time. `PublicSections` is the shared half; both branches
 * render the same component, so a route added there cannot appear for one kind
 * of user and not the other.
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

        {/*
          EVERY DESTINATION IN THE APP, GROUPED BY WHOSE THING IT IS.
          Profile is the only complete index of the app — Home shows discovery,
          the dock shows four tabs, and everything else is reachable from here
          or nowhere. So the test for this list is coverage, not brevity.

          Three groups: things that are YOURS, things that are the PRODUCT,
          then the account itself.
        */}
        <ListGroup title="Your activity" className="mt-xl">
          <ListRow
            icon="heart-outline"
            label="Interested listings"
            detail="Properties you have enquired about"
            onPress={() => router.push('/(tabs)/saved')}
          />
          <ListRow
            icon="notifications-outline"
            label="Notifications"
            onPress={() => router.push('/notifications')}
          />
          <ListRow
            icon="gift-outline"
            label="Rewards"
            detail="Points, tier and referrals"
            onPress={() => router.push('/rewards')}
          />
          <ListRow
            icon="calendar-outline"
            label="My bookings"
            onPress={() => router.push('/projects/bookings')}
          />
        </ListGroup>

        <PublicSections />

        <ListGroup title="Account" className="mt-xl">
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
 * Everything on this screen that works without an account.
 *
 * Rendered by BOTH branches, and that is the point rather than a convenience:
 * the previous version listed these only for signed-in users, so a guest was
 * shown a wall in front of five destinations that were open the whole time.
 * Sharing one component means a route added here cannot go missing for one
 * kind of user.
 *
 * The calculators get their own group rather than folding into "Explore".
 * Browsing listings and working out a budget are different activities, and a
 * row reading "What can I afford?" under a heading that otherwise means "look
 * at things" is a category error the reader has to see past. They are listed
 * here as well as on Home because Home's copy sits behind `Reveal` most of a
 * scroll down a long screen — right for finding them once, useless for going
 * back to one.
 */
function PublicSections() {
  const router = useRouter();

  return (
    <>
      <ListGroup title="Explore" className="mt-xl">
        <ListRow
          icon="search-outline"
          label="Browse properties"
          onPress={() => router.push('/(tabs)/properties')}
        />
        <ListRow
          icon="business-outline"
          label="Builder projects"
          onPress={() => router.push('/projects')}
        />
        <ListRow icon="newspaper-outline" label="Blog" onPress={() => router.push('/blog')} />
      </ListGroup>

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
          label="Help & about"
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
  const { balance, tier, isLoading } = useWallet();

  return (
    <Card onPress={() => router.push('/rewards')} className="flex-row items-center justify-between">
      <View>
        <Text variant="footnote" tone="secondary">
          Reward points
        </Text>
        {isLoading ? (
          <Skeleton width={80} height={26} className="mt-xs" />
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
 * Buyer/user role: the upgrade entry point. The two-step OTP flow runs inside
 * a sheet so leaving it mid-flow does not lose the screen underneath.
 */
function UpgradeCard() {
  const [open, setOpen] = useState(false);
  const { user } = useAuth();

  return (
    <>
      <Card className="mt-xl">
        <Text variant="bodyEmphasis">List your property on DealDirect</Text>
        <Text variant="footnote" tone="secondary" className="mt-xs mb-base">
          Upgrade to an owner account to post a listing and manage leads directly.
        </Text>
        <Button
          label="Become an owner"
          variant="secondary"
          disabled={!user?.isVerified}
          onPress={() => setOpen(true)}
        />
        {!user?.isVerified ? (
          <Text variant="footnote" tone="secondary" className="mt-sm">
            Verify your email first to unlock this.
          </Text>
        ) : null}
      </Card>

      <OwnerUpgradeSheet visible={open} onClose={() => setOpen(false)} />
    </>
  );
}

function OwnerUpgradeSheet({ visible, onClose }: { visible: boolean; onClose: () => void }) {
  const { otpSent, sendOtp, isSending, sendError, verifyOtp, isVerifying, verifyError, reset } =
    useOwnerUpgrade();
  const [otp, setOtp] = useState('');

  const close = () => {
    reset();
    setOtp('');
    onClose();
  };

  const handleSend = async () => {
    try {
      await sendOtp();
    } catch {
      // surfaced via sendError below
    }
  };

  const handleVerify = async () => {
    try {
      await verifyOtp(otp);
      close();
    } catch {
      // surfaced via verifyError below
    }
  };

  return (
    <Sheet visible={visible} onClose={close} title="Become an owner">
      <View className="px-lg pb-lg">
        {!otpSent ? (
          <>
            <Text variant="callout" tone="secondary" className="mb-lg">
              We will send a one-time code to your registered email to confirm the upgrade.
            </Text>
            {sendError instanceof ApiError ? (
              <Text variant="footnote" tone="danger" className="mb-base">
                {sendError.message}
              </Text>
            ) : null}
            <Button label="Send code" loading={isSending} onPress={() => void handleSend()} />
          </>
        ) : (
          <>
            <Text variant="callout" tone="secondary" className="mb-base">
              Enter the code we just sent you.
            </Text>
            <Input
              label="Verification code"
              placeholder="6-digit code"
              keyboardType="number-pad"
              value={otp}
              onChangeText={setOtp}
              maxLength={6}
              error={verifyError instanceof ApiError ? verifyError.message : undefined}
            />
            <Button
              label="Confirm"
              className="mt-base"
              loading={isVerifying}
              disabled={otp.length < 4}
              onPress={() => void handleVerify()}
            />
          </>
        )}
      </View>
    </Sheet>
  );
}
