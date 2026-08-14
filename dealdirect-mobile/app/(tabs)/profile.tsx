import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useState } from 'react';
import { Alert, View } from 'react-native';

import { ApiError } from '@/api';
import { useAuth, SignInPrompt } from '@/auth';
import { useOwnerUpgrade } from '@/features/profile';
import { useWallet } from '@/features/rewards';
import { screenPadding, tabBarClearance, useTheme } from '@/theme';
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
  Sheet,
  Skeleton,
  Text,
} from '@/ui';

/**
 * Profile tab.
 *
 * The account hub: identity, the rewards summary, the owner surface (either
 * an entry point if already an owner, or the upgrade CTA if not), and
 * settings. Guests see a sign-in prompt instead of a broken authenticated
 * screen — nothing here has a public reading.
 */
export default function ProfileScreen() {
  const router = useRouter();
  const theme = useTheme();
  const { status, user, logout } = useAuth();

  // `EmptyState` rather than a hand-built centred block — this screen was one
  // of six that reimplemented that component's exact layout by hand.
  if (status !== 'authenticated' || !user) {
    return (
      <Screen edges={['top']}>
        <ScreenHeader title="Profile" showBack={false} />
        <SignInPrompt
          icon="person-circle-outline"
          title="Your account"
          description="Your profile, rewards and listings live here once you are signed in."
        />
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
          The identity card. A surface rather than bare rows on the page,
          because this is the one block on the screen that is ABOUT the user
          rather than a link to somewhere else — and it earns the distinction
          by being tappable straight through to editing.
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

        <RewardsSummaryCard />

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

        <ListGroup title="Account" className="mt-xl">
          <ListRow
            icon="settings-outline"
            label="Settings"
            detail="Profile, password and devices"
            onPress={() => router.push('/settings')}
          />
          <ListRow
            icon="help-circle-outline"
            label="Help & about"
            onPress={() => router.push('/support')}
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
      <Card className="mt-lg">
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
