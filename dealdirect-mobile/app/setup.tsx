import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useState } from 'react';
import { ActivityIndicator, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { detectCity, setSelectedCity } from '@/features/home';
import { markSetupSeen } from '@/features/onboarding';
import { getCoordinates, hasLocationPermission, locationAvailable } from '@/native';
import {
  hasNotificationPermission,
  registerPushTokenIfPermitted,
  requestNotificationPermissionOnce,
} from '@/notifications';
import { radius, screenPadding, spacing, useTheme } from '@/theme';
import { Button, PressableScale, Screen, Text } from '@/ui';

/**
 * The permissions primer, shown once after the welcome screen (2026-09-06).
 *
 * ---------------------------------------------------------------------------
 * WHY IT EXISTS
 *
 * Every permission in this app is requested at the moment it is needed:
 * location when "use my location" is tapped, photos when a listing adds one,
 * notifications when something worth notifying about is saved. That is the
 * right default and it stays. What it lacked was a first moment: a new user
 * opened the app and was never asked anything, so their city was "All
 * cities" and their notifications were off until they happened to find the
 * controls that ask. This screen is that moment, and it is a request, not a
 * gate: both rows are optional, "Continue" is always available, and the OS
 * prompt appears only when a row's button is tapped.
 *
 * Photos and camera are deliberately NOT here. Nobody has a listing to
 * photograph on their first minute in the app, and Google Play reads a
 * camera prompt with no camera in sight as a policy problem.
 *
 * ---------------------------------------------------------------------------
 * WHAT A GRANT DOES
 *
 * Location: detects the city and scopes the session to it, the same path as
 * the picker's "use my location". Notifications: registers the push token
 * for the signed-in user, if there is one; a guest's grant is remembered by
 * the OS and used the moment they sign in.
 */

type RowState = 'idle' | 'asking' | 'granted' | 'denied' | 'unavailable';

export default function SetupScreen() {
  const router = useRouter();
  const theme = useTheme();
  const insets = useSafeAreaInsets();
  const { next } = useLocalSearchParams<{ next?: string }>();

  const [location, setLocation] = useState<RowState>(locationAvailable ? 'idle' : 'unavailable');
  const [locationDetail, setLocationDetail] = useState<string | null>(null);
  const [notifications, setNotifications] = useState<RowState>('idle');

  // Existing grants, so an install that already said yes sees "Allowed"
  // rather than being asked to say it again.
  useEffect(() => {
    void hasLocationPermission().then((granted) => {
      if (granted) setLocation('granted');
    });
    void hasNotificationPermission().then((granted) => {
      if (granted) setNotifications('granted');
    });
  }, []);

  const allowLocation = async () => {
    setLocation('asking');
    const located = await getCoordinates();
    if (located.status !== 'ok') {
      setLocation(located.status === 'denied' ? 'denied' : 'unavailable');
      return;
    }
    setLocation('granted');
    const city = await detectCity();
    if (city.status === 'found') {
      setSelectedCity(city.city);
      setLocationDetail(`Showing properties in ${city.city.label}`);
    } else if (city.status === 'outside' && city.placeName) {
      setLocationDetail(`We are not in ${city.placeName} yet, so you will see every city`);
    }
  };

  const allowNotifications = async () => {
    setNotifications('asking');
    await requestNotificationPermissionOnce();
    const granted = await hasNotificationPermission();
    setNotifications(granted ? 'granted' : 'denied');
    if (granted) void registerPushTokenIfPermitted();
  };

  const finish = () => {
    markSetupSeen();
    router.replace((next && next.startsWith('/') ? next : '/(tabs)') as never);
  };

  return (
    <Screen>
      <View
        style={{
          flex: 1,
          paddingHorizontal: screenPadding,
          paddingTop: spacing['3xl'],
          paddingBottom: Math.max(insets.bottom, spacing.md) + spacing.md,
        }}
      >
        <Text variant="display" accessibilityRole="header">
          Set up DealDirect
        </Text>
        <Text variant="callout" tone="secondary" className="mt-sm">
          Two quick things, both optional. You can change either later in your phone&apos;s
          Settings.
        </Text>

        <View style={{ gap: spacing.md, marginTop: spacing['2xl'] }}>
          <PermissionRow
            icon="location-outline"
            title="Your location"
            detail={
              locationDetail ??
              'Picks your city and finds properties near you. Only while you use the app.'
            }
            state={location}
            onAllow={() => void allowLocation()}
            theme={theme}
          />
          <PermissionRow
            icon="notifications-outline"
            title="Notifications"
            detail="Replies from owners, price drops on what you have saved, and updates on your enquiries."
            state={notifications}
            onAllow={() => void allowNotifications()}
            theme={theme}
          />
        </View>

        <View style={{ flex: 1 }} />

        <Button label="Continue" fullWidth onPress={finish} />
        <Text variant="caption" tone="muted" className="mt-md text-center">
          We never track your location in the background, and never sell your data.
        </Text>
      </View>
    </Screen>
  );
}

function PermissionRow({
  icon,
  title,
  detail,
  state,
  onAllow,
  theme,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  title: string;
  detail: string;
  state: RowState;
  onAllow: () => void;
  theme: ReturnType<typeof useTheme>;
}) {
  const granted = state === 'granted';

  return (
    <View
      style={{
        flexDirection: 'row',
        alignItems: 'center',
        gap: spacing.md,
        padding: spacing.base,
        borderRadius: radius.lg,
        borderWidth: 1,
        borderColor: granted ? theme.colors.accent : theme.colors.border,
        backgroundColor: granted ? theme.colors.accentMuted : theme.colors.surface,
      }}
    >
      <View
        style={{
          width: 44,
          height: 44,
          borderRadius: 22,
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: granted ? theme.colors.accent : theme.colors.surfaceMuted,
        }}
      >
        <Ionicons
          name={granted ? 'checkmark' : icon}
          size={22}
          color={granted ? theme.colors.surface : theme.colors.textSecondary}
        />
      </View>

      <View style={{ flex: 1 }}>
        <Text variant="bodyEmphasis">{title}</Text>
        <Text variant="footnote" tone="secondary" className="mt-xs">
          {state === 'denied'
            ? 'Turned off. You can allow it any time in Settings.'
            : state === 'unavailable'
              ? 'Not available on this device.'
              : detail}
        </Text>
      </View>

      {state === 'asking' ? (
        <ActivityIndicator color={theme.colors.accent} />
      ) : granted ? (
        <Text variant="footnote" tone="accent" style={{ fontWeight: '600' }}>
          Allowed
        </Text>
      ) : state === 'idle' ? (
        <PressableScale
          accessibilityRole="button"
          accessibilityLabel={`Allow ${title.toLowerCase()}`}
          onPress={onAllow}
          activeScale={0.95}
          style={{
            paddingHorizontal: spacing.base,
            paddingVertical: spacing.sm,
            borderRadius: radius.full,
            backgroundColor: theme.colors.accent,
          }}
        >
          <Text variant="footnote" tone="onAccent" style={{ fontWeight: '600' }}>
            Allow
          </Text>
        </PressableScale>
      ) : null}
    </View>
  );
}
