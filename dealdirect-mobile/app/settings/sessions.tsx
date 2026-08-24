import { Alert, FlatList, Pressable, View } from 'react-native';

import { RequireAuth } from '@/auth';
import { useRevokeSession, useSessions } from '@/features/profile';
import type { UserSessionSummary } from '@/types/backend/user';
import { Badge, Card, EmptyState, ErrorState, Screen, ScreenHeader, Skeleton, Text, useToast } from '@/ui';

export default function SessionsRoute() {
  return (
    <RequireAuth
      title="Active devices"
      promptTitle="Your active devices"
      promptDescription="Sign in to see everywhere your account is currently signed in, and to sign out a device you no longer use."
      icon="phone-portrait-outline"
      backTo="/settings"
    >
      <SessionsScreen />
    </RequireAuth>
  );
}

/**
 * Active devices. `GET /users/sessions` returns every session that would
 * otherwise be silently trusted, so this is also the recovery path for "I
 * think someone else is signed into my account."
 */
function SessionsScreen() {
  const { sessions, isLoading, isRefreshing, error, refresh } = useSessions();
  const { revoke, pendingId } = useRevokeSession();
  const toast = useToast();

  const handleRevoke = (session: UserSessionSummary) => {
    Alert.alert(
      'Sign out this device?',
      `This ends the session on ${describeDevice(session)}.`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Sign out',
          style: 'destructive',
          /*
            The toast reports the OUTCOME, not the attempt.

            It used to fire unconditionally after an `await` on a fire-and-
            forget `mutate`, so a failed revoke told the user a device had been
            signed out while the session stayed live and the row stayed in the
            list. On the screen whose entire purpose is "someone else is signed
            into my account", that is the one thing it must never say wrongly.
          */
          onPress: async () => {
            try {
              await revoke(session.id);
              toast.show('That device has been signed out.');
            } catch {
              toast.show('Could not sign out that device. Please try again.', 'danger');
            }
          },
        },
      ]
    );
  };

  return (
    <Screen>
      <ScreenHeader title="Active devices" backTo="/settings" />

      {isLoading ? (
        <View className="px-base">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} height={72} className="mb-base" radius={12} />
          ))}
        </View>
      ) : error ? (
        <ErrorState title="Could not load your devices" onRetry={refresh} />
      ) : sessions.length === 0 ? (
        <EmptyState title="No active sessions" />
      ) : (
        <FlatList
          data={sessions}
          keyExtractor={(item) => item.id}
          contentContainerStyle={{ padding: 16, paddingBottom: 48 }}
          refreshing={isRefreshing}
          onRefresh={refresh}
          renderItem={({ item }) => (
            <Card className="mb-base flex-row items-start justify-between">
              <View className="flex-1 pr-base">
                <View className="flex-row items-center">
                  <Text variant="bodyEmphasis">{describeDevice(item)}</Text>
                  {item.isCurrent ? (
                    <Badge label="This device" tone="accent" className="ml-sm" />
                  ) : null}
                </View>
                <Text variant="footnote" tone="secondary" className="mt-xs">
                  {item.ipAddress} · last active{' '}
                  {new Date(item.lastActivity).toLocaleString('en-IN', {
                    dateStyle: 'medium',
                    timeStyle: 'short',
                  })}
                </Text>
              </View>

              {!item.isCurrent ? (
                <Pressable
                  accessibilityRole="button"
                  onPress={() => handleRevoke(item)}
                  disabled={pendingId === item.id}
                  hitSlop={8}
                >
                  <Text variant="footnote" tone="danger">
                    {pendingId === item.id ? 'Signing out…' : 'Sign out'}
                  </Text>
                </Pressable>
              ) : null}
            </Card>
          )}
        />
      )}
    </Screen>
  );
}

function describeDevice(session: UserSessionSummary): string {
  const { device } = session;
  const platform = device.platform ?? (device.isMobile ? 'Mobile' : 'Desktop');
  return device.browser ? `${platform} · ${device.browser}` : platform;
}
