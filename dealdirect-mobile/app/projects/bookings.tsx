import { useRouter } from 'expo-router';
import { FlatList, Pressable, View } from 'react-native';

import { useMyBookings } from '@/features/projects';
import type { ProjectBooking } from '@/types/backend/project';
import { Badge, Card, EmptyState, ErrorState, Screen, ScreenHeader, Skeleton, Text } from '@/ui';

/**
 * My bookings. Not part of the M0 route scaffold — screen #42 in the
 * architecture plan's build order, added here since `bookingsEndpoints.mine`
 * already existed with nowhere in the app that called it.
 */
export default function MyBookingsScreen() {
  const router = useRouter();
  const { bookings, isLoading, isRefreshing, error, refresh } = useMyBookings();

  return (
    <Screen>
      <ScreenHeader title="My bookings" backTo="/(tabs)/profile" />

      {isLoading ? (
        <View className="px-base">
          {[0, 1].map((i) => (
            <Skeleton key={i} height={88} className="mb-base" radius={12} />
          ))}
        </View>
      ) : error ? (
        <ErrorState title="Could not load your bookings" onRetry={refresh} />
      ) : bookings.length === 0 ? (
        <EmptyState
          title="No bookings yet"
          description="Book a unit from any project to see it here."
          actionLabel="Browse projects"
          onAction={() => router.push('/projects')}
        />
      ) : (
        <FlatList
          data={bookings}
          keyExtractor={(item) => item._id}
          contentContainerStyle={{ padding: 16, paddingBottom: 48 }}
          refreshing={isRefreshing}
          onRefresh={refresh}
          renderItem={({ item }) => (
            <BookingRow booking={item} onPress={() => router.push(`/projects/booking/${item._id}`)} />
          )}
        />
      )}
    </Screen>
  );
}

function BookingRow({ booking, onPress }: { booking: ProjectBooking; onPress: () => void }) {
  const projectName = typeof booking.project === 'object' ? booking.project?.basics?.name : undefined;
  const unitName = typeof booking.unitType === 'object' ? booking.unitType?.config?.name : undefined;

  return (
    <Pressable accessibilityRole="button" onPress={onPress}>
      <Card className="mb-base flex-row items-center justify-between">
        <View className="flex-1 pr-base">
          <Text variant="bodyEmphasis" numberOfLines={1}>
            {projectName ?? 'Project'}
          </Text>
          {unitName ? (
            <Text variant="footnote" tone="secondary" numberOfLines={1}>
              {unitName}
            </Text>
          ) : null}
          {booking.payment?.tokenAmount ? (
            <Text variant="footnote" tone="secondary" className="mt-xs">
              Token ₹{booking.payment.tokenAmount.toLocaleString('en-IN')}
            </Text>
          ) : null}
        </View>
        <Badge label={booking.status} tone={booking.status === 'confirmed' ? 'success' : 'neutral'} />
      </Card>
    </Pressable>
  );
}
