import Ionicons from '@expo/vector-icons/Ionicons';
import type * as ImagePickerModule from 'expo-image-picker';
import { useLocalSearchParams } from 'expo-router';
import { useState } from 'react';
import { Pressable, ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import { optionalNativeModule } from '@/config/optionalNative';
import { usePaymentConfig, useMyBookings, useSubmitBookingPayment } from '@/features/projects';
import { useTheme } from '@/theme';
import { Badge, Button, Card, EmptyState, ErrorState, Image, Input, Screen, ScreenHeader, Skeleton, Text } from '@/ui';

/**
 * Booking detail and token payment submission.
 *
 * Sourced from `useMyBookings()` rather than a dedicated by-id endpoint —
 * `bookingsEndpoints` has no single-booking GET, only `mine` (list) and the
 * two write routes. The list this app already has cached after
 * `useCreateBooking` is where the just-created booking lives.
 */
/**
 * Optional: absent in Expo Go, where a top-level import would throw while this
 * route module is evaluated. Expo Router walks every route file to build the
 * route tree, so that throw does not just break this screen — it breaks
 * routing. See `config/optionalNative.ts`.
 */
const ImagePicker = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('expo-image-picker') as typeof ImagePickerModule,
  'expo-image-picker',
  'Attaching a payment screenshot needs a full build of the app.'
);

export default function BookingScreen() {
  const theme = useTheme();
  const { bookingId } = useLocalSearchParams<{ bookingId: string }>();
  const { bookings, isLoading, error, refresh } = useMyBookings();
  const { config, isLoading: configLoading } = usePaymentConfig();
  const { submitPayment, isPending, error: submitError } = useSubmitBookingPayment(bookingId);

  const [screenshotUri, setScreenshotUri] = useState<string | undefined>(undefined);
  const [utr, setUtr] = useState('');
  const [submitted, setSubmitted] = useState(false);

  const booking = bookings.find((b) => b._id === bookingId);

  const handlePickScreenshot = async () => {
    if (!ImagePicker) return;

    const permission = await ImagePicker.requestMediaLibraryPermissionsAsync();
    if (!permission.granted) return;

    const result = await ImagePicker.launchImageLibraryAsync({ mediaTypes: ['images'], quality: 0.8 });
    if (result.canceled || !result.assets[0]) return;
    setScreenshotUri(result.assets[0].uri);
  };

  // Either proof suffices, matching the backend (it rejects only when both are
  // missing) and the website. Requiring both blocked anyone who had the bank
  // reference to hand but no screenshot.
  const hasProof = Boolean(screenshotUri) || utr.trim().length > 0;

  const handleSubmit = async () => {
    if (!hasProof) return;
    try {
      await submitPayment({ screenshotUri, utr: utr.trim() || undefined });
      setSubmitted(true);
    } catch {
      // surfaced via submitError below
    }
  };

  const paymentStatus = booking?.payment?.status;
  // `submitted` covers the gap between a successful POST and the refetched
  // list carrying the new status.
  const awaitingVerification =
    paymentStatus === 'submitted' || (submitted && paymentStatus !== 'rejected');

  return (
    <Screen>
      {/* Back to the bookings list. With no `backTo`, `ScreenHeader` falls
          back to `/(tabs)`, which dropped the user out of the flow entirely. */}
      <ScreenHeader title="Booking" backTo="/projects/bookings" />

      {isLoading ? (
        <View className="p-base">
          <Skeleton height={200} radius={16} />
        </View>
      ) : error ? (
        <ErrorState title="Could not load your bookings" onRetry={refresh} />
      ) : !booking ? (
        <EmptyState title="Booking not found" />
      ) : (
        <ScrollView contentContainerStyle={{ padding: 16, paddingBottom: 48 }}>
          <Card>
            <View className="flex-row items-center justify-between">
              <Text variant="title3">
                {typeof booking.project === 'object' ? booking.project?.basics?.name : 'Booking'}
              </Text>
              <Badge label={booking.status} tone={booking.status === 'confirmed' ? 'success' : 'neutral'} />
            </View>
            <Text variant="footnote" tone="secondary" className="mt-sm">
              {booking.clientName} · {booking.clientPhone}
            </Text>
            {booking.payment?.tokenAmount ? (
              <Text variant="bodyEmphasis" className="mt-base">
                Token amount: ₹{booking.payment.tokenAmount.toLocaleString('en-IN')}
              </Text>
            ) : null}
          </Card>

          {paymentStatus === 'verified' ? (
            <Card padded={false} className="mt-base items-center px-base py-lg">
              <Ionicons name="checkmark-circle" size={40} color={theme.colors.success} />
              <Text variant="bodyEmphasis" className="mt-base">
                Payment verified
              </Text>
              {booking.payment?.utrNumber ? (
                <Text variant="footnote" tone="secondary" className="mt-xs">
                  Reference: {booking.payment.utrNumber}
                </Text>
              ) : null}
            </Card>
          ) : awaitingVerification ? (
            <Card padded={false} className="mt-base items-center px-base py-lg">
              <Ionicons name="time-outline" size={40} color={theme.colors.textMuted} />
              <Text variant="bodyEmphasis" className="mt-base">
                Payment submitted, awaiting verification
              </Text>
              {booking.payment?.utrNumber ? (
                <Text variant="footnote" tone="secondary" className="mt-xs">
                  Reference: {booking.payment.utrNumber}
                </Text>
              ) : null}
            </Card>
          ) : (
            <Card className="mt-base">
              {/* A rejected payment is resubmittable through this same form,
                  which is why the rejection notice sits above it rather than
                  replacing it — the website does the same. */}
              {paymentStatus === 'rejected' ? (
                <View className="mb-base rounded-lg border border-danger/40 bg-danger/10 p-base">
                  <Text variant="bodyEmphasis" tone="danger">
                    Payment rejected
                  </Text>
                  {booking.payment?.rejectionReason ? (
                    <Text variant="footnote" tone="secondary" className="mt-xs">
                      {booking.payment.rejectionReason}
                    </Text>
                  ) : null}
                  <Text variant="footnote" tone="secondary" className="mt-xs">
                    Please submit your payment proof again.
                  </Text>
                </View>
              ) : null}

              <Text variant="bodyEmphasis" className="mb-sm">
                Pay the token amount
              </Text>

              {configLoading ? (
                <Skeleton height={160} radius={12} />
              ) : config?.qrUrl ? (
                <View className="items-center">
                  <Image uri={config.qrUrl} size="medium" style={{ width: 200, height: 200 }} />
                  {config.upiId ? (
                    <Text variant="footnote" tone="secondary" className="mt-sm">
                      UPI ID: {config.upiId}
                    </Text>
                  ) : null}
                </View>
              ) : null}

              <Text variant="footnote" tone="secondary" className="mb-sm mt-lg">
                After paying, add the payment screenshot or the UTR / reference number.
                Either one is enough.
              </Text>

              <Pressable
                accessibilityRole="button"
                onPress={() => void handlePickScreenshot()}
                className="mb-base h-32 items-center justify-center rounded-lg border border-dashed border-border"
              >
                {screenshotUri ? (
                  <Image uri={screenshotUri} style={{ width: '100%', height: '100%', borderRadius: 8 }} />
                ) : (
                  <>
                    <Ionicons name="camera-outline" size={24} color={theme.colors.textMuted} />
                    <Text variant="footnote" tone="secondary" className="mt-xs">
                      Add screenshot
                    </Text>
                  </>
                )}
              </Pressable>

              <Input label="UTR / reference number" value={utr} onChangeText={setUtr} />

              {submitError instanceof ApiError ? (
                <Text variant="footnote" tone="danger" className="mt-base">
                  {submitError.message}
                </Text>
              ) : null}

              <Button
                label="Submit payment"
                className="mt-lg"
                loading={isPending}
                disabled={!hasProof}
                onPress={() => void handleSubmit()}
              />
            </Card>
          )}
        </ScrollView>
      )}
    </Screen>
  );
}
