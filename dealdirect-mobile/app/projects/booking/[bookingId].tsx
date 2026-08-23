import Ionicons from '@expo/vector-icons/Ionicons';
import type * as ImagePickerModule from 'expo-image-picker';
import { useLocalSearchParams } from 'expo-router';
import { useState } from 'react';
import { Pressable, ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import { SignInPrompt } from '@/auth';
import { optionalNativeModule } from '@/config/optionalNative';
import {
  useCancelBooking,
  useMyBookings,
  usePaymentConfig,
  useSubmitBookingPayment,
} from '@/features/projects';
import { gesture, useTheme } from '@/theme';
import { USER_CANCELLABLE_STATUSES } from '@/types/backend/project';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Image,
  Input,
  Screen,
  ScreenHeader,
  Skeleton,
  Text,
  useToast,
} from '@/ui';

/**
 * Booking detail and token payment submission.
 *
 * Sourced from `useMyBookings()` rather than a dedicated by-id endpoint —
 * `bookingsEndpoints` has no single-booking GET, only `mine` (list) and the
 * write routes. The list this app already has cached after `useCreateBooking`
 * is where the just-created booking lives.
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
  const toast = useToast();
  const { bookingId } = useLocalSearchParams<{ bookingId: string }>();
  const { bookings, isLoading, isRefreshing, error, refresh, signedIn } = useMyBookings();
  const { config, isLoading: configLoading } = usePaymentConfig();
  const { submitPayment, isPending, error: submitError } = useSubmitBookingPayment(bookingId);
  const { cancelBooking, isPending: isCancelling, error: cancelError } =
    useCancelBooking(bookingId);

  const [screenshotUri, setScreenshotUri] = useState<string | undefined>(undefined);
  const [utr, setUtr] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [confirmingCancel, setConfirmingCancel] = useState(false);

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

  const handleCancel = async () => {
    try {
      const response = await cancelBooking(undefined);
      setConfirmingCancel(false);
      // The refund sentence comes from the server, because only the server
      // knows whether money was ever recorded against this booking.
      toast.show(
        response.data.refundMayBeDue
          ? 'Request withdrawn. Contact us about the payment you already made — your details are on record.'
          : 'Request withdrawn.'
      );
    } catch {
      // surfaced via cancelError below
    }
  };

  // A guest reaching this by deep link met "Could not load your bookings",
  // which blames the network for not being signed in. Checked after `isLoading`
  // so the undecided cold-start moment does not flash this at a signed-in user.
  if (!isLoading && !signedIn) {
    return (
      <Screen>
        <ScreenHeader title="Booking" backTo="/projects/bookings" />
        <SignInPrompt
          title="Sign in to see this booking"
          description="Your bookings and payment history are tied to your account."
        />
      </Screen>
    );
  }

  const paymentStatus = booking?.payment?.status;
  const tokenAmount = booking?.payment?.tokenAmount ?? 0;
  /**
   * An enquiry owes nothing, so it must never be shown a payment form.
   *
   * Checked on the amount as well as `source`, because a booking created before
   * `source` existed carries no discriminator — and a zero token is the same
   * situation either way: there is nothing to pay.
   */
  const isEnquiryOnly = booking?.source === 'enquiry' || tokenAmount <= 0;
  // `submitted` covers the gap between a successful POST and the refetched
  // list carrying the new status.
  const awaitingVerification =
    paymentStatus === 'submitted' || (submitted && paymentStatus !== 'rejected');
  const canCancel = booking ? USER_CANCELLABLE_STATUSES.includes(booking.status) : false;

  return (
    <Screen>
      {/* Back to the bookings list. With no `backTo`, `ScreenHeader` falls
          back to `/(tabs)`, which dropped the user out of the flow entirely. */}
      <ScreenHeader title="Booking" backTo="/projects/bookings" />

      {/*
        `!booking && isRefreshing` is the just-created case, and it is the
        common one: arriving here straight from the booking sheet, the cached
        list is one item out of date, so `find` misses and a background refetch
        is already in flight. Without this the first thing a buyer saw after a
        successful booking was "Booking not found".
      */}
      {isLoading || (!booking && isRefreshing) ? (
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
              <Badge
                label={booking.status === 'enquiry' && isEnquiryOnly ? 'enquiry' : booking.status}
                tone={
                  booking.status === 'confirmed'
                    ? 'success'
                    : booking.status === 'cancelled'
                      ? 'danger'
                      : 'neutral'
                }
              />
            </View>
            <Text variant="footnote" tone="secondary" className="mt-sm">
              {booking.clientName} · {booking.clientPhone}
            </Text>
            {/* An enquiry on a unit that HAS a booking amount still carries
                that figure in `payment.tokenAmount` — the server resolves and
                stores it either way. Showing it here would quote a price to
                someone who was told no payment was needed. */}
            {!isEnquiryOnly && tokenAmount > 0 ? (
              <Text variant="bodyEmphasis" className="mt-base">
                Token amount: ₹{tokenAmount.toLocaleString('en-IN')}
              </Text>
            ) : null}
          </Card>

          {booking.status === 'cancelled' ? (
            <Card className="mt-base">
              <Text variant="bodyEmphasis">Withdrawn</Text>
              <Text variant="footnote" tone="secondary" className="mt-xs">
                This request is no longer active. If you had already paid, contact us and we
                will arrange the refund.
              </Text>
            </Card>
          ) : isEnquiryOnly ? (
            /*
              The enquiry path. No money was asked for, so there is no payment
              form here — the previous version showed one regardless, quoting a
              token of ₹0 and asking for proof of a payment nobody requested.
            */
            <Card padded={false} className="mt-base items-center px-base py-lg">
              <Ionicons name="call-outline" size={40} color={theme.colors.textMuted} />
              <Text variant="bodyEmphasis" className="mt-base">
                Enquiry received
              </Text>
              <Text variant="footnote" tone="secondary" className="mt-xs text-center">
                Our team will call you about this unit. Nothing is owed and there is nothing
                to pay right now.
              </Text>
            </Card>
          ) : paymentStatus === 'verified' ? (
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

          {/*
            Withdrawal, kept quiet and two-step.

            Only offered from the states the server actually accepts
            (USER_CANCELLABLE_STATUSES) — a confirmed booking holds decremented
            inventory and is an admin decision, so offering it here would be an
            action whose normal outcome is a refusal.

            The warning is the honest part: this is not a refund. There is no
            gateway behind these payments, so cancelling changes a status and
            nothing else, and a person has to arrange the money coming back.
          */}
          {canCancel ? (
            <View className="mt-lg items-center">
              {confirmingCancel ? (
                <Card className="w-full">
                  <Text variant="bodyEmphasis">Withdraw this request?</Text>
                  <Text variant="footnote" tone="secondary" className="mt-xs">
                    {booking.status === 'payment_submitted'
                      ? 'Your payment details stay on record, but this is not an automatic refund — contact us and we will arrange it.'
                      : 'You can start again from the unit page at any time.'}
                  </Text>

                  {cancelError instanceof ApiError ? (
                    <Text variant="footnote" tone="danger" className="mt-base">
                      {cancelError.message}
                    </Text>
                  ) : null}

                  <View className="mt-base flex-row">
                    <Button
                      label="Keep it"
                      variant="secondary"
                      className="flex-1"
                      onPress={() => setConfirmingCancel(false)}
                    />
                    <Button
                      label="Withdraw"
                      variant="danger"
                      className="ml-sm flex-1"
                      loading={isCancelling}
                      onPress={() => void handleCancel()}
                    />
                  </View>
                </Card>
              ) : (
                <Pressable
                  accessibilityRole="button"
                  accessibilityLabel="Withdraw this request"
                  hitSlop={gesture.hitSlop}
                  onPress={() => setConfirmingCancel(true)}
                  className="flex-row items-center justify-center active:opacity-60"
                >
                  <Text variant="footnote" tone="danger">
                    Withdraw this request
                  </Text>
                </Pressable>
              )}
            </View>
          ) : null}
        </ScrollView>
      )}
    </Screen>
  );
}
