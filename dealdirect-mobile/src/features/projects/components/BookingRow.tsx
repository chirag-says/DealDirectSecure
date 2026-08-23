import { View } from 'react-native';

import type { ProjectBooking } from '@/types/backend/project';
import { Badge, Card, Text } from '@/ui';

/**
 * One booking or enquiry, as a row.
 *
 * Lifted out of `app/projects/bookings.tsx` on 2026-08-24 so the Activity tab
 * can show the same rows without a second implementation of the enquiry-versus-
 * booking distinction below, which is the part worth not duplicating.
 */

export interface BookingRowProps {
  booking: ProjectBooking;
  onPress: () => void;
  className?: string;
}

export function BookingRow({ booking, onPress, className = 'mb-base' }: BookingRowProps) {
  const projectName = typeof booking.project === 'object' ? booking.project?.basics?.name : undefined;
  const unitName = typeof booking.unitType === 'object' ? booking.unitType?.config?.name : undefined;

  const tokenAmount = booking.payment?.tokenAmount ?? 0;
  /*
    An enquiry and a booking both begin life in `status: 'enquiry'`, so the
    status alone cannot tell them apart — and they owe the reader different
    things. One is waiting on a phone call, the other on a payment.
  */
  const isEnquiryOnly = booking.source === 'enquiry' || tokenAmount <= 0;

  /*
    `Card`'s own `onPress`, not a wrapping `Pressable`. The bare Pressable this
    used carried no `style` callback and no accessible label, so the row gave
    no feedback on touch and announced nothing. `projects/[id]` and
    `unit/[unitTypeId]` both document this exact correction; this row and the
    leads list were the two the fix never reached.
  */
  return (
    <Card
      onPress={onPress}
      accessibilityLabel={[projectName, unitName].filter(Boolean).join(', ')}
      className={`${className} flex-row items-center justify-between`}
    >
      <View className="flex-1 pr-base">
        <Text variant="bodyEmphasis" numberOfLines={1}>
          {projectName ?? 'Project'}
        </Text>
        {unitName ? (
          <Text variant="footnote" tone="secondary" numberOfLines={1}>
            {unitName}
          </Text>
        ) : null}
        <Text variant="footnote" tone="secondary" className="mt-xs">
          {isEnquiryOnly
            ? 'Enquiry · no payment needed'
            : `Token ₹${tokenAmount.toLocaleString('en-IN')}`}
        </Text>
      </View>
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
    </Card>
  );
}
