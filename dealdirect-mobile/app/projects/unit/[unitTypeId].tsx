import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useState } from 'react';
import { ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import { useAuth } from '@/auth';
import {
  useCampaignsForUnitType,
  useCreateBooking,
  useUnitTypeDetail,
} from '@/features/projects';
import { useTheme } from '@/theme';
import type { GroupBuyCampaign } from '@/types/backend/project';
import {
  Badge,
  Button,
  Card,
  ErrorState,
  Image,
  Input,
  KeyboardAvoider,
  PriceLabel,
  Screen,
  ScreenHeader,
  Sheet,
  Skeleton,
  Text,
} from '@/ui';

export default function UnitTypeScreen() {
  const router = useRouter();
  const theme = useTheme();
  const { unitTypeId } = useLocalSearchParams<{ unitTypeId: string }>();
  const { unitType, isLoading, error, refresh } = useUnitTypeDetail(unitTypeId);
  const { campaigns } = useCampaignsForUnitType(unitTypeId);
  const { status } = useAuth();
  const [bookingOpen, setBookingOpen] = useState(false);

  const isAuthenticated = status === 'authenticated';

  // `POST /bookings` is authMiddleware-gated, so a guest who filled this form
  // in would only discover that at submit — and a 401 there reads as a dead
  // session rather than "please sign in". Gate before the form opens, which
  // is what the website does too.
  const handleBookPress = () => {
    if (!isAuthenticated) {
      router.push('/(auth)/login');
      return;
    }
    setBookingOpen(true);
  };

  if (isLoading) {
    return (
      <Screen>
        <View className="p-base">
          <Skeleton height={200} radius={16} className="mb-base" />
          <Skeleton height={120} radius={12} />
        </View>
      </Screen>
    );
  }

  if (error || !unitType) {
    return (
      <Screen>
        <ErrorState title="Could not load this unit type" onRetry={refresh} />
      </Screen>
    );
  }

  const price = unitType.pricing?.effectivePrice ?? unitType.pricing?.basePrice;
  const available = unitType.inventory?.available;
  const floorPlan = unitType.floorPlans?.twoDFloorPlan ?? unitType.floorPlans?.threeDFloorPlan;
  const projectId = typeof unitType.project === 'object' ? unitType.project?._id : unitType.project;

  return (
    <Screen>
      <ScreenHeader title={unitType.config?.name ?? 'Unit type'} backTo="/projects" />

      <ScrollView contentContainerStyle={{ padding: 16, paddingBottom: 100 }}>
        {floorPlan ? (
          <Image uri={floorPlan} size="full" style={{ width: '100%', height: 220, borderRadius: 12 }} />
        ) : null}

        <Card className="mt-base">
          {price ? <PriceLabel price={price} variant="title1" /> : null}
          <View className="mt-sm flex-row flex-wrap">
            {unitType.config?.bedrooms ? (
              <SpecChip label={`${unitType.config.bedrooms} Bed`} />
            ) : null}
            {unitType.config?.bathrooms ? (
              <SpecChip label={`${unitType.config.bathrooms} Bath`} />
            ) : null}
            {typeof available === 'number' ? <SpecChip label={`${available} available`} /> : null}
          </View>
        </Card>

        {unitType.highlights && unitType.highlights.length > 0 ? (
          <Card className="mt-base">
            <Text variant="bodyEmphasis" className="mb-sm">
              Highlights
            </Text>
            {unitType.highlights.map((h) => (
              <View key={h} className="mb-xs flex-row items-start">
                <Ionicons name="checkmark-circle" size={16} color={theme.colors.success} />
                <Text variant="body" className="ml-sm flex-1">
                  {h}
                </Text>
              </View>
            ))}
          </Card>
        ) : null}

        {campaigns.length > 0 ? (
          <View className="mt-base">
            <Text variant="title3" className="mb-sm">
              Group buy
            </Text>
            {campaigns.map((campaign) => (
              <CampaignRow
                key={campaign._id}
                campaign={campaign}
                onPress={() => router.push(`/projects/campaign/${campaign._id}`)}
              />
            ))}
          </View>
        ) : null}
      </ScrollView>

      <View className="border-t border-border px-lg py-md">
        <Button
          label={isAuthenticated ? 'Book this unit' : 'Sign in to book'}
          disabled={typeof available === 'number' && available <= 0}
          onPress={handleBookPress}
        />
      </View>

      {projectId ? (
        <BookingSheet
          visible={bookingOpen}
          onClose={() => setBookingOpen(false)}
          projectId={projectId}
          unitTypeId={unitType._id}
        />
      ) : null}
    </Screen>
  );
}

function SpecChip({ label }: { label: string }) {
  return <Badge label={label} className="mb-xs mr-sm" />;
}

function CampaignRow({ campaign, onPress }: { campaign: GroupBuyCampaign; onPress: () => void }) {
  const theme = useTheme();

  // `Card`'s own `onPress` rather than a wrapping `Pressable`: the bare
  // Pressable this used had no `style` callback, so the row gave no feedback
  // on touch at all. Card springs.
  return (
    <Card onPress={onPress} className="mb-base flex-row items-center justify-between">
      <View className="flex-1 pr-base">
        <Text variant="bodyEmphasis">{campaign.basics?.name ?? 'Group buy'}</Text>
        <Text variant="footnote" tone="secondary" className="mt-xs">
          {campaign.memberCount ?? 0} joined
          {campaign.status ? ` · ${campaign.status}` : ''}
        </Text>
      </View>
      <Ionicons name="chevron-forward" size={20} color={theme.colors.textMuted} />
    </Card>
  );
}

function BookingSheet({
  visible,
  onClose,
  projectId,
  unitTypeId,
}: {
  visible: boolean;
  onClose: () => void;
  projectId: string;
  unitTypeId: string;
}) {
  const router = useRouter();
  const { user } = useAuth();
  const { createBooking, isPending, error } = useCreateBooking();

  const [clientName, setClientName] = useState(user?.name ?? '');
  const [clientPhone, setClientPhone] = useState(user?.phone ?? '');
  const [clientEmail, setClientEmail] = useState(user?.email ?? '');
  const [notes, setNotes] = useState('');

  const handleSubmit = async () => {
    try {
      const response = await createBooking({
        projectId,
        unitTypeId,
        clientName: clientName.trim(),
        clientPhone: clientPhone.trim(),
        clientEmail: clientEmail.trim() || undefined,
        notes: notes.trim() || undefined,
      });
      onClose();
      router.push(`/projects/booking/${response.data.bookingId}`);
    } catch {
      // surfaced via `error` below
    }
  };

  return (
    <Sheet visible={visible} onClose={onClose} title="Book this unit" heightRatio={0.75}>
      <KeyboardAvoider>
        <ScrollView contentContainerStyle={{ padding: 24 }} keyboardShouldPersistTaps="handled">
          <Text variant="footnote" tone="secondary" className="mb-base">
            This reserves the unit with a token payment, submitted after the builder confirms your
            request.
          </Text>
          <Input label="Full name" value={clientName} onChangeText={setClientName} />
          <Input
            label="Phone"
            value={clientPhone}
            onChangeText={setClientPhone}
            keyboardType="phone-pad"
            containerClassName="mt-base"
          />
          <Input
            label="Email (optional)"
            value={clientEmail}
            onChangeText={setClientEmail}
            keyboardType="email-address"
            autoCapitalize="none"
            containerClassName="mt-base"
          />
          <Input
            label="Notes (optional)"
            value={notes}
            onChangeText={setNotes}
            multiline
            containerClassName="mt-base"
          />

          {error instanceof ApiError ? (
            <Text variant="footnote" tone="danger" className="mt-base">
              {error.message}
            </Text>
          ) : null}

          <Button
            label="Confirm booking"
            className="mt-lg"
            loading={isPending}
            disabled={!clientName.trim() || !clientPhone.trim()}
            onPress={() => void handleSubmit()}
          />
        </ScrollView>
      </KeyboardAvoider>
    </Sheet>
  );
}
