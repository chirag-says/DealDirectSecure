import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useEffect, useState } from 'react';
import { Alert, Pressable, View } from 'react-native';

import { ApiError } from '@/api';
import { OwnerOnly } from '@/auth';
import {
  EMPTY_LISTING_FORM,
  ListingForm,
  clearListingDraft,
  hasListingDraft,
  loadListingDraft,
  saveListingDraft,
  useAddListing,
  type CategorizedPhoto,
} from '@/features/listings';
import { RewardReveal } from '@/features/rewards';
import { useTheme } from '@/theme';
import type { ActionReward } from '@/types/backend/property';
import { Screen, Text } from '@/ui';

/**
 * Add listing.
 *
 * Draft autosave writes on every field change via `saveListingDraft`, cheap
 * because MMKV is synchronous. A resumed draft is offered once on mount
 * rather than silently applied, since a stale abandoned draft overwriting a
 * fresh start would be worse than asking.
 */
function NewPropertyScreenContent() {
  const router = useRouter();
  const theme = useTheme();
  const { add, isPending, error } = useAddListing();

  const [values, setValues] = useState(EMPTY_LISTING_FORM);
  const [newPhotos, setNewPhotos] = useState<CategorizedPhoto[]>([]);
  const [pendingReward, setPendingReward] = useState<ActionReward | null>(null);
  const [createdId, setCreatedId] = useState<string | null>(null);

  useEffect(() => {
    if (!hasListingDraft()) return;
    Alert.alert('Resume draft?', 'You have an unfinished listing. Continue where you left off?', [
      { text: 'Start over', style: 'destructive', onPress: () => clearListingDraft() },
      { text: 'Resume', onPress: () => setValues(loadListingDraft()) },
    ]);
    // Only on mount.
  }, []);

  const handleChange = (next: typeof values) => {
    setValues(next);
    saveListingDraft(next);
  };

  /**
   * Listing a property earns points, and the response says how many. The
   * reveal is shown BEFORE navigating away — dismissing it is what completes
   * the submit. Navigating first would unmount this screen and take the reveal
   * with it, which is how the award went unseen before 2026-08-13.
   */
  const handleSubmit = async () => {
    try {
      const response = await add({ values, newPhotos });
      clearListingDraft();

      const propertyId = response.data._id;
      if (response.reward && response.reward.pointsAwarded > 0) {
        setPendingReward(response.reward);
        setCreatedId(propertyId);
        return;
      }

      router.replace(`/property/${propertyId}`);
    } catch {
      // surfaced via `error` below
    }
  };

  const dismissReward = () => {
    setPendingReward(null);
    if (createdId) router.replace(`/property/${createdId}`);
  };

  return (
    <Screen edges={['top']}>
      <View className="flex-row items-center px-lg pt-md pb-sm">
        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Cancel"
          onPress={() => router.back()}
          hitSlop={12}
          className="mr-sm -ml-xs h-9 w-9 items-center justify-center"
        >
          <Ionicons name="close" size={24} color={theme.colors.textPrimary} />
        </Pressable>
        <Text variant="title2">Add listing</Text>
      </View>

      <ListingForm
        values={values}
        onChange={handleChange}
        existingPhotos={[]}
        onChangeExistingPhotos={() => {}}
        newPhotos={newPhotos}
        onChangeNewPhotos={setNewPhotos}
        onSubmit={() => void handleSubmit()}
        submitLabel="Publish listing"
        isSubmitting={isPending}
        submitError={error instanceof ApiError ? error.message : undefined}
      />

      <RewardReveal reward={pendingReward} onDismiss={dismissReward} />
    </Screen>
  );
}

/**
 * Owner-gated. See `auth/components/OwnerOnly.tsx` for why a role the
 * server already enforces still needs a client-side refusal: without it a
 * buyer who reaches this route is shown an error state for something that
 * is not an error.
 */
export default function NewPropertyScreen() {
  return (
    <OwnerOnly title="Add listing">
      <NewPropertyScreenContent />
    </OwnerOnly>
  );
}
