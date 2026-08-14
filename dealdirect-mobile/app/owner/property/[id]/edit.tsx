import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useState } from 'react';
import { Pressable, View } from 'react-native';

import { ApiError } from '@/api';
import {
  ListingForm,
  existingCategorizedPhotos,
  propertyToFormValues,
  useMyProperties,
  useUpdateListing,
  type CategorizedPhoto,
  type ListingFormValues,
} from '@/features/listings';
import { useTheme } from '@/theme';
import { ErrorState, Screen, Skeleton, Text } from '@/ui';

/**
 * Edit listing.
 *
 * Reads the property from `useMyProperties` rather than
 * `GET /properties/:id`, deliberately: the detail endpoint increments the
 * view counter on every call (see `features/properties/hooks.ts`), and an
 * owner opening their own listing to edit it is not a view worth counting.
 * An owner account only ever has the one listing, so this list is cheap to
 * search.
 */
export default function EditPropertyScreen() {
  const router = useRouter();
  const theme = useTheme();
  const { id } = useLocalSearchParams<{ id: string }>();
  const { properties, isLoading, error, refresh } = useMyProperties();
  const { update, isPending, error: updateError } = useUpdateListing(id);

  const property = properties.find((p) => p._id === id);

  const [values, setValues] = useState<ListingFormValues | null>(
    property ? propertyToFormValues(property) : null
  );
  const [existingPhotos, setExistingPhotos] = useState<CategorizedPhoto[] | null>(
    property ? existingCategorizedPhotos(property) : null
  );
  const [newPhotos, setNewPhotos] = useState<CategorizedPhoto[]>([]);

  if (!values && property) {
    setValues(propertyToFormValues(property));
    setExistingPhotos(existingCategorizedPhotos(property));
  }

  const handleSubmit = async () => {
    if (!values || !property) return;
    try {
      await update({ values, newPhotos, existingPhotos: existingPhotos ?? [] });
      router.back();
    } catch {
      // surfaced via `updateError` below
    }
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
        <Text variant="title2">Edit listing</Text>
      </View>

      {isLoading && !property ? (
        <View className="px-base">
          <Skeleton height={400} radius={16} />
        </View>
      ) : error ? (
        <ErrorState title="Could not load your listing" onRetry={refresh} />
      ) : !property || !values ? (
        <ErrorState title="Listing not found" onRetry={refresh} />
      ) : (
        <ListingForm
          values={values}
          onChange={setValues}
          existingPhotos={existingPhotos ?? []}
          onChangeExistingPhotos={setExistingPhotos}
          newPhotos={newPhotos}
          onChangeNewPhotos={setNewPhotos}
          onSubmit={() => void handleSubmit()}
          submitLabel="Save changes"
          isSubmitting={isPending}
          submitError={updateError instanceof ApiError ? updateError.message : undefined}
        />
      )}
    </Screen>
  );
}
