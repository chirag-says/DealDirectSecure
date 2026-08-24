import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { Linking, View } from 'react-native';

import { LeafletMap, mapAvailable, usePropertyDetail, type MapMarker } from '@/features/properties';
import { screenPadding, spacing, useTheme } from '@/theme';
import { Button, EmptyState, ErrorState, Screen, ScreenHeader, Skeleton, Text } from '@/ui';

/**
 * A listing's location, on a map.
 *
 * The last placeholder in the app. It was `Placeholder milestone="M4"` — a
 * warning badge reading "not built" on the one screen type a property app is
 * most expected to have.
 *
 * ---------------------------------------------------------------------------
 * DEGRADES TO LOCALITY TEXT
 *
 * Coordinates are absent or (0,0) on a large share of the corpus — the adapter
 * already filters a (0,0) pin, because it lands in the Gulf of Guinea rather
 * than in India. When there is nothing to plot, this shows the locality in
 * words and an "open in maps" link keyed on the locality name, rather than a
 * map centred on the ocean. A wrong pin is worse than no pin.
 *
 * ---------------------------------------------------------------------------
 * THE WEBVIEW CARRIES NO API CALL
 *
 * `LeafletMap` is presentational; the coordinate is passed in, and the only
 * thing that comes back is a "view details" tap, handled here in RN. See
 * `leafletHtml.ts` for why that boundary is a session-security invariant.
 */
export default function PropertyMapScreen() {
  const router = useRouter();
  const theme = useTheme();
  const { id } = useLocalSearchParams<{ id: string }>();

  const { property, isLoading, isMissing, error, refresh } = usePropertyDetail(id);

  if (isLoading) {
    return (
      <Screen edges={['top']}>
        <ScreenHeader title="Location" backTo={`/property/${id}`} />
        <View style={{ flex: 1, padding: screenPadding }}>
          <Skeleton height={400} radius={12} />
        </View>
      </Screen>
    );
  }

  if (isMissing || !property) {
    return (
      <Screen edges={['top']}>
        <ScreenHeader title="Location" backTo={`/property/${id}`} />
        <EmptyState
          title="Listing no longer available"
          description="It may have been sold, rented, or taken down by its owner."
        />
      </Screen>
    );
  }

  if (error) {
    return (
      <Screen edges={['top']}>
        <ScreenHeader title="Location" backTo={`/property/${id}`} />
        <ErrorState title="Could not load the location" onRetry={refresh} />
      </Screen>
    );
  }

  const coords = property.coordinates;
  const label = property.locationLabel || property.addressLine || property.title;

  // No usable coordinate, or a host without the WebView: locality in words.
  if (!coords || !mapAvailable) {
    return (
      <Screen edges={['top']}>
        <ScreenHeader title="Location" backTo={`/property/${id}`} />
        <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', padding: spacing.xl, gap: spacing.base }}>
          <View
            className="items-center justify-center rounded-full"
            style={{ width: 72, height: 72, backgroundColor: theme.colors.surfaceMuted }}
          >
            <Ionicons name="location-outline" size={30} color={theme.colors.textSecondary} />
          </View>
          <Text variant="title3" className="text-center">
            {label}
          </Text>
          <Text variant="footnote" tone="secondary" className="text-center">
            {coords
              ? 'A map is not available in this version of the app.'
              : 'The owner did not pin an exact location for this listing.'}
          </Text>
          <Button
            label="Open in maps"
            variant="secondary"
            onPress={() =>
              void Linking.openURL(`https://www.openstreetmap.org/search?query=${encodeURIComponent(label)}`)
            }
          />
        </View>
      </Screen>
    );
  }

  const marker: MapMarker = {
    id: property.id,
    lat: coords.lat,
    lng: coords.lng,
    price: property.priceRupees,
    intent: property.intent,
    title: property.headline ?? property.title,
    locationLabel: label,
  };

  return (
    <Screen edges={['top']}>
      <ScreenHeader title={label} backTo={`/property/${id}`} tight />
      <LeafletMap
        markers={[marker]}
        mode="detail"
        center={{ lat: coords.lat, lng: coords.lng, zoom: 15 }}
        selectedId={property.id}
        // The listing is already open one screen back, so "view details" from
        // the pin returns there rather than pushing a duplicate.
        onViewDetails={() => router.back()}
      />
    </Screen>
  );
}
