import Ionicons from '@expo/vector-icons/Ionicons';
import { useCallback, useEffect, useRef, useState } from 'react';
import { ActivityIndicator, View } from 'react-native';

import { LeafletMap, mapAvailable } from '@/features/properties';
import { describeCoordinates, geocodeAddress, getCoordinates, locationAvailable } from '@/native';
import { radius, spacing, useTheme } from '@/theme';
import { PressableScale, Text, useToast } from '@/ui';

/**
 * Pin the property on a map, the listing form's location step.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT IS FOR
 *
 * A coordinate is the one thing on a listing that cannot be typed accurately.
 * Owners write "near the water tank" and buyers get a pin in the wrong suburb —
 * which is why the property detail screen's map, the search map and the
 * distance sort all silently skip a large share of the corpus. The website
 * solved this by making the owner tap a map; mobile had no equivalent, so a
 * listing created here carried no coordinate AT ALL.
 *
 * Three ways in, matching the website and adding the one it cannot have:
 *
 *   1. Tap the map.
 *   2. "Use my location" — the phone knows, and on a mobile listing flow the
 *      owner is very often standing in the property.
 *   3. Typing into the address fields, which forward-geocodes and moves the pin
 *      so it is roughly right before they touch it.
 *
 * ---------------------------------------------------------------------------
 * GEOCODING IS THE OS'S, NOT NOMINATIM'S
 *
 * The website calls `nominatim.openstreetmap.org` directly, with no API key, no
 * identifying User-Agent and no rate-limit handling, from every keystroke-
 * debounced address change. That breaches Nominatim's usage policy and is the
 * first thing that would fail under real traffic. `@/native/location` uses
 * expo-location's geocoder — the OS's — so this costs no quota, needs no key,
 * and cannot be cut off from under the form.
 *
 * ---------------------------------------------------------------------------
 * IT DEGRADES, LIKE EVERY OTHER NATIVE SURFACE HERE
 *
 * The map is a WebView and the locator is a native module; either can be
 * absent. Without them the two coordinate fields are still editable text, which
 * is exactly what the form had before this component existed. Nothing here is
 * load-bearing for publishing a listing — a coordinate is optional server-side,
 * and the step must not become a wall for someone whose device cannot show it.
 */

export interface LocationPickerProps {
  latitude: string;
  longitude: string;
  onChange: (next: { latitude: string; longitude: string }) => void;
  /** Filled in from a reverse geocode when the owner uses their location. */
  onResolvePlace?: (place: {
    city: string;
    locality: string;
    addressLine: string;
    state: string;
    pincode: string;
    landmark: string;
  }) => void;
  /** Re-geocoded when this changes, to follow what the owner typed. */
  addressQuery: string;
}

/** Centre of India, the website's `defaultCenter`, for an unpinned map. */
const INDIA_CENTRE = { lat: 20.5937, lng: 78.9629, zoom: 4 };

/** Six decimals, matching what the website stores and shows. */
const toFixed6 = (value: number) => value.toFixed(6);

/**
 * Long enough that the map is not chasing every keystroke, short enough that it
 * has moved by the time the owner looks up from the keyboard.
 */
const GEOCODE_DEBOUNCE_MS = 900;

export function LocationPicker({
  latitude,
  longitude,
  onChange,
  onResolvePlace,
  addressQuery,
}: LocationPickerProps) {
  const theme = useTheme();
  const toast = useToast();
  const [locating, setLocating] = useState(false);

  const lat = Number.parseFloat(latitude);
  const lng = Number.parseFloat(longitude);
  const pinned = Number.isFinite(lat) && Number.isFinite(lng);
  const pin = pinned ? { lat, lng } : null;

  const handleMapPress = useCallback(
    (nextLat: number, nextLng: number) => {
      onChange({ latitude: toFixed6(nextLat), longitude: toFixed6(nextLng) });
    },
    [onChange]
  );

  /**
   * The device's position, plus the address it resolves to.
   *
   * The reverse geocode is a bonus rather than a requirement: a coordinate with
   * no address is still a useful pin, so a failed lookup leaves the pin in place
   * and says nothing. Failing to get the COORDINATE is worth reporting, because
   * the owner pressed a button and nothing visible happened.
   */
  const detectLocation = useCallback(async () => {
    setLocating(true);
    try {
      const located = await getCoordinates();

      if (located.status === 'denied') {
        toast.show('Location access is off. Turn it on to drop a pin here.', 'neutral');
        return;
      }
      if (located.status !== 'ok') {
        toast.show('Could not get your location. Tap the map instead.', 'neutral');
        return;
      }

      const { latitude: gotLat, longitude: gotLng } = located.coordinates;
      onChange({ latitude: toFixed6(gotLat), longitude: toFixed6(gotLng) });

      const described = await describeCoordinates(gotLat, gotLng);
      if (described.status === 'ok' && onResolvePlace) {
        onResolvePlace(described.place);
        toast.show('Location pinned and address filled in.', 'success');
      } else {
        toast.show('Location pinned.', 'success');
      }
    } finally {
      setLocating(false);
    }
  }, [onChange, onResolvePlace, toast]);

  /*
    Follow the typed address, but never fight the owner.

    `pinnedRef` is read rather than `pinned` so this effect does not re-run when
    the pin changes — it must depend on the ADDRESS only. Once a pin exists the
    geocoder stops moving it: a coordinate the owner placed deliberately
    outranks one inferred from a locality name, and silently relocating their
    pin while they edit a landmark is the worst thing this could do.
  */
  const pinnedRef = useRef(pinned);
  pinnedRef.current = pinned;

  useEffect(() => {
    if (pinnedRef.current) return;
    if (addressQuery.trim().length < 3) return;

    let cancelled = false;
    const timer = setTimeout(async () => {
      const found = await geocodeAddress(addressQuery);
      // Re-checked after the await: the owner may have tapped the map while the
      // lookup was in flight, and their tap wins.
      if (cancelled || pinnedRef.current || found.status !== 'ok') return;
      onChange({
        latitude: toFixed6(found.coordinates.latitude),
        longitude: toFixed6(found.coordinates.longitude),
      });
    }, GEOCODE_DEBOUNCE_MS);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [addressQuery, onChange]);

  return (
    <View>
      <View className="mb-sm flex-row items-center justify-between">
        <Text variant="bodyEmphasis">Pin the location</Text>

        {locationAvailable ? (
          <PressableScale
            accessibilityRole="button"
            accessibilityLabel="Use my location"
            onPress={() => void detectLocation()}
            activeScale={0.96}
            style={{
              flexDirection: 'row',
              alignItems: 'center',
              gap: 6,
              paddingHorizontal: spacing.md,
              height: 34,
              borderRadius: radius.full,
              backgroundColor: theme.colors.accentMuted,
            }}
          >
            {locating ? (
              <ActivityIndicator size="small" color={theme.colors.accent} />
            ) : (
              <Ionicons name="navigate" size={15} color={theme.colors.accent} />
            )}
            <Text variant="footnote" tone="accent" style={{ fontWeight: '600' }}>
              {locating ? 'Locating…' : 'Use my location'}
            </Text>
          </PressableScale>
        ) : null}
      </View>

      <Text variant="footnote" tone="muted" className="mb-sm">
        Tap the map to place the pin exactly. Buyers use this to judge distance,
        so it is worth getting right.
      </Text>

      <View
        style={{
          height: 300,
          borderRadius: radius.lg,
          overflow: 'hidden',
          borderWidth: 1,
          borderColor: theme.colors.border,
        }}
      >
        <LeafletMap
          markers={[]}
          mode="search"
          pinDrop
          pin={pin}
          center={pin ? { ...pin, zoom: 16 } : INDIA_CENTRE}
          onMapPress={handleMapPress}
          fallback={
            <View
              className="flex-1 items-center justify-center"
              style={{ padding: spacing.base, gap: spacing.sm }}
            >
              <Ionicons name="map-outline" size={28} color={theme.colors.textMuted} />
              <Text variant="footnote" tone="muted" className="text-center">
                The map is unavailable on this device. You can still type the
                coordinates below, or leave them blank.
              </Text>
            </View>
          }
        />
      </View>

      {pinned ? (
        <View className="mt-sm flex-row items-center justify-between">
          <Text variant="footnote" tone="secondary">
            Pinned at {lat.toFixed(4)}, {lng.toFixed(4)}
          </Text>
          <PressableScale
            accessibilityRole="button"
            accessibilityLabel="Clear the pin"
            onPress={() => onChange({ latitude: '', longitude: '' })}
          >
            <Text variant="footnote" tone="accent">
              Clear
            </Text>
          </PressableScale>
        </View>
      ) : (
        <Text variant="footnote" tone="muted" className="mt-sm">
          {mapAvailable
            ? 'No pin yet. Your listing still publishes without one.'
            : 'No pin yet.'}
        </Text>
      )}
    </View>
  );
}
