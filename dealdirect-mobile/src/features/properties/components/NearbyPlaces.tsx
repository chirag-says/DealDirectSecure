import { View } from 'react-native';

import { Tag } from '@/ui';

/**
 * `address.nearby`, matching the website's treatment on the detail page. Typed
 * and adapted since M4, never rendered until M16 — see the note on
 * `PropertyDetail.nearby`.
 *
 * Tags, not chips: nothing here is selectable, and `Chip` announces itself to a
 * screen reader as a button. The section heading is the screen's, not this
 * component's, so a landmark's list reads the same as the amenity list above it.
 */
export interface NearbyPlacesProps {
  places: string[];
}

export function NearbyPlaces({ places }: NearbyPlacesProps) {
  if (places.length === 0) return null;

  return (
    <View className="flex-row flex-wrap gap-sm">
      {places.map((place) => (
        <Tag key={place} label={place} icon="location-outline" />
      ))}
    </View>
  );
}
