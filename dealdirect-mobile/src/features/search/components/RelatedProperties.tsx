import { useRouter } from 'expo-router';
import { useCallback } from 'react';
import { View } from 'react-native';

import { PropertyRail, type PropertySummary } from '@/features/properties';
import { Text } from '@/ui';

/**
 * "You might also like" rail, shown by the search results screen when the
 * direct match count is thin. See `../related.ts` for how `items` is chosen.
 */
export interface RelatedPropertiesProps {
  items: readonly PropertySummary[];
}

export function RelatedProperties({ items }: RelatedPropertiesProps) {
  const router = useRouter();

  const openProperty = useCallback(
    (id: string) => router.push(`/property/${id}`),
    [router]
  );

  if (items.length === 0) return null;

  return (
    <View className="mt-xl">
      <Text variant="title3" className="mb-md px-base">
        You might also like
      </Text>
      <PropertyRail items={items} onSelect={openProperty} accessibilityLabel="Related properties" />
    </View>
  );
}
