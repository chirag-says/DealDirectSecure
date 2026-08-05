import { View } from 'react-native';

import { Badge, Screen, Text } from '@/ui';

/**
 * Route scaffolding.
 *
 * M1's completion criterion is that every route in the approved structure is
 * reachable. These stubs make the navigation graph real and walkable before any
 * feature exists, which is what surfaces routing mistakes early.
 *
 * Every stub names the milestone that replaces it, so an unfinished screen
 * reached during review is self-explaining rather than looking like a bug.
 *
 * This entire directory is deleted once the last stub is replaced.
 */

export interface PlaceholderProps {
  title: string;
  /** Milestone that implements this screen, e.g. "M4". */
  milestone: string;
  description?: string;
}

export function Placeholder({ title, milestone, description }: PlaceholderProps) {
  return (
    <Screen>
      <View className="flex-1 items-center justify-center px-xl">
        <Badge label={`${milestone} · not built`} tone="warning" />

        <Text variant="title2" className="mt-base text-center">
          {title}
        </Text>

        {description ? (
          <Text variant="callout" tone="secondary" className="mt-sm text-center">
            {description}
          </Text>
        ) : null}
      </View>
    </Screen>
  );
}
