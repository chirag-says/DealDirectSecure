import Ionicons from '@expo/vector-icons/Ionicons';
import { Pressable, ScrollView, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import type { PropertySummary } from '@/features/properties';
import { useTheme } from '@/theme';
import { Button, Image, Text } from '@/ui';
import { MIN_COMPARE } from '../compare';

/**
 * Sticky bar for compare mode. Ported from the website's fixed bottom bar
 * (`PropertyListContent.jsx` ~L2221-2274) - thumbnails-with-remove, Clear,
 * Compare Now.
 *
 * ---------------------------------------------------------------------------
 * IT SHOWS WHENEVER THE MODE IS ON, NOT ONCE SOMETHING IS SELECTED
 *
 * It used to return null at zero items, which left compare mode with no
 * on-screen statement of itself at exactly the moment a user has just entered
 * it and selected nothing: a lit toolbar icon, checkboxes where the hearts
 * were, and no explanation. A mode with an invisible state is the mode error
 * every review of this app is meant to catch.
 *
 * Now the bar IS the mode indicator. It states what to do at zero, the count
 * once there is one, and it always carries the way out - which is the other
 * thing an unmissable mode owes the user.
 */
export interface CompareBarProps {
  items: readonly PropertySummary[];
  /** Compare mode is on. The bar renders on this, not on the item count. */
  active: boolean;
  onRemove: (id: string) => void;
  onClear: () => void;
  onCompare: () => void;
  onExit: () => void;
}

export function CompareBar({
  items,
  active,
  onRemove,
  onClear,
  onCompare,
  onExit,
}: CompareBarProps) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();

  if (!active) return null;

  return (
    <View
      className="absolute inset-x-0 bottom-0 border-t border-border bg-surface px-base pt-sm"
      style={{ paddingBottom: insets.bottom + 8 }}
    >
      <Text variant="footnote" tone="secondary">
        {items.length === 0
          ? 'Select ' + MIN_COMPARE + ' or more properties to compare'
          : items.length + (items.length === 1 ? ' property' : ' properties') + ' selected for comparison'}
      </Text>

      <ScrollView horizontal showsHorizontalScrollIndicator={false} className="mt-sm" contentContainerStyle={CHIP_ROW_STYLE}>
        {items.map((item) => (
          <Pressable
            key={item.id}
            accessibilityRole="button"
            accessibilityLabel={`Remove ${item.title} from comparison`}
            onPress={() => onRemove(item.id)}
            className="flex-row items-center rounded-full border border-border bg-surface-muted py-xs pl-xs pr-sm"
          >
            {item.coverImage ? (
              <Image uri={item.coverImage} size="thumb" style={THUMB_STYLE} />
            ) : (
              <View className="h-6 w-6 rounded-full bg-surface" />
            )}
            <Text variant="caption" numberOfLines={1} className="ml-xs max-w-[120px]">
              {item.title}
            </Text>
            <Ionicons name="close" size={12} color={theme.colors.textMuted} className="ml-xs" />
          </Pressable>
        ))}
      </ScrollView>

      <View className="mt-sm flex-row items-center gap-sm pb-sm">
        {/* Exit leaves the mode; Clear only empties the selection. Two
            different things, and collapsing them would mean a user who wants
            to keep comparing but start over has to re-enter the mode. */}
        <Button
          label={items.length === 0 ? 'Exit compare' : 'Clear'}
          variant="secondary"
          onPress={items.length === 0 ? onExit : onClear}
          className="flex-1"
        />
        <Button
          label="Compare now"
          disabled={items.length < MIN_COMPARE}
          onPress={onCompare}
          className="flex-1"
        />
      </View>
    </View>
  );
}

const CHIP_ROW_STYLE = { gap: 8 } as const;
const THUMB_STYLE = { width: 24, height: 24, borderRadius: 12 } as const;
