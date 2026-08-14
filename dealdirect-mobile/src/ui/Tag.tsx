import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { useTheme } from '@/theme';
import { Text } from './Text';

/**
 * A static, non-interactive label.
 *
 * This exists because `Chip` was being used for it, and `Chip` is a CONTROL: it
 * renders a `Pressable` with `accessibilityRole="button"`, so a screen reader
 * announces every amenity on a listing as a button that does nothing when
 * activated. Twenty of those in a row is twenty dead controls.
 *
 * So: same visual family, no interaction, no role. `Chip` stays what it is —
 * the selectable filter — and neither has to grow a `readOnly` prop that would
 * make its accessibility behaviour conditional.
 *
 * Filled rather than outlined. A page of outlined pills is a page of borders,
 * and the surface ramp already separates a recessed fill from the page behind
 * it without one.
 */

export interface TagProps {
  label: string;
  /** Optional leading glyph. Sized to the label, not to the touch target. */
  icon?: keyof typeof Ionicons.glyphMap;
  className?: string;
}

export function Tag({ label, icon, className = '' }: TagProps) {
  const theme = useTheme();

  return (
    <View
      className={`flex-row items-center self-start rounded-full bg-surface-muted px-md py-sm ${className}`}
    >
      {icon ? (
        <Ionicons
          name={icon}
          size={14}
          color={theme.colors.textMuted}
          style={{ marginRight: 6 }}
        />
      ) : null}
      <Text variant="callout" tone="secondary">
        {label}
      </Text>
    </View>
  );
}
