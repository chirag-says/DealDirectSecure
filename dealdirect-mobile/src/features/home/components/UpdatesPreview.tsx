import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { relativeDay } from '@/lib';
import { radius, spacing, useTheme } from '@/theme';
import type { AppNotification } from '@/types/backend/notification';
import { PressableScale, Text } from '@/ui';

/**
 * The two most recent unread events, with a way into Updates.
 *
 * ---------------------------------------------------------------------------
 * TWO, AND ONLY WHEN UNREAD
 *
 * This is a preview, not a second inbox. Its job is to answer "did anything
 * happen while I was away" without the user opening a tab to find out, and two
 * rows answers that; five would be Updates rendered twice, and Home has to stay
 * short.
 *
 * It renders nothing when everything is read. A permanent "Recent activity"
 * block that says "nothing new" is a section spending the fold to report an
 * absence — the tab bar's Updates entry is already where a user looks when
 * they want the full list.
 *
 * ---------------------------------------------------------------------------
 * NO BADGE, STILL
 *
 * Unread here means unread among the hundred rows `GET /notifications`
 * returns, because that endpoint offers no count and no cursor. That is honest
 * for a preview — these are rows the app is holding — and it is exactly why
 * the dock carries no badge: a badge implies a number the server does not
 * provide, and one that only becomes true after you open the screen it is
 * meant to send you to is worse than none.
 *
 * The query is `useNotifications`, the same one the Updates tab runs, so this
 * costs no additional request.
 */

export interface UpdatesPreviewProps {
  items: readonly AppNotification[];
  onOpen: (notification: AppNotification) => void;
  onSeeAll: () => void;
}

const PREVIEW_COUNT = 2;

export function UpdatesPreview({ items, onOpen, onSeeAll }: UpdatesPreviewProps) {
  const theme = useTheme();
  const unread = items.filter((item) => !item.isRead).slice(0, PREVIEW_COUNT);

  if (unread.length === 0) return null;

  return (
    <View>
      <View className="mb-sm flex-row items-baseline justify-between">
        <Text variant="bodyEmphasis">What changed</Text>
        <PressableScale accessibilityRole="button" accessibilityLabel="See all updates" onPress={onSeeAll}>
          <Text variant="footnote" tone="accent">
            See all
          </Text>
        </PressableScale>
      </View>

      <View
        style={{
          borderRadius: radius.lg,
          borderWidth: 1,
          borderColor: theme.colors.border,
          backgroundColor: theme.colors.surface,
          overflow: 'hidden',
        }}
      >
        {unread.map((item, index) => (
          <PressableScale
            key={item._id}
            accessibilityRole="button"
            accessibilityLabel={item.title}
            onPress={() => onOpen(item)}
            activeScale={0.99}
            style={{
              flexDirection: 'row',
              alignItems: 'center',
              padding: spacing.md,
              borderTopWidth: index === 0 ? 0 : 1,
              borderTopColor: theme.colors.border,
            }}
          >
            {/* The unread dot is the only state this row carries. Everything
                in the list is unread by construction, so a read/unread
                distinction would be drawn and never vary. */}
            <View
              style={{
                width: 8,
                height: 8,
                borderRadius: radius.full,
                backgroundColor: theme.colors.accent,
                marginRight: spacing.md,
              }}
            />

            <View className="flex-1">
              <Text variant="footnote" numberOfLines={1}>
                {item.title}
              </Text>
              <Text variant="caption" tone="muted" numberOfLines={1}>
                {relativeDay(item.createdAt)}
              </Text>
            </View>

            <Ionicons name="chevron-forward" size={16} color={theme.colors.textMuted} />
          </PressableScale>
        ))}
      </View>
    </View>
  );
}
