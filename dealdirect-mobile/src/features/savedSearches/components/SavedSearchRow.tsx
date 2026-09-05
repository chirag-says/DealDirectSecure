import Ionicons from '@expo/vector-icons/Ionicons';
import { memo, useCallback } from 'react';
import { Pressable, View } from 'react-native';

import { spacing, useTheme } from '@/theme';
import { Text } from '@/ui';
import { matchLine } from '../adapters';
import type { SavedSearchSummary } from '../types';

/**
 * One saved search.
 *
 * ---------------------------------------------------------------------------
 * THREE CHANNELS, NOT ONE SWITCH (Phase 1, F8)
 *
 * The row used to carry a single switch labelled "Alert me in the app",
 * writing `notifyInApp`, because that was the only channel the matcher
 * actually honoured. Phase 1 made all three real, so all three are offered:
 * in-app, email and push. They are chips rather than three stacked switches —
 * three rows of switch would make the alert settings taller than the search
 * they belong to, and the question ("where do I want to hear about this?") is
 * a multiple choice, which is what a chip row reads as.
 *
 * ---------------------------------------------------------------------------
 * ALL THREE OFF IS MUTED, AND IT SAYS MUTED
 *
 * Turning everything off is a legitimate thing to want: keep the search, run
 * it by hand, stop the noise. Left unlabelled it looks identical to a search
 * that is failing, which is the exact confusion `isInert` exists to prevent
 * for the other cause. So the row states it, in the same place and the same
 * voice.
 *
 * ---------------------------------------------------------------------------
 * A SEARCH THAT CANNOT ALERT STILL SAYS SO
 *
 * The backend accepts a search whose only filter is free text, and its matcher
 * never reads that field, so such a search is silent forever. The channels are
 * disabled and the reason is given, rather than offering three switches on
 * something that cannot fire.
 *
 * The switch never controlled the search's existence and still does not. The
 * backend's `isActive` toggle is deliberately wired to nothing: turning it off
 * removes the search from the only endpoint that lists it, so the user could
 * never turn it back on. See `hooks.ts`.
 */

export interface SavedSearchRowProps {
  search: SavedSearchSummary;
  onPress: (search: SavedSearchSummary) => void;
  onToggleAlerts: (
    id: string,
    next: { notifyEmail?: boolean; notifyInApp?: boolean; notifyPush?: boolean }
  ) => void;
  onDelete: (search: SavedSearchSummary) => void;
}

interface Channel {
  key: 'notifyInApp' | 'notifyEmail' | 'notifyPush';
  label: string;
  icon: keyof typeof Ionicons.glyphMap;
}

/** In app first: it is the one that costs the user nothing and never lands
 *  in a spam folder or behind an OS permission. */
const CHANNELS: readonly Channel[] = [
  { key: 'notifyInApp', label: 'In app', icon: 'notifications-outline' },
  { key: 'notifyEmail', label: 'Email', icon: 'mail-outline' },
  { key: 'notifyPush', label: 'Push', icon: 'phone-portrait-outline' },
];

function SavedSearchRowComponent({
  search,
  onPress,
  onToggleAlerts,
  onDelete,
}: SavedSearchRowProps) {
  const theme = useTheme();

  const handlePress = useCallback(() => onPress(search), [onPress, search]);
  const handleDelete = useCallback(() => onDelete(search), [onDelete, search]);

  const matches = matchLine(search);

  return (
    <View className="rounded-xl border border-border bg-surface">
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={`Run search ${search.name}`}
        onPress={handlePress}
        className="flex-row items-center px-md pt-md pb-sm active:opacity-70"
      >
        <View className="flex-1">
          <Text variant="bodyEmphasis" numberOfLines={1}>
            {search.name}
          </Text>
          {search.description ? (
            <Text variant="footnote" tone="muted" numberOfLines={2} className="mt-xs">
              {search.description}
            </Text>
          ) : null}
          {matches ? (
            <Text variant="caption" tone="secondary" className="mt-xs">
              {matches}
            </Text>
          ) : null}
        </View>

        <Ionicons name="chevron-forward" size={18} color={theme.colors.textMuted} />
      </Pressable>

      {search.isInert ? (
        <View className="flex-row items-start px-md pb-sm">
          <Ionicons name="alert-circle-outline" size={15} color={theme.colors.warning} />
          <Text variant="caption" tone="muted" className="ml-xs flex-1">
            This search has no filter that alerts can match, so it will not notify you. Tap it to
            run the search, or save a new one with a city or price range.
          </Text>
        </View>
      ) : null}

      <View className="border-t border-border px-md py-sm">
        <View className="flex-row items-center">
          <View className="flex-1 flex-row items-center" style={{ gap: spacing.xs }}>
            {CHANNELS.map((channel) => {
              const on = search[channel.key] && !search.isInert;

              return (
                <Pressable
                  key={channel.key}
                  accessibilityRole="switch"
                  accessibilityLabel={`${channel.label} alerts for ${search.name}`}
                  accessibilityState={{ checked: on, disabled: search.isInert }}
                  disabled={search.isInert}
                  onPress={() => onToggleAlerts(search.id, { [channel.key]: !search[channel.key] })}
                  className="flex-row items-center rounded-full border px-sm py-xs active:opacity-60"
                  style={{
                    borderColor: on ? theme.colors.accent : theme.colors.border,
                    backgroundColor: on ? theme.colors.accentMuted : 'transparent',
                    opacity: search.isInert ? 0.5 : 1,
                  }}
                >
                  <Ionicons
                    name={channel.icon}
                    size={13}
                    color={on ? theme.colors.accent : theme.colors.textMuted}
                  />
                  <Text
                    variant="caption"
                    tone={on ? 'accent' : 'muted'}
                    className="ml-xs"
                  >
                    {channel.label}
                  </Text>
                </Pressable>
              );
            })}
          </View>

          <Pressable
            accessibilityRole="button"
            accessibilityLabel={`Delete search ${search.name}`}
            onPress={handleDelete}
            hitSlop={10}
            className="ml-md active:opacity-60"
          >
            <Ionicons name="trash-outline" size={19} color={theme.colors.textMuted} />
          </Pressable>
        </View>

        {search.isMuted && !search.isInert ? (
          <Text variant="caption" tone="muted" className="mt-sm">
            Muted. The search is still saved and still runs; you just will not hear about it.
          </Text>
        ) : null}
      </View>
    </View>
  );
}

export const SavedSearchRow = memo(SavedSearchRowComponent);
