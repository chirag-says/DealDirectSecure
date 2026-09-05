import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { relativeDay } from '@/lib';
import { spacing, useTheme } from '@/theme';
import type { DealProgressRow } from '@/types/backend/deal';
import { Text } from '@/ui';
import { stageIcon, stageProgressLabel } from '../stage';

/**
 * The vertical tracker: five rows, one per stage, in order.
 *
 * Three visual states, and each is stated in more than colour: a done row has
 * a filled check and its date; the current row has the stage's own icon on
 * the accent and a heavier label; an upcoming row is an outlined circle in
 * muted text. `reason` (a no-show, a cancellation) sits under the label in
 * the row it explains, because a tracker that only shows the happy path
 * leaves the reader wondering why it stopped.
 *
 * "Current" is the first row that is not done. The server marks `contacted`
 * done always, so there is always at least one done row above it.
 */

const DOT = 26;
const LINE = 2;

export interface DealProgressProps {
  progress: DealProgressRow[];
}

export function DealProgress({ progress }: DealProgressProps) {
  const theme = useTheme();
  const currentIndex = progress.findIndex((row) => !row.done);

  return (
    <View accessibilityRole="list">
      {progress.map((row, index) => {
        const isLast = index === progress.length - 1;
        const isCurrent = index === currentIndex;
        const state = row.done ? 'done' : isCurrent ? 'current' : 'upcoming';
        const when = row.at ? relativeDay(row.at) : null;

        const dotColor =
          state === 'done'
            ? theme.colors.success
            : state === 'current'
              ? theme.colors.accent
              : theme.colors.borderStrong;

        return (
          <View
            key={row.key}
            className="flex-row"
            accessible
            accessibilityLabel={[
              stageProgressLabel(row.key),
              state === 'done' ? 'done' : state === 'current' ? 'current step' : 'upcoming',
              when ?? undefined,
              row.reason ?? undefined,
            ]
              .filter(Boolean)
              .join(', ')}
          >
            {/* The rail: a dot, then a line down to the next dot. */}
            <View style={{ width: DOT, alignItems: 'center' }}>
              <View
                style={{
                  width: DOT,
                  height: DOT,
                  borderRadius: DOT / 2,
                  alignItems: 'center',
                  justifyContent: 'center',
                  backgroundColor:
                    state === 'upcoming'
                      ? 'transparent'
                      : state === 'done'
                        ? theme.colors.successMuted
                        : theme.colors.accentMuted,
                  borderWidth: state === 'upcoming' ? LINE : 0,
                  borderColor: theme.colors.borderStrong,
                }}
              >
                <Ionicons
                  name={state === 'done' ? 'checkmark' : stageIcon(row.key)}
                  size={state === 'done' ? 15 : 14}
                  color={dotColor}
                />
              </View>
              {!isLast ? (
                <View
                  style={{
                    flex: 1,
                    width: LINE,
                    minHeight: spacing.lg,
                    backgroundColor: row.done ? theme.colors.success : theme.colors.border,
                  }}
                />
              ) : null}
            </View>

            <View
              className="ml-md flex-1"
              style={{ paddingBottom: isLast ? 0 : spacing.base, paddingTop: 3 }}
            >
              <Text
                variant={state === 'current' ? 'bodyEmphasis' : 'body'}
                tone={state === 'upcoming' ? 'muted' : 'primary'}
              >
                {stageProgressLabel(row.key)}
              </Text>
              {when ? (
                <Text variant="caption" tone="muted" className="mt-xs">
                  {when}
                </Text>
              ) : null}
              {row.reason ? (
                <Text variant="footnote" tone="secondary" className="mt-xs">
                  {row.reason}
                </Text>
              ) : null}
            </View>
          </View>
        );
      })}
    </View>
  );
}
