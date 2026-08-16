import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { radius, spacing, touchTarget, useTheme } from '@/theme';
import type { LeadStatus } from '@/types/backend/lead';
import { PressableScale, Text } from '@/ui';
import { LEAD_STATUSES, statusLabel, statusTone } from '../status';

/**
 * The pipeline: how many leads sit at each stage, in stage order.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A COMPONENT AND NOT A CHART
 *
 * `statusStats` is six numbers. A chart library for six numbers is a
 * dependency and a rendering surface bought for nothing; the app has none
 * installed and this is not the reason to add one. What the owner needs from
 * these six is a ranking they can read in a glance and a way to act on one of
 * them, and a labelled bar does both.
 *
 * ---------------------------------------------------------------------------
 * STAGE ORDER, NOT COUNT ORDER
 *
 * Rows follow `LEAD_STATUSES` — new, contacted, interested, negotiating,
 * converted, lost — which is the order a lead actually moves through. Sorting
 * by count would reshuffle the pipeline every time a status changed, so the
 * owner could never learn where to look, and it would break the one thing this
 * shape is good at: reading top-to-bottom as a funnel.
 *
 * A stage with no leads is dropped rather than drawn at zero. Six rows of
 * which four are empty is a chart of an empty pipeline; the stages that exist
 * are the ones worth the vertical space.
 *
 * ---------------------------------------------------------------------------
 * THE COUNT IS ALWAYS TEXT, AND THE BAR IS NEVER THE ONLY SIGNAL
 *
 * Colour comes from `statusTone`, the same mapping the badges on the leads list
 * and the lead detail use, so a stage is the same colour everywhere in the CRM.
 * But the label and the number carry the whole meaning on their own: strip the
 * colour and nothing here becomes unreadable, which is the test that matters
 * for a status visualisation.
 *
 * ---------------------------------------------------------------------------
 * EVERY ROW IS A DESTINATION
 *
 * Tapping a stage opens the leads list already filtered to it. That is the
 * bridge between the two owner screens and it is real rather than decorative:
 * `useLeads(status)` takes exactly this value, and the list screen reads it
 * off the route. Without it the pipeline is a picture of work the owner then
 * has to go and find by hand.
 */

/** Scale-independent proportion. The largest stage fills the track. */
function share(count: number, max: number): number {
  return Math.max(0.04, count / Math.max(1, max));
}

export interface LeadPipelineProps {
  statusStats: Partial<Record<LeadStatus, number>>;
  onSelectStatus?: (status: LeadStatus) => void;
}

export function LeadPipeline({ statusStats, onSelectStatus }: LeadPipelineProps) {
  const theme = useTheme();

  const rows = LEAD_STATUSES.map((status) => ({ status, count: statusStats[status] ?? 0 })).filter(
    (row) => row.count > 0
  );

  if (rows.length === 0) return null;

  const max = Math.max(...rows.map((row) => row.count));

  /** `statusTone` names a semantic role; this resolves it to the scheme's colour. */
  const barColor = (status: LeadStatus): string => {
    switch (statusTone(status)) {
      case 'accent':
        return theme.colors.accent;
      case 'success':
        return theme.colors.success;
      case 'danger':
        return theme.colors.danger;
      case 'warning':
        return theme.colors.warning;
      default:
        return theme.colors.textMuted;
    }
  };

  return (
    <View>
      {rows.map(({ status, count }) => {
        const content = (
          <View style={{ minHeight: touchTarget.min, justifyContent: 'center' }}>
            <View className="flex-row items-baseline justify-between">
              <Text variant="subhead" numberOfLines={1} className="flex-1 pr-md">
                {statusLabel(status)}
              </Text>
              <Text
                variant="subhead"
                style={{ fontVariant: ['tabular-nums'], fontWeight: '600' }}
              >
                {count}
              </Text>
            </View>

            {/* The track is `surfaceMuted`, not a tinted version of the fill —
                a track that shares the fill's hue reads as a partially filled
                bar even at zero. */}
            <View
              className="mt-sm overflow-hidden rounded-full bg-surface-muted"
              style={{ height: 6 }}
            >
              <View
                style={{
                  height: 6,
                  borderRadius: radius.full,
                  width: `${share(count, max) * 100}%`,
                  backgroundColor: barColor(status),
                }}
              />
            </View>
          </View>
        );

        if (!onSelectStatus) {
          return (
            <View key={status} style={{ marginBottom: spacing.md }}>
              {content}
            </View>
          );
        }

        return (
          <PressableScale
            key={status}
            accessibilityRole="button"
            accessibilityLabel={`${count} ${statusLabel(status).toLowerCase()} ${count === 1 ? 'lead' : 'leads'}, open`}
            onPress={() => onSelectStatus(status)}
            activeScale={0.99}
            style={{ marginBottom: spacing.md }}
          >
            {content}
          </PressableScale>
        );
      })}

      {onSelectStatus ? (
        <View className="flex-row items-center" style={{ marginTop: spacing.xs }}>
          <Ionicons name="information-circle-outline" size={13} color={theme.colors.textMuted} />
          <Text variant="caption" tone="muted" className="ml-xs flex-1">
            Tap a stage to see those leads.
          </Text>
        </View>
      ) : null}
    </View>
  );
}
