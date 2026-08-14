import { View } from 'react-native';

import { statusLabel, statusTone, useLeadAnalytics } from '@/features/leads';
import { screenPadding, scrollBottomPadding } from '@/theme';
import type { LeadStatus } from '@/types/backend/lead';
import {
  Badge,
  Card,
  EmptyState,
  ErrorState,
  Refreshable,
  Screen,
  ScreenHeader,
  Skeleton,
  Stat,
  StatRow,
  Text,
} from '@/ui';

/**
 * Lead analytics. No chart library is added for this — the mobile app has
 * none installed, and a dependency for five numbers and a status breakdown
 * is not worth it. Bars are plain `View`s sized by proportion.
 */
export default function AnalyticsScreen() {
  const { analytics, isLoading, error, refresh } = useLeadAnalytics(30);

  return (
    <Screen>
      <ScreenHeader title="Analytics" backTo="/(tabs)/profile" />

      {isLoading ? (
        <View className="px-base">
          <Skeleton height={300} radius={16} />
        </View>
      ) : error ? (
        <ErrorState title="Could not load analytics" onRetry={refresh} />
      ) : !analytics ? (
        // Was `null`, which left a titled screen with a blank body and no way
        // to tell "no data yet" from "something broke".
        <EmptyState
          title="No analytics yet"
          description="Once your listing starts receiving leads, you will see the numbers here."
        />
      ) : (
        <Refreshable
          contentContainerStyle={{
            padding: screenPadding,
            paddingBottom: scrollBottomPadding,
          }}
        >
          <StatRow>
            <Stat label="Total leads" value={analytics.totalLeads} emphasis />
            <Stat label="This week" value={analytics.newLeadsThisWeek} />
          </StatRow>
          <View className="mt-md">
            <StatRow>
              <Stat label="Unread" value={analytics.unreadLeads} />
              <Stat
                label="Conversion"
                value={`${Math.round((analytics.conversionRate ?? 0) * 100) / 100}%`}
              />
            </StatRow>
          </View>
          <View className="mb-base" />

          <Card>
            <Text variant="bodyEmphasis" className="mb-base">
              By status
            </Text>
            <StatusBreakdown statusStats={analytics.statusStats} />
          </Card>

          {analytics.dailyLeads?.length > 0 ? (
            <Card className="mt-base">
              <Text variant="bodyEmphasis" className="mb-base">
                Last 30 days
              </Text>
              <DailyTrend data={analytics.dailyLeads} />
            </Card>
          ) : null}
        </Refreshable>
      )}
    </Screen>
  );
}

function StatusBreakdown({ statusStats }: { statusStats: Partial<Record<LeadStatus, number>> }) {
  const entries = Object.entries(statusStats) as [LeadStatus, number][];
  const max = Math.max(1, ...entries.map(([, count]) => count ?? 0));

  return (
    <View>
      {entries.map(([status, count]) => (
        <View key={status} className="mb-base">
          <View className="mb-xs flex-row items-center justify-between">
            <Badge label={statusLabel(status)} tone={statusTone(status)} />
            <Text variant="footnote" tone="secondary">
              {count ?? 0}
            </Text>
          </View>
          <View className="h-2 overflow-hidden rounded-full bg-surface-muted">
            <View
              className="h-2 rounded-full bg-accent"
              style={{ width: `${Math.max(4, ((count ?? 0) / max) * 100)}%` }}
            />
          </View>
        </View>
      ))}
    </View>
  );
}

function DailyTrend({ data }: { data: { _id: string; count: number }[] }) {
  const max = Math.max(1, ...data.map((d) => d.count));
  const recent = data.slice(-14);

  return (
    <View className="flex-row items-end" style={{ height: 100 }}>
      {recent.map((day) => (
        <View key={day._id} className="mr-xs flex-1 items-center justify-end" style={{ height: '100%' }}>
          <View
            className="w-full rounded-t bg-accent"
            style={{ height: `${Math.max(4, (day.count / max) * 100)}%` }}
          />
        </View>
      ))}
    </View>
  );
}
