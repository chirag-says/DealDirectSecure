import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { View } from 'react-native';

import { OwnerOnly } from '@/auth';
import { LeadPipeline, useLeadAnalytics } from '@/features/leads';
import { radius, screenPadding, scrollBottomPadding, spacing, useTheme } from '@/theme';
import type { LeadStatus } from '@/types/backend/lead';
import {
  Card,
  EmptyState,
  ErrorState,
  PressableScale,
  Refreshable,
  Screen,
  ScreenHeader,
  SectionLabel,
  Skeleton,
  Stat,
  StatRow,
  Text,
} from '@/ui';

/**
 * Lead analytics.
 *
 * ---------------------------------------------------------------------------
 * WHAT `GET /leads/analytics` ACTUALLY RETURNS, AND WHAT IT DOES NOT
 *
 * Read from `backend/controllers/leadController.js:348`, not inferred, because
 * the shape of this screen follows from it:
 *
 *   statusStats        counts per status — ALL TIME. The aggregate has no date
 *                      match, so `days` does not touch it.
 *   dailyLeads         daily counts WITHIN `days`. The only period-scoped
 *                      series in the response.
 *   leadsByProperty    top 10 listings by lead count.
 *   totalLeads         all time
 *   convertedLeads     all time
 *   conversionRate     all time, as a string from `toFixed(1)`
 *   newLeadsThisWeek   last 7 days, HARD-CODED — not derived from `days`
 *   unreadLeads        all time
 *
 * Three consequences, and each one removed something this screen might
 * otherwise have shipped:
 *
 * **No period selector.** `days` scopes exactly one field. A "Last 30 days"
 * control that changes a sparkline while five numbers above it stay still is
 * worse than no control at all: it states that the numbers are scoped when
 * they are not. Each figure is LABELLED with its own true period instead —
 * "all time", "last 7 days" — which costs a line and lies about nothing.
 *
 * **No trend arrows, no "+12% vs last period".** There is no previous-period
 * figure anywhere in the response to compare against. Computing one would mean
 * inventing it.
 *
 * **No leads-by-property table.** The data is real and unused, but an owner
 * account is capped at ONE listing server-side (see `useMyProperties`), so for
 * every owner today that table is one row restating the total. It is left
 * unrendered rather than shown as a chart of one bar; if the cap is ever
 * lifted this is the first thing to add.
 *
 * ---------------------------------------------------------------------------
 * THE COMPOSITION ANSWERS ONE QUESTION AT A TIME
 *
 *   attention   what needs doing right now, and a way to do it
 *   scale       one primary number, with the rest subordinate to it
 *   pipeline    where those leads are, and a route into each stage
 *   activity    whether anything is happening lately
 *
 * The old screen was four equal cards and a bar chart, which reads as four
 * equally important facts — so none of them led, and the owner had to decide
 * what mattered. The lead-in line decides for them, because there is exactly
 * one thing on this screen that is actionable: unread leads.
 */
function AnalyticsScreenContent() {
  const router = useRouter();
  const theme = useTheme();
  const { analytics, isLoading, error, refresh } = useLeadAnalytics(ANALYTICS_DAYS);

  const openLeads = (status?: LeadStatus) =>
    router.push(status ? `/owner/leads?status=${status}` : '/owner/leads');

  if (isLoading) return <AnalyticsSkeleton />;

  if (error) return <ErrorState title="Could not load analytics" onRetry={refresh} />;

  if (!analytics) {
    // Was `null`, which left a titled screen with a blank body and no way to
    // tell "no data yet" from "something broke".
    return (
      <EmptyState
        title="No analytics yet"
        description="Once your listing starts receiving leads, you will see the numbers here."
      />
    );
  }

  const unread = analytics.unreadLeads ?? 0;
  const total = analytics.totalLeads ?? 0;
  const thisWeek = analytics.newLeadsThisWeek ?? 0;
  const converted = analytics.convertedLeads ?? 0;
  // The controller returns this via `toFixed(1)`, so it arrives as a string on
  // the wire and as a number only when there are no leads. `Number()` covers
  // both without pretending the field is one or the other.
  const conversion = Number(analytics.conversionRate ?? 0);
  const daily = analytics.dailyLeads ?? [];

  return (
    <Refreshable
      contentContainerStyle={{
        padding: screenPadding,
        paddingBottom: scrollBottomPadding,
      }}
    >
      {/*
        THE ONE ACTIONABLE THING, FIRST.

        Unread is the only figure here an owner can do something about in the
        next minute, so it leads and it is a control rather than a statistic.
        It disappears entirely at zero — an "0 leads need attention" banner is
        chrome that exists to congratulate, and it would push the numbers down
        the page on exactly the screen where nothing is happening.
      */}
      {unread > 0 ? <AttentionBanner count={unread} onPress={() => openLeads()} /> : null}

      <SectionLabel>Your leads</SectionLabel>

      {/*
        ONE PRIMARY NUMBER, THEN THE REST.

        `emphasis` fills the tile with the accent tint — the existing `Stat`
        already carries this, so the hierarchy costs no new component. Total is
        the denominator every other figure on the screen is a fraction of,
        which is what makes it the one to lead with.

        Every value carries its own period in `detail`, because they genuinely
        differ and the difference is not guessable from the labels.
      */}
      {/* `StatRow`, even with one child: `Stat`'s body is `flex: 1`, which
          needs a row parent to mean "full width" rather than collapsing to
          zero height in a column. */}
      <View className="mt-sm">
        <StatRow>
          <Stat
            label="Total leads"
            value={total}
            detail="All time"
            emphasis
            onPress={() => openLeads()}
          />
        </StatRow>
      </View>

      <View className="mt-md">
        <StatRow>
          <Stat label="New" value={thisWeek} detail="Last 7 days" />
          <Stat
            label="Unread"
            value={unread}
            detail={unread > 0 ? 'Needs a first look' : 'All caught up'}
            onPress={unread > 0 ? () => openLeads() : undefined}
          />
        </StatRow>
      </View>

      <View className="mt-md">
        <StatRow>
          <Stat label="Converted" value={converted} detail="All time" />
          <Stat
            label="Conversion"
            value={`${conversion}%`}
            detail={total > 0 ? `${converted} of ${total}` : 'No leads yet'}
          />
        </StatRow>
      </View>

      {/*
        THE PIPELINE.

        Stage order, not count order, and every row is a route into the leads
        list filtered to it — see `LeadPipeline`. This is the bridge the two
        owner screens were missing: before it, the only way from "4 negotiating"
        to those four leads was to leave, open Leads, and find the chip.
      */}
      <View className="mt-2xl">
        <SectionLabel>Pipeline</SectionLabel>
        <Card className="mt-sm">
          <LeadPipeline statusStats={analytics.statusStats ?? {}} onSelectStatus={openLeads} />
        </Card>
      </View>

      {daily.length > 0 ? (
        <View className="mt-2xl">
          <SectionLabel>Enquiries over time</SectionLabel>
          <Card className="mt-sm">
            <DailyTrend data={daily} />
          </Card>
        </View>
      ) : null}

      <PressableScale
        accessibilityRole="button"
        accessibilityLabel="View all leads"
        onPress={() => openLeads()}
        activeScale={0.98}
        className="mt-2xl flex-row items-center justify-center"
        style={{ paddingVertical: spacing.md }}
      >
        <Text variant="callout" tone="accent">
          View all leads
        </Text>
        <Ionicons
          name="arrow-forward"
          size={16}
          color={theme.colors.accent}
          style={{ marginLeft: 6 }}
        />
      </PressableScale>
    </Refreshable>
  );
}

/**
 * Owner-gated. See `auth/components/OwnerOnly.tsx` for why a role the server
 * already enforces still needs a client-side refusal.
 */
export default function AnalyticsScreen() {
  return (
    <OwnerOnly title="Analytics">
      <Screen>
        <ScreenHeader title="Analytics" backTo="/(tabs)/profile" />
        <AnalyticsScreenContent />
      </Screen>
    </OwnerOnly>
  );
}

/** The window `dailyLeads` is aggregated over. Not exposed as a control — see
 *  the module doc for why a period selector would misrepresent this screen. */
const ANALYTICS_DAYS = 30;

/** Days of the series actually plotted. Beyond this the bars are narrower than
 *  the gaps between them and the shape stops being readable on a phone. */
const TREND_DAYS = 14;

/**
 * The lead-in.
 *
 * Accent-tinted rather than warning-toned: unread leads are opportunity, not a
 * fault, and an amber banner on a screen an owner opens to feel good about
 * their listing reads as an error they have caused.
 */
function AttentionBanner({ count, onPress }: { count: number; onPress: () => void }) {
  const theme = useTheme();

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={`${count} ${count === 1 ? 'lead needs' : 'leads need'} a first look, open leads`}
      onPress={onPress}
      activeScale={0.99}
      style={{
        flexDirection: 'row',
        alignItems: 'center',
        padding: spacing.base,
        marginBottom: spacing.xl,
        borderRadius: radius.lg,
        backgroundColor: theme.colors.accentMuted,
      }}
    >
      <Ionicons name="mail-unread-outline" size={20} color={theme.colors.accent} />
      <View className="ml-md flex-1">
        <Text variant="bodyEmphasis" tone="accent">
          {count} {count === 1 ? 'lead needs' : 'leads need'} a first look
        </Text>
        <Text variant="caption" tone="secondary" className="mt-xs">
          Nobody has opened {count === 1 ? 'it' : 'them'} yet.
        </Text>
      </View>
      <Ionicons name="chevron-forward" size={18} color={theme.colors.accent} />
    </PressableScale>
  );
}

/**
 * Enquiries per day.
 *
 * Plain `View`s sized by proportion — no chart library is installed and one
 * would be a dependency for fourteen bars. What changed from the previous
 * version is not the drawing but the LABELLING: an unlabelled row of bars is a
 * texture, and the reader could not tell whether the tallest one was two leads
 * or twenty, nor which day any bar was.
 *
 * Days with no leads are drawn as an empty track rather than skipped, so the
 * horizontal axis is time rather than a list of the days something happened —
 * a gap is information here.
 */
function DailyTrend({ data }: { data: { _id: string; count: number }[] }) {
  const theme = useTheme();

  const recent = data.slice(-TREND_DAYS);
  const max = Math.max(1, ...recent.map((day) => day.count));
  const totalInWindow = recent.reduce((sum, day) => sum + day.count, 0);

  const label = (iso: string) =>
    new Date(iso).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });

  const first = recent[0];
  const last = recent[recent.length - 1];

  return (
    <View>
      <View className="flex-row items-baseline justify-between">
        <Text variant="footnote" tone="secondary">
          {totalInWindow} {totalInWindow === 1 ? 'enquiry' : 'enquiries'}
        </Text>
        {/* The peak, so the tallest bar has a number attached to it. Without
            this the chart's vertical scale is unknowable. */}
        <Text variant="caption" tone="muted">
          Peak {max} in a day
        </Text>
      </View>

      <View
        className="mt-md flex-row items-end"
        style={{ height: 88, gap: 3 }}
        accessible
        accessibilityLabel={`Daily enquiries. ${totalInWindow} in the last ${recent.length} days, peaking at ${max} in one day.`}
      >
        {recent.map((day) => (
          <View key={day._id} className="flex-1 justify-end" style={{ height: '100%' }}>
            <View
              style={{
                // A hairline for a zero day rather than nothing: the bar's
                // absence and the chart's baseline would otherwise be the same
                // pixel, so an empty day would read as missing data.
                height: `${Math.max(2, (day.count / max) * 100)}%`,
                borderRadius: 3,
                backgroundColor:
                  day.count > 0 ? theme.colors.accent : theme.colors.borderStrong,
              }}
            />
          </View>
        ))}
      </View>

      {first && last ? (
        <View className="mt-sm flex-row justify-between">
          <Text variant="caption" tone="muted">
            {label(first._id)}
          </Text>
          <Text variant="caption" tone="muted">
            {label(last._id)}
          </Text>
        </View>
      ) : null}
    </View>
  );
}

/** Mirrors the loaded composition, so nothing jumps when the data lands. */
function AnalyticsSkeleton() {
  return (
    <View style={{ padding: screenPadding }}>
      <Skeleton height={72} radius={radius.lg} />
      <Skeleton width="34%" height={13} className="mt-xl" />
      <Skeleton height={96} radius={radius.lg} className="mt-sm" />
      <View className="mt-md flex-row" style={{ gap: spacing.md }}>
        <View className="flex-1">
          <Skeleton height={88} radius={radius.lg} />
        </View>
        <View className="flex-1">
          <Skeleton height={88} radius={radius.lg} />
        </View>
      </View>
      <Skeleton width="26%" height={13} className="mt-2xl" />
      <Skeleton height={180} radius={radius.lg} className="mt-sm" />
    </View>
  );
}
