import { FlashList } from '@shopify/flash-list';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useState } from 'react';
import { ScrollView, View } from 'react-native';

import { OwnerOnly } from '@/auth';
import { LEAD_STATUSES, LeadCard, statusLabel, useLeads } from '@/features/leads';
import { screenPadding, scrollBottomPadding, spacing } from '@/theme';
import type { LeadStatus } from '@/types/backend/lead';
import {
  Chip,
  EmptyState,
  ErrorState,
  Screen,
  ScreenHeader,
  Skeleton,
} from '@/ui';

/**
 * The owner's leads.
 *
 * ---------------------------------------------------------------------------
 * THE BLANK REGION BETWEEN THE FILTERS AND THE LIST — fixed 2026-08-16
 *
 * Reported as "a massive empty vertical region". The cause was structural and
 * nothing to do with padding: the filter rail was a HORIZONTAL `FlatList`, and
 * React Native's `ScrollView` applies `baseHorizontal` to those, which is
 * `{ flexGrow: 1, flexShrink: 1, flexDirection: 'row', overflow: 'scroll' }`
 * (`Libraries/Components/ScrollView/ScrollView.js:1867`).
 *
 * `flexGrow: 1` in a column parent means the rail claimed every remaining
 * point of vertical space and pushed the list below it off the screen. The
 * chips drew at the top of that space, so it read as a gap under them.
 *
 * The fix is to cap it, which is exactly what `QuickFilterBar` does on the
 * Properties screen — its rail is wrapped in a plain `View`, whose own height
 * is content-driven, so the `flexGrow` inside has nothing to grow into. Same
 * pattern here. No negative margins, and nothing was moved to hide it.
 *
 * ---------------------------------------------------------------------------
 * THE SUMMARY IS A LINE, NOT A ROW OF CARDS
 *
 * Three stat pills sat above the rail — total, new, today — and between them
 * and the rail they spent about a fifth of the viewport before the first lead.
 * On a screen whose entire job is "who should I contact first", the list is the
 * content and everything above it is chrome.
 *
 * So the counts became one line under the title. The same three numbers, an
 * eighth of the height, and `new` leads the line because it is the count that
 * implies work.
 *
 * The stats block is NOT scoped by the status query — `getLeads` computes it
 * over every lead the owner has, regardless of the filter — so while a filter
 * is on, the line switches to describing the filtered view instead. A subtitle
 * reading "18 leads" above a list of one would otherwise be quietly wrong.
 *
 * ---------------------------------------------------------------------------
 * THE STATUS FILTER CAN ARRIVE FROM ANALYTICS
 *
 * `?status=` is read once on mount. That is the bridge from the pipeline rows
 * on the analytics screen — tapping "4 negotiating" lands here already
 * filtered, rather than leaving the owner to find the chip themselves. It is
 * validated against `LEAD_STATUSES` rather than trusted, so a hand-typed deep
 * link cannot set a filter no chip can clear.
 */
function LeadsScreenContent() {
  const router = useRouter();
  const route = useLocalSearchParams<{ status?: string }>();

  // Read once, on mount, and validated. Re-reading on every render would fight
  // the user: tap a chip, re-render, and the param stamps the old value back.
  const [filter, setFilter] = useState<LeadStatus | undefined>(() =>
    LEAD_STATUSES.find((status) => status === route.status)
  );

  const { leads, stats, isLoading, isRefreshing, isFetchingMore, error, refresh, loadMore } =
    useLeads(filter);

  const s = (stats ?? {}) as LeadStats;

  const openLead = (id: string) => router.push(`/owner/leads/${id}`);

  return (
    <Screen>
      <ScreenHeader
        title="Leads"
        backTo="/(tabs)/profile"
        subtitle={summaryLine(s, filter, leads.length, isLoading)}
      />

      {/*
        THE RAIL, CAPPED.

        This wrapper is the fix described in the module doc — without it the
        horizontal list inside grows to fill the screen. It is a plain `View`,
        so its height is whatever the chips come to, and `flexGrow: 1` inside
        it has nothing left to claim.
      */}
      <View>
        <ScrollView
          horizontal
          showsHorizontalScrollIndicator={false}
          contentContainerStyle={{
            paddingHorizontal: screenPadding,
            paddingBottom: spacing.md,
            gap: spacing.sm,
          }}
          keyboardShouldPersistTaps="handled"
        >
          <Chip label="All" selected={filter === undefined} onPress={() => setFilter(undefined)} />
          {LEAD_STATUSES.map((status) => (
            <Chip
              key={status}
              label={statusLabel(status)}
              selected={filter === status}
              onPress={() => setFilter(status)}
            />
          ))}
        </ScrollView>
      </View>

      {isLoading ? (
        <LeadsSkeleton />
      ) : error ? (
        <ErrorState title="Could not load leads" onRetry={refresh} />
      ) : leads.length === 0 ? (
        <EmptyState
          title={filter ? `No ${statusLabel(filter).toLowerCase()} leads` : 'No leads yet'}
          description={
            filter
              ? 'Nothing is at this stage right now. Clear the filter to see every lead.'
              : 'When a buyer enquires about your listing, they appear here with their contact details.'
          }
          // Only offered when a filter is what emptied the list. On a genuinely
          // empty pipeline "Show all leads" would lead to the same screen.
          actionLabel={filter ? 'Show all leads' : undefined}
          onAction={filter ? () => setFilter(undefined) : undefined}
        />
      ) : (
        <FlashList
          data={leads}
          keyExtractor={(item) => item._id}
          contentContainerStyle={{
            paddingHorizontal: screenPadding,
            paddingBottom: scrollBottomPadding,
          }}
          // A separator, not a container `gap`: FlashList positions cells
          // absolutely, so flex gap on the content container is inert. See
          // `PropertyList` for the full note.
          ItemSeparatorComponent={LeadSeparator}
          refreshing={isRefreshing}
          onRefresh={refresh}
          onEndReached={loadMore}
          onEndReachedThreshold={0.4}
          ListFooterComponent={
            isFetchingMore ? (
              <View style={{ paddingTop: spacing.md }}>
                <Skeleton height={112} radius={14} />
              </View>
            ) : null
          }
          renderItem={({ item }) => <LeadCard lead={item} onPress={openLead} />}
        />
      )}
    </Screen>
  );
}

/**
 * Owner-gated. See `auth/components/OwnerOnly.tsx` for why a role the server
 * already enforces still needs a client-side refusal.
 */
export default function LeadsScreen() {
  return (
    <OwnerOnly title="Leads">
      <LeadsScreenContent />
    </OwnerOnly>
  );
}

/**
 * The stats block, read from `leadController.getLeads:484`.
 *
 * It carries a count for every status plus `total` and `today`, and it is
 * computed over ALL of the owner's leads — the status filter on the query does
 * not touch it. Only the three used here are declared; the per-status counts
 * are the pipeline's job on the analytics screen and repeating them here would
 * be the duplication this pass keeps removing.
 */
interface LeadStats {
  total?: number;
  today?: number;
  new?: number;
}

/**
 * The three counts as one line, in the header's subtitle slot.
 *
 * Ordered by what implies work rather than by magnitude: new first, because it
 * is the number an owner acts on, then today, then the total as context. Zero
 * values are dropped rather than printed — "0 today" is a fact nobody needs
 * and it makes the line longer on exactly the days there is nothing to do.
 *
 * Returns undefined when the stats block has not arrived, so `ScreenHeader`
 * renders the title alone rather than an empty second line that would shift
 * the whole screen down when the data lands.
 */
function summaryLine(
  stats: LeadStats,
  filter: LeadStatus | undefined,
  shown: number,
  loading: boolean
): string | undefined {
  if (loading) return undefined;

  // Filtered: describe what is on screen, because `stats` describes what is
  // not. `shown` is what has loaded so far rather than a server total, so the
  // wording says "showing" instead of asserting a count.
  if (filter) {
    return `Showing ${shown} ${statusLabel(filter).toLowerCase()}`;
  }

  const total = stats.total;
  if (total === undefined) return undefined;

  const parts = [
    stats.new ? `${stats.new} new` : null,
    stats.today ? `${stats.today} today` : null,
  ].filter(Boolean);

  const base = `${total} ${total === 1 ? 'lead' : 'leads'}`;
  return parts.length > 0 ? `${base}  ·  ${parts.join('  ·  ')}` : base;
}

/** Module-level so the reference is stable across renders. */
const LeadSeparator = () => <View style={{ height: spacing.md }} />;

/**
 * Matches `LeadCard`'s real geometry — avatar row, two text lines, a footer
 * past a hairline — so the list does not reflow when the data lands.
 */
function LeadsSkeleton() {
  return (
    <View style={{ paddingHorizontal: screenPadding, gap: spacing.md }}>
      {[0, 1, 2, 3].map((row) => (
        <View key={row} className="overflow-hidden bg-surface" style={{ borderRadius: 14 }}>
          <View style={{ padding: spacing.base }}>
            <View className="flex-row">
              <Skeleton width={40} height={40} radius={9999} />
              <View className="ml-md flex-1">
                <Skeleton width="52%" height={16} />
                <Skeleton width="70%" height={13} className="mt-xs" />
                <Skeleton width="38%" height={15} className="mt-xs" />
              </View>
            </View>
            <Skeleton width="60%" height={12} className="mt-md" />
          </View>
        </View>
      ))}
    </View>
  );
}
