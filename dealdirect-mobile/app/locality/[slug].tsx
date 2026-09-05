import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams } from 'expo-router';
import { useEffect, useMemo, useRef, useState } from 'react';
import { ScrollView, View } from 'react-native';

import { track } from '@/analytics';
import {
  TrendBars,
  configurationHeading,
  formatMedian,
  formatQoq,
  formatRange,
  formatSampleLine,
  useLocality,
} from '@/features/locality';
import { radius, screenPadding, scrollBottomPadding, spacing, useTheme } from '@/theme';
import type { LocalityListingType } from '@/types/backend/locality';
import {
  EmptyState,
  ErrorState,
  Screen,
  ScreenHeader,
  Segmented,
  Skeleton,
  Text,
  formatPrice,
} from '@/ui';

/**
 * What homes in one locality are asking.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS PAGE IS ALLOWED TO CLAIM
 *
 * Medians of ASKING prices from DealDirect listings, per quarter, published
 * only where there are at least five of them. Not sale prices, not a
 * valuation, not an index. Every large portal in this market publishes
 * something that looks like this and most of them let the reader believe it is
 * transaction data. The footer here says plainly what it is, and the sample
 * count sits under the headline number rather than in a tooltip, because a
 * median of six and a median of two hundred are different kinds of statement.
 *
 * ---------------------------------------------------------------------------
 * NOT ENOUGH DATA IS AN EMPTY STATE
 *
 * Below the sample floor the server 404s, and that is the correct answer to
 * "what do 2 BHKs go for in this lane" when four of them are listed. It
 * renders as "Not enough listings here yet", never as an error, and never as a
 * made-up number.
 *
 * The listing type is a segmented control rather than two routes: sale and
 * rent are the same question about the same place, and the answer for one is
 * frequently absent while the other is fine.
 */
export default function LocalityScreen() {
  const theme = useTheme();
  const { slug, listingType: initialType } = useLocalSearchParams<{
    slug: string;
    listingType?: string;
  }>();

  const [listingType, setListingType] = useState<LocalityListingType>(
    initialType === 'rent' ? 'rent' : 'sale'
  );

  const { locality, isLoading, isMissing, error, refresh } = useLocality(slug, listingType);

  // One event per slug per mount. Switching sale and rent is the same visit.
  const reported = useRef<string | null>(null);
  useEffect(() => {
    if (!slug || reported.current === slug) return;
    reported.current = slug;
    track('locality_view', { slug });
  }, [slug]);

  const headline = locality?.headline;

  const median = useMemo(
    () => formatMedian(headline?.medianAsking, formatPrice),
    [headline?.medianAsking]
  );
  const range = useMemo(
    () => formatRange(headline?.p25, headline?.p75, formatPrice),
    [headline?.p25, headline?.p75]
  );
  const qoq = useMemo(() => formatQoq(headline?.qoqPct), [headline?.qoqPct]);

  const qoqColor =
    qoq?.direction === 'up'
      ? theme.colors.warning
      : qoq?.direction === 'down'
        ? theme.colors.success
        : theme.colors.textSecondary;

  return (
    <Screen edges={['top']}>
      <ScreenHeader title={locality?.locality ?? 'Locality prices'} backTo="/(tabs)" />

      <View style={{ paddingHorizontal: screenPadding, paddingBottom: spacing.md }}>
        <Segmented
          options={LISTING_TYPES}
          value={listingType}
          onChange={setListingType}
        />
      </View>

      {isLoading ? (
        <View style={{ paddingHorizontal: screenPadding, gap: spacing.md }}>
          <Skeleton width="55%" height={34} />
          <Skeleton width="70%" height={16} />
          <Skeleton height={120} radius={radius.lg} />
          <Skeleton height={140} radius={radius.lg} />
        </View>
      ) : isMissing ? (
        <EmptyState
          icon={
            <View
              className="items-center justify-center rounded-full"
              style={{ width: 72, height: 72, backgroundColor: theme.colors.surfaceMuted }}
            >
              <Ionicons name="stats-chart-outline" size={30} color={theme.colors.textMuted} />
            </View>
          }
          title="Not enough listings here yet"
          description={
            listingType === 'sale'
              ? 'We only publish a median once there are enough homes for sale in a locality for it to mean something. Try rentals, or come back as more listings arrive.'
              : 'We only publish a median once there are enough rentals in a locality for it to mean something. Try homes for sale, or come back as more listings arrive.'
          }
        />
      ) : error ? (
        <ErrorState title="Could not load prices for this locality" onRetry={refresh} />
      ) : locality && headline ? (
        <ScrollView
          contentContainerStyle={{
            paddingHorizontal: screenPadding,
            paddingBottom: scrollBottomPadding,
          }}
          showsVerticalScrollIndicator={false}
        >
          {/* The headline. One number, and immediately under it what it is
              made of — the sample size is not a footnote to a median. */}
          <Text variant="display" tone="accent">
            {median ?? '—'}
          </Text>
          <Text variant="footnote" tone="secondary" className="mt-xs">
            {formatSampleLine(headline.count, locality.period)}
          </Text>

          {qoq ? (
            <View className="mt-sm flex-row items-center">
              <Ionicons
                name={
                  qoq.direction === 'up'
                    ? 'trending-up-outline'
                    : qoq.direction === 'down'
                      ? 'trending-down-outline'
                      : 'remove-outline'
                }
                size={16}
                color={qoqColor}
              />
              <Text variant="callout" className="ml-xs" style={{ color: qoqColor }}>
                {qoq.text}
              </Text>
            </View>
          ) : null}

          {range ? (
            <Text variant="callout" tone="secondary" className="mt-sm">
              {range}
            </Text>
          ) : null}

          {headline.medianPerSqft && headline.medianPerSqft > 0 ? (
            <Text variant="footnote" tone="muted" className="mt-xs">
              Around {formatPrice(headline.medianPerSqft)} per sq.ft
            </Text>
          ) : null}

          {locality.trend.length > 0 ? (
            <View className="mt-2xl">
              <Text variant="bodyEmphasis">By quarter</Text>
              <View className="mt-md">
                <TrendBars trend={locality.trend} />
              </View>
            </View>
          ) : null}

          {locality.byConfiguration.length > 0 ? (
            <View className="mt-2xl">
              <Text variant="bodyEmphasis">By configuration</Text>

              <View className="mt-md rounded-xl bg-surface">
                {locality.byConfiguration.map((row, index) => {
                  const rowMedian = formatMedian(row.medianAsking, formatPrice);
                  const rowRange = formatRange(row.p25, row.p75, formatPrice);
                  const rowQoq = formatQoq(row.qoqPct);

                  return (
                    <View
                      key={`${row.bhk}-${index}`}
                      className="px-md py-md"
                      style={
                        index > 0
                          ? { borderTopWidth: 1, borderTopColor: theme.colors.border }
                          : undefined
                      }
                    >
                      <View className="flex-row items-baseline">
                        <Text variant="body" className="flex-1">
                          {configurationHeading(row.bhk)}
                        </Text>
                        <Text variant="bodyEmphasis">{rowMedian ?? '—'}</Text>
                      </View>

                      <View className="mt-xs flex-row items-baseline">
                        <Text variant="caption" tone="muted" className="flex-1">
                          {row.count} {row.count === 1 ? 'listing' : 'listings'}
                          {rowRange ? ` · ${rowRange.replace('Most ask between ', '')}` : ''}
                        </Text>
                        {rowQoq ? (
                          <Text variant="caption" tone="muted">
                            {rowQoq.text.replace(' on the previous quarter', '')}
                          </Text>
                        ) : null}
                      </View>
                    </View>
                  );
                })}
              </View>
            </View>
          ) : null}

          {/*
            THE DISCLOSURE. Not small print, and not optional.

            It says what the number is (asking, not sold), where it comes from
            (DealDirect listings only), and why some localities have no page at
            all (the sample floor). A reader who takes one of these medians to
            a negotiation deserves to know all three.
          */}
          <View
            className="mt-2xl rounded-xl bg-surface-muted"
            style={{ padding: spacing.base, borderRadius: radius.lg }}
          >
            <Text variant="caption" tone="muted">
              These are asking prices from listings on DealDirect in {locality.locality},{' '}
              {locality.city} — what owners are asking, not what homes sold for. We publish a
              locality only once it has at least {locality.sampleFloor} listings in the quarter, so
              some areas will not appear here at all.
            </Text>
          </View>
        </ScrollView>
      ) : (
        <EmptyState
          title="Nothing to show for this locality"
          description="There is no published price data at this address."
        />
      )}
    </Screen>
  );
}

const LISTING_TYPES = [
  { label: 'For sale', value: 'sale' as const },
  { label: 'For rent', value: 'rent' as const },
];
