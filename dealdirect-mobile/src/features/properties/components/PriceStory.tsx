import Ionicons from '@expo/vector-icons/Ionicons';
import { useMemo, useState } from 'react';
import { Pressable, View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
import type { PriceIntelligence } from '@/types/backend/property';
import { Text, formatPrice } from '@/ui';
import { describePriceIntelligence } from '../priceIntelligence';

/**
 * What this price has done, and how it compares.
 *
 * ---------------------------------------------------------------------------
 * THREE FACTS, NONE OF THEM ADVICE
 *
 * A price on its own is unreadable: a buyer cannot tell whether 82 lakh is a
 * bargain, a stretch or a listing nobody has wanted for four months. Three
 * facts change that, and this section carries exactly those three:
 *
 *   the last drop      the owner has already moved once
 *   how long it is up  a listing that has sat is a listing with room in it
 *   the market line    what the neighbours are asking for the same thing
 *
 * None of them is a recommendation. "Asks 8% below the Wakad median" is a
 * measurement; "a good deal" would be a claim this data cannot support, and
 * the moment the app makes one, every number on the screen becomes marketing.
 *
 * ---------------------------------------------------------------------------
 * EVERY LINE IS OPTIONAL AND THE SECTION UNMOUNTS
 *
 * Most listings will carry one of these, some will carry none, and a section
 * that renders "Price history: none" for the majority is worse than a section
 * that is not there. `describePriceIntelligence` reports `isEmpty` precisely
 * so the caller can decide not to render this at all.
 *
 * ---------------------------------------------------------------------------
 * THE HISTORY IS BEHIND A DISCLOSURE
 *
 * The last drop is the fact; the full list of changes is evidence for it. A
 * listing that has been repriced five times has a story worth reading, and one
 * that has been repriced once does not need three lines spent on it. So the
 * headline is always visible and the list is one tap away.
 */

export interface PriceStoryProps {
  intelligence: PriceIntelligence | null;
  /** Opens the locality page. Omitted when there is nowhere to send the user. */
  onOpenLocality?: (slug: string) => void;
  /**
   * Set false where the screen already says when the listing went up.
   *
   * The detail screen prints "Posted 3 days ago" under the facts, from
   * `createdAt`. `daysListed` comes from `listedAt`, which is a different
   * field and can hold a different number, and printing both is how a page
   * ends up telling the reader two ages for the same listing.
   */
  showDaysListed?: boolean;
}

export function PriceStory({
  intelligence,
  onOpenLocality,
  showDaysListed = true,
}: PriceStoryProps) {
  const theme = useTheme();
  const [showingHistory, setShowingHistory] = useState(false);

  const lines = useMemo(
    () => describePriceIntelligence(intelligence, formatPrice),
    [intelligence]
  );

  const daysListed = showDaysListed ? lines.daysListed : null;

  if (!lines.lastDrop && !daysListed && !lines.market && lines.history.length === 0) return null;

  const verdictColor =
    lines.market?.verdict === 'below'
      ? theme.colors.success
      : lines.market?.verdict === 'above'
        ? theme.colors.warning
        : theme.colors.textSecondary;

  return (
    <View style={{ gap: spacing.sm }}>
      {lines.lastDrop ? (
        <View className="flex-row items-center">
          <Ionicons name="trending-down-outline" size={16} color={theme.colors.success} />
          <Text variant="callout" className="ml-sm flex-1">
            {lines.lastDrop}
          </Text>
        </View>
      ) : null}

      {daysListed ? (
        <View className="flex-row items-center">
          <Ionicons name="calendar-outline" size={16} color={theme.colors.textMuted} />
          <Text variant="callout" tone="secondary" className="ml-sm flex-1">
            {daysListed}
          </Text>
        </View>
      ) : null}

      {lines.market ? (
        <Pressable
          accessibilityRole={onOpenLocality ? 'button' : 'text'}
          accessibilityLabel={
            onOpenLocality ? `${lines.market.text}. See locality prices.` : lines.market.text
          }
          disabled={!onOpenLocality}
          onPress={() => onOpenLocality?.(lines.market!.slug)}
          className="flex-row items-center rounded-lg active:opacity-70"
          style={{
            marginTop: spacing.xs,
            padding: spacing.sm,
            borderRadius: radius.md,
            backgroundColor: theme.colors.surfaceMuted,
          }}
        >
          <Ionicons name="stats-chart-outline" size={16} color={verdictColor} />
          <View className="ml-sm flex-1">
            <Text variant="callout" style={{ color: verdictColor }}>
              {lines.market.text}
            </Text>
            {/*
              The sample size, always. A median of six listings and a median of
              two hundred are different kinds of statement, and the reader is
              entitled to know which one they are being shown.
            */}
            <Text variant="caption" tone="muted" className="mt-xs">
              Based on {lines.market.count} asking{' '}
              {lines.market.count === 1 ? 'price' : 'prices'} on DealDirect
            </Text>
          </View>
          {onOpenLocality ? (
            <Ionicons name="chevron-forward" size={18} color={theme.colors.textMuted} />
          ) : null}
        </Pressable>
      ) : null}

      {lines.history.length > 0 ? (
        <View style={{ marginTop: spacing.xs }}>
          <Pressable
            accessibilityRole="button"
            accessibilityLabel={showingHistory ? 'Hide price history' : 'See price history'}
            accessibilityState={{ expanded: showingHistory }}
            onPress={() => setShowingHistory((current) => !current)}
            hitSlop={8}
            className="flex-row items-center active:opacity-60"
          >
            <Text variant="footnote" tone="accent">
              {showingHistory ? 'Hide price history' : 'See price history'}
            </Text>
            <Ionicons
              name={showingHistory ? 'chevron-up' : 'chevron-down'}
              size={15}
              color={theme.colors.accent}
              style={{ marginLeft: 4 }}
            />
          </Pressable>

          {showingHistory ? (
            <View style={{ marginTop: spacing.sm, gap: spacing.xs }}>
              {lines.history.map((row, index) => (
                <View
                  key={`${row.when}-${row.from}-${row.to}-${index}`}
                  className="flex-row items-center"
                >
                  <Ionicons
                    name={row.isDrop ? 'arrow-down' : 'arrow-up'}
                    size={13}
                    color={row.isDrop ? theme.colors.success : theme.colors.textMuted}
                  />
                  <Text variant="footnote" tone="secondary" className="ml-xs flex-1">
                    {row.from} to {row.to}
                  </Text>
                  {row.when ? (
                    <Text variant="caption" tone="muted">
                      {row.when}
                    </Text>
                  ) : null}
                </View>
              ))}
            </View>
          ) : null}
        </View>
      ) : null}
    </View>
  );
}
