import Ionicons from '@expo/vector-icons/Ionicons';
import { memo } from 'react';
import { View } from 'react-native';

import { relativeDay } from '@/lib';
import { radius, spacing, useTheme } from '@/theme';
import type { Lead } from '@/types/backend/lead';
import { Avatar, Badge, PressableScale, PriceLabel, Text } from '@/ui';
import { statusLabel, statusTone } from '../status';

/**
 * One lead, as a row an owner can triage from.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE ROW HAS TO ANSWER, IN ORDER
 *
 *   who        the person, which is the only thing here that is a person
 *   what       the listing they enquired about, and its price
 *   when       how long they have been waiting — the urgency signal
 *   where      which stage they are at
 *
 * The row this replaces carried the name, the listing, the price and the
 * status — and the status TWICE, once as a "New" badge beside the name and
 * again as a status badge under the price. Two badges saying the same thing on
 * a 90pt row is the loudest possible way to say nothing, and it cost the slot
 * where the age of the lead should have been.
 *
 * ---------------------------------------------------------------------------
 * UNREAD IS A WEIGHT, NOT A BADGE
 *
 * `isViewed` was a second pill competing with the status pill. It is now the
 * left rail and the name's weight, which is the convention every mail client
 * uses and the one users already know: an unread thing is heavier and marked
 * at the edge, not labelled.
 *
 * That frees the top-right for the ONE badge — the stage — and the bottom line
 * for recency. It also means unread survives being read at a glance: a column
 * of rows shows its unread ones by their rail, without the reader parsing a
 * single word.
 *
 * Not colour-only: the rail is paired with a heavier name, and the status is a
 * `Badge` whose label is the status in words.
 *
 * ---------------------------------------------------------------------------
 * RECENCY IS `relativeDay`, NOT A NEW FORMATTER
 *
 * `lib/relativeTime.ts` already answers this exact question in this exact
 * register ("just now", "yesterday", "3 days ago", then a date past five
 * weeks), and its docstring explains why a terse variant exists separately for
 * tight metadata slots. This line is the whole of what it says, so the long
 * form is right.
 *
 * ---------------------------------------------------------------------------
 * NO SCORING, NO PRIORITY, NO "HOT"
 *
 * The backend supplies `isViewed`, `status`, `createdAt` and `contactHistory`.
 * Those are facts. Ranking them into a priority number would be a model this
 * product has not agreed to and cannot explain to the owner acting on it, so
 * the row shows the signals and lets the owner rank.
 */

/** The unread rail. Narrow enough to read as an edge marker rather than a bar. */
const RAIL_WIDTH = 3;

export interface LeadCardProps {
  lead: Lead;
  onPress: (id: string) => void;
}

function LeadCardComponent({ lead, onPress }: LeadCardProps) {
  const theme = useTheme();

  const property = typeof lead.property === 'object' ? lead.property : undefined;
  const title = property?.title ?? lead.propertySnapshot?.title ?? 'Listing';
  const price = property?.price ?? lead.propertySnapshot?.price;

  // Locality and BHK come from the snapshot taken at enquiry time, so they
  // describe the listing as it was when the lead was created rather than as it
  // is now. That is the correct reading for a CRM record.
  const place = [lead.propertySnapshot?.locality, lead.propertySnapshot?.city]
    .filter(Boolean)
    .join(', ');
  const config = lead.propertySnapshot?.bhk;

  const unread = lead.isViewed === false;
  const when = relativeDay(lead.createdAt);
  const contacts = lead.contactHistory?.length ?? 0;

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={[
        unread ? 'Unread lead' : 'Lead',
        lead.userSnapshot.name,
        title,
        statusLabel(lead.status),
        when ?? undefined,
      ]
        .filter(Boolean)
        .join(', ')}
      onPress={() => onPress(lead._id)}
      activeScale={0.99}
      style={{
        flexDirection: 'row',
        borderRadius: radius.lg,
        backgroundColor: theme.colors.surface,
        overflow: 'hidden',
        shadowColor: '#000',
        shadowOpacity: 0.06,
        shadowRadius: 10,
        shadowOffset: { width: 0, height: 3 },
        elevation: 2,
      }}
    >
      {/* The unread rail. Rendered as a sibling at full height rather than as a
          border, so it cannot be clipped by the card's own radius on one end
          and not the other. */}
      <View
        style={{
          width: RAIL_WIDTH,
          backgroundColor: unread ? theme.colors.accent : 'transparent',
        }}
      />

      <View style={{ flex: 1, padding: spacing.base }}>
        <View className="flex-row items-start">
          <Avatar uri={lead.userSnapshot.profileImage} name={lead.userSnapshot.name} />

          <View className="ml-md flex-1">
            {/*
              Name and stage on one line. The name wraps to two — people have
              long names and truncating one is worse than a second line — and
              the badge is `flexShrink: 0` so it never gets squeezed to make
              room for that.
            */}
            <View className="flex-row items-start justify-between">
              <Text
                variant={unread ? 'bodyEmphasis' : 'body'}
                numberOfLines={2}
                className="flex-1 pr-sm"
              >
                {lead.userSnapshot.name}
              </Text>
              <View style={{ flexShrink: 0 }}>
                <Badge label={statusLabel(lead.status)} tone={statusTone(lead.status)} />
              </View>
            </View>

            <Text variant="footnote" tone="secondary" numberOfLines={1} className="mt-xs">
              {[config, place].filter(Boolean).join(' · ') || title}
            </Text>

            {price ? (
              <PriceLabel price={price} variant="subhead" numberOfLines={1} className="mt-xs" />
            ) : null}
          </View>
        </View>

        {/*
          The footer: when, and whether anything has been done about it. Past a
          hairline because it is metadata ABOUT the lead rather than part of
          it, and it is the line an owner scans down the list to triage by.
        */}
        {when || contacts > 0 ? (
          <View
            className="mt-md flex-row items-center"
            style={{
              paddingTop: spacing.sm,
              borderTopWidth: 1,
              borderTopColor: theme.colors.border,
            }}
          >
            <Ionicons
              name={contacts > 0 ? 'checkmark-circle-outline' : 'time-outline'}
              size={13}
              color={contacts > 0 ? theme.colors.success : theme.colors.textMuted}
            />
            <Text variant="caption" tone="muted" numberOfLines={1} className="ml-xs flex-1">
              {[
                when ? `Enquired ${when}` : null,
                contacts > 0
                  ? `${contacts} contact${contacts === 1 ? '' : 's'} logged`
                  : 'Not contacted yet',
              ]
                .filter(Boolean)
                .join('  ·  ')}
            </Text>
            <Ionicons name="chevron-forward" size={16} color={theme.colors.textMuted} />
          </View>
        ) : null}
      </View>
    </PressableScale>
  );
}

export const LeadCard = memo(LeadCardComponent);
