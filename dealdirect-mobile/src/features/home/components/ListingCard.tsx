import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
import { PressableScale, Text } from '@/ui';

/**
 * The posting and owner surface on Home, in one card that adapts.
 *
 * ---------------------------------------------------------------------------
 * THIS IS WHAT THE DOCK'S POST BUTTON BECAME
 *
 * A raised, permanent Post action sat in the tab bar until 2026-08-24. It was
 * removed because an owner account is capped at ONE listing, enforced
 * server-side in a transaction: a buyer pressing it met an upgrade wall, and an
 * owner who already had a listing would have been refused. A button that
 * cannot work for most of the people who can press it is the worst possible
 * occupant of a permanent slot.
 *
 * A card can say something different to each of them, which is the whole
 * argument for moving it here:
 *
 *   guest             what listing costs and that it is direct — the one place
 *                     on Home where the product's proposition is stated, and
 *                     only because it is the answer to "should I tap this".
 *   buyer             becoming an owner takes a phone verification.
 *   owner, no listing post it.
 *   owner, listed     their listing and their leads, which is the thing an
 *                     owner opens the app for once the posting is done.
 *
 * ---------------------------------------------------------------------------
 * NO INVENTED METRICS
 *
 * The listed state shows the lead count and nothing else, because the lead
 * count is what `GET /leads` actually returns alongside the list. There is no
 * per-period view series, no listing-quality score and no response-time
 * statistic in the backend today; a card claiming any of them would be
 * decoration that happens to look like data.
 */

export type ListingCardState =
  | { kind: 'guest' }
  | { kind: 'buyer' }
  | { kind: 'ownerEmpty' }
  | { kind: 'ownerListed'; newLeads: number | null };

export interface ListingCardProps {
  state: ListingCardState;
  onPress: () => void;
}

export function ListingCard({ state, onPress }: ListingCardProps) {
  const theme = useTheme();
  const copy = COPY[state.kind];

  const detail =
    state.kind === 'ownerListed'
      ? state.newLeads === null
        ? 'Your listing and its enquiries'
        : state.newLeads > 0
          ? `${state.newLeads} new ${state.newLeads === 1 ? 'enquiry' : 'enquiries'} to respond to`
          : 'No new enquiries right now'
      : copy.detail;

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={copy.title}
      onPress={onPress}
      activeScale={0.985}
      style={{
        flexDirection: 'row',
        alignItems: 'center',
        borderRadius: radius.lg,
        borderWidth: 1,
        borderColor: theme.colors.border,
        backgroundColor: theme.colors.surface,
        padding: spacing.base,
      }}
    >
      <View
        className="items-center justify-center"
        style={{
          width: 40,
          height: 40,
          borderRadius: radius.full,
          backgroundColor: theme.colors.brandMuted,
        }}
      >
        <Ionicons name={copy.icon} size={20} color={theme.colors.brand} />
      </View>

      <View className="ml-base flex-1">
        <Text variant="bodyEmphasis" numberOfLines={1}>
          {copy.title}
        </Text>
        <Text variant="caption" tone="secondary" numberOfLines={2} className="mt-xs">
          {detail}
        </Text>
      </View>

      <Ionicons name="chevron-forward" size={20} color={theme.colors.textMuted} />
    </PressableScale>
  );
}

const COPY: Record<
  ListingCardState['kind'],
  { title: string; detail: string; icon: keyof typeof Ionicons.glyphMap }
> = {
  guest: {
    title: 'List your property',
    detail: 'Free to post, and buyers contact you directly.',
    icon: 'add-circle-outline',
  },
  buyer: {
    title: 'List your property',
    detail: 'Verify your phone number to post a listing.',
    icon: 'add-circle-outline',
  },
  ownerEmpty: {
    title: 'Post your listing',
    detail: 'Owner accounts can hold one active listing.',
    icon: 'add-circle-outline',
  },
  ownerListed: {
    title: 'Your listing',
    detail: 'Your listing and its enquiries',
    icon: 'home-outline',
  },
};
