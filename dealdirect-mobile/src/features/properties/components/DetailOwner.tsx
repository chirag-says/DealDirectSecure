import { View } from 'react-native';

import { Avatar, Card, Text } from '@/ui';
import type { PropertyOwnerContact } from '../types';

/**
 * Who posted the listing.
 *
 * The whole premise of this marketplace is that the person on the other end is
 * the owner rather than an agent, so naming them is not decoration.
 *
 * Contact controls are NOT here yet — they arrive with the interest action in
 * M4's action phase, which needs the optimistic-update path and the signed-out
 * case. Identity renders first because it is true whether or not the viewer is
 * allowed to act on it.
 *
 * The phone number and email are populated by `GET /properties/:id` but are
 * deliberately not rendered. Printing a private contact detail on a public
 * screen makes every listing a scrapeable directory; the action buttons will
 * dial or open a thread without ever displaying the value.
 *
 * `owner` is null on listings whose owner account was deleted, and on every
 * endpoint other than the detail one, which returns a bare id instead of a
 * document. Nothing renders in that case rather than an "Unknown" row.
 */

export interface DetailOwnerProps {
  owner: PropertyOwnerContact | null;
}

export function DetailOwner({ owner }: DetailOwnerProps) {
  if (!owner) return null;

  return (
    <Card bordered={false} radius="xl" className="flex-row items-center">
      <Avatar uri={owner.profileImage} name={owner.name} size="md" />

      <View className="ml-base flex-1">
        <Text variant="caption" tone="muted">
          Posted by
        </Text>
        <Text variant="bodyEmphasis" numberOfLines={1}>
          {owner.name ?? 'Owner'}
        </Text>
      </View>
    </Card>
  );
}
