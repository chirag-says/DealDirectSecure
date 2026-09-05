import Ionicons from '@expo/vector-icons/Ionicons';
import { Linking, View } from 'react-native';

import { spacing, useTheme } from '@/theme';
import type { DealCounterpart, DealRole } from '@/types/backend/deal';
import { Avatar, Button, Card, Text } from '@/ui';

/**
 * The person on the other side of the deal.
 *
 * The buyer sees the owner's phone only once the owner has engaged
 * (`contactRevealed`): a number handed out on enquiry is a number handed to
 * every enquirer, and the rule exists so an owner is reached by people they
 * have chosen to answer. The rule is rendered as one plain line, not hidden.
 *
 * The owner sees the buyer's contact at once, which is unchanged from the
 * lead: enquiring IS handing the owner your details, and the enquiry sheet
 * says so before the tap.
 *
 * Verified means the owner's identity was checked by DealDirect. Shown with
 * a shield and the word, never the shield alone.
 */

export interface CounterpartCardProps {
  counterpart: DealCounterpart | null;
  role: DealRole;
  contactRevealed: boolean;
}

export function CounterpartCard({ counterpart, role, contactRevealed }: CounterpartCardProps) {
  const theme = useTheme();

  if (!counterpart) {
    return (
      <Card>
        <Text variant="footnote" tone="muted">
          The other party&apos;s account is no longer available.
        </Text>
      </Card>
    );
  }

  const label = role === 'buyer' ? 'Owner' : 'Buyer';
  const phone = counterpart.phone?.trim() || null;
  const email = counterpart.email?.trim() || null;

  return (
    <Card>
      <View className="flex-row items-center">
        <Avatar uri={counterpart.profileImage ?? undefined} name={counterpart.name} size="md" />
        <View className="ml-base flex-1">
          <Text variant="caption" tone="muted">
            {label}
          </Text>
          <Text variant="bodyEmphasis" numberOfLines={1}>
            {counterpart.name}
          </Text>
          {counterpart.verified ? (
            <View className="mt-xs flex-row items-center">
              <Ionicons name="shield-checkmark" size={14} color={theme.colors.success} />
              <Text variant="caption" tone="success" className="ml-xs">
                Verified {label.toLowerCase()}
              </Text>
            </View>
          ) : null}
        </View>
      </View>

      {phone || email ? (
        <View className="mt-base flex-row" style={{ gap: spacing.sm }}>
          {phone ? (
            <View className="flex-1">
              <Button
                label={phone}
                variant="secondary"
                size="sm"
                fullWidth
                accessibilityLabel={`Call ${counterpart.name} on ${phone}`}
                leading={<Ionicons name="call-outline" size={15} color={theme.colors.textPrimary} />}
                onPress={() => void Linking.openURL(`tel:${phone}`)}
              />
            </View>
          ) : null}
          {email ? (
            <View className="flex-1">
              <Button
                label="Email"
                variant="secondary"
                size="sm"
                fullWidth
                accessibilityLabel={`Email ${counterpart.name}`}
                leading={<Ionicons name="mail-outline" size={15} color={theme.colors.textPrimary} />}
                onPress={() => void Linking.openURL(`mailto:${email}`)}
              />
            </View>
          ) : null}
        </View>
      ) : role === 'buyer' && !contactRevealed ? (
        <View className="mt-base flex-row items-start">
          <Ionicons
            name="lock-closed-outline"
            size={14}
            color={theme.colors.textMuted}
            style={{ marginTop: 2 }}
          />
          <Text variant="caption" tone="muted" className="ml-xs flex-1">
            Phone appears once the owner responds.
          </Text>
        </View>
      ) : null}
    </Card>
  );
}
