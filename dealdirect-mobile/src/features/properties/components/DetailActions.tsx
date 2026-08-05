import Ionicons from '@expo/vector-icons/Ionicons';
import { useCallback } from 'react';
import { Alert, Linking, Pressable, Share, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { WEB_URL } from '@/config/env';
import { useTheme } from '@/theme';
import { Button, formatPrice, Text } from '@/ui';
import type { InterestState } from '../interest';
import type { PropertyDetail } from '../types';

/**
 * The action bar, pinned to the bottom of the detail screen.
 *
 * Pinned rather than placed inline because it is the only thing on this screen
 * the user is meant to DO, and the screen is long enough that an inline button
 * would sit several scrolls below where the decision is actually made.
 *
 * ---------------------------------------------------------------------------
 * WHY THE PRIMARY ACTION IS A LABELLED BUTTON AND NOT A HEART
 *
 * Marking interest notifies the owner, creates a lead against the user's name,
 * email and phone, and counts against a cap of five. A heart icon communicates
 * the opposite of every one of those: private, free, unlimited, undoable
 * without consequence. So the control is labelled, and the consequence line
 * under it says what happens before the press rather than after.
 *
 * Reversing it is offered — `DELETE /interested/:id` works — but the line does
 * not promise that undoing unsends the notification, because it does not. The
 * lead survives.
 *
 * ---------------------------------------------------------------------------
 * Calling is offered only to signed-in users. Worth being honest about what
 * that is and is not: `GET /properties/:id` is a PUBLIC endpoint and populates
 * the owner's phone and email into its response, so the number is already
 * readable by anyone who calls the API directly. The gate here is a product
 * decision about what the app encourages, not a control that protects the
 * data. Protecting it means changing what the endpoint returns.
 */

export interface DetailActionsProps {
  property: PropertyDetail;
  interest: InterestState;
  onReport: () => void;
}

export function DetailActions({ property, interest, onReport }: DetailActionsProps) {
  const insets = useSafeAreaInsets();
  const theme = useTheme();

  const phone = property.owner?.phone?.replace(/[^\d+]/g, '');
  const canCall = !!phone && !interest.requiresAuth;

  const handleCall = useCallback(async () => {
    if (!phone) return;

    const url = `tel:${phone}`;
    const supported = await Linking.canOpenURL(url);

    // A simulator and some tablets have no dialler. Failing with an
    // explanation beats a press that does nothing at all.
    if (!supported) {
      Alert.alert('Cannot place calls', `Owner's number: ${phone}`);
      return;
    }

    await Linking.openURL(url);
  }, [phone]);

  const handleShare = useCallback(() => {
    const parts = [
      property.title,
      formatPrice(property.priceRupees),
      property.locationLabel,
    ].filter(Boolean);

    // The link is included only when a web origin is configured. A share that
    // carries a guessed domain produces a dead link, which is worse than a
    // share that carries only the facts.
    const link = WEB_URL ? `${WEB_URL}/properties/${property.id}` : undefined;
    const message = link ? `${parts.join(' — ')}\n${link}` : parts.join(' — ');

    void Share.share({ message, ...(link ? { url: link } : {}) });
  }, [property]);

  return (
    <View
      className="border-t border-border bg-surface px-lg pt-md"
      style={{ paddingBottom: insets.bottom + 12 }}
    >
      {interest.error ? (
        <Text variant="footnote" tone="danger" className="mb-sm">
          {interest.error}
        </Text>
      ) : (
        <Text variant="caption" tone="muted" className="mb-sm">
          {interest.isInterested
            ? 'The owner has your contact details and can reach you.'
            : 'The owner will be notified and can contact you directly.'}
        </Text>
      )}

      <View className="flex-row items-center">
        <View className="flex-1">
          <Button
            label={interest.isInterested ? "You're interested" : "I'm interested"}
            variant={interest.isInterested ? 'secondary' : 'primary'}
            loading={interest.isPending || interest.isLoading}
            onPress={interest.toggle}
            fullWidth
            leading={
              interest.isInterested ? (
                <Ionicons name="checkmark" size={17} color={theme.colors.textPrimary} />
              ) : undefined
            }
          />
        </View>

        {canCall ? (
          <IconAction icon="call-outline" label="Call owner" onPress={handleCall} />
        ) : null}
        <IconAction icon="share-outline" label="Share listing" onPress={handleShare} />
        <IconAction icon="flag-outline" label="Report listing" onPress={onReport} />
      </View>
    </View>
  );
}

function IconAction({
  icon,
  label,
  onPress,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  onPress: () => void;
}) {
  const theme = useTheme();

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      onPress={onPress}
      hitSlop={6}
      className="ml-sm h-12 w-12 items-center justify-center rounded-xl border border-border"
      style={({ pressed }) => (pressed ? { opacity: 0.6 } : undefined)}
    >
      <Ionicons name={icon} size={20} color={theme.colors.textSecondary} />
    </Pressable>
  );
}
