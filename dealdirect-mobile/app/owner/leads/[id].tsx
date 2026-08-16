import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useState } from 'react';
import { Linking, ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import { OwnerOnly } from '@/auth';
import {
  LEAD_STATUSES,
  statusLabel,
  useAddContactHistory,
  useLeads,
  useMarkLeadViewed,
  useUpdateLeadStatus,
} from '@/features/leads';
import type { LeadContactAction } from '@/types/backend/lead';
import { relativeDay } from '@/lib';
import { screenPadding, scrollBottomPadding } from '@/theme';
import {
  Avatar,
  Badge,
  Button,
  Card,
  Chip,
  ErrorState,
  Input,
  PriceLabel,
  Screen,
  ScreenHeader,
  Skeleton,
  Text,
} from '@/ui';

const CONTACT_ACTIONS: LeadContactAction[] = ['called', 'emailed', 'whatsapp', 'met'];

/**
 * Lead detail. Sourced from the same `useLeads()` list the leads screen
 * already has cached rather than a dedicated by-id endpoint — none exists;
 * `GET /leads` is the only read path and this app never fetches a single lead
 * out of it separately.
 */
function LeadDetailScreenContent() {
  const router = useRouter();
  const { id } = useLocalSearchParams<{ id: string }>();
  const { leads, isLoading, error, refresh } = useLeads();
  const { markViewed } = useMarkLeadViewed();
  const { updateStatus, isPending: isUpdatingStatus } = useUpdateLeadStatus();
  const { addContact, isPending: isAddingContact, error: contactError } = useAddContactHistory();

  const lead = leads.find((l) => l._id === id);
  const [note, setNote] = useState('');
  /**
   * Which contact action is in flight.
   *
   * `isAddingContact` is one flag for one mutation, so passing it to all four
   * buttons spun all four when any one was pressed — the owner could not tell
   * which action they had actually logged. The mutation stays single; the
   * screen remembers which button asked for it.
   */
  const [pendingAction, setPendingAction] = useState<LeadContactAction | null>(null);

  useEffect(() => {
    if (lead && !lead.isViewed) markViewed(lead._id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lead?._id]);

  if (isLoading && !lead) {
    return (
      <Screen>
        <View className="p-base">
          <Skeleton height={300} radius={16} />
        </View>
      </Screen>
    );
  }

  if (error || !lead) {
    return (
      <Screen>
        <ErrorState title="Could not load this lead" onRetry={refresh} />
      </Screen>
    );
  }

  const property = typeof lead.property === 'object' ? lead.property : undefined;
  const title = property?.title ?? lead.propertySnapshot?.title ?? 'Listing';
  const price = property?.price ?? lead.propertySnapshot?.price;
  const place = [lead.propertySnapshot?.locality, lead.propertySnapshot?.city]
    .filter(Boolean)
    .join(', ');
  // The same helper and the same register the list row uses, so "3 days ago"
  // means the same thing on both screens.
  const enquiredAt = relativeDay(lead.createdAt);

  const handleContact = async (action: LeadContactAction) => {
    if (pendingAction) return;
    setPendingAction(action);
    try {
      await addContact({ id: lead._id, action, note: note.trim() || undefined });
      setNote('');
    } catch {
      // surfaced via contactError below
    } finally {
      setPendingAction(null);
    }
  };

  return (
    <Screen>
      {/* Back to the list, not `ScreenHeader`'s `/(tabs)` fallback. */}
      <ScreenHeader title="Lead" backTo="/owner/leads" />

      <ScrollView
        contentContainerStyle={{ padding: screenPadding, paddingBottom: scrollBottomPadding }}
      >
        <Card className="flex-row items-center">
          <Avatar uri={lead.userSnapshot.profileImage} name={lead.userSnapshot.name} size="lg" />
          <View className="ml-base flex-1">
            <Text variant="title3">{lead.userSnapshot.name}</Text>
            <Text variant="footnote" tone="secondary">
              {lead.userSnapshot.email}
            </Text>
            {lead.userSnapshot.phone ? (
              <Text variant="footnote" tone="secondary">
                {lead.userSnapshot.phone}
              </Text>
            ) : null}
            {/*
              WHEN, carried over from the list row.

              The row an owner taps to get here shows name, listing, price and
              recency. Landing on a screen that drops two of those makes the
              detail read as a different record from the one that was tapped.
              Status is not repeated as a badge here because the chip row below
              already IS the status - its selected chip states it and edits it,
              and a read-only badge saying the same thing would be the
              duplication this pass keeps removing.
            */}
            {enquiredAt ? (
              <Text variant="caption" tone="muted" className="mt-xs">
                Enquired {enquiredAt}
              </Text>
            ) : null}
          </View>
        </Card>

        <View className="mt-base flex-row">
          {lead.userSnapshot.phone ? (
            <Button
              label="Call"
              variant="secondary"
              size="sm"
              className="mr-sm flex-1"
              onPress={() => Linking.openURL(`tel:${lead.userSnapshot.phone}`)}
            />
          ) : null}
          <Button
            label="Email"
            variant="secondary"
            size="sm"
            className="flex-1"
            onPress={() => Linking.openURL(`mailto:${lead.userSnapshot.email}`)}
          />
        </View>

        {/*
          The listing, with its price - the third line of the list row, which
          this screen was dropping. `Card`'s own `onPress` rather than a bare
          `Pressable` around the text: that one had no accessible name and gave
          no feedback on touch, and it made only the title tappable rather than
          the card the user aims at.
        */}
        <Card
          className="mt-base"
          onPress={property?._id ? () => router.push(`/property/${property._id}`) : undefined}
          accessibilityLabel={`Open listing ${title}`}
        >
          <Text variant="footnote" tone="secondary">
            Interested in
          </Text>
          <Text variant="bodyEmphasis" className="mt-xs" numberOfLines={2}>
            {title}
          </Text>
          <View className="mt-xs flex-row items-center justify-between">
            {price ? <PriceLabel price={price} variant="subhead" numberOfLines={1} /> : <View />}
            {place ? (
              <Text variant="caption" tone="muted" numberOfLines={1} className="ml-sm flex-1 text-right">
                {place}
              </Text>
            ) : null}
          </View>
        </Card>

        <Card className="mt-base">
          {/* A verb, because this block is the editor rather than a second
              statement of a status the header already carries. */}
          <Text variant="bodyEmphasis">Move to stage</Text>
          <Text variant="caption" tone="muted" className="mb-base mt-xs">
            The buyer is not notified when you change this.
          </Text>
          <View className="flex-row flex-wrap">
            {LEAD_STATUSES.map((status) => (
              <Chip
                key={status}
                label={statusLabel(status)}
                selected={lead.status === status}
                disabled={isUpdatingStatus}
                onPress={() => updateStatus({ id: lead._id, status })}
                className="mb-sm mr-sm"
              />
            ))}
          </View>
        </Card>

        <Card className="mt-base">
          <Text variant="bodyEmphasis" className="mb-base">
            Log contact
          </Text>
          <Input
            label="Note (optional)"
            value={note}
            onChangeText={setNote}
            placeholder="What did you discuss?"
            multiline
          />
          <View className="mt-base flex-row flex-wrap">
            {CONTACT_ACTIONS.map((action) => (
              <Button
                key={action}
                label={action.charAt(0).toUpperCase() + action.slice(1)}
                variant="secondary"
                size="sm"
                className="mb-sm mr-sm"
                loading={pendingAction === action}
                disabled={isAddingContact && pendingAction !== action}
                onPress={() => void handleContact(action)}
              />
            ))}
          </View>
          {contactError instanceof ApiError ? (
            <Text variant="footnote" tone="danger">
              {contactError.message}
            </Text>
          ) : null}
        </Card>

        {lead.contactHistory && lead.contactHistory.length > 0 ? (
          <Card className="mt-base">
            <Text variant="bodyEmphasis" className="mb-base">
              History
            </Text>
            {/* Keyed on the entry's own timestamp and action, not the array
                index — a new contact logged at the top of a reversed list
                shifts every index below it, so React reconciles the wrong
                rows. */}
            {[...lead.contactHistory].reverse().map((entry) => (
              <View
                key={`${entry.date}-${entry.action ?? 'contact'}`}
                className="mb-sm border-b border-border pb-sm"
              >
                <View className="flex-row items-center justify-between">
                  <Badge label={entry.action ?? 'Contact'} tone="neutral" />
                  <Text variant="caption" tone="muted">
                    {new Date(entry.date).toLocaleDateString('en-IN', { dateStyle: 'medium' })}
                  </Text>
                </View>
                {entry.note ? (
                  <Text variant="footnote" className="mt-xs">
                    {entry.note}
                  </Text>
                ) : null}
              </View>
            ))}
          </Card>
        ) : null}
      </ScrollView>
    </Screen>
  );
}

/**
 * Owner-gated. See `auth/components/OwnerOnly.tsx` for why a role the
 * server already enforces still needs a client-side refusal: without it a
 * buyer who reaches this route is shown an error state for something that
 * is not an error.
 */
export default function LeadDetailScreen() {
  return (
    <OwnerOnly title="Lead">
      <LeadDetailScreenContent />
    </OwnerOnly>
  );
}
