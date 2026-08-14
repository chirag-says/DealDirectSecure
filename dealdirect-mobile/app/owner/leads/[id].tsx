import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useState } from 'react';
import { Linking, Pressable, ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import {
  LEAD_STATUSES,
  statusLabel,
  useAddContactHistory,
  useLeads,
  useMarkLeadViewed,
  useUpdateLeadStatus,
} from '@/features/leads';
import type { LeadContactAction } from '@/types/backend/lead';
import { Avatar, Badge, Button, Card, Chip, ErrorState, Input, Screen, ScreenHeader, Skeleton, Text } from '@/ui';

const CONTACT_ACTIONS: LeadContactAction[] = ['called', 'emailed', 'whatsapp', 'met'];

/**
 * Lead detail. Sourced from the same `useLeads()` list the leads screen
 * already has cached rather than a dedicated by-id endpoint — none exists;
 * `GET /leads` is the only read path and this app never fetches a single lead
 * out of it separately.
 */
export default function LeadDetailScreen() {
  const router = useRouter();
  const { id } = useLocalSearchParams<{ id: string }>();
  const { leads, isLoading, error, refresh } = useLeads();
  const { markViewed } = useMarkLeadViewed();
  const { updateStatus, isPending: isUpdatingStatus } = useUpdateLeadStatus();
  const { addContact, isPending: isAddingContact, error: contactError } = useAddContactHistory();

  const lead = leads.find((l) => l._id === id);
  const [note, setNote] = useState('');

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

  const handleContact = async (action: LeadContactAction) => {
    try {
      await addContact({ id: lead._id, action, note: note.trim() || undefined });
      setNote('');
    } catch {
      // surfaced via contactError below
    }
  };

  return (
    <Screen>
      <ScreenHeader title="Lead" />

      <ScrollView contentContainerStyle={{ padding: 16, paddingBottom: 48 }}>
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

        <Card className="mt-base">
          <Text variant="footnote" tone="secondary">
            Interested in
          </Text>
          <Pressable
            accessibilityRole="button"
            onPress={() => property?._id && router.push(`/property/${property._id}`)}
          >
            <Text variant="bodyEmphasis" className="mt-xs">
              {title}
            </Text>
          </Pressable>
        </Card>

        <Card className="mt-base">
          <Text variant="bodyEmphasis" className="mb-base">
            Status
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
                loading={isAddingContact}
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
            {[...lead.contactHistory].reverse().map((entry, index) => (
              <View key={index} className="mb-sm border-b border-border pb-sm">
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
