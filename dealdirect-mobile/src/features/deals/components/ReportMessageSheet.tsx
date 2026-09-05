import { useMutation } from '@tanstack/react-query';
import { useCallback, useEffect, useState } from 'react';
import { View } from 'react-native';

import { ApiError, call, chatEndpoints } from '@/api';
import { spacing } from '@/theme';
import type { ObjectId } from '@/types/backend/common';
import { Button, Chip, Input, Sheet, Text } from '@/ui';

/**
 * Report a message.
 *
 * The server wants a reason of at least 3 characters and keeps one report
 * per user per message: a second is answered 200 `duplicate: true`, which is
 * shown as the truth it is ("already reported"), not as an error. The
 * presets fill the field with a sentence the user can edit; free text stays
 * because a list never covers everything.
 */

const PRESETS = [
  'Asking me to pay outside DealDirect',
  'Asking for a deposit before a visit',
  'Threatening or abusive',
  'Not the owner of this property',
  'Spam or unrelated',
];

const MIN_REASON = 3;

export interface ReportMessageSheetProps {
  messageId: ObjectId | null;
  onClose: () => void;
}

export function ReportMessageSheet({ messageId, onClose }: ReportMessageSheetProps) {
  const [reason, setReason] = useState('');
  const [outcome, setOutcome] = useState<'reported' | 'duplicate' | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!messageId) return;
    setReason('');
    setOutcome(null);
    setError(null);
  }, [messageId]);

  const mutation = useMutation({
    mutationFn: (body: { messageId: ObjectId; reason: string }) =>
      call(chatEndpoints.reportMessage, { data: body }),
  });

  const submit = useCallback(async () => {
    if (!messageId) return;
    const trimmed = reason.trim();
    if (trimmed.length < MIN_REASON) {
      setError('Say a little more about what is wrong.');
      return;
    }
    setError(null);
    try {
      const response = await mutation.mutateAsync({ messageId, reason: trimmed });
      setOutcome(response.duplicate ? 'duplicate' : 'reported');
    } catch (caught) {
      if (caught instanceof ApiError) {
        setError(
          caught.code === 'OWN_MESSAGE'
            ? 'You cannot report your own message.'
            : caught.code === 'REASON_REQUIRED'
              ? 'Say a little more about what is wrong.'
              : caught.message
        );
      } else {
        setError('Could not send the report. Please try again.');
      }
    }
  }, [messageId, reason, mutation]);

  return (
    <Sheet visible={!!messageId} onClose={onClose} title="Report message" heightRatio={0.62}>
      {outcome ? (
        <View>
          <Text variant="bodyEmphasis">
            {outcome === 'reported' ? 'Thanks, we will look at it' : 'Already reported'}
          </Text>
          <Text variant="footnote" tone="secondary" className="mt-xs">
            {outcome === 'reported'
              ? 'The DealDirect team reviews reports. The other party is not told who reported.'
              : 'You reported this message earlier. It is with the team.'}
          </Text>
          <View className="mt-lg">
            <Button label="Done" onPress={onClose} />
          </View>
        </View>
      ) : (
        <View>
          <Text variant="footnote" tone="secondary" className="mb-base">
            What is wrong with this message?
          </Text>
          <View className="mb-base flex-row flex-wrap" style={{ gap: spacing.sm }}>
            {PRESETS.map((preset) => (
              <Chip
                key={preset}
                label={preset}
                selected={reason === preset}
                onPress={() => {
                  setReason(preset);
                  setError(null);
                }}
              />
            ))}
          </View>
          <Input
            label="Reason"
            placeholder="In your own words"
            value={reason}
            onChangeText={(next) => {
              setReason(next);
              setError(null);
            }}
            multiline
            maxLength={500}
            error={error ?? undefined}
          />
          <View className="mt-md">
            <Button
              label="Send report"
              loading={mutation.isPending}
              disabled={reason.trim().length < MIN_REASON}
              onPress={() => void submit()}
            />
          </View>
        </View>
      )}
    </Sheet>
  );
}
