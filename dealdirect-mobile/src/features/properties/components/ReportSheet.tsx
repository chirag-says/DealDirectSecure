import { useMutation } from '@tanstack/react-query';
import { useCallback, useState } from 'react';
import { View } from 'react-native';

import { ApiError, call, propertiesEndpoints } from '@/api';
import { useAuth } from '@/auth';
import type { ObjectId } from '@/types/backend/common';
import { Button, Chip, Input, Sheet, Text } from '@/ui';

/**
 * Report a listing.
 *
 * The backend requires a `reason` of at least 10 characters after trimming and
 * rejects anything shorter with a 400. Rather than let a user write "fake" and
 * be told off, the common reasons are offered as chips that fill the field
 * with a full sentence, which they can then edit. Free text stays available
 * because the preset list will never cover everything.
 *
 * The controller takes `reason` ONLY. An earlier contract declared a `details`
 * field; it was never read, and sending it would have silently discarded
 * whatever the user typed there.
 *
 * A second report of the same listing while one is pending also returns 400,
 * with a message saying so. That is shown as-is rather than as an error: it is
 * a correct answer to a reasonable action, and the user's report is already
 * doing its job.
 */

const PRESET_REASONS = [
  'This listing appears to be fake',
  'The photos do not match the property',
  'The price is misleading',
  'This property is already sold or rented',
  'The owner is unreachable or unresponsive',
  'This listing contains offensive content',
];

const MIN_REASON_LENGTH = 10;

export interface ReportSheetProps {
  propertyId: ObjectId;
  visible: boolean;
  onClose: () => void;
}

export function ReportSheet({ propertyId, visible, onClose }: ReportSheetProps) {
  const { status } = useAuth();
  const [reason, setReason] = useState('');
  const [submitted, setSubmitted] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const trimmed = reason.trim();
  const tooShort = trimmed.length > 0 && trimmed.length < MIN_REASON_LENGTH;

  const reset = useCallback(() => {
    setReason('');
    setSubmitted(null);
    setError(null);
    onClose();
  }, [onClose]);

  const submit = useMutation({
    mutationFn: () =>
      call(propertiesEndpoints.report, {
        params: { id: propertyId },
        data: { reason: trimmed },
      }),
    onSuccess: (response) => {
      // The server's message names the reward the user just earned, which this
      // client has no other way to know about.
      setSubmitted(response?.message ?? 'Thank you. Your report has been submitted.');
      setError(null);
    },
    onError: (err) => {
      // 400 here means "already reported" or "too short" — both are answers.
      if (err instanceof ApiError && err.status === 400) setError(err.message);
      else setError('Could not submit your report. Please try again.');
    },
  });

  if (status !== 'authenticated') {
    return (
      <Sheet visible={visible} onClose={reset} title="Report this listing" heightRatio={0.3}>
        <Text variant="body" tone="secondary">
          Sign in to report a listing. Reports are reviewed by the DealDirect team.
        </Text>
      </Sheet>
    );
  }

  if (submitted) {
    return (
      <Sheet visible={visible} onClose={reset} title="Report submitted" heightRatio={0.32}>
        <Text variant="body" tone="secondary">
          {submitted}
        </Text>
        <Button label="Done" onPress={reset} fullWidth className="mt-lg" />
      </Sheet>
    );
  }

  return (
    <Sheet visible={visible} onClose={reset} title="Report this listing" heightRatio={0.72}>
      <Text variant="footnote" tone="muted">
        Tell us what is wrong. Reports go to the DealDirect team, not to the owner.
      </Text>

      <View className="mt-md flex-row flex-wrap gap-sm">
        {PRESET_REASONS.map((preset) => (
          <Chip
            key={preset}
            label={preset}
            selected={trimmed === preset}
            onPress={() => {
              setReason(preset);
              setError(null);
            }}
          />
        ))}
      </View>

      <Input
        label="Reason"
        value={reason}
        onChangeText={(next) => {
          setReason(next);
          setError(null);
        }}
        multiline
        numberOfLines={3}
        placeholder="Describe the problem"
        containerClassName="mt-lg"
        error={
          error ?? (tooShort ? `Please write at least ${MIN_REASON_LENGTH} characters.` : undefined)
        }
      />

      <Button
        label="Submit report"
        onPress={() => submit.mutate()}
        loading={submit.isPending}
        disabled={trimmed.length < MIN_REASON_LENGTH || submit.isPending}
        fullWidth
        className="mt-lg"
      />
    </Sheet>
  );
}
