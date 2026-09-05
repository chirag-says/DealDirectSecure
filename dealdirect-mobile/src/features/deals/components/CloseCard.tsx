import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useState } from 'react';
import { View } from 'react-native';

import { ApiError } from '@/api';
import { spacing, useTheme } from '@/theme';
import type { AttestRequest, DealVerification } from '@/types/backend/deal';
import { Button, Card, Input, Text } from '@/ui';

/**
 * The close, from the moment an owner reports it to the moment it pays.
 *
 * Three verification states, and each says what is true and what, if
 * anything, the user can do:
 *
 *   pending    DealDirect is checking. Each party may attest ONCE that the
 *              deal happened (confirm) or did not (dispute). An attestation
 *              is a statement, not a claim form; it feeds the fraud check.
 *   approved   The reward can be claimed, unless the payout is on hold
 *              (`payoutHoldUntil` in the future), in which case the date is
 *              stated calmly. A review can be written once eligible.
 *   rejected   Stated once, without a reason the server does not give.
 *
 * Nothing here follows a deep link into a claim or a payment; the claim is
 * a tap on a labelled button that opens the claim screen.
 */

const NOTE_MAX = 300;

export interface CloseCardProps {
  verification: DealVerification;
  counterpartName: string;
  pending: AttestRequest | null;
  onAttest: (body: AttestRequest) => Promise<unknown>;
}

function formatDate(iso: string): string | null {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' });
}

export function CloseCard({ verification, counterpartName, pending, onAttest }: CloseCardProps) {
  const theme = useTheme();
  const router = useRouter();
  const [disputing, setDisputing] = useState(false);
  const [note, setNote] = useState('');
  const [error, setError] = useState<string | null>(null);

  const attest = async (body: AttestRequest) => {
    setError(null);
    try {
      await onAttest(body);
      setDisputing(false);
      setNote('');
    } catch (caught) {
      setError(
        caught instanceof ApiError && caught.code === 'ALREADY_ATTESTED'
          ? 'You have already attested to this close.'
          : caught instanceof ApiError
            ? caught.message
            : 'Could not record that. Please try again.'
      );
    }
  };

  const reviewButton = verification.review.eligible ? (
    <Button
      label={verification.review.submitted ? 'Your review' : 'Review this deal'}
      variant="secondary"
      size="sm"
      onPress={() => router.push(`/review/${verification.id}`)}
      leading={<Ionicons name="star-outline" size={15} color={theme.colors.textPrimary} />}
    />
  ) : null;

  if (verification.status === 'pending') {
    const mine = verification.attestation.mine;
    return (
      <Card>
        <View className="flex-row items-center">
          <Ionicons name="hourglass-outline" size={18} color={theme.colors.warning} />
          <Text variant="bodyEmphasis" className="ml-sm">
            Awaiting DealDirect verification
          </Text>
        </View>
        <Text variant="footnote" tone="secondary" className="mt-xs">
          The close has been reported. DealDirect checks it before any reward is released.
        </Text>

        {mine ? (
          <Text variant="footnote" tone="secondary" className="mt-base">
            You {mine.statement === 'confirm' ? 'confirmed' : 'disputed'} this close
            {formatDate(mine.at) ? ` on ${formatDate(mine.at)}` : ''}.{' '}
            {verification.attestation.counterpartDone
              ? `${counterpartName} has also attested.`
              : `Waiting for ${counterpartName} to attest.`}
          </Text>
        ) : (
          <View className="mt-base">
            <Text variant="footnote" tone="secondary" className="mb-sm">
              Did this deal happen as reported? You can answer once.
            </Text>
            {disputing ? (
              <View>
                <Input
                  label="What is wrong? (optional)"
                  value={note}
                  onChangeText={(next) => setNote(next.slice(0, NOTE_MAX))}
                  maxLength={NOTE_MAX}
                  multiline
                  hint={note.length >= NOTE_MAX - 50 ? `${note.length} / ${NOTE_MAX}` : undefined}
                />
                <View className="flex-row" style={{ gap: spacing.sm }}>
                  <Button
                    label="Send dispute"
                    variant="danger"
                    size="sm"
                    loading={pending?.statement === 'dispute'}
                    disabled={!!pending}
                    onPress={() =>
                      void attest({ statement: 'dispute', note: note.trim() || undefined })
                    }
                  />
                  <Button
                    label="Back"
                    variant="ghost"
                    size="sm"
                    disabled={!!pending}
                    onPress={() => setDisputing(false)}
                  />
                </View>
              </View>
            ) : (
              <View className="flex-row" style={{ gap: spacing.sm }}>
                <Button
                  label="Confirm"
                  size="sm"
                  loading={pending?.statement === 'confirm'}
                  disabled={!!pending}
                  onPress={() => void attest({ statement: 'confirm' })}
                />
                <Button
                  label="Dispute"
                  variant="secondary"
                  size="sm"
                  disabled={!!pending}
                  onPress={() => setDisputing(true)}
                />
              </View>
            )}
          </View>
        )}

        {error ? (
          <Text variant="footnote" tone="danger" className="mt-sm">
            {error}
          </Text>
        ) : null}
      </Card>
    );
  }

  if (verification.status === 'approved') {
    const holdUntil = verification.payoutHoldUntil ? new Date(verification.payoutHoldUntil) : null;
    const onHold = !!holdUntil && holdUntil.getTime() > Date.now();
    const holdDate = verification.payoutHoldUntil ? formatDate(verification.payoutHoldUntil) : null;

    return (
      <Card>
        <View className="flex-row items-center">
          <Ionicons name="checkmark-circle" size={18} color={theme.colors.success} />
          <Text variant="bodyEmphasis" className="ml-sm">
            Deal verified
          </Text>
        </View>

        {verification.claimed ? (
          <Text variant="footnote" tone="secondary" className="mt-xs">
            Your reward for this deal has been claimed.
          </Text>
        ) : onHold ? (
          <Text variant="footnote" tone="secondary" className="mt-xs">
            Your reward is reserved{holdDate ? ` and unlocks on ${holdDate}` : ''}. Nothing to do
            until then.
          </Text>
        ) : (
          <Text variant="footnote" tone="secondary" className="mt-xs">
            Your reward is ready to claim.
          </Text>
        )}

        <View className="mt-base flex-row flex-wrap" style={{ gap: spacing.sm }}>
          {!verification.claimed && !onHold ? (
            <Button
              label="Claim reward"
              size="sm"
              onPress={() => router.push(`/claim-reward/${verification.id}`)}
              leading={<Ionicons name="gift-outline" size={15} color={theme.colors.textOnAccent} />}
            />
          ) : null}
          {reviewButton}
        </View>

        {verification.review.submitted && verification.review.status === 'pending' ? (
          <Text variant="caption" tone="muted" className="mt-sm">
            Your review publishes when {counterpartName} reviews too, or after 14 days.
          </Text>
        ) : null}
      </Card>
    );
  }

  return (
    <Card>
      <View className="flex-row items-center">
        <Ionicons name="close-circle-outline" size={18} color={theme.colors.textMuted} />
        <Text variant="bodyEmphasis" className="ml-sm">
          Close not verified
        </Text>
      </View>
      <Text variant="footnote" tone="secondary" className="mt-xs">
        DealDirect could not verify this close, so no reward applies.
      </Text>
      <View className="mt-base">
        <Button
          label="Contact support"
          variant="ghost"
          size="sm"
          onPress={() => router.push('/support')}
        />
      </View>
    </Card>
  );
}
