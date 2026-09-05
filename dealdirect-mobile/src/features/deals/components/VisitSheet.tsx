import { useCallback, useEffect, useMemo, useState } from 'react';
import { ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import { spacing } from '@/theme';
import { Button, DateField, Input, Select, Sheet, Text } from '@/ui';
import {
  composeVisitDate,
  MAX_DAYS_AHEAD,
  validateVisitTime,
  visitTimeErrorCopy,
} from '../visitTime';

/**
 * Propose a visit: a day, a time, an optional note.
 *
 * The day is `DateField` (the native picker where it exists, typed entry
 * where it does not) and the time is two `Select`s, hour and minute, because
 * a native TIME picker would be a second mode of a component this app uses
 * only for dates, and every real visit is on the quarter hour anyway.
 *
 * Validation runs here first, with the SAME codes the server uses, so a
 * time in the past says so under the field rather than after a round trip;
 * and when the server still refuses (clock skew, a slow finger across
 * midnight) its code goes through the same copy table.
 *
 * The note is capped at 200, the server's limit, with a counter once it is
 * long enough for the cap to matter.
 */

const NOTE_MAX = 200;
const NOTE_COUNTER_FROM = 150;

const HOURS = Array.from({ length: 24 }, (_, hour) => ({
  value: String(hour),
  label: new Date(2000, 0, 1, hour).toLocaleTimeString('en-IN', { hour: 'numeric' }),
}));

const MINUTES = ['00', '15', '30', '45'].map((minute) => ({ value: minute, label: minute }));

function isoDay(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

export interface VisitSheetProps {
  visible: boolean;
  onClose: () => void;
  /** Resolves on success; rejects with the server's `ApiError` on refusal. */
  onSubmit: (scheduledAt: string, note?: string) => Promise<unknown>;
  isPending: boolean;
  /** "Propose another time" cancels a visit first; the title says which act this is. */
  replacing?: boolean;
}

export function VisitSheet({ visible, onClose, onSubmit, isPending, replacing }: VisitSheetProps) {
  const [day, setDay] = useState('');
  const [hour, setHour] = useState('11');
  const [minute, setMinute] = useState('00');
  const [note, setNote] = useState('');
  const [error, setError] = useState<string | null>(null);

  // A fresh sheet each time it opens: a stale "that time has passed" from a
  // previous attempt must not greet the next one.
  useEffect(() => {
    if (!visible) return;
    setDay('');
    setHour('11');
    setMinute('00');
    setNote('');
    setError(null);
  }, [visible]);

  const bounds = useMemo(() => {
    const today = new Date();
    const latest = new Date(today);
    latest.setDate(latest.getDate() + MAX_DAYS_AHEAD);
    return { today, latest };
  }, []);

  const submit = useCallback(async () => {
    const composed = composeVisitDate(day, Number(hour), Number(minute));
    if (!composed) {
      setError(visitTimeErrorCopy('INVALID_TIME'));
      return;
    }
    const problem = validateVisitTime(composed, new Date());
    if (problem) {
      setError(visitTimeErrorCopy(problem));
      return;
    }

    setError(null);
    try {
      await onSubmit(composed.toISOString(), note.trim() || undefined);
      onClose();
    } catch (caught) {
      setError(
        caught instanceof ApiError
          ? caught.code
            ? visitTimeErrorCopy(caught.code)
            : caught.message
          : visitTimeErrorCopy(undefined)
      );
    }
  }, [day, hour, minute, note, onSubmit, onClose]);

  return (
    <Sheet
      visible={visible}
      onClose={onClose}
      title={replacing ? 'Propose another time' : 'Plan a visit'}
      heightRatio={0.78}
    >
      <ScrollView keyboardShouldPersistTaps="handled" showsVerticalScrollIndicator={false}>
        <Text variant="footnote" tone="secondary" className="mb-base">
          {replacing
            ? 'The current proposal is withdrawn and the other side is asked to confirm this one.'
            : 'The other side is asked to confirm. Both of you get a reminder before it.'}
        </Text>

        <DateField
          label="Day"
          value={day}
          onChange={(next) => {
            setDay(next);
            setError(null);
          }}
          placeholder="Pick a day"
          minimumDate={bounds.today}
          maximumDate={bounds.latest}
        />

        <View className="mt-base flex-row" style={{ gap: spacing.md }}>
          <View className="flex-1">
            <Select
              label="Hour"
              value={hour}
              options={HOURS}
              onChange={(next) => {
                setHour(next);
                setError(null);
              }}
            />
          </View>
          <View className="flex-1">
            <Select
              label="Minute"
              value={minute}
              options={MINUTES}
              onChange={(next) => {
                setMinute(next);
                setError(null);
              }}
            />
          </View>
        </View>

        <Input
          label="Note (optional)"
          placeholder="Anything the other side should know"
          value={note}
          onChangeText={(next) => setNote(next.slice(0, NOTE_MAX))}
          maxLength={NOTE_MAX}
          multiline
          hint={note.length >= NOTE_COUNTER_FROM ? `${note.length} / ${NOTE_MAX}` : undefined}
        />

        {error ? (
          <Text variant="footnote" tone="danger" className="mt-sm">
            {error}
          </Text>
        ) : null}

        <Text variant="caption" tone="muted" className="mt-sm">
          Times are in your phone&apos;s time zone. Within the next {MAX_DAYS_AHEAD} days.
        </Text>

        <View className="mt-lg" style={{ paddingBottom: spacing.xl }}>
          <Button
            label={replacing ? 'Propose this time' : 'Propose visit'}
            loading={isPending}
            disabled={!day}
            fullWidth
            onPress={() => void submit()}
          />
        </View>
      </ScrollView>
    </Sheet>
  );
}
