import Ionicons from '@expo/vector-icons/Ionicons';
import { useMemo } from 'react';
import { View } from 'react-native';

import { spacing, useTheme } from '@/theme';
import type { DealRole, Visit, VisitAction, VisitFeedback } from '@/types/backend/deal';
import { Badge, Button, Card, Chip, Text, type BadgeTone } from '@/ui';
import { visitState, visitWaitingCopy, type VisitControl } from '../visitState';

/**
 * One visit, rendered per status and per role.
 *
 * The buttons come from `visitState`, which mirrors the server's rules, so
 * this file is only presentation: which label goes on which control, and the
 * one line above them that says what the visit is waiting on. It never
 * decides whether an action is allowed.
 *
 * "Mark done" by one party and "Confirm it happened" by the other are the
 * SAME server action (`done`), sent twice. The second send is what makes the
 * visit count: the milestone and the `visited` stage need both ids in
 * `doneConfirmedBy`. The labels differ because the two moments feel
 * different to the person pressing them.
 */

export interface VisitCardProps {
  visit: Visit;
  role: DealRole;
  userId: string;
  counterpartName: string;
  /** The action in flight, so only its button spins. */
  pending: { visitId: string; action: VisitAction } | null;
  feedbackPending: boolean;
  onAction: (visit: Visit, action: VisitAction) => void;
  onProposeAnother: (visit: Visit) => void;
  onFeedback: (visit: Visit, feedback: VisitFeedback) => void;
}

const STATUS_LABEL: Record<Visit['status'], string> = {
  proposed: 'Proposed',
  confirmed: 'Confirmed',
  done: 'Done',
  no_show: 'Did not happen',
  cancelled: 'Cancelled',
};

const STATUS_TONE: Record<Visit['status'], BadgeTone> = {
  proposed: 'accent',
  confirmed: 'success',
  done: 'success',
  no_show: 'warning',
  cancelled: 'neutral',
};

const FEEDBACK_LABEL: Record<VisitFeedback, string> = {
  interested: 'Interested',
  thinking: 'Still thinking',
  not_interested: 'Not for me',
};

function formatWhen(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return 'Unknown time';
  return `${date.toLocaleDateString('en-IN', { weekday: 'short', day: 'numeric', month: 'short' })}, ${date.toLocaleTimeString('en-IN', { hour: 'numeric', minute: '2-digit' })}`;
}

export function VisitCard({
  visit,
  role,
  userId,
  counterpartName,
  pending,
  feedbackPending,
  onAction,
  onProposeAnother,
  onFeedback,
}: VisitCardProps) {
  const theme = useTheme();
  // `now` is read once per render, not per second. A visit crossing its
  // scheduled time while the screen is open is corrected on the next
  // interaction or refresh; a ticking clock here would re-render the whole
  // deal page every second for a boundary that matters once.
  const state = useMemo(
    () => visitState(visit, role, userId, new Date()),
    [visit, role, userId]
  );

  const busy = (action: VisitAction) =>
    pending?.visitId === visit.id && pending.action === action;
  const anyBusy = pending?.visitId === visit.id || feedbackPending;

  const waiting = visitWaitingCopy(state.waiting, counterpartName);
  const terminal = visit.status === 'cancelled' || visit.status === 'no_show';

  return (
    <Card>
      <View className="flex-row items-start justify-between">
        <View className="flex-1 pr-sm">
          <View className="flex-row items-center">
            <Ionicons name="calendar-outline" size={16} color={theme.colors.textSecondary} />
            <Text variant="bodyEmphasis" tone={terminal ? 'muted' : 'primary'} className="ml-xs">
              {formatWhen(visit.scheduledAt)}
            </Text>
          </View>
          {visit.note ? (
            <Text variant="footnote" tone="secondary" className="mt-xs">
              {visit.note}
            </Text>
          ) : null}
        </View>
        <Badge label={STATUS_LABEL[visit.status] ?? visit.status} tone={STATUS_TONE[visit.status] ?? 'neutral'} />
      </View>

      {visit.status === 'done' ? (
        <Text variant="footnote" tone="secondary" className="mt-sm">
          {state.bothDone
            ? `Both you and ${counterpartName} confirmed this visit happened.`
            : state.iMarkedDone
              ? 'You marked this done.'
              : `${counterpartName} marked this done.`}
        </Text>
      ) : waiting ? (
        <Text variant="footnote" tone="secondary" className="mt-sm">
          {waiting}
        </Text>
      ) : null}

      {visit.status === 'done' && visit.feedback ? (
        <View className="mt-sm flex-row items-center">
          <Text variant="caption" tone="muted" className="mr-sm">
            {role === 'buyer' ? 'You said' : `${counterpartName} said`}
          </Text>
          <Chip label={FEEDBACK_LABEL[visit.feedback]} selected />
        </View>
      ) : null}

      {state.controls.length > 0 ? (
        <View className="mt-base" style={{ gap: spacing.sm }}>
          {state.controls.includes('feedback') ? (
            <View>
              <Text variant="footnote" tone="secondary" className="mb-sm">
                How did the visit go? The owner sees your answer.
              </Text>
              <View className="flex-row flex-wrap" style={{ gap: spacing.sm }}>
                {(Object.keys(FEEDBACK_LABEL) as VisitFeedback[]).map((feedback) => (
                  <Chip
                    key={feedback}
                    label={FEEDBACK_LABEL[feedback]}
                    disabled={anyBusy}
                    onPress={() => onFeedback(visit, feedback)}
                  />
                ))}
              </View>
            </View>
          ) : null}

          <ControlRow
            controls={state.controls.filter((control) => control !== 'feedback')}
            busy={busy}
            disabled={anyBusy}
            onAction={(action) => onAction(visit, action)}
            onProposeAnother={() => onProposeAnother(visit)}
          />
        </View>
      ) : null}
    </Card>
  );
}

/**
 * The buttons, one row. The primary act (confirm, mark done) is filled; the
 * ways out (cancel, no-show) are secondary; a proposal of a different time
 * is a ghost since it is a longer path. Order is primary first, so the thumb
 * lands on the likely act.
 */
function ControlRow({
  controls,
  busy,
  disabled,
  onAction,
  onProposeAnother,
}: {
  controls: VisitControl[];
  busy: (action: VisitAction) => boolean;
  disabled: boolean;
  onAction: (action: VisitAction) => void;
  onProposeAnother: () => void;
}) {
  if (controls.length === 0) return null;

  return (
    <View className="flex-row flex-wrap" style={{ gap: spacing.sm }}>
      {controls.includes('confirm') ? (
        <Button
          label="Confirm"
          size="sm"
          loading={busy('confirm')}
          disabled={disabled}
          onPress={() => onAction('confirm')}
        />
      ) : null}
      {controls.includes('done') ? (
        <Button
          label="Mark done"
          size="sm"
          loading={busy('done')}
          disabled={disabled}
          onPress={() => onAction('done')}
        />
      ) : null}
      {controls.includes('confirm_done') ? (
        <Button
          label="Confirm it happened"
          size="sm"
          loading={busy('done')}
          disabled={disabled}
          onPress={() => onAction('done')}
        />
      ) : null}
      {controls.includes('no_show') ? (
        <Button
          label="Didn't happen"
          variant="secondary"
          size="sm"
          loading={busy('no_show')}
          disabled={disabled}
          onPress={() => onAction('no_show')}
        />
      ) : null}
      {controls.includes('propose_another') ? (
        <Button
          label="Propose another time"
          variant="ghost"
          size="sm"
          disabled={disabled}
          onPress={onProposeAnother}
        />
      ) : null}
      {controls.includes('cancel') ? (
        <Button
          label="Cancel"
          variant="ghost"
          size="sm"
          loading={busy('cancel')}
          disabled={disabled}
          onPress={() => onAction('cancel')}
        />
      ) : null}
    </View>
  );
}
