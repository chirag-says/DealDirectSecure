import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { spacing, useTheme } from '@/theme';
import { Button, Sheet, Text } from '@/ui';
import { INTEREST_LIMIT } from '../hooks';

/**
 * What happens when you enquire, said BEFORE it happens.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A CONFIRMATION, WHICH IS NORMALLY THE WRONG ANSWER
 *
 * The standing rule is that a confirmation dialog is an admission the action
 * cannot be taken back, and the fix is reversibility rather than better
 * wording. That rule assumes reversal is available. Here it is not, and the
 * audit in `saveToggle.ts` says exactly which parts are not: the `Lead`
 * carrying the user's name, email and phone, the owner's notification, and the
 * WhatsApp message all survive a withdrawal.
 *
 * The previous pass shipped the other model — one tap, then a toast with
 * "Undo" — and it failed on both counts. It fired an irreversible disclosure
 * from a heart icon, and then claimed to have undone it.
 *
 * So this states the consequence at the only moment it can be acted on. Three
 * conditions make a confirmation correct here rather than lazy, and all three
 * have to hold or this should go back to one tap:
 *
 *  1. The action is genuinely irreversible.
 *  2. The consequence is one the user cannot infer from the control.
 *  3. It is rare. Enquiries are capped at five, so this is a sheet a user sees
 *     at most five times, not one standing between them and every scroll.
 *
 * ---------------------------------------------------------------------------
 * IT LISTS FACTS, NOT A WARNING
 *
 * No "are you sure", no alert colouring, no exclamation. Sending an enquiry is
 * the thing the app is for and the sheet should not read as talking the user
 * out of it. Three lines saying what the owner receives, and the quota, and
 * the button says the verb.
 *
 * The quota line is the part users cannot discover anywhere else at the moment
 * they need it. Five is small enough that the fourth one is a decision.
 *
 * ---------------------------------------------------------------------------
 * PLAIN PROPS, TWO DRIVERS
 *
 * Two surfaces raise this: the feed and Saved, through `useSaveToggle`, and the
 * property detail screen, through `useInterest`. Those are different hooks
 * against the same endpoint, and binding the sheet to either would have meant a
 * second copy for the other — which is how two confirmations end up wording the
 * same consequence differently.
 */
export interface EnquirySheetProps {
  visible: boolean;
  /** Which listing. The location reads better than the machine-made title. */
  subtitle?: string;
  /**
   * Slots left BEFORE this enquiry, or null when unknown (signed out, or the
   * saved list has not resolved). Null hides the quota line rather than
   * guessing at it.
   */
  remaining: number | null;
  onConfirm: () => void;
  onCancel: () => void;
}

export function EnquirySheet({
  visible,
  subtitle,
  remaining,
  onConfirm,
  onCancel,
}: EnquirySheetProps) {
  const theme = useTheme();

  // Counted as it will be AFTER this enquiry, because that is the number the
  // user is deciding about.
  const remainingAfter = remaining === null ? null : Math.max(0, remaining - 1);

  return (
    <Sheet
      visible={visible}
      onClose={onCancel}
      title="Send enquiry?"
      // The default 0.6. Sized against the tallest state — three two-line
      // consequences, the quota line and two buttons — on the shortest phone
      // still shipping (667pt), where 0.6 leaves about 40pt of headroom.
      // Anything past the default accessibility text sizes will need this to
      // become a scroll; flagged rather than pre-built.
    >
      <View style={{ paddingHorizontal: spacing.lg, paddingBottom: spacing.lg }}>
        {subtitle ? (
          <Text variant="callout" tone="secondary" numberOfLines={2}>
            {subtitle}
          </Text>
        ) : null}

        <View style={{ marginTop: spacing.lg, gap: spacing.md }}>
          <Consequence icon="person-outline">
            The owner gets your name, email and phone number.
          </Consequence>
          <Consequence icon="notifications-outline">
            They are notified straight away, on WhatsApp and in the app.
          </Consequence>
          <Consequence icon="time-outline">
            Withdrawing later frees your slot, but the owner keeps the enquiry
            they have already received.
          </Consequence>
        </View>

        {remainingAfter !== null ? (
          <View
            className="flex-row items-center"
            style={{
              marginTop: spacing.lg,
              paddingTop: spacing.md,
              borderTopWidth: 1,
              borderTopColor: theme.colors.border,
            }}
          >
            <Ionicons name="mail-outline" size={15} color={theme.colors.textMuted} />
            <Text variant="footnote" tone="muted" className="ml-sm flex-1">
              {remainingAfter} of {INTEREST_LIMIT} enquiries left after this one.
            </Text>
          </View>
        ) : null}

        <Button label="Send enquiry" className="mt-lg" fullWidth onPress={onConfirm} />
        <Button
          label="Cancel"
          variant="ghost"
          align="center"
          className="mt-xs"
          onPress={onCancel}
        />
      </View>
    </Sheet>
  );
}

function Consequence({
  icon,
  children,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  children: React.ReactNode;
}) {
  const theme = useTheme();

  return (
    <View className="flex-row items-start">
      <Ionicons
        name={icon}
        size={17}
        color={theme.colors.textSecondary}
        style={{ marginTop: 2 }}
      />
      <Text variant="callout" className="ml-md flex-1">
        {children}
      </Text>
    </View>
  );
}
