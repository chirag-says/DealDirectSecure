import Ionicons from '@expo/vector-icons/Ionicons';
import { useCallback } from 'react';
import { StyleSheet, View, type LayoutChangeEvent } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { screenPadding, spacing, useTheme } from '@/theme';
import { Button, Text } from '@/ui';
import type { InterestState } from '../interest';

/**
 * The action bar, pinned to the bottom of the detail screen.
 *
 * Pinned rather than inline because it is the only thing on this screen the
 * user is meant to DO, and the page is long enough that an inline button would
 * sit several scrolls below where the decision is actually made.
 *
 * ---------------------------------------------------------------------------
 * THE CALL BUTTON IS GONE — removed 2026-08-15
 *
 * A grey circular `tel:` shortcut sat beside the primary action. It is removed
 * on instruction, and the instruction is right on its own terms: the bar now
 * carries one action, which is what a sticky action bar is for.
 *
 * Worth recording what it was, so nobody restores it thinking it was an
 * oversight. It read `property.owner.phone` and opened the dialler. That field
 * arrives from `GET /properties/:id`, which is a PUBLIC endpoint that populates
 * the owner's phone and email into every response — so removing the button
 * removes the encouragement, not the exposure. If the number should not be
 * reachable, the fix is what the endpoint returns, not what this bar draws.
 * Documented in `docs/HANDOFF.md` §13.
 *
 * Nothing phone-shaped replaces it. The route to the owner is the enquiry,
 * which is also the route the backend is built around: it creates the lead the
 * owner works from.
 *
 * ---------------------------------------------------------------------------
 * WHY THE PRIMARY ACTION IS A LABELLED BUTTON AND NOT A HEART
 *
 * Marking interest notifies the owner, creates a lead against the user's name,
 * email and phone, sends that to them over WhatsApp, and counts against a cap
 * of five. A heart communicates the opposite of every one of those: private,
 * free, unlimited, undoable without consequence. So the control is labelled,
 * and the consequence is stated in a sheet BEFORE the press rather than in a
 * toast after it — see `features/saved/components/EnquirySheet.tsx`.
 *
 * This bar does not fire the enquiry. It asks the screen to, and the screen
 * raises the confirmation. Withdrawing is immediate: it is cheap, it frees a
 * slot, and there is nothing to warn about because the owner keeps the lead
 * either way.
 */

export interface DetailActionsProps {
  interest: InterestState;
  /**
   * Enquiry slots left, or null when unknown (signed out, or the saved list
   * has not resolved). Null must not disable the button — the server is the
   * authority on the cap and will say so.
   */
  remaining: number | null;
  /** Raises the confirmation. Never sends the enquiry itself. */
  onRequestEnquire: () => void;
  /**
   * Reports the painted height, so the scroll view above can end its content
   * clear of the bar. A hard-coded constant here would be wrong on the first
   * device with a different bottom inset, and wrong again the moment the
   * consequence line wraps at a large text size.
   */
  onHeightChange?: (height: number) => void;
}

export function DetailActions({
  interest,
  remaining,
  onRequestEnquire,
  onHeightChange,
}: DetailActionsProps) {
  const insets = useSafeAreaInsets();
  const theme = useTheme();

  const handleLayout = useCallback(
    (event: LayoutChangeEvent) => onHeightChange?.(event.nativeEvent.layout.height),
    [onHeightChange]
  );

  const outOfSlots = !interest.isInterested && remaining === 0;
  const busy = interest.isPending || interest.isLoading;

  const handlePress = useCallback(() => {
    // Withdrawing goes straight through; enquiring goes through the sheet.
    if (interest.isInterested) interest.toggle();
    else onRequestEnquire();
  }, [interest, onRequestEnquire]);

  return (
    <View
      onLayout={handleLayout}
      className="bg-surface"
      style={{
        paddingHorizontal: screenPadding,
        paddingTop: spacing.md,
        paddingBottom: insets.bottom + spacing.md,
        borderTopWidth: StyleSheet.hairlineWidth,
        borderTopColor: theme.colors.border,
        // An UPWARD shadow. This bar is chrome floating over content that keeps
        // scrolling beneath it, and a hairline alone does not say that — it
        // says "the page ends here". The shadow is what makes the last row of
        // the attribute table read as passing under the bar rather than being
        // cut off by it.
        shadowColor: '#000',
        shadowOpacity: 0.1,
        shadowRadius: 16,
        shadowOffset: { width: 0, height: -4 },
        elevation: 16,
      }}
    >
      <SupportingLine
        error={interest.error}
        interested={interest.isInterested}
        outOfSlots={outOfSlots}
      />

      <Button
        label={interest.isInterested ? "You're interested" : "I'm interested"}
        variant={interest.isInterested ? 'secondary' : 'primary'}
        loading={busy}
        // Disabled only for the one refusal this client can predict. Every
        // other rejection belongs to the server, which words it better and
        // stays correct if the rule changes.
        disabled={outOfSlots}
        onPress={handlePress}
        fullWidth
        leading={
          interest.isInterested ? (
            <Ionicons name="checkmark" size={17} color={theme.colors.textPrimary} />
          ) : undefined
        }
      />
    </View>
  );
}

/**
 * One line above the button, and it always says the thing that is true right
 * now rather than a fixed strapline.
 *
 * Four states, in priority order: the server's last refusal, the cap, the
 * already-enquired state, and the default. The cap line explains WHY the
 * button below it is dead, which is the whole reason a disabled control needs
 * a caption — a greyed button with no explanation is the most common way an
 * interface makes a user feel stupid.
 */
function SupportingLine({
  error,
  interested,
  outOfSlots,
}: {
  error: string | null;
  interested: boolean;
  outOfSlots: boolean;
}) {
  if (error) {
    return (
      <Text variant="footnote" tone="danger" className="mb-sm">
        {error}
      </Text>
    );
  }

  if (outOfSlots) {
    return (
      <Text variant="caption" tone="muted" className="mb-sm">
        You have used all 5 enquiries. Withdraw one from Saved to free a slot.
      </Text>
    );
  }

  return (
    <Text variant="caption" tone="muted" className="mb-sm">
      {interested
        ? 'The owner has your contact details and can reach you.'
        : 'The owner will be notified and can contact you directly.'}
    </Text>
  );
}
