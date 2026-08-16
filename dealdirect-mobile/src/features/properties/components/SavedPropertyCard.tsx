import { memo } from 'react';

import { PropertyCard } from './PropertyCard';
import type { PropertySummary } from '../types';

/**
 * A property on the Saved screen.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS AND WHY IT IS FOUR LINES
 *
 * The Saved screen used to render a `PropertyCard` and then, in the gap
 * BELOW it, a small red "⊗ Remove" link, and then the next card. Read down the
 * screen, that produces:
 *
 *     [ property A ]
 *     ⊗ Remove
 *     [ property B ]
 *     ⊗ Remove
 *
 * The control sits nearer to the card it does NOT act on than to the one it
 * does. Every rule that governs this says the same thing — Norman's mapping
 * (put the control next to what it changes), Cooper's "keep actions near the
 * object they affect", the plain Gestalt reading of proximity — and the layout
 * violates all of them identically. Worst case is not confusion, it is removing
 * the wrong listing off a list capped at five.
 *
 * The fix is not to restyle the link. It is that the action was never a
 * sibling of the card: it belongs ON it, in the corner the user already
 * associates with saving, as the same filled heart they pressed to get here.
 * Tap it and the enquiry is withdrawn — see `features/saved/saveToggle.ts`
 * for what that does and does not reverse.
 *
 * That leaves this component with nothing of its own to draw, which is the
 * correct outcome and the reason it is a wrapper rather than a third card. A
 * saved property is not a different KIND of object from a browsed one; it is
 * the same object in a known state. Duplicating the markup to say so would
 * guarantee the two drift.
 *
 * The `Alert.alert` that used to gate removal is gone with it, and nothing
 * replaced it. Withdrawing is cheap and it frees a slot; the owner keeps the
 * lead they already have either way, so there is no consequence to warn about.
 * The confirmation on this app's save action belongs on the ADD, where the
 * irreversible disclosure happens — see `EnquirySheet`.
 */
export interface SavedPropertyCardProps {
  property: PropertySummary;
  onPress: (id: string) => void;
  onRemove: (property: PropertySummary) => void;
  /** A withdrawal is in flight; the heart locks rather than queueing a second. */
  busy?: boolean;
}

function SavedPropertyCardComponent({
  property,
  onPress,
  onRemove,
  busy = false,
}: SavedPropertyCardProps) {
  return (
    <PropertyCard
      property={property}
      onPress={onPress}
      // Always `saved`: this list is the definition of the state. Reading it
      // back from the toggle hook would let a mid-flight optimistic write
      // render an unfilled heart on a card that is, by construction, saved.
      save={{ saved: true, busy, onToggle: () => onRemove(property) }}
    />
  );
}

export const SavedPropertyCard = memo(SavedPropertyCardComponent);
