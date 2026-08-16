import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'expo-router';
import { useCallback, useMemo, useState } from 'react';

import { ApiError, call, propertiesEndpoints, qk } from '@/api';
import { useAuth } from '@/auth';
import type { PropertySummary } from '@/features/properties';
import type { ObjectId } from '@/types/backend/common';
import { useToast } from '@/ui';
import { INTEREST_LIMIT, useSavedProperties } from './hooks';

/**
 * THE SAVE CONTROL, ONCE, FOR EVERY SCREEN THAT HAS ONE.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE HEART ACTUALLY DOES — audited against the controller 2026-08-15
 *
 * Read from `backend/controllers/propertyController.js:1505` (`markInterested`)
 * and `:1660` (`removeInterest`), not inferred. One tap on an unsaved heart:
 *
 *   1. rejects if the user already holds 5 interests, anywhere in the app
 *   2. rejects their own listing, and a duplicate
 *   3. pushes to `Property.interestedUsers` and `$inc likes`
 *   4. CREATES A `Lead` carrying a `userSnapshot` of name, email, phone and
 *      profile image
 *   5. creates a `Notification` for the owner
 *   6. sends the owner a WHATSAPP MESSAGE containing the user's name, email
 *      and phone
 *   7. awards reward points
 *
 * No email is sent, despite what the older comment in
 * `features/properties/interest.ts` says — the notification is an in-app
 * document plus WhatsApp.
 *
 * Removing reverses exactly one of those. `removeInterest` pulls the user from
 * `interestedUsers` and decrements `likes`. It does NOT delete the `Lead`, the
 * `Notification` or the WhatsApp message, and it does not revoke the points.
 * The quota IS restored, because the cap counts `interestedUsers` rather than
 * leads.
 *
 * ---------------------------------------------------------------------------
 * SO THE HEART IS NOT A BOOKMARK, AND IT NO LONGER PRETENDS TO BE
 *
 * The previous pass shipped a one-tap heart with an "Undo" in the toast. That
 * was wrong twice, and both were reported:
 *
 *  - **The icon promised a bookmark.** A heart means private, free, unlimited
 *    and reversible. This is public, capped at five, and hands a stranger a
 *    phone number over WhatsApp within a second of the tap.
 *  - **The Undo was not an undo.** It restored the slot and nothing else. The
 *    lead, the notification and the WhatsApp had already landed and stay
 *    landed. Offering "Undo" told the user a side effect had been reversed
 *    that had not been.
 *
 * Until the backend can separate a private bookmark from an enquiry — see
 * `docs/HANDOFF.md` §12 for the minimum change — the control asks first. A
 * confirmation is the right shape here for the one reason it usually is not:
 * the action is genuinely irreversible, and its consequence cannot be stated
 * after the fact. It is also capped at five, so this is a sheet a user sees at
 * most five times, not on every scroll.
 *
 * Withdrawing needs no confirmation and gets no Undo. It is cheap and it frees
 * a slot; the owner keeps the lead either way, so there is nothing to warn
 * about. An "Undo" there would re-fire the notification and the WhatsApp,
 * which is the opposite of undoing.
 *
 * ---------------------------------------------------------------------------
 * ONE SHARED QUERY, NOT ONE REQUEST PER CARD
 *
 * `useInterest` fetches `GET /properties/interested/:id/check` per listing.
 * That is correct on a detail screen and ruinous on a feed — thirty-six cards
 * would be thirty-six requests against a shared limiter. Membership is read
 * from the saved LIST instead, and written back optimistically to both that
 * list and the per-listing flag so a detail screen opened straight afterwards
 * agrees.
 *
 * This hook is called ONCE PER SCREEN and the per-card props are derived from
 * it, which is what makes reading the list here safe: it is the same
 * `useSavedProperties` query the Saved tab runs, deduplicated by TanStack
 * across both.
 *
 * It lives in its own file rather than in `hooks.ts` because it imports from
 * `@/features/properties`, and `hooks.ts` is imported BY that feature's own
 * modules — same file would close the cycle.
 */
export interface SaveToggle {
  isSaved: (id: ObjectId) => boolean;
  /** Withdraws immediately, or raises the enquiry confirmation for an add. */
  toggle: (property: PropertySummary) => void;
  /** The listing awaiting confirmation, for `EnquirySheet`. Null when none. */
  pending: PropertySummary | null;
  confirm: () => void;
  cancel: () => void;
  /** A request is in flight for this id — the control locks rather than
   *  queueing a second one. */
  isBusy: (id: ObjectId) => boolean;
  used: number;
  remaining: number;
}

export function useSaveToggle(): SaveToggle {
  const router = useRouter();
  const toast = useToast();
  const queryClient = useQueryClient();
  const { status } = useAuth();
  const signedIn = status === 'authenticated';

  // The same query the Saved tab runs, deduplicated by TanStack. One request
  // per session for the whole feed's worth of hearts.
  const list = useSavedProperties();
  const saved = list.requiresAuth || list.isLoading ? undefined : list.items;
  const used = saved?.length ?? 0;

  const [pending, setPending] = useState<PropertySummary | null>(null);
  /**
   * Ids with a request in flight, so a second tap on the same heart is
   * ignored rather than sent. Keyed per property rather than one global flag:
   * withdrawing two listings in a row on the Saved screen is a normal thing to
   * do and must not be blocked by the first still settling.
   */
  const [busy, setBusy] = useState<readonly ObjectId[]>([]);

  const write = useCallback(
    (next: PropertySummary[] | undefined) => {
      queryClient.setQueryData<PropertySummary[]>(qk.savedProperties(), next ?? []);
    },
    [queryClient]
  );

  const mutation = useMutation({
    mutationFn: async ({ property, add }: { property: PropertySummary; add: boolean }) => {
      const endpoint = add
        ? propertiesEndpoints.markInterested
        : propertiesEndpoints.removeInterest;
      await call(endpoint, { params: { id: property.id } });
    },

    onMutate: async ({ property, add }) => {
      setBusy((current) => [...current, property.id]);
      await queryClient.cancelQueries({ queryKey: qk.savedProperties() });
      const previous = queryClient.getQueryData<PropertySummary[]>(qk.savedProperties());

      write(
        add
          ? [property, ...(previous ?? []).filter((item) => item.id !== property.id)]
          : (previous ?? []).filter((item) => item.id !== property.id)
      );
      queryClient.setQueryData(qk.propertyInterest(property.id), add);

      return { previous };
    },

    onSuccess: (_data, { add }) => {
      // An acknowledgement, not a disclosure: the enquiry's consequences were
      // stated before it was sent, so this only has to confirm it landed.
      toast.show(
        add ? 'Enquiry sent. The owner has your contact details.' : 'Enquiry withdrawn.',
        add ? 'success' : 'neutral'
      );
    },

    onError: (error, { property, add }, context) => {
      // Restore, exactly. The heart goes back to the state it was in before
      // the tap rather than to a guess about it.
      write(context?.previous);
      void queryClient.invalidateQueries({ queryKey: qk.propertyInterest(property.id) });

      // A 400 here is an answer, not a fault — the cap, your own listing, one
      // already marked. The server's wording beats anything invented here and
      // stays correct if the rule changes.
      const message =
        error instanceof ApiError && error.status === 400
          ? error.message
          : add
            ? 'Could not send that enquiry. Please try again.'
            : 'Could not withdraw that. Please try again.';
      toast.show(message, 'danger');
    },

    onSettled: (_data, _error, { property }) => {
      setBusy((current) => current.filter((id) => id !== property.id));
      void queryClient.invalidateQueries({ queryKey: qk.savedProperties() });
      void queryClient.invalidateQueries({ queryKey: qk.propertyInterest(property.id) });
      // Marking interest earns points; the wallet is now stale by that much.
      void queryClient.invalidateQueries({ queryKey: qk.rewardsWallet() });
    },
  });

  const { mutate } = mutation;

  const isSaved = useCallback(
    (id: ObjectId) => (saved ?? []).some((item) => item.id === id),
    [saved]
  );

  const isBusy = useCallback((id: ObjectId) => busy.includes(id), [busy]);

  const toggle = useCallback(
    (property: PropertySummary) => {
      if (isBusy(property.id)) return;

      if (!signedIn) {
        // Not a silent no-op and not a dialog. The control is offered to
        // guests because hiding it would hide the feature; pressing it takes
        // them to the one thing that unblocks it.
        router.push('/(auth)/login');
        return;
      }

      if (isSaved(property.id)) {
        mutate({ property, add: false });
        return;
      }

      if (saved && saved.length >= INTEREST_LIMIT) {
        // Pre-empted only because the list is genuinely in hand. `useInterest`
        // deliberately cannot do this and lets the server answer; here the
        // count is known, so spending a request to be told what we already
        // know is worse than saying it.
        toast.show(
          `You have used all ${INTEREST_LIMIT} enquiries. Withdraw one from Saved to free a slot.`,
          'danger'
        );
        return;
      }

      setPending(property);
    },
    [isBusy, signedIn, router, isSaved, saved, mutate, toast]
  );

  const confirm = useCallback(() => {
    if (!pending) return;
    mutate({ property: pending, add: true });
    setPending(null);
  }, [pending, mutate]);

  const cancel = useCallback(() => setPending(null), []);

  /**
   * Memoised, and this is a performance requirement rather than tidiness.
   *
   * The screen derives its per-card `save` props from this object inside a
   * `useCallback`. A fresh literal here changes that callback's identity on
   * every render, which changes `renderItem`, which makes FlashList re-render
   * every visible row for any state change anywhere on the screen — typing in
   * the search field included. Every member below is already stable.
   */
  return useMemo(
    () => ({
      isSaved,
      toggle,
      pending,
      confirm,
      cancel,
      isBusy,
      used,
      remaining: Math.max(0, INTEREST_LIMIT - used),
    }),
    [isSaved, toggle, pending, confirm, cancel, isBusy, used]
  );
}
