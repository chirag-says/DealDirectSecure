/**
 * Add-listing draft autosave.
 *
 * Only the ADD flow drafts. An edit form starts from a listing that already
 * exists on the server, so there is no local-only state to protect against an
 * app kill the way a half-finished new listing has.
 */

import { draftStorage } from '@/storage';
import { EMPTY_LISTING_FORM, type ListingFormValues } from './types';

const DRAFT_KEY = 'listing.new';

export function loadListingDraft(): ListingFormValues {
  const raw = draftStorage.getString(DRAFT_KEY);
  if (!raw) return EMPTY_LISTING_FORM;
  try {
    return { ...EMPTY_LISTING_FORM, ...(JSON.parse(raw) as Partial<ListingFormValues>) };
  } catch {
    return EMPTY_LISTING_FORM;
  }
}

export function saveListingDraft(values: ListingFormValues): void {
  draftStorage.set(DRAFT_KEY, JSON.stringify(values));
}

export function clearListingDraft(): void {
  draftStorage.remove(DRAFT_KEY);
}

export function hasListingDraft(): boolean {
  return draftStorage.getString(DRAFT_KEY) !== undefined;
}
