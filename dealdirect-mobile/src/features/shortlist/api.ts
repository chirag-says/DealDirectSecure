/**
 * Shortlist data access. The only place the shortlist endpoints are called.
 *
 * Every function here returns the feature's own types, never the envelope, so
 * a change to the wire shape is absorbed in one file rather than in six hooks.
 */

import { call, shortlistEndpoints } from '@/api';
import type { ObjectId } from '@/types/backend/common';
import { adaptShortlistEntry } from './adapters';
import type { ShortlistItem } from './types';

/** One page of `GET /shortlist`, rows already adapted. */
export interface ShortlistPage {
  items: ShortlistItem[];
  page: number;
  pages: number;
  total: number;
}

/**
 * A hundred rows a page.
 *
 * Higher than the property feed's twelve on purpose: this is a list a user
 * scans as a SET, the payload is the card projection rather than the full
 * document, and a shortlist long enough to need a second page is already
 * unusual. One request draws the whole thing for almost everyone.
 */
export const SHORTLIST_PAGE_SIZE = 100;

export async function fetchShortlistPage(
  page: number,
  signal?: AbortSignal
): Promise<ShortlistPage> {
  const response = await call(shortlistEndpoints.list, {
    data: { page, limit: SHORTLIST_PAGE_SIZE },
    signal,
  });

  const pagination = response.pagination;

  return {
    items: (response.data ?? []).map(adaptShortlistEntry),
    page: pagination?.page ?? page,
    pages: pagination?.pages ?? 1,
    total: pagination?.total ?? response.data?.length ?? 0,
  };
}

/** The cheap membership sync. Property ids, not entry ids. */
export async function fetchShortlistIds(signal?: AbortSignal): Promise<string[]> {
  const response = await call(shortlistEndpoints.ids, { signal });
  return response.data ?? [];
}

export async function addToShortlist(propertyId: ObjectId, note?: string): Promise<void> {
  await call(shortlistEndpoints.add, { data: { propertyId, note } });
}

export async function removeFromShortlistOnServer(propertyId: ObjectId): Promise<void> {
  await call(shortlistEndpoints.remove, { params: { propertyId } });
}

export async function setShortlistNoteOnServer(
  propertyId: ObjectId,
  note: string
): Promise<string> {
  const response = await call(shortlistEndpoints.setNote, {
    params: { propertyId },
    data: { note },
  });
  return response.data?.note ?? note;
}

export async function mergeShortlist(propertyIds: string[]) {
  return call(shortlistEndpoints.merge, { data: { propertyIds } });
}

export async function createShortlistShare() {
  const response = await call(shortlistEndpoints.share);
  return response.data;
}

export async function revokeShortlistShare(): Promise<boolean> {
  const response = await call(shortlistEndpoints.revokeShare);
  return response.revoked !== false;
}

export interface SharedShortlist {
  label: string;
  expiresAt: string;
  items: ShortlistItem[];
}

/** Someone else's list. Public, and carries no note by contract. */
export async function fetchSharedShortlist(
  token: string,
  signal?: AbortSignal
): Promise<SharedShortlist> {
  const response = await call(shortlistEndpoints.shared, { params: { token }, signal });
  const data = response.data;

  return {
    label: data?.label ?? '',
    expiresAt: data?.expiresAt ?? '',
    items: (data?.properties ?? []).map((entry) =>
      adaptShortlistEntry({ ...entry, note: undefined })
    ),
  };
}
