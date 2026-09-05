/**
 * Shortlist: listings the user is considering.
 *
 * Server-backed since Phase 1 (F7), with the device-local MMKV store kept as
 * the guest list and the offline cache. Read `store.ts` for the split, and
 * `merge.ts` for the one-time handover — the separation from the interested /
 * enquiry list is the entire reason this module exists and is enforced by the
 * shortlist endpoints being the only ones it can reach.
 */

export {
  useIsShortlisted,
  useShortlist,
  useShortlistList,
  useShortlistNote,
  useShortlistShare,
  useShortlistSync,
  useSharedShortlist,
  useToggleShortlist,
  isLocallyShortlisted,
  type ShortlistListState,
  type ShortlistNoteResult,
  type ShortlistShareState,
  type ToggleShortlistResult,
} from './hooks';

export {
  clearLocalShortlist,
  localShortlistIds,
  removeLocalShortlist,
  toggleLocalShortlist,
  useLocalShortlist,
  type ShortlistedProperty,
  type StoredShortlistEntry,
} from './store';

export {
  adaptShortlistEntry,
  adaptShortlistProperty,
  shortlistItemToComparable,
} from './adapters';
export { MERGE_CAP, decideMerge, type MergeDecision } from './merge';
export { SHORTLIST_PAGE_SIZE, type SharedShortlist, type ShortlistPage } from './api';

export { UNAVAILABLE_LABELS, type ShortlistItem, type ShortlistUnavailableReason } from './types';

export { ShortlistRow, type ShortlistRowProps } from './components/ShortlistRow';
export { ShortlistButton, type ShortlistButtonProps } from './components/ShortlistButton';
export {
  ShareShortlistSheet,
  sharedShortlistUrl,
  type ShareShortlistSheetProps,
} from './components/ShareShortlistSheet';
export {
  ShortlistNoteSheet,
  type ShortlistNoteSheetProps,
} from './components/ShortlistNoteSheet';
