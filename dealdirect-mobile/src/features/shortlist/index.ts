/**
 * Shortlist: listings the user is considering, kept on this device.
 *
 * Deliberately has no API surface. Read `store.ts` before adding one — the
 * separation from the interested/enquiry list is the entire reason this module
 * exists, and it is enforced by this feature importing no client.
 */

export {
  isShortlisted,
  removeFromShortlist,
  toggleShortlist,
  useIsShortlisted,
  useShortlist,
  type ShortlistedProperty,
} from './store';

export { ShortlistRow, type ShortlistRowProps } from './components/ShortlistRow';
export { ShortlistButton, type ShortlistButtonProps } from './components/ShortlistButton';
