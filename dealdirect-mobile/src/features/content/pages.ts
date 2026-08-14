import { WEB_URL } from '@/config/env';

/**
 * Pages that live on the website and open there.
 *
 * See the module doc in `index.ts` for why the legal pages are not ported into
 * the app. The short version: legal text needs one source of truth, and a
 * stale copy baked into a shipped binary cannot be corrected until the next
 * release is adopted.
 *
 * `WEB_URL` is optional in this app's config, and every consumer must handle
 * its absence: a link built against a guessed origin produces a dead page,
 * which is worse than not offering the link. `legalLinks()` returns an empty
 * list rather than fabricating one, and the Support screen simply omits the
 * section.
 */

export interface ExternalPage {
  id: string;
  label: string;
  path: string;
}

const PAGES: readonly ExternalPage[] = [
  { id: 'about', label: 'About DealDirect', path: '/about' },
  { id: 'why-us', label: 'Why DealDirect', path: '/why-us' },
  { id: 'privacy', label: 'Privacy policy', path: '/privacy' },
  { id: 'terms', label: 'Terms of service', path: '/terms' },
];

/** Absolute URLs, or an empty list when no web origin is configured. */
export function LEGAL_LINKS(): { page: ExternalPage; url: string }[] {
  if (!WEB_URL) return [];
  return PAGES.map((page) => ({ page, url: `${WEB_URL}${page.path}` }));
}

/**
 * Taken from the website's footer (`Footer.jsx:98,102`) rather than invented.
 * `POST /contact` exists but requires a session and is not wired up here — a
 * support screen that only works when signed in is the wrong shape for a
 * screen people reach when something is wrong.
 */
export const SUPPORT_CONTACT = {
  email: 'contact@dealdirect.in',
  phone: '+919289638963',
} as const;
