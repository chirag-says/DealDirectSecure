import { WEB_URL } from '@/config/env';

/**
 * Pages that live on the website and open there.
 *
 * See the module doc in `index.ts` for why the legal pages are not ported into
 * the app. The short version: legal text needs one source of truth, and a
 * stale copy baked into a shipped binary cannot be corrected until the next
 * release is adopted.
 *
 * `WEB_URL` now always resolves — see the note on its default in `config/env.ts`.
 * It used to be optional, and because nothing set it, this function returned an
 * empty list in every build and the Support screen silently omitted the section
 * carrying the Privacy policy and Terms. An app store will not accept that. The
 * guard below is kept as a belt-and-braces against a future empty override
 * rather than as a state the shipped app is expected to reach.
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
