/**
 * Content: the blog, and the website's help and legal pages rendered natively.
 *
 * ---------------------------------------------------------------------------
 * WHY THE LEGAL PAGES ARE SCREENS NOW, AND WHAT THAT COSTS — 2026-09-12
 *
 * Until today the privacy policy and terms opened the website, first in the
 * browser and then in a WebView, on the argument that legal text needs one
 * source of truth and a copy baked into a store binary drifts silently. That
 * argument was sound and it lost to two facts:
 *
 *   1. Store review reads the policy INSIDE the app. A WebView of a web page
 *      is a web page: it needs a network, it renders in the website's theme
 *      with the website's nav, and reviewers flag apps that wrap their site.
 *      The owner's instruction was explicit: everything Play Store checks has
 *      to be in the APK itself, themed like the app.
 *
 *   2. The website's pages are bespoke JSX, so there was never a shared data
 *      source the app could have read. The choice was "copy the text" or
 *      "show the website"; there was no third option short of building one.
 *
 * So the copy is here, as DATA (`pages/*.ts`, one file per website route),
 * rendered by one component (`components/ContentPageView.tsx`). The drift risk
 * is real and is handled, not wished away:
 *
 *   - each page file names the website file it mirrors, and the rule is that
 *     a change to one lands in the other in the same commit;
 *   - every page keeps an "Open on website" action, so the canonical text is
 *     one tap away and a stale copy is comparable, not hidden;
 *   - dates are carried as text from the source, never computed, so a page
 *     cannot claim to be newer than it is;
 *   - the FAQ, the one page whose website source IS data, is checked against
 *     that source by `pages/pages.test.ts` when both checkouts are present.
 *
 * `SUPPORT_CONTACT` is how to reach a human; `pages/contact.ts` explains why
 * it differs from the website's contact page.
 */

export { useBlogFeed, useBlogPost } from './blog';
export { SUPPORT_CONTACT } from './support';
export {
  CONTENT_PAGES,
  CONTENT_GROUP_TITLES,
  contactPage,
  contentPagesByGroup,
  getContentPage,
  webUrlFor,
  type ContentGroup,
  type ContentPageEntry,
} from './pages';
export {
  parseRichText,
  type Block,
  type ContentPage,
  type ContentPart,
  type RichText,
  type Section,
} from './pages/model';
export { ContentPageView, type ContentPageViewProps } from './components/ContentPageView';
export { ContactForm } from './components/ContactForm';
