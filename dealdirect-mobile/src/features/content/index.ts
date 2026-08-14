/**
 * Content: the blog, the FAQ, and the links out to the website's legal pages.
 *
 * ---------------------------------------------------------------------------
 * WHY PRIVACY AND TERMS ARE LINKS AND NOT SCREENS
 *
 * The website ships `/privacy` and `/terms` as full pages, and the obvious
 * parity move is to port the copy. That would be a mistake: legal text has to
 * have exactly one source of truth. Two copies drift, and the app's copy would
 * drift SILENTLY — an app-store binary cannot be corrected the way a web page
 * can, so a terms change would leave stale terms live on every installed
 * device until the next release ships and is adopted.
 *
 * So they open the website. `WEB_URL` is the one place the origin is
 * configured, and `LEGAL_LINKS` below is the one place the paths are.
 */

export { useBlogFeed, useBlogPost } from './blog';
export { FAQ_CATEGORIES, type FaqCategory, type FaqEntry } from './faq';
export { LEGAL_LINKS, SUPPORT_CONTACT, type ExternalPage } from './pages';
