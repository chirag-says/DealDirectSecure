/**
 * What Sentry Session Replay may keep from a visitor's screen.
 *
 * A replay is a recording of the DOM, so anything the page shows can end up in
 * Sentry: names, phone numbers, addresses, enquiry text, payment references.
 * The SDK's own masking covers text nodes and form values. It does not cover
 * every channel a recording carries, so this module closes the rest:
 *
 *   - attribute values that hold text (image alt text, tooltips, labels);
 *   - link targets that hold contact details or form input: tel:, mailto:,
 *     WhatsApp links and any link with a query string;
 *   - iframes, whose src carries a map address or a storefront token;
 *   - console breadcrumbs, which log whatever the code logged;
 *   - query strings in navigation and network URLs, and in the replay's list
 *     of visited pages;
 *   - attribute values the click breadcrumb copies into its CSS selector.
 *
 * Two SDK behaviours decide where each rule has to live, both confirmed by
 * capturing a real replay from this site (privacy phase 1, 2026-10-17):
 *
 *   - rrweb never passes `href`, `src` or `srcset` to the attribute mask hook;
 *     it turns them into absolute URLs and returns. Listing them in
 *     `maskAttributes` does nothing, so sensitive links are BLOCKED instead.
 *   - `beforeAddRecordingEvent` only ever receives Sentry's custom events
 *     (breadcrumbs, network spans). DOM snapshots and mutations never reach
 *     it, so it cannot rewrite anything on the page itself.
 *
 * Every option is stated explicitly even where it matches the SDK default, so
 * an SDK upgrade that changes a default cannot quietly unmask anything.
 * `sentryReplayPrivacy.test.mjs` pins all of it.
 *
 * Breadcrumbs are not only a replay channel. Error and performance events
 * carry the same trail, so `dropConsoleBreadcrumb` is set as `beforeBreadcrumb`
 * in `Sentry.init` and keeps console output out of every event type.
 */

/** Attributes whose values are replaced with asterisks in the recording. */
const MASKED_ATTRIBUTES = Object.freeze([
  // The SDK's defaults.
  'title',
  'placeholder',
  'aria-label',
  // Text the defaults leave visible.
  'alt',
  'value',
  'label',
  'action',
  'download',
  'poster',
  'aria-description',
  'aria-valuetext',
]);

/**
 * Elements recorded as an empty box of the same size, attributes and all.
 * Added to the SDK's own block list (`.sentry-block`, `base`, srcdoc frames),
 * which it keeps.
 */
const BLOCKED_ELEMENTS = Object.freeze([
  // Map embeds carry an address or coordinates in src; the rewards storefront
  // carries a session token.
  'iframe',
  // Contact links: an owner's lead list renders the buyer's number and email.
  'a[href^="tel:"]',
  'a[href^="mailto:"]',
  'a[href^="sms:"]',
  'a[href*="wa.me"]',
  'a[href*="whatsapp"]',
  // Any link with a query string: share links, mailto subjects, map searches,
  // and whatever a form put in a URL.
  'a[href*="?"]',
]);

/** Cut a URL at its query string or fragment. Non-strings pass through. */
export function withoutQuery(value) {
  if (typeof value !== 'string') return value;
  const cut = value.search(/[?#]/);
  return cut === -1 ? value : value.slice(0, cut);
}

/** `button[aria-label="Call Asha"]` becomes `button[aria-label="***"]`. */
export function maskSelectorValues(selector) {
  if (typeof selector !== 'string') return selector;
  return selector.replace(/\[([^\]=]+)=(["'])[\s\S]*?\2\]/g, '[$1="***"]');
}

/**
 * `beforeAddRecordingEvent`. The SDK calls it for custom events only:
 * breadcrumbs and performance spans. Returns a scrubbed copy, or null to drop
 * the event.
 */
export function scrubRecordingEvent(event) {
  const tag = event?.data?.tag;
  const payload = event?.data?.payload;
  if (!payload || typeof payload !== 'object') return event;

  if (tag === 'breadcrumb') {
    if (payload.category === 'console') return null;

    const next = { ...payload };
    if (typeof next.category === 'string' && next.category.startsWith('ui.')) {
      next.message = maskSelectorValues(next.message);
    }
    if (next.category === 'navigation' && next.data) {
      next.data = { ...next.data, from: withoutQuery(next.data.from), to: withoutQuery(next.data.to) };
    }
    return { ...event, data: { ...event.data, payload: next } };
  }

  if (tag === 'performanceSpan' && typeof payload.description === 'string') {
    return {
      ...event,
      data: { ...event.data, payload: { ...payload, description: withoutQuery(payload.description) } },
    };
  }

  return event;
}

/**
 * `beforeBreadcrumb` for `Sentry.init`. Error and performance events carry the
 * breadcrumb trail as well as replays do, and the site logs property titles
 * and coordinates to the console. Console breadcrumbs are dropped before any
 * event can pick them up; every other breadcrumb passes through unchanged.
 *
 * The replay's own console check in `scrubRecordingEvent` stays as a second
 * layer, so removing this hook cannot put console output back into replays.
 */
export function dropConsoleBreadcrumb(breadcrumb) {
  return breadcrumb?.category === 'console' ? null : breadcrumb;
}

/**
 * Global event processor, for the replay event itself: the list of pages the
 * session visited and the request it started on. Other event types pass
 * through unchanged.
 */
export function scrubReplayEvent(event) {
  if (event?.type !== 'replay_event') return event;

  const next = { ...event };
  if (Array.isArray(next.urls)) next.urls = next.urls.map(withoutQuery);
  if (next.request) {
    next.request = { ...next.request, url: withoutQuery(next.request.url) };
    if (next.request.headers?.Referer) {
      next.request.headers = { ...next.request.headers, Referer: withoutQuery(next.request.headers.Referer) };
    }
  }
  return next;
}

/** Options for `Sentry.replayIntegration()`. */
export const REPLAY_PRIVACY_OPTIONS = Object.freeze({
  maskAllText: true,
  maskAllInputs: true,
  blockAllMedia: true,
  maskAttributes: MASKED_ATTRIBUTES,
  block: BLOCKED_ELEMENTS,
  // Nothing on the site may opt back out of masking.
  unmask: Object.freeze([]),
  unblock: Object.freeze([]),
  // No request or response bodies or headers, for any URL.
  networkDetailAllowUrls: Object.freeze([]),
  networkCaptureBodies: false,
  beforeAddRecordingEvent: scrubRecordingEvent,
});
