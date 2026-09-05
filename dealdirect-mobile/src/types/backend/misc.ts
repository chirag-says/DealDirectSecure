/**
 * Blog and contact-inquiry contracts.
 * Source: backend/models/{Blog,ContactInquiry}.js and their controllers.
 */

import type { IsoDate, ObjectId, Timestamps } from './common';

// --- Blog -----------------------------------------------------------------

export interface Blog extends Timestamps {
  _id: ObjectId;
  title: string;
  slug: string;
  excerpt?: string;
  content?: string;
  coverImage?: string;
  category?: string;
  tags?: string[];
  /** The public list filters on `status: 'published'`. There is no boolean flag. */
  status?: string;
  publishedAt?: IsoDate;
}

/**
 * `GET /blogs`.
 *
 * The free-text parameter is `q` here, whereas property search uses `search`.
 * The two are not interchangeable. `q` runs a Mongo $text query, so it matches
 * whole words rather than prefixes.
 */
export interface BlogListParams {
  page?: number;
  /** Backend default is 10. */
  limit?: number;
  category?: string;
  tag?: string;
  q?: string;
}

/** `GET /blogs/:slug`. Also returns a `related` list alongside the post. */
export interface BlogDetailResponse {
  success: true;
  data: Blog;
  related: Blog[];
}

// --- Contact inquiry ------------------------------------------------------

export interface ContactInquiry extends Timestamps {
  _id: ObjectId;
  user?: ObjectId;
  subject: string;
  message: string;
  category?: string;
  isRead?: boolean;
  status?: string;
}

/**
 * `POST /contact`. Requires an authenticated user despite reading like a public
 * contact form, and the JSON body is capped at 20 KB.
 */
export interface CreateInquiryRequest {
  subject: string;
  message: string;
  category?: string;
}

export interface CreateInquiryResponse {
  success: true;
  message: string;
  inquiry: ContactInquiry;
}

/** `GET /contact/my-inquiries`. Response key is `inquiries`, not `data`. */
export interface MyInquiriesResponse {
  success: true;
  inquiries: ContactInquiry[];
}

// --- Usage events (Phase 0) -----------------------------------------------

/**
 * `POST /events`. The name whitelist and the allowed props per name live in
 * `src/analytics/events.ts`; the wire shape here is deliberately loose because
 * the backend drops unknown names and props silently rather than rejecting the
 * batch, so a typo costs an event, not a request.
 */
export interface UsageEventPayload {
  name: string;
  props?: Record<string, unknown>;
  /** ISO-8601, the moment the event happened, not the moment it was sent. */
  at?: IsoDate;
}

export interface IngestEventsRequest {
  /** At most 50 per batch; the backend rejects a larger one. */
  events: UsageEventPayload[];
  platform: 'android' | 'ios';
  /** Stable per-install id, so guests can be counted across sessions. */
  anon?: string;
}

/** 202. `accepted` is how many of `events` survived the whitelist. */
export interface IngestEventsResponse {
  success: true;
  accepted: number;
}
