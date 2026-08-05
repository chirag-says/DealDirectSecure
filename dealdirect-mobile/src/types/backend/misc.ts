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
