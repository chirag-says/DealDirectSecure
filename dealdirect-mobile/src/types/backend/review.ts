/**
 * Review contract. Source: backend/controllers/reviewController.js and
 * backend/models/Review.js (Phase 3 of the upgrade master plan).
 *
 * Only a party to a verified close can write one, and it is keyed by the
 * close-deal VERIFICATION, not by the lead. Both sides' reviews are revealed
 * together: a review publishes when the other side has also written one, or
 * fourteen days after the first, whichever comes first.
 */

import type { IsoDate, ObjectId } from './common';
import type { DealRole } from './deal';

export interface ReviewRatings {
  accuracy: number;
  responsiveness: number;
  seriousness: number;
}

export type ReviewStatus = 'pending' | 'published';

/** A published review as the public endpoint returns it. */
export interface Review {
  id: ObjectId;
  authorRole: DealRole;
  ratings: ReviewRatings;
  /** Mean of the three, one decimal. */
  overall: number;
  text: string | null;
  publishedAt: IsoDate | null;
  author: { name: string; profileImage?: string | null };
}

/** `GET /reviews/eligibility/:verificationId`. */
export interface ReviewEligibilityResponse {
  success: true;
  data: {
    eligible: boolean;
    role: DealRole;
    submitted: boolean;
    mine: { status: ReviewStatus; submittedAt: IsoDate; windowEndsAt: IsoDate } | null;
    counterpartSubmitted: boolean;
    counterpartPublished: Review | null;
  };
}

export interface SubmitReviewRequest {
  verificationId: ObjectId;
  /** Integers, 1 to 5. */
  ratings: ReviewRatings;
  /** At most 600 characters. */
  text?: string;
}

export interface SubmitReviewResponse {
  success: true;
  data: { id: ObjectId; status: ReviewStatus; windowEndsAt: IsoDate };
}

export interface UserReviewsParams {
  page?: number;
  limit?: number;
}

export interface ReviewSummary {
  count: number;
  accuracy?: number;
  responsiveness?: number;
  seriousness?: number;
  overall?: number;
}

/** `GET /reviews/user/:userId`. Public; published reviews only. */
export interface UserReviewsResponse {
  success: true;
  data: Review[];
  summary: ReviewSummary;
  pagination: { page: number; limit: number; total: number; pages: number };
}

/** `GET /reviews/mine`. */
export interface MyReviewsResponse {
  success: true;
  data: { written: Review[]; received: Review[] };
}
