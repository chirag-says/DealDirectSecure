/**
 * Review endpoints. Mounted at `/api/reviews` (backend/routes/reviewRoutes.js).
 *
 * A review is keyed by the close-deal VERIFICATION, and only its two parties
 * can write one. Both sides are revealed together (when both are in, or 14
 * days after the first), so a freshly submitted review is `pending` and
 * invisible to everyone, including its subject, until then.
 */

import type {
  MyReviewsResponse,
  ReviewEligibilityResponse,
  SubmitReviewRequest,
  SubmitReviewResponse,
  UserReviewsParams,
  UserReviewsResponse,
} from '@/types/backend/review';
import type { ObjectId } from '@/types/backend/common';
import { defineEndpoint } from './_contract';

export const reviewsEndpoints = {
  eligibility: defineEndpoint<void, ReviewEligibilityResponse, { verificationId: ObjectId }>({
    method: 'GET',
    path: ({ verificationId }) => `/reviews/eligibility/${verificationId}`,
    auth: 'user',
    envelope: 'data',
    note: '`eligible` is false for a non-party, an unapproved verification, or after submitting.',
  }),

  submit: defineEndpoint<SubmitReviewRequest, SubmitReviewResponse>({
    method: 'POST',
    path: '/reviews',
    auth: 'user',
    envelope: 'data',
    note: '201. Ratings are integers 1-5. 409 NOT_VERIFIED | ALREADY_REVIEWED; 400 INVALID_RATING.',
  }),

  forUser: defineEndpoint<UserReviewsParams, UserReviewsResponse, { userId: ObjectId }>({
    method: 'GET',
    path: ({ userId }) => `/reviews/user/${userId}`,
    auth: 'public',
    envelope: 'paginated',
    note: 'Published reviews only. `summary` carries means only when `count` > 0.',
  }),

  mine: defineEndpoint<void, MyReviewsResponse>({
    method: 'GET',
    path: '/reviews/mine',
    auth: 'user',
    envelope: 'data',
  }),
} as const;
