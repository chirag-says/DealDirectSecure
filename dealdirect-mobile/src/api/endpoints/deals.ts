/**
 * Deal endpoints. Mounted at `/api/deals` (backend/routes/dealRoutes.js).
 * Every route is behind `authMiddleware`.
 *
 * The deal is the lead seen from either side. Every route here answers for
 * the buyer who enquired AND for the listing's owner, and refuses anyone else
 * with 403 `NOT_A_PARTY`. `stage` is derived server-side and returned on
 * every write so the client can update without a refetch; it is never sent.
 */

import type {
  AttestRequest,
  AttestResponse,
  DealDetailResponse,
  DealListParams,
  DealListResponse,
  OpenConversationResponse,
  ProposeVisitRequest,
  ProposeVisitResponse,
  UpdateVisitRequest,
  UpdateVisitResponse,
  VisitFeedbackRequest,
  VisitFeedbackResponse,
} from '@/types/backend/deal';
import type { ObjectId } from '@/types/backend/common';
import { defineEndpoint } from './_contract';

export const dealsEndpoints = {
  list: defineEndpoint<DealListParams, DealListResponse>({
    method: 'GET',
    path: '/deals',
    auth: 'user',
    envelope: 'paginated',
    note:
      'Both sides of the caller by default; `role` narrows. Sorted by updatedAt desc. ' +
      '`counterpartName` is present on owner-side rows only.',
  }),

  detail: defineEndpoint<void, DealDetailResponse, { leadId: ObjectId }>({
    method: 'GET',
    path: ({ leadId }) => `/deals/${leadId}`,
    auth: 'user',
    envelope: 'data',
    note:
      '403 NOT_A_PARTY, 404 NOT_FOUND, 400 INVALID_ID. `counterpart.phone` is null on the ' +
      "buyer side until `contactRevealed`; the owner side sees the buyer's contact at once.",
  }),

  proposeVisit: defineEndpoint<ProposeVisitRequest, ProposeVisitResponse, { leadId: ObjectId }>({
    method: 'POST',
    path: ({ leadId }) => `/deals/${leadId}/visits`,
    auth: 'user',
    envelope: 'data',
    note:
      '201. 400 INVALID_TIME | TIME_IN_PAST | TOO_FAR_AHEAD (60 days); 409 VISIT_ALREADY_OPEN ' +
      '(one open visit per deal, body carries `visitId`); 409 DEAL_CLOSED.',
  }),

  updateVisit: defineEndpoint<
    UpdateVisitRequest,
    UpdateVisitResponse,
    { leadId: ObjectId; visitId: ObjectId }
  >({
    method: 'PUT',
    path: ({ leadId, visitId }) => `/deals/${leadId}/visits/${visitId}`,
    auth: 'user',
    envelope: 'data',
    note:
      'confirm | cancel | done | no_show. 409 OWN_PROPOSAL (only the other party confirms), ' +
      'NOT_PROPOSED, TIME_PASSED, NOT_OPEN, TOO_EARLY (before scheduledAt minus 30 min), ' +
      'ALREADY_CONFIRMED. `done` by the second party is how both confirm a visit happened.',
  }),

  visitFeedback: defineEndpoint<
    VisitFeedbackRequest,
    VisitFeedbackResponse,
    { leadId: ObjectId; visitId: ObjectId }
  >({
    method: 'POST',
    path: ({ leadId, visitId }) => `/deals/${leadId}/visits/${visitId}/feedback`,
    auth: 'user',
    envelope: 'data',
    note: 'Buyer only, once, visit must be done. 403 BUYER_ONLY; 409 VISIT_NOT_DONE | FEEDBACK_GIVEN.',
  }),

  openConversation: defineEndpoint<void, OpenConversationResponse, { leadId: ObjectId }>({
    method: 'POST',
    path: ({ leadId }) => `/deals/${leadId}/conversation`,
    auth: 'user',
    envelope: 'data',
    note:
      'Idempotent: 200 with the existing conversation, 201 when created. 503 CHAT_DISABLED ' +
      'unless the server has CHAT_ENABLED=true; treat that as a quiet state, not a fault.',
  }),

  attest: defineEndpoint<AttestRequest, AttestResponse, { leadId: ObjectId }>({
    method: 'POST',
    path: ({ leadId }) => `/deals/${leadId}/attest`,
    auth: 'user',
    envelope: 'data',
    note: 'Once per party per verification. 409 NO_VERIFICATION | ALREADY_ATTESTED.',
  }),
} as const;
