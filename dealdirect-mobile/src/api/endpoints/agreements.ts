/**
 * ⚠️ AGREEMENTS ARE WITHDRAWN FROM THE PRODUCT. DO NOT BUILD AGAINST THIS.
 *
 * Client decision 2026-08-01, reconfirmed 2026-08-13 (HANDOFF §9.1 D1). The
 * website's `/agreements` page returns 404 and its three navbar links are
 * commented out; the backend mount is commented out too
 * (`backend/server.js:869`), so after the next deploy every route below 404s.
 * The mobile placeholder screens were deleted in the same pass.
 *
 * This file is kept, unregistered and uncalled, for two reasons: the typing
 * work is done if the feature is ever restored, and its absence would leave
 * nothing to explain WHY there is no agreements client. Six typed endpoints
 * sitting in the registry read as an invitation without this header.
 *
 * If it is ever restored, note the precondition recorded at
 * `backend/server.js:860-863`: `POST /agreements/webhook/payment` skips HMAC
 * verification entirely when `PAYMENT_WEBHOOK_SECRET` is unset. That must be
 * fixed before the mount returns, and this app must never be the reason it
 * returns early.
 *
 * ---------------------------------------------------------------------------
 * ROLE GATE (for whenever it comes back): the protected routes require
 * `requireUserRole('owner', 'user')`. An account whose role is literally
 * `buyer` gets a 403 here, even though authUser.js accepts `buyer` as a valid
 * role elsewhere. Hide the entry point for that role and explain the 403
 * rather than showing a generic failure.
 */

import type {
  AgreementDetailResponse,
  AgreementTemplatesResponse,
  GenerateAgreementRequest,
  GenerateAgreementResponse,
  IndianStatesResponse,
  MyAgreementsResponse,
  SignAgreementResponse,
} from '@/types/backend/agreement';
import type { ObjectId } from '@/types/backend/common';
import { defineEndpoint } from './_contract';

export const agreementsEndpoints = {
  templates: defineEndpoint<void, AgreementTemplatesResponse>({
    method: 'GET',
    path: '/agreements/templates',
    auth: 'public',
    envelope: 'keyed',
  }),

  states: defineEndpoint<void, IndianStatesResponse>({
    method: 'GET',
    path: '/agreements/states',
    auth: 'public',
    envelope: 'keyed',
  }),

  generate: defineEndpoint<GenerateAgreementRequest, GenerateAgreementResponse>({
    method: 'POST',
    path: '/agreements/generate',
    auth: 'user',
    envelope: 'keyed',
    rateLimit: 'transactional',
    note:
      'TWENTY PER HOUR per IP; exhausting it costs the user an hour. Body capped at 50KB. ' +
      'Slow (AI generation) — treat as a long-running job, block double submission, and keep ' +
      'the progress state alive across navigation. Two success shapes: 201 created, or 200 ' +
      'with isDuplicate=true and a reduced agreement object. Monetary amounts are read from ' +
      'the Property server-side and cannot be set by the client.',
  }),

  mine: defineEndpoint<void, MyAgreementsResponse>({
    method: 'GET',
    path: '/agreements/my-agreements',
    auth: 'user',
    envelope: 'keyed',
    note: 'List responses strip `content` and `signature`; fetch the detail route for those.',
  }),

  detail: defineEndpoint<void, AgreementDetailResponse, { id: ObjectId }>({
    method: 'GET',
    path: ({ id }) => `/agreements/${id}`,
    auth: 'user',
    envelope: 'keyed',
    note:
      'IDOR-protected in the controller. Also returns an `integrity` block from the HMAC ' +
      'check; surface a warning if `integrity.valid` is false rather than hiding it.',
  }),

  sign: defineEndpoint<void, SignAgreementResponse, { id: ObjectId }>({
    method: 'POST',
    path: ({ id }) => `/agreements/${id}/sign`,
    auth: 'user',
    envelope: 'keyed',
    note: '`fullySigned` is true only once BOTH parties have signed.',
  }),
} as const;
