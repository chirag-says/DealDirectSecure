/**
 * Agreement endpoints. Mounted at `/api/agreements`
 * (backend/routes/agreementRoutes.js).
 *
 * ROLE GATE: the protected routes require `requireUserRole('owner', 'user')`.
 * An account whose role is literally `buyer` gets a 403 here, even though
 * authUser.js accepts `buyer` as a valid role elsewhere. Hide the entry point
 * for that role and explain the 403 rather than showing a generic failure.
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
