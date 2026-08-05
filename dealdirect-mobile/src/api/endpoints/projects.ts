/**
 * Builder-project vertical. Mounted at `/api/projects`, `/api/unit-types`,
 * `/api/campaigns` and `/api/bookings`.
 *
 * Public GET routes use `attachAdminIfPresent`, which widens visibility to
 * inactive records for an admin session. The mobile app never holds one, so it
 * always sees the active-only view.
 *
 * Builder-posted properties are excluded from the regular property feeds, so
 * this vertical is the only way they surface.
 */

import type {
  CreateBookingRequest,
  CreateBookingResponse,
  GroupBuyCampaign,
  JoinCampaignResponse,
  PaymentConfigResponse,
  Project,
  ProjectBooking,
  ProjectListParams,
  UnitType,
} from '@/types/backend/project';
import type {
  DataEnvelope,
  ObjectId,
  OkEnvelope,
  PaginatedDataEnvelope,
} from '@/types/backend/common';
import { defineEndpoint } from './_contract';

export const projectsEndpoints = {
  list: defineEndpoint<ProjectListParams, PaginatedDataEnvelope<Project>>({
    method: 'GET',
    path: '/projects',
    auth: 'optional',
    envelope: 'paginated',
    note:
      'Default limit 20. `search` runs a Mongo $text query, so it needs whole words and will ' +
      'not do prefix matching the way the property search regex does.',
  }),

  detail: defineEndpoint<void, DataEnvelope<Project>, { id: ObjectId }>({
    method: 'GET',
    path: ({ id }) => `/projects/${id}`,
    auth: 'optional',
    envelope: 'data',
  }),

  byBuilder: defineEndpoint<void, DataEnvelope<Project[]>, { builderId: ObjectId }>({
    method: 'GET',
    path: ({ builderId }) => `/projects/builder/${builderId}`,
    auth: 'optional',
    envelope: 'data',
    note: 'Not paginated.',
  }),
} as const;

export const unitTypesEndpoints = {
  byProject: defineEndpoint<void, DataEnvelope<UnitType[]>, { projectId: ObjectId }>({
    method: 'GET',
    path: ({ projectId }) => `/unit-types/project/${projectId}`,
    auth: 'optional',
    envelope: 'data',
    note: 'Sorted oldest-first (createdAt ascending), unlike most list endpoints.',
  }),

  detail: defineEndpoint<void, DataEnvelope<UnitType>, { id: ObjectId }>({
    method: 'GET',
    path: ({ id }) => `/unit-types/${id}`,
    auth: 'optional',
    envelope: 'data',
  }),
} as const;

export const campaignsEndpoints = {
  byUnitType: defineEndpoint<
    { status?: string },
    DataEnvelope<GroupBuyCampaign[]>,
    { unitTypeId: ObjectId }
  >({
    method: 'GET',
    path: ({ unitTypeId }) => `/campaigns/unit-type/${unitTypeId}`,
    auth: 'public',
    envelope: 'data',
  }),

  byProject: defineEndpoint<
    { status?: string },
    DataEnvelope<GroupBuyCampaign[]>,
    { projectId: ObjectId }
  >({
    method: 'GET',
    path: ({ projectId }) => `/campaigns/project/${projectId}`,
    auth: 'public',
    envelope: 'data',
  }),

  detail: defineEndpoint<void, DataEnvelope<GroupBuyCampaign>, { id: ObjectId }>({
    method: 'GET',
    path: ({ id }) => `/campaigns/${id}`,
    auth: 'public',
    envelope: 'data',
  }),

  join: defineEndpoint<void, JoinCampaignResponse, { id: ObjectId }>({
    method: 'POST',
    path: ({ id }) => `/campaigns/${id}/join`,
    auth: 'user',
    envelope: 'data',
    rateLimit: 'groupBuy',
    note: 'Ten per 15 minutes per IP, shared with exit. Returns 201 with the new memberId.',
  }),

  exit: defineEndpoint<void, OkEnvelope, { id: ObjectId }>({
    method: 'POST',
    path: ({ id }) => `/campaigns/${id}/exit`,
    auth: 'user',
    envelope: 'ok',
    rateLimit: 'groupBuy',
  }),

  uploadPaymentProof: defineEndpoint<FormData, OkEnvelope, { id: ObjectId }>({
    method: 'POST',
    path: ({ id }) => `/campaigns/${id}/payment-proof`,
    auth: 'user',
    envelope: 'ok',
    note:
      'multipart/form-data, single file field `paymentProof`. Returns only a message; the ' +
      'updated member record is not echoed back, so refetch if the UI needs it.',
  }),
} as const;

export const bookingsEndpoints = {
  create: defineEndpoint<CreateBookingRequest, CreateBookingResponse>({
    method: 'POST',
    path: '/bookings',
    auth: 'user',
    envelope: 'data',
    note:
      'Requires login despite reading like a public lead form. Required fields are projectId, ' +
      'unitTypeId, clientName and clientPhone.',
  }),

  submitPayment: defineEndpoint<FormData, OkEnvelope, { id: ObjectId }>({
    method: 'POST',
    path: ({ id }) => `/bookings/${id}/payment`,
    auth: 'user',
    envelope: 'keyed',
    note: 'multipart/form-data, single file field `screenshot`, plus the UTR fields.',
  }),

  mine: defineEndpoint<void, DataEnvelope<ProjectBooking[]>>({
    method: 'GET',
    path: '/bookings/my',
    auth: 'user',
    envelope: 'data',
  }),

  paymentConfig: defineEndpoint<void, PaymentConfigResponse>({
    method: 'GET',
    path: '/bookings/payment-config',
    auth: 'user',
    envelope: 'data',
    note: 'Returns the UPI id and QR image used for the manual token payment.',
  }),
} as const;
