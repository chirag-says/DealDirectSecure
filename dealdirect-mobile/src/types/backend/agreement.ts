/**
 * Agreement contract. Source: backend/models/Agreement.js and
 * backend/controllers/agreementController.js.
 *
 * Access is gated by `requireUserRole('owner', 'user')`, so an account whose
 * role is literally `buyer` receives 403 here even though authUser.js treats
 * `buyer` as a valid role elsewhere. Hide the entry point for that role and
 * explain the 403 rather than showing a generic error.
 */

import type { ObjectId, Timestamps } from './common';
import type { Property } from './property';

export type AgreementStatus = 'draft' | 'partially_signed' | 'signed' | string;

export interface Agreement extends Timestamps {
  _id: ObjectId;
  property?:
    | ObjectId
    | Pick<Property, '_id' | 'title' | 'price'> & { address?: { city?: string } };
  status: AgreementStatus;
  createdBy?: ObjectId;
  createdByRole?: string;
  idempotencyKey?: string;
  contentHash?: string;
  /** Stripped from list responses via `.select('-content -signature')`. */
  content?: string;
  signature?: unknown;
}

export interface AgreementTemplate {
  id?: string;
  name?: string;
  duration?: string;
  requiredRoles?: string[];
  [key: string]: unknown;
}

// --- Requests -------------------------------------------------------------

/**
 * `POST /agreements/generate`.
 *
 * Rate limited to 20 per hour per IP and body-capped at 50 KB. Monetary amounts
 * are NOT accepted from the client: the controller reads them from the Property
 * document server-side, so sending them has no effect.
 */
export interface GenerateAgreementRequest {
  propertyId: ObjectId;
  buyerId: ObjectId;
  landlordName: string;
  landlordAge?: number | string;
  landlordAddress?: string;
  landlordPhone?: string;
  landlordAadhaar?: string;
  tenantName: string;
  tenantAge?: number | string;
  tenantAddress?: string;
  tenantPhone?: string;
  tenantAadhaar?: string;
  startDate?: string;
  /** Backend default is 11. */
  durationMonths?: number;
  /** Backend default is 1. */
  noticePeriod?: number;
  /** Backend default is 5. */
  rentDueDay?: number;
  additionalTerms?: string;
}

// --- Responses ------------------------------------------------------------

/**
 * `POST /agreements/generate` returns 201 on creation, but 200 with
 * `isDuplicate: true` and a REDUCED agreement object when the idempotency key
 * matches an existing record. Branch on `isDuplicate`, not on status code
 * alone, because the two success shapes differ.
 */
export interface GenerateAgreementCreatedResponse {
  success: true;
  /** The generated agreement TEXT, not the document. */
  agreement: string;
  agreementId: ObjectId;
  idempotencyKey: string;
  contentHash: string;
  metadata?: Record<string, unknown>;
  isDuplicate?: undefined;
}

export interface GenerateAgreementDuplicateResponse {
  success: true;
  message: string;
  isDuplicate: true;
  agreement: {
    id: ObjectId;
    idempotencyKey: string;
    status: AgreementStatus;
  };
}

export type GenerateAgreementResponse =
  | GenerateAgreementCreatedResponse
  | GenerateAgreementDuplicateResponse;

export interface MyAgreementsResponse {
  success: true;
  count: number;
  agreements: Agreement[];
}

export interface AgreementDetailResponse {
  success: true;
  agreement: Agreement;
  integrity: {
    valid: boolean;
    reason?: string;
  };
}

export interface SignAgreementResponse {
  success: true;
  message: string;
  status: AgreementStatus;
  fullySigned: boolean;
}

export interface AgreementTemplatesResponse {
  success: true;
  templates: AgreementTemplate[];
  note: string;
}

export interface IndianStatesResponse {
  success: true;
  states: string[];
}
