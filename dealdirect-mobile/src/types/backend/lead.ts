/**
 * Lead contract. Source: backend/models/Lead.js and
 * backend/controllers/leadController.js.
 *
 * A Lead is created when a buyer marks interest in a property
 * (`POST /properties/interested/:id`), which is why "interested" is not a
 * private bookmark.
 */

import type { IsoDate, ObjectId, Timestamps } from './common';
import type { BuyerContext, DealStage } from './deal';
import type { Property } from './property';

export type LeadStatus =
  | 'new'
  | 'contacted'
  | 'interested'
  | 'negotiating'
  | 'converted'
  | 'lost';

export type LeadContactAction = 'called' | 'emailed' | 'whatsapp' | 'met';

export interface Lead extends Timestamps {
  _id: ObjectId;
  /** Populated with `title price listingType city locality images categorizedImages`. */
  property:
    | ObjectId
    | Pick<
        Property,
        | '_id'
        | 'title'
        | 'price'
        | 'listingType'
        | 'city'
        | 'locality'
        | 'images'
        | 'categorizedImages'
      >;
  propertyOwner: ObjectId;
  user: ObjectId;

  /** Snapshot taken at interest time, so it does not follow later profile edits. */
  userSnapshot: {
    name: string;
    email: string;
    phone?: string;
    profileImage?: string;
  };

  propertySnapshot?: {
    title?: string;
    price?: number;
    listingType?: string;
    city?: string;
    locality?: string;
    propertyType?: string;
    bhk?: string;
  };

  status: LeadStatus;
  notes?: string;
  contactHistory?: Array<{
    action?: string;
    note?: string;
    date: IsoDate;
  }>;
  isViewed?: boolean;

  // --- Phase 2 (the deal spine). All optional: rows written before it carry
  // none of these, and every reader must tolerate their absence.

  /** Derived server-side; never sent by a client. */
  stage?: DealStage;
  /** When the owner first replied (status change, contact log, or message). */
  firstOwnerResponseAt?: IsoDate | null;
  /** Aggregate facts about the buyer, on `GET /leads` rows. Never a history. */
  buyerContext?: BuyerContext | null;
}

// --- Requests -------------------------------------------------------------

export interface LeadListParams {
  status?: LeadStatus;
  property?: ObjectId;
  page?: number;
  /** Backend default is 20. */
  limit?: number;
  /** Mongoose sort string. Backend default is `-createdAt`. */
  sort?: string;
  startDate?: string;
  endDate?: string;
}

export interface UpdateLeadStatusRequest {
  status: LeadStatus;
  notes?: string;
}

export interface AddContactHistoryRequest {
  action: LeadContactAction | string;
  note?: string;
}

// --- Responses ------------------------------------------------------------

/**
 * `GET /leads`. Note this carries BOTH a `stats` block and a `pagination`
 * block, which no other list endpoint does.
 */
export interface LeadListResponse {
  success: true;
  data: Lead[];
  stats: unknown;
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

/** `GET /leads/analytics`. */
export interface LeadAnalyticsResponse {
  success: true;
  data: {
    /** Aggregated into an object keyed by status. */
    statusStats: Partial<Record<LeadStatus, number>>;
    dailyLeads: Array<{ _id: string; count: number }>;
    leadsByProperty: unknown[];
    totalLeads: number;
    convertedLeads: number;
    conversionRate: number;
    newLeadsThisWeek: number;
    unreadLeads: number;
  };
}

export interface LeadAnalyticsParams {
  /** Backend default is 30. */
  days?: number;
}
