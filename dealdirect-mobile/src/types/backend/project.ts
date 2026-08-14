/**
 * Builder-project vertical contract. Source: backend/models/{Project,UnitType,
 * GroupBuyCampaign,ProjectBooking,Builder}.js and their controllers.
 *
 * These four models are large and mostly admin-authored. Typed here are the
 * nested groups the PUBLIC read endpoints return, which is all the mobile app
 * consumes. Admin-only write payloads are deliberately not modelled: the app
 * never sends them, and inventing types for them would be fiction.
 *
 * Public list endpoints hide inactive records. `attachAdminIfPresent` widens
 * visibility for an admin session only, which the mobile app never has.
 */

import type { IsoDate, ObjectId, Timestamps } from './common';

export interface Builder {
  _id: ObjectId;
  name?: string;
  company?: string;
  logoUrl?: string;
  logo?: string;
  city?: string;
}

// --- Project --------------------------------------------------------------

export interface Project extends Timestamps {
  _id: ObjectId;
  builder?: ObjectId | Builder;
  createdBy?: ObjectId;
  basics?: {
    name?: string;
    category?: string;
    status?: string;
    description?: string;
    [key: string]: unknown;
  };
  location?: {
    city?: string;
    state?: string;
    locality?: string;
    address?: string;
    latitude?: number;
    longitude?: number;
    [key: string]: unknown;
  };
  nearbyPlaces?: unknown[];
  overview?: Record<string, unknown>;
  amenities?: unknown[];
  media?: {
    exteriorImages?: string[];
    droneImages?: string[];
    masterPlan?: string[];
    locationMap?: string[];
    amenityImages?: string[];
    [key: string]: unknown;
  };
  documents?: Record<string, unknown>;
  legal?: Record<string, unknown>;
  paymentPlans?: unknown[];
  financials?: Record<string, unknown>;
  bankApprovals?: unknown[];
  constructionUpdates?: unknown[];
  salesContact?: Record<string, unknown>;
  priceRange?: {
    min?: number;
    max?: number;
    [key: string]: unknown;
  };
  activeCampaignCount?: number;
  unitTypeCount?: number;
  isActive?: boolean;
}

/** `GET /projects`. */
export interface ProjectListParams {
  search?: string;
  city?: string;
  category?: string;
  status?: string;
  page?: number;
  /** Backend default is 20. */
  limit?: number;
}

// --- UnitType -------------------------------------------------------------

export interface UnitType extends Timestamps {
  _id: ObjectId;
  project?: ObjectId | Pick<Project, '_id' | 'basics' | 'location'>;
  builder?: ObjectId | Builder;
  createdBy?: ObjectId;
  config?: {
    name?: string;
    bedrooms?: number;
    bathrooms?: number;
    [key: string]: unknown;
  };
  area?: Record<string, unknown>;
  facing?: string[];
  furnishing?: Record<string, unknown>;
  parking?: Record<string, unknown>;
  specifications?: Record<string, unknown>;
  floorPlans?: {
    twoDFloorPlan?: string;
    threeDFloorPlan?: string;
    [key: string]: unknown;
  };
  photos?: unknown[];
  pricing?: {
    basePrice?: number;
    effectivePrice?: number;
    [key: string]: unknown;
  };
  paymentTerms?: Record<string, unknown>;
  inventory?: {
    total?: number;
    available?: number;
    [key: string]: unknown;
  };
  highlights?: string[];
  isActive?: boolean;
  activeCampaignCount?: number;
}

// --- Group-buy campaign ---------------------------------------------------

export type CampaignStatus = string;

export interface GroupBuyCampaign extends Timestamps {
  _id: ObjectId;
  unitType?: ObjectId | Pick<UnitType, '_id' | 'config' | 'area' | 'pricing'>;
  project?: ObjectId | Pick<Project, '_id' | 'basics' | 'location'>;
  builder?: ObjectId | Builder;
  createdBy?: ObjectId;
  basics?: {
    name?: string;
    description?: string;
    [key: string]: unknown;
  };
  buyerTargets?: Record<string, unknown>;
  duration?: {
    startDate?: IsoDate;
    endDate?: IsoDate;
    [key: string]: unknown;
  };
  discountPerBuyer?: unknown;
  perks?: Record<string, unknown>;
  status?: CampaignStatus;
  memberCount?: number;
  paidMemberCount?: number;
}

export interface JoinCampaignResponse {
  success: true;
  message: string;
  data: {
    memberId: ObjectId;
    campaignName?: string;
    discountPerBuyer?: unknown;
    [key: string]: unknown;
  };
}

// --- Booking --------------------------------------------------------------

export type BookingStatus = string;

/**
 * `payment.status` on ProjectBooking. Closed enum, unlike `BookingStatus`.
 * Source: backend/models/ProjectBooking.js.
 */
export type BookingPaymentStatus = 'pending' | 'submitted' | 'verified' | 'rejected';

export interface ProjectBooking extends Timestamps {
  _id: ObjectId;
  project?: ObjectId | Pick<Project, '_id' | 'basics'>;
  unitType?: ObjectId | Pick<UnitType, '_id' | 'config'>;
  builder?: ObjectId | Builder;
  user?: ObjectId;
  clientName: string;
  clientPhone: string;
  clientEmail?: string;
  notes?: string;
  status: BookingStatus;
  statusHistory?: unknown[];
  /**
   * Corrected 2026-08-13 (defect F6) against `backend/models/ProjectBooking.js`.
   *
   * Previously declared `utr` and a `verified` boolean. Neither exists: the
   * field is `utrNumber`, and verification state is the `status` enum below.
   * Both old reads were permanently `undefined`, so the booking screen could
   * never show a verified or rejected payment and re-offered the submit form
   * forever.
   */
  payment?: {
    tokenAmount?: number;
    utrNumber?: string;
    screenshotUrl?: string;
    submittedAt?: IsoDate;
    verifiedAt?: IsoDate;
    verifiedBy?: ObjectId;
    status?: BookingPaymentStatus;
    rejectionReason?: string;
  };
}

/** `POST /bookings`. Requires an authenticated user. */
export interface CreateBookingRequest {
  projectId: ObjectId;
  unitTypeId: ObjectId;
  clientName: string;
  clientPhone: string;
  clientEmail?: string;
  notes?: string;
}

export interface CreateBookingResponse {
  success: true;
  message: string;
  data: {
    bookingId: ObjectId;
    tokenAmount?: number;
    status: BookingStatus;
  };
}

/** `GET /bookings/payment-config`. */
export interface PaymentConfigResponse {
  success: true;
  data: {
    qrUrl?: string;
    upiId?: string;
  };
}
