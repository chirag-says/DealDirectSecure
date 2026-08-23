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
  /** Project-level money. `bookingAmount` here is the LEGACY fallback for the
   *  booking token; `UnitType.paymentTerms.bookingAmount` takes precedence. */
  financials?: {
    bookingAmount?: number;
    gstPercentage?: number;
    stampDutyPercentage?: number;
    registrationCharges?: number;
    [key: string]: unknown;
  };
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
  /**
   * Publication lifecycle, added server-side 2026-08-22. A project is created
   * as a `draft` and only becomes publicly readable once an admin publishes it
   * past a blocking checklist.
   *
   * Nothing in this app needs to branch on it: the public list and detail
   * routes already filter to published (plus a legacy fallback for records
   * predating the field), so a draft simply is not returned. It is typed
   * because the old assumption — that visibility follows `isActive` — is no
   * longer how this works, and because `basics.status` is a CONSTRUCTION stage
   * ("Under Construction", "Ready To Move") that must never be read as
   * visibility.
   */
  publication?: {
    status?: 'draft' | 'published';
    publishedAt?: IsoDate;
    [key: string]: unknown;
  };
  /** Incremented on public detail reads only. */
  views?: number;
}

/** `GET /projects`. */
export interface ProjectListParams {
  search?: string;
  city?: string;
  category?: string;
  status?: string;
  page?: number;
  /** Backend default is 20, and it CLAMPS to a maximum of 60 — asking for more
   *  silently returns 60, it does not error. */
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
  area?: {
    carpetSqft?: number;
    builtUpSqft?: number;
    superBuiltUpSqft?: number;
    plotAreaSqft?: number;
    plotDimensions?: { length?: number; width?: number };
    [key: string]: unknown;
  };
  facing?: string[];
  /** A single enum string ("Semi Furnished"), not an object. */
  furnishing?: string;
  parking?: { covered?: number; open?: number; ev?: number };
  specifications?: {
    structure?: string;
    flooring?: Record<string, string | undefined>;
    kitchen?: {
      countertop?: string;
      isModular?: boolean;
      chimney?: boolean;
      sink?: string;
    };
    bathroom?: { sanitaryBrand?: string; fittingsBrand?: string; dadoHeight?: string };
    doors?: { mainDoor?: string; internalDoors?: string; finish?: string };
    windows?: { type?: string; mosquitoMesh?: boolean };
    electrical?: { wiringType?: string; switchBrand?: string; acPointsPerRoom?: number };
    [key: string]: unknown;
  };
  /**
   * Corrected 2026-08-22. Previously declared `twoDFloorPlan` /
   * `threeDFloorPlan`, which are not fields on this model —
   * `backend/models/UnitType.js:119-123` declares `twoDUrl`, `threeDUrl` and
   * `videoUrl`. Both old reads were permanently `undefined`, so the floor plan
   * at the top of the unit screen never rendered once: the screen's hero image
   * has been blank since it shipped.
   */
  floorPlans?: {
    twoDUrl?: string;
    threeDUrl?: string;
    videoUrl?: string;
  };
  photos?: { url: string; room?: string; caption?: string }[];
  pricing?: {
    basePrice?: number;
    pricePerSqft?: number;
    /** base + additional charges + view premium. Taxes are NOT in here. */
    effectivePrice?: number;
    additionalCharges?: {
      plc?: number;
      parking?: number;
      clubhouse?: number;
      legal?: number;
      maintenance?: number;
    };
    viewPremium?: number;
    [key: string]: unknown;
  };
  /**
   * `bookingAmount` is the token the buyer is asked for, and the first half of
   * the resolution the server performs — `UnitType.paymentTerms.bookingAmount`
   * first, `Project.financials.bookingAmount` as a legacy fallback. A unit type
   * where both are absent cannot be booked at all (400
   * `BOOKING_NOT_CONFIGURED`); it can still be enquired about.
   *
   * The three tax fields are additive and are deliberately NOT folded into
   * `pricing.effectivePrice` — they are government charges, not list price.
   */
  paymentTerms?: {
    bookingAmount?: number;
    gstPercentage?: number;
    stampDutyPercentage?: number;
    registrationCharges?: number;
    [key: string]: unknown;
  };
  /**
   * Corrected 2026-08-22. Previously declared `{ total, available }`, which are
   * not fields on this model — `backend/models/UnitType.js:160-165` declares
   * `totalUnits`, `availableUnits`, `bookedUnits` and `blockedUnits`. Both
   * reads were therefore permanently `undefined`, so the availability chip
   * never rendered and a sold-out unit type never disabled its own booking
   * button: the buyer filled in the form and met `NO_INVENTORY` at submit.
   *
   * The invariant the server maintains is
   * `totalUnits = availableUnits + bookedUnits + blockedUnits`.
   */
  inventory?: {
    totalUnits?: number;
    availableUnits?: number;
    bookedUnits?: number;
    blockedUnits?: number;
    towerAllocation?: unknown[];
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

/**
 * What the buyer was ASKED for. Both start life in `status: 'enquiry'`, so this
 * is the only way to tell them apart after the fact.
 *
 * `booking` — the buyer was quoted a token amount and is expected to pay it.
 * `enquiry` — the buyer asked a question; no payment was requested and none is
 *             owed. Sending `intent: 'enquiry'` is what skips the token gate,
 *             which is the only way to reach a unit type with no booking amount
 *             configured.
 *
 * Defaults to `booking` server-side when no intent is sent.
 */
export type BookingSource = 'enquiry' | 'booking';

/**
 * Statuses a BUYER may cancel from. Mirrors `USER_CANCELLABLE_STATES` in
 * `backend/controllers/bookingController.js:826`.
 *
 * `confirmed` and `completed` are excluded deliberately: they hold decremented
 * inventory and, on the group-buy path, a membership. Releasing those is an
 * admin decision with side effects.
 */
export const USER_CANCELLABLE_STATUSES: readonly BookingStatus[] = [
  'enquiry',
  'payment_submitted',
];

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
  /** Whether this began as a paid booking or a no-payment enquiry. */
  source?: BookingSource;
  statusHistory?: unknown[];
  /** Admin-maintained outreach log. Returned on `GET /bookings/my` because it
   *  lives on the document; the app does not write it. */
  contactHistory?: unknown[];
  /** Admin owning the follow-up. Not shown to the buyer. */
  assignedTo?: ObjectId | null;
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

/**
 * `POST /bookings`. Requires an authenticated user.
 *
 * Refusals worth handling individually, all of them actionable:
 * - 400 `NO_INVENTORY` — `availableUnits` is not at least 1, or was never set.
 * - 400 `BOOKING_NOT_CONFIGURED` — no token amount resolves. Only ever returned
 *   for a booking; an enquiry is exempt, which is the whole point of `intent`.
 * - 409 `DUPLICATE_ENQUIRY` — this user already has one open on this unit type.
 *   Cancelling the existing one frees the slot immediately.
 */
export interface CreateBookingRequest {
  projectId: ObjectId;
  unitTypeId: ObjectId;
  clientName: string;
  clientPhone: string;
  clientEmail?: string;
  notes?: string;
  /**
   * Send `'enquiry'` to ask without paying. Anything else — including omitting
   * it — is a booking and must satisfy the token-amount gate.
   */
  intent?: 'enquiry';
}

export interface CreateBookingResponse {
  success: true;
  message: string;
  data: {
    bookingId: ObjectId;
    /**
     * Resolved and persisted BY THE SERVER. Display this; never compute a
     * payable figure client-side. Zero for an enquiry.
     */
    tokenAmount?: number;
    status: BookingStatus;
    source?: BookingSource;
  };
}

/** `POST /bookings/:id/cancel`. */
export interface CancelBookingRequest {
  reason?: string;
}

export interface CancelBookingResponse {
  success: true;
  message: string;
  data: {
    status: BookingStatus;
    previousStatus: BookingStatus;
    /**
     * True when the buyer had already submitted payment evidence.
     *
     * Cancelling is NOT a refund and does not touch the payment fields: there
     * is no gateway behind this, so the UTR and screenshot are the only record
     * the money moved. A refund is arranged by a human, and the copy must say
     * so rather than implying the money comes back automatically.
     */
    refundMayBeDue: boolean;
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
