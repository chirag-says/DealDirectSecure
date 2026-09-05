/**
 * Deal contract. Source: backend/controllers/dealController.js and
 * backend/utils/dealStage.js (Phase 2 of the upgrade master plan).
 *
 * A deal IS a lead, read from either side. `GET /deals/:leadId` answers for
 * the buyer who enquired and for the owner of the listing, and `role` says
 * which one the caller is. `stage` is derived server-side from the facts on
 * the lead (visits, agreement, verification) and is never sent by a client.
 */

import type { IsoDate, ObjectId } from './common';
import type { LeadStatus } from './lead';

export type DealRole = 'buyer' | 'owner';

/** In order. The first is always done; the last is a verified close. */
export type DealStage = 'contacted' | 'visit_scheduled' | 'visited' | 'agreement' | 'closed';

export type VisitStatus = 'proposed' | 'confirmed' | 'done' | 'no_show' | 'cancelled';

export type VisitFeedback = 'interested' | 'thinking' | 'not_interested';

export interface Visit {
  id: ObjectId;
  scheduledAt: IsoDate;
  status: VisitStatus;
  /** User ids that have marked the visit done. Both parties' ids means both agree. */
  doneConfirmedBy: ObjectId[];
  proposedBy: ObjectId;
  confirmedBy?: ObjectId | null;
  completedBy?: ObjectId | null;
  note?: string | null;
  feedback: VisitFeedback | null;
  feedbackAt?: IsoDate | null;
  createdAt: IsoDate;
  updatedAt: IsoDate;
}

/** The listing, reduced to what a row and a strip need. */
export interface DealProperty {
  id: ObjectId;
  title: string;
  price?: number | null;
  priceUnit?: string | null;
  listingType?: string | null;
  city?: string | null;
  locality?: string | null;
  image?: string | null;
  status?: string | null;
}

/** Aggregate only. Never a history, never a name. */
export interface BuyerContext {
  activeWeeks: number | null;
  enquiries: number;
  visitsDone: number;
  budgetFit: 'within' | 'above' | 'below' | null;
}

// --- GET /deals -------------------------------------------------------------

export interface DealListParams {
  role?: DealRole;
  stage?: DealStage;
  page?: number;
  limit?: number;
}

export interface DealListRow {
  id: ObjectId;
  role: DealRole;
  stage: DealStage;
  status: LeadStatus;
  property: DealProperty | null;
  /** Owner side only: the buyer's name. The buyer side gets no name here. */
  counterpartName?: string;
  nextVisit: Visit | null;
  unread: number;
  /** Owner side: the buyer moved last and the owner has not replied. */
  awaitingOwner: boolean;
  updatedAt: IsoDate;
  createdAt: IsoDate;
}

export interface DealListResponse {
  success: true;
  data: DealListRow[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

// --- GET /deals/:leadId -----------------------------------------------------

export interface DealProgressRow {
  key: DealStage;
  done: boolean;
  at: IsoDate | null;
  /** One line of why, when the server has one ("No-show", "Cancelled"). */
  reason: string | null;
}

export interface DealCounterpart {
  id: ObjectId;
  name: string;
  profileImage?: string | null;
  /** Null until revealed; see `DealDetail.contactRevealed`. */
  phone: string | null;
  /** Owner side only. */
  email: string | null;
  verified: boolean;
}

export interface DealConversation {
  id: ObjectId;
  unread: number;
  lastMessage: { text: string; sender: ObjectId; at: IsoDate } | null;
}

export interface DealAttestation {
  mine: { statement: 'confirm' | 'dispute'; at: IsoDate } | null;
  counterpartDone: boolean;
}

export interface DealReviewState {
  eligible: boolean;
  submitted: boolean;
  status: 'pending' | 'published' | null;
  counterpartSubmitted: boolean;
}

export interface DealVerification {
  id: ObjectId;
  status: 'pending' | 'approved' | 'rejected';
  closingType?: string | null;
  claimed: boolean;
  payoutHoldUntil: IsoDate | null;
  attestation: DealAttestation;
  review: DealReviewState;
}

export interface DealDetail {
  id: ObjectId;
  role: DealRole;
  stage: DealStage;
  stageUpdatedAt?: IsoDate | null;
  status: LeadStatus;
  createdAt: IsoDate;
  /** Five rows, in stage order. The first is always done. */
  progress: DealProgressRow[];
  property: DealProperty | null;
  counterpart: DealCounterpart | null;
  /** Buyer side: the owner's phone appears only after the owner has engaged. */
  contactRevealed: boolean;
  firstOwnerResponseAt?: IsoDate | null;
  visits: Visit[];
  conversation: DealConversation | null;
  chatEnabled: boolean;
  agreementsEnabled: boolean;
  agreement: { id: ObjectId; at: IsoDate } | null;
  verification: DealVerification | null;
  /** Owner only. The owner's own CRM note on the lead. */
  notes?: string;
  /** Owner only. */
  userSnapshot?: { name: string; email: string; phone?: string; profileImage?: string };
  /** Owner only. */
  buyerContext?: BuyerContext | null;
}

export interface DealDetailResponse {
  success: true;
  data: DealDetail;
}

// --- Visits -----------------------------------------------------------------

export interface ProposeVisitRequest {
  scheduledAt: IsoDate;
  /** At most 200 characters. */
  note?: string;
}

export interface ProposeVisitResponse {
  success: true;
  data: Visit;
  stage: DealStage;
}

export type VisitAction = 'confirm' | 'cancel' | 'done' | 'no_show';

export interface UpdateVisitRequest {
  action: VisitAction;
}

export interface UpdateVisitResponse {
  success: true;
  data: Visit;
  stage: DealStage;
  /** Non-null when this update awarded the visit milestone. Never cashable. */
  milestone: { pointsAwarded: number; cashable: false } | null;
}

export interface VisitFeedbackRequest {
  feedback: VisitFeedback;
}

export interface VisitFeedbackResponse {
  success: true;
  data: Visit;
  status: LeadStatus;
  stage: DealStage;
}

// --- Conversation and attestation ------------------------------------------

/** 200 when reused, 201 when created; 503 `CHAT_DISABLED` when chat is off. */
export interface OpenConversationResponse {
  success: true;
  data: { conversationId: ObjectId };
  isNew: boolean;
}

export interface AttestRequest {
  statement: 'confirm' | 'dispute';
  /** At most 300 characters. */
  note?: string;
}

export interface AttestResponse {
  success: true;
  data: { statement: 'confirm' | 'dispute'; at: IsoDate };
}
