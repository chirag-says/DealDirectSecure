/**
 * Shared primitives for the backend contract.
 *
 * These types describe what the DealDirect backend ACTUALLY returns, verified
 * against the controller source. They are not a wish list and not a
 * normalisation target. Where the backend is inconsistent, that inconsistency
 * is represented here faithfully and absorbed by the adapter layer above.
 */

/** A Mongo ObjectId, serialised as a 24-character hex string. */
export type ObjectId = string;

/** An ISO-8601 date string. Mongoose serialises all Date fields this way. */
export type IsoDate = string;

/**
 * A field declared `mongoose.Schema.Types.Mixed`. Several property fields
 * accept either a number or a free-text string ("Included", "On request"), so
 * neither alone is safe to assume.
 */
export type MixedValue = string | number;

/**
 * A `ref` field that may arrive either as a raw id or as a populated document,
 * depending on whether the specific controller called `.populate()`. Every use
 * site in this contract states which form that endpoint returns, so this helper
 * is only for the genuinely conditional cases.
 */
export type Ref<T> = ObjectId | T;

/** Fields added by `{ timestamps: true }`. */
export interface Timestamps {
  createdAt: IsoDate;
  updatedAt: IsoDate;
}

/**
 * Backend error codes, taken from the controllers and middleware. Branch on
 * these rather than on `message`, which is prose and is rewritten by the error
 * handler.
 */
export type BackendErrorCode =
  // Session and authentication (middleware/authUser.js)
  | 'NO_SESSION'
  | 'INVALID_SESSION'
  | 'SESSION_REVOKED'
  | 'TOKEN_EXPIRED'
  | 'INVALID_TOKEN'
  | 'USER_NOT_FOUND'
  | 'AUTH_ERROR'
  | 'NOT_AUTHENTICATED'
  | 'INVALID_ROLE'
  | 'PASSWORD_CHANGED'
  // Account state (controllers/userController.js)
  | 'ACCOUNT_BLOCKED'
  | 'ACCOUNT_DEACTIVATED'
  | 'ACCOUNT_LOCKED'
  | 'EMAIL_NOT_VERIFIED'
  // Authorisation
  | 'FORBIDDEN'
  | 'NOT_OWNER'
  | 'NOT_FOUND'
  | 'OWNERSHIP_CHECK_ERROR'
  // Rate limiting (server.js)
  | 'RATE_LIMITED'
  | 'AUTH_RATE_LIMITED'
  | 'SEARCH_RATE_LIMITED'
  | 'TRANSACTION_RATE_LIMITED'
  | 'WEBHOOK_RATE_LIMITED'
  // Account deletion (controllers/userController.js). INVALID_PASSWORD arrives
  // with a 401, which is the ONE 401 on this API that does not mean the session
  // is over — see the note on it in api/errors.ts.
  | 'PASSWORD_REQUIRED'
  | 'INVALID_PASSWORD'
  // Google sign-in (controllers/authGoogleController.js).
  //
  // GOOGLE_LINK_REQUIRED is the important one: a 409 saying the email already
  // has a password account, which must be proved before Google is attached. It
  // is NOT a failure to show as an error — it is a step in the flow.
  | 'GOOGLE_LINK_REQUIRED'
  | 'GOOGLE_ALREADY_LINKED'
  | 'GOOGLE_INVALID_TOKEN'
  | 'GOOGLE_EMAIL_NOT_VERIFIED'
  | 'GOOGLE_NOT_CONFIGURED'
  | 'GOOGLE_CONFIRMATION_REQUIRED'
  | 'INVALID_GOOGLE_CONFIRMATION'
  | 'USE_GOOGLE_SIGNIN'
  | 'NO_PASSWORD_SET'
  | 'NO_PHONE_ON_ACCOUNT'
  // Just-in-time phone verification (middleware/requirePhoneVerified.js and
  // controllers/phoneVerificationController.js).
  //
  // PHONE_VERIFICATION_REQUIRED is a 403 that the API layer INTERCEPTS: it
  // opens the verification sheet and replays the original request on success,
  // so screens never see it. See auth/phoneGate.ts.
  | 'PHONE_VERIFICATION_REQUIRED'
  | 'PHONE_ALREADY_LINKED'
  | 'INVALID_PHONE'
  | 'OTP_EXPIRED'
  | 'OTP_INVALID'
  | 'OTP_ATTEMPTS_EXCEEDED'
  | 'OTP_SEND_LIMIT'
  | 'SMS_NOT_CONFIGURED'
  | 'SMS_SEND_FAILED'
  // Bookings and inventory (controllers/bookingController.js). Every one of
  // these is a refusal the buyer can act on, so each needs its own copy and its
  // own next step rather than a generic error line.
  | 'NO_INVENTORY'
  | 'BOOKING_NOT_CONFIGURED'
  | 'DUPLICATE_ENQUIRY'
  | 'NOT_CANCELLABLE'
  // Properties (controllers/propertyController.js)
  | 'LEGACY_BUILDER_LISTING'
  | 'DELETE_BLOCKED_DEPENDENTS'
  // Group buy (controllers/campaignController.js)
  | 'CAMPAIGN_MEMBER_PAYMENT_PROTECTED'
  // Deals (controllers/dealController.js). Each is a refusal the user can act
  // on, so each maps to its own line of copy in `features/deals`.
  | 'NOT_A_PARTY'
  | 'INVALID_ID'
  | 'INVALID_TIME'
  | 'TIME_IN_PAST'
  | 'TOO_FAR_AHEAD'
  | 'VISIT_ALREADY_OPEN'
  | 'DEAL_CLOSED'
  | 'OWN_PROPOSAL'
  | 'NOT_PROPOSED'
  | 'TIME_PASSED'
  | 'NOT_OPEN'
  | 'TOO_EARLY'
  | 'ALREADY_CONFIRMED'
  | 'BUYER_ONLY'
  | 'VISIT_NOT_DONE'
  | 'FEEDBACK_GIVEN'
  | 'CHAT_DISABLED'
  | 'NO_VERIFICATION'
  | 'ALREADY_ATTESTED'
  // Chat report (controllers/chatController.js)
  | 'OWN_MESSAGE'
  | 'REASON_REQUIRED'
  // Reviews (controllers/reviewController.js)
  | 'NOT_VERIFIED'
  | 'ALREADY_REVIEWED'
  | 'INVALID_RATING'
  // Reward claim (controllers/propertyController.js)
  | 'PAYOUT_ON_HOLD'
  // Shortlist (Phase 1, F7). `NOT_SHORTLISTED` is a 404 on the note route and
  // means the row went away on another device; `EMPTY_SHORTLIST` is a 409 on
  // share and is a state, not a fault.
  | 'NOT_SHORTLISTED'
  | 'EMPTY_SHORTLIST'
  // Locality price data (Phase 4, F18). Both are normal answers: below the
  // sample floor there is nothing honest to publish.
  | 'LOCALITY_NOT_FOUND'
  | 'LOCATION_REQUIRED';

/**
 * The error body. Note that `message` is a STRING here. On a small number of
 * SUCCESS responses the backend uses `message` for an object instead; those are
 * called out individually where they occur.
 */
export interface BackendErrorBody {
  success?: false;
  message: string;
  code?: BackendErrorCode;
  requestId?: string;
  /** Present on 429 responses. */
  retryAfter?: number;
  /** Present on 423 (account lockout). */
  lockoutUntil?: IsoDate;
  /** Present on 403 when the account is blocked. */
  blockReason?: string;
  /** Present on 403 from `requireRole`. */
  requiredRoles?: string[];
  /** Present on 409 `PAYOUT_ON_HOLD`: when the held payout becomes claimable. */
  holdUntil?: IsoDate;
  /** Present on 409 `VISIT_ALREADY_OPEN`: the visit that is already open. */
  visitId?: ObjectId;
  /**
   * Present on 409 `GOOGLE_LINK_REQUIRED`: the address that already has an
   * account, read out of the verified Google token rather than the request.
   * Shown in the link prompt so the user knows which password is being asked
   * for — they may well have several.
   */
  email?: string;
  /**
   * Present on 400 `OTP_INVALID`: guesses left before the code is burned.
   *
   * Worth surfacing. A code that silently stops working after five tries reads
   * as a broken app; a count reads as a rule.
   */
  attemptsRemaining?: number;
}

// ---------------------------------------------------------------------------
// Response envelopes
//
// The backend uses SIX different envelope shapes across its endpoints. There is
// no single generic unwrapper. Each endpoint declares which of these it
// returns, and the adapter layer normalises above this point.
// ---------------------------------------------------------------------------

/** `{ success: true, data: T }` */
export interface DataEnvelope<T> {
  success: true;
  data: T;
  message?: string;
}

/** `{ success: true, data: T[], count: number }` */
export interface CountedDataEnvelope<T> {
  success: true;
  data: T[];
  count: number;
}

/**
 * `{ data: T[], total, page, pages }`
 *
 * Used only by `GET /properties/search`. Note the absent `success` key: this
 * envelope does NOT carry one, so a truthiness check on `success` would treat
 * every successful search as a failure.
 */
export interface PagedEnvelope<T> {
  data: T[];
  total: number;
  page: number;
  pages: number;
}

/** `{ success: true, data: T[], pagination: { total, page, pages } }` */
export interface PaginatedDataEnvelope<T> {
  success: true;
  data: T[];
  pagination: {
    total: number;
    page: number;
    pages: number;
  };
}

/** `{ success: true }` with no payload. */
export interface OkEnvelope {
  success: true;
  message?: string;
}

/**
 * A bare, unwrapped payload. `GET /properties/list` returns a naked array and
 * `GET /properties/:id` returns a naked object, with no envelope at all.
 */
export type BareEnvelope<T> = T;

/** Standard page/limit query parameters. */
export interface PaginationParams {
  page?: number;
  limit?: number;
}
