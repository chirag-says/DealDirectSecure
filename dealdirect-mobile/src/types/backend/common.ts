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
  | 'CAMPAIGN_MEMBER_PAYMENT_PROTECTED';

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
