/**
 * Endpoint descriptor primitives.
 *
 * M0 declares endpoints, it does not call them. Nothing in this directory
 * imports axios or performs I/O; the transport layer arrives in M2 and consumes
 * these descriptors. Keeping the two apart means the contract compiles and can
 * be reviewed on its own, and a path can only ever be written in one place.
 */

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/**
 * Which credential the route requires.
 *
 * `user`  — the `user_session` cookie (middleware/authUser.authMiddleware).
 * `optional` — `optionalAuth`, or `attachAdminIfPresent`, which widens the
 *              response for an admin session but works anonymously.
 * `admin` — `protectAdmin`. The mobile app NEVER holds an admin session; these
 *           are catalogued only so nobody mistakes them for callable.
 */
export type AuthRequirement = 'public' | 'optional' | 'user' | 'admin';

/**
 * Which of the backend's six response envelopes this route returns. Recorded so
 * the adapter layer can be checked against the contract rather than against
 * whatever a given screen happened to assume.
 */
export type EnvelopeKind =
  | 'bare' // no wrapper at all
  | 'data' // { success, data }
  | 'counted' // { success, data, count }
  | 'paged' // { data, total, page, pages } — no `success` key
  | 'paginated' // { success, data, pagination: {...} }
  | 'keyed' // { success, <domainKey>: ... }
  | 'ok'; // { success } with no payload

/** Rate limiters applied in backend/server.js, by mount path. */
export type RateLimitTier =
  | 'global' // 500 / 15 min
  | 'auth' // 5 / 15 min, successful requests not counted
  | 'search' // 20 / min
  | 'transactional' // 20 / hour
  | 'groupBuy'; // 10 / 15 min

export interface EndpointSpec<TPathParams = void> {
  readonly method: HttpMethod;
  /**
   * Path relative to the API base, WITHOUT the `/api` prefix (the base URL
   * already carries it).
   *
   * A route with no path parameters declares a plain string. A parameterised
   * route declares a builder, so an id is interpolated in exactly one place and
   * the parameter names are checked at the call site.
   */
  readonly path: TPathParams extends void ? string : (params: TPathParams) => string;
  readonly auth: AuthRequirement;
  readonly envelope: EnvelopeKind;
  /** Only set where a limiter stricter than `global` applies. */
  readonly rateLimit?: RateLimitTier;
  /** Anything a caller would otherwise get wrong. */
  readonly note?: string;
}

/**
 * An endpoint carrying its request and response types.
 *
 * `__request` and `__response` are phantom: they exist to be read by the
 * transport layer in M2 and are never populated at runtime.
 */
export interface Endpoint<TRequest, TResponse, TPathParams = void>
  extends EndpointSpec<TPathParams> {
  readonly __request?: TRequest;
  readonly __response?: TResponse;
}

/**
 * Declare an endpoint.
 *
 *   defineEndpoint<LoginRequest, AuthResponse>({ ... })
 *   defineEndpoint<void, OkEnvelope, { sessionId: ObjectId }>({ ... })
 */
export const defineEndpoint = <TRequest = void, TResponse = unknown, TPathParams = void>(
  spec: EndpointSpec<TPathParams>
): Endpoint<TRequest, TResponse, TPathParams> =>
  spec as Endpoint<TRequest, TResponse, TPathParams>;

/**
 * Extracts the response type of an endpoint. Used by the M2 client.
 *
 * These read the phantom fields structurally rather than matching against
 * `Endpoint<...>`. Matching the full interface does not work: `path` is a
 * conditional type keyed on `TPathParams`, so a wildcard in that position
 * resolves to the function form and silently fails to match every endpoint
 * declared with a static string path. `Exclude<_, undefined>` strips the
 * optionality of the phantom field while leaving a `void` request intact.
 */
export type ResponseOf<E> = E extends { __response?: infer R } ? Exclude<R, undefined> : never;

/** Extracts the request type of an endpoint. Used by the M2 client. */
export type RequestOf<E> = E extends { __request?: infer Q } ? Exclude<Q, undefined> : never;
