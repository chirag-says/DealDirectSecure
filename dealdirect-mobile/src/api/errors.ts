import axios from 'axios';

import type { BackendErrorBody, BackendErrorCode } from '@/types/backend/common';

/**
 * Error normalisation.
 *
 * Everything that can fail becomes one shape here, so no screen ever inspects
 * an axios error. Callers branch on `code`, never on `message`: the message is
 * prose, it gets rewritten, and it is localised for humans rather than for
 * control flow.
 */

export type ApiErrorKind =
  | 'network' // request never reached the server
  | 'timeout'
  | 'session' // credentials are gone or rejected; user must log in
  | 'forbidden' // authenticated but not allowed
  | 'notFound'
  | 'validation' // 4xx the user can correct
  | 'rateLimited'
  | 'server' // 5xx
  | 'unknown';

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | undefined;
  readonly code: BackendErrorCode | undefined;
  /** `X-Request-ID`, for correlating a user report with a backend log line. */
  readonly requestId: string | undefined;
  /** Seconds until a rate limit resets, when the server told us. */
  readonly retryAfterSeconds: number | undefined;
  /** Extra fields the backend attaches to specific failures. */
  readonly details: Pick<BackendErrorBody, 'blockReason' | 'lockoutUntil' | 'requiredRoles'>;

  constructor(init: {
    message: string;
    kind: ApiErrorKind;
    status?: number;
    code?: BackendErrorCode;
    requestId?: string;
    retryAfterSeconds?: number;
    details?: ApiError['details'];
  }) {
    super(init.message);
    this.name = 'ApiError';
    this.kind = init.kind;
    this.status = init.status;
    this.code = init.code;
    this.requestId = init.requestId;
    this.retryAfterSeconds = init.retryAfterSeconds;
    this.details = init.details ?? {};
  }
}

/**
 * Codes that mean the session is over.
 *
 * These bypass the query layer entirely and go straight to the auth store,
 * which tears down the socket, clears storage and routes to login. Retrying any
 * of them is pointless: no amount of repetition makes a revoked session valid.
 */
const SESSION_FATAL_CODES: ReadonlySet<string> = new Set<BackendErrorCode>([
  'NO_SESSION',
  'INVALID_SESSION',
  'SESSION_REVOKED',
  'TOKEN_EXPIRED',
  'INVALID_TOKEN',
  'USER_NOT_FOUND',
  'AUTH_ERROR',
  'NOT_AUTHENTICATED',
  'INVALID_ROLE',
  'PASSWORD_CHANGED',
  'ACCOUNT_BLOCKED',
  'ACCOUNT_DEACTIVATED',
]);

export function isSessionFatal(error: unknown): boolean {
  if (!(error instanceof ApiError)) return false;
  if (error.code && SESSION_FATAL_CODES.has(error.code)) return true;
  return error.kind === 'session';
}

/** Rate-limit reset, from either the standard headers or the body. */
function readRetryAfter(headers: unknown, body: BackendErrorBody | undefined): number | undefined {
  const record = (headers ?? {}) as Record<string, string | undefined>;

  const retryAfter = record['retry-after'];
  if (retryAfter) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds)) return seconds;
  }

  // express-rate-limit runs with standardHeaders: true, so this is present on
  // every limited response and is more precise than the body.
  const reset = record['ratelimit-reset'];
  if (reset) {
    const seconds = Number(reset);
    if (Number.isFinite(seconds)) return seconds;
  }

  return body?.retryAfter;
}

/**
 * The URL a failed request was aimed at, read off the axios config.
 *
 * Taken from the config rather than imported from `@/config/env` so this module
 * keeps its single dependency on the backend types, and so the line reports the
 * URL the request ACTUALLY used rather than what the config says it should have.
 */
function describeTarget(config: { baseURL?: string; url?: string } | undefined): string | undefined {
  const base = config?.baseURL;
  if (!base) return undefined;
  return `Dev: could not reach ${base}${config?.url ?? ''}`;
}

function kindForStatus(status: number, code: BackendErrorCode | undefined): ApiErrorKind {
  if (status === 401) return 'session';
  if (status === 403) {
    // 403 is overloaded: a blocked or deactivated account is a session failure,
    // while a role or ownership rejection is a permission failure the user
    // stays logged in for.
    return code && SESSION_FATAL_CODES.has(code) ? 'session' : 'forbidden';
  }
  if (status === 404) return 'notFound';
  if (status === 429) return 'rateLimited';
  if (status >= 500) return 'server';
  if (status >= 400) return 'validation';
  return 'unknown';
}

const FALLBACK_MESSAGE: Record<ApiErrorKind, string> = {
  network: 'No connection. Check your network and try again.',
  timeout: 'That took too long. Please try again.',
  session: 'Your session has ended. Please log in again.',
  forbidden: 'You do not have permission to do that.',
  notFound: 'We could not find that.',
  validation: 'Please check the details and try again.',
  rateLimited: 'Too many requests. Please wait a moment.',
  server: 'Something went wrong on our side. Please try again.',
  unknown: 'Something went wrong. Please try again.',
};

/**
 * Converts anything thrown by axios into an ApiError.
 *
 * The backend already sanitises its messages, but this deliberately does not
 * depend on that: a server-side regression must not put a stack trace on a
 * user's screen. Only 4xx messages, which are written for users, are surfaced.
 * 5xx messages are replaced with a generic line.
 */
export function normalizeError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;

  if (axios.isAxiosError(error)) {
    const { response, code: axiosCode } = error;

    if (!response) {
      const kind: ApiErrorKind =
        axiosCode === 'ECONNABORTED' || axiosCode === 'ETIMEDOUT' ? 'timeout' : 'network';

      // "Check your network" is true and useless on its own: it does not say
      // WHAT could not be reached. In development that is almost always the
      // whole answer — a device on a different network from the dev machine, or
      // a firewall on the API port. `--tunnel` carries Metro only, so the app
      // bundles fine and every request still fails, which reads as a bug in the
      // screen rather than a routing problem.
      //
      // Dev only. Release builds must never put an internal URL on screen.
      const target = __DEV__ ? describeTarget(error.config) : undefined;

      return new ApiError({
        kind,
        message: target ? `${FALLBACK_MESSAGE[kind]}\n\n${target}` : FALLBACK_MESSAGE[kind],
      });
    }

    const body = response.data as BackendErrorBody | undefined;
    const status = response.status;
    const backendCode = body?.code;
    const kind = kindForStatus(status, backendCode);

    const serverMessage =
      typeof body?.message === 'string' && body.message.trim().length > 0
        ? body.message.trim()
        : undefined;

    // 5xx messages are for operators, not users.
    const message = status < 500 && serverMessage ? serverMessage : FALLBACK_MESSAGE[kind];

    const headers = response.headers as unknown as Record<string, string | undefined>;

    return new ApiError({
      kind,
      message,
      status,
      code: backendCode,
      requestId: headers?.['x-request-id'] ?? body?.requestId,
      retryAfterSeconds: readRetryAfter(headers, body),
      details: {
        blockReason: body?.blockReason,
        lockoutUntil: body?.lockoutUntil,
        requiredRoles: body?.requiredRoles,
      },
    });
  }

  return new ApiError({
    kind: 'unknown',
    message: error instanceof Error ? error.message : FALLBACK_MESSAGE.unknown,
  });
}
