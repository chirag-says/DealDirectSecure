import type * as SentryModule from '@sentry/react-native';
import type { ComponentType } from 'react';

import { APP_VERSION } from '@/config/env';
import { optionalNativeModule } from '@/config/optionalNative';
import type { UserRole } from '@/types/backend/user';

/**
 * Crash reporting.
 *
 * ---------------------------------------------------------------------------
 * WHAT LEAVES THE DEVICE
 *
 * `sendDefaultPii: false`, and the user is `{ id, role }` and nothing else:
 * no name, no email, no phone, ever. The session cookie must not appear in
 * any report either, so `beforeSend` strips `request.cookies` and
 * `request.headers` outright and drops any breadcrumb data key named for a
 * credential. Those are removed rather than redacted because nothing in a
 * crash report needs them: a stack trace and a release are what get a bug
 * fixed.
 *
 * `release` and `dist` are derived from `APP_VERSION`, the same value the
 * `X-App-Version` header carries, so a Sentry issue and a backend log line
 * for the same build agree on what "the build" was.
 *
 * ---------------------------------------------------------------------------
 * OPTIONAL, TWICE OVER
 *
 * The DSN is `EXPO_PUBLIC_SENTRY_DSN`. Unset, `initSentry` does nothing and
 * every other export is a no-op, so a local build reports nowhere by default.
 * And the module itself loads through `optionalNativeModule`: a host without
 * the native half (Expo Go, or a dev client built before this was added)
 * still boots. `wrapRoot` returns the component untouched in that case.
 */

const Sentry = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('@sentry/react-native') as typeof SentryModule,
  '@sentry/react-native',
  'Crashes will not be reported.'
);

const DSN = process.env.EXPO_PUBLIC_SENTRY_DSN?.trim() ?? '';

/** Breadcrumb data keys that must never travel. Compared lower-cased. */
const SENSITIVE_KEYS = new Set(['cookie', 'authorization', 'set-cookie']);

type SentryEvent = SentryModule.ErrorEvent | SentryModule.TransactionEvent;

function scrub<E extends SentryEvent>(event: E): E {
  if (event.request) {
    delete event.request.cookies;
    delete event.request.headers;
  }

  for (const crumb of event.breadcrumbs ?? []) {
    if (!crumb.data) continue;
    for (const key of Object.keys(crumb.data)) {
      if (SENSITIVE_KEYS.has(key.toLowerCase())) delete crumb.data[key];
    }
  }

  return event;
}

let initialised = false;

export function initSentry(): void {
  if (!Sentry || !DSN || initialised) return;
  initialised = true;

  Sentry.init({
    dsn: DSN,
    sendDefaultPii: false,
    tracesSampleRate: 0.1,
    release: `dealdirect-mobile@${APP_VERSION}`,
    dist: APP_VERSION,
    beforeSend: (event) => scrub(event),
    beforeSendTransaction: (event) => scrub(event),
  });
}

/**
 * Who the report is about, in the two fields that identify without
 * describing. Called by `AuthProvider` as the session comes and goes; `null`
 * on sign-out so a later crash is not pinned on the previous user.
 */
export function setSentryUser(user: { id: string; role: UserRole } | null): void {
  if (!Sentry || !initialised) return;
  Sentry.setUser(user ? { id: user.id, role: user.role } : null);
}

/** `Sentry.wrap` when the module resolved, the component itself when not. */
export function wrapRoot<P extends Record<string, unknown>>(
  component: ComponentType<P>
): ComponentType<P> {
  if (!Sentry || !DSN) return component;
  return Sentry.wrap(component);
}
