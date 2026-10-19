// This file configures the initialization of Sentry on the client.
// The config you add here will be used whenever a user loads a page in their browser.
// https://docs.sentry.io/platforms/javascript/guides/nextjs/

// Next.js 16+ with Turbopack uses instrumentation-client.js instead of
// sentry.client.config.js. That older file used to sit alongside this one with a
// near-identical Sentry.init() that Next never loaded — it has been deleted, so
// this is now the only place client Sentry options are set.

import * as Sentry from "@sentry/nextjs";
import { REPLAY_PRIVACY_OPTIONS, dropConsoleBreadcrumb, scrubReplayEvent } from "./utils/sentryReplayPrivacy";

Sentry.init({
    dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,

    // Performance Monitoring
    tracesSampleRate: process.env.NODE_ENV === "production" ? 0.2 : 1.0,

    // Session Replay
    replaysSessionSampleRate: 0.1,
    replaysOnErrorSampleRate: 1.0,

    // Environment tag
    environment: process.env.NODE_ENV || "development",

    // Only enable when DSN is present
    enabled: !!process.env.NEXT_PUBLIC_SENTRY_DSN,

    // Match the backend's instrument.js: never let the SDK attach IPs, cookies
    // or form values on its own. Anything Sentry needs is set deliberately —
    // see setSentryUser() in src/utils/sentryUser.js.
    sendDefaultPii: false,

    // Error and performance events carry the breadcrumb trail too, and the
    // site logs property titles and coordinates to the console. Console
    // breadcrumbs are dropped before any event can include them.
    beforeBreadcrumb: dropConsoleBreadcrumb,

    // Debug mode - set to true temporarily if issues persist
    debug: false,

    // Set release version for source map association
    release: process.env.NEXT_PUBLIC_APP_VERSION || "dealdirect-frontend@1.0.0",

    // Filter out noisy errors
    ignoreErrors: [
        "top.GLOBALS",
        "NetworkError",
        "Failed to fetch",
        "Load failed",
        "AbortError",
        "The operation was aborted",
        "ResizeObserver loop",
        "Non-Error promise rejection",
    ],

    // Integrations
    integrations: [
        // Text, form values, media, iframes, console output and URL query
        // strings are all masked or dropped. Replays used to keep text
        // visible, which recorded names, phone numbers and addresses from
        // every page. See utils/sentryReplayPrivacy.js.
        Sentry.replayIntegration(REPLAY_PRIVACY_OPTIONS),
        Sentry.browserTracingIntegration(),
    ],

    // Before sending events
    beforeSend(event) {
        if (process.env.NODE_ENV === "development" && !process.env.NEXT_PUBLIC_SENTRY_DSN) {
            return null;
        }
        return event;
    },
});

// The replay event lists every page URL the session visited.
Sentry.addEventProcessor(scrubReplayEvent);
