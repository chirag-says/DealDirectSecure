// This file configures the initialization of Sentry on the client.
// The config you add here will be used whenever a user loads a page in their browser.
// https://docs.sentry.io/platforms/javascript/guides/nextjs/

// Next.js 16+ with Turbopack uses instrumentation-client.js instead of sentry.client.config.js

import * as Sentry from "@sentry/nextjs";

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
        Sentry.replayIntegration({
            maskAllText: false,
            blockAllMedia: false,
        }),
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
