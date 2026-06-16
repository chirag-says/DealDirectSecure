// This file configures the initialization of Sentry on the client.
// The config you add here will be used whenever a user loads a page in their browser.
// https://docs.sentry.io/platforms/javascript/guides/nextjs/

import * as Sentry from "@sentry/nextjs";

Sentry.init({
    dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,

    // Performance Monitoring
    // Adjust this value in production, or use tracesSampler for fine-grained control
    tracesSampleRate: process.env.NODE_ENV === "production" ? 0.2 : 1.0,

    // Session Replay
    replaysSessionSampleRate: 0.1, // 10% of sessions in production
    replaysOnErrorSampleRate: 1.0, // 100% of sessions with errors

    // Environment tag
    environment: process.env.NODE_ENV || "development",

    // Only enable in production or when DSN is present
    enabled: !!process.env.NEXT_PUBLIC_SENTRY_DSN,

    // Set release version for source map association
    release: process.env.NEXT_PUBLIC_APP_VERSION || "dealdirect-frontend@1.0.0",

    // Filter out noisy errors
    ignoreErrors: [
        // Browser extensions
        "top.GLOBALS",
        // Network errors
        "NetworkError",
        "Failed to fetch",
        "Load failed",
        // Cancelled requests
        "AbortError",
        "The operation was aborted",
        // Browser-specific noise
        "ResizeObserver loop",
        "Non-Error promise rejection",
    ],

    // Integrations
    integrations: [
        Sentry.replayIntegration({
            // Mask all text and block all media in replays for privacy
            maskAllText: false,
            blockAllMedia: false,
        }),
        Sentry.browserTracingIntegration(),
    ],

    // Before sending events, add extra context
    beforeSend(event) {
        // Don't send events in development unless DSN is explicitly set
        if (process.env.NODE_ENV === "development" && !process.env.NEXT_PUBLIC_SENTRY_DSN) {
            return null;
        }
        return event;
    },
});
