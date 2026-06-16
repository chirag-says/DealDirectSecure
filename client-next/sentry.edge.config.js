// This file configures the initialization of Sentry for edge features (middleware, edge routes).
// https://docs.sentry.io/platforms/javascript/guides/nextjs/

import * as Sentry from "@sentry/nextjs";

Sentry.init({
    dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,

    // Performance Monitoring
    tracesSampleRate: process.env.NODE_ENV === "production" ? 0.2 : 1.0,

    // Environment tag
    environment: process.env.NODE_ENV || "development",

    // Only enable when DSN is present
    enabled: !!process.env.NEXT_PUBLIC_SENTRY_DSN,

    // Set release version
    release: process.env.NEXT_PUBLIC_APP_VERSION || "dealdirect-frontend@1.0.0",
});
