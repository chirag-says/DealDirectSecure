/**
 * Sentry instrumentation — MUST be the first import in server.js.
 *
 * WHY THIS FILE EXISTS AS A SEPARATE MODULE
 *
 * ES module `import` statements are hoisted: every import in server.js is
 * evaluated before any of its top-level code, including its dotenv.config()
 * call. Calling Sentry.init() inline in server.js would therefore run *after*
 * express, http and mongoose were already loaded, and after dotenv had NOT yet
 * populated process.env — so the DSN would be undefined and the automatic
 * instrumentation would have nothing left to patch.
 *
 * Loading environment variables and initialising Sentry here, then importing
 * this module first, fixes both problems: env is populated before init, and
 * init runs before the libraries it instruments are imported.
 *
 * server.js still calls dotenv.config() itself. That is intentional and safe —
 * dotenv does not overwrite variables that are already set, so the second call
 * is a no-op and server.js remains readable on its own.
 */
import * as Sentry from "@sentry/node";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Mirrors the Hostinger .env / .env.production fallback in server.js.
const envPath = path.join(__dirname, ".env");
const envProdPath = path.join(__dirname, ".env.production");
if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath });
} else if (fs.existsSync(envProdPath)) {
  dotenv.config({ path: envProdPath });
} else {
  dotenv.config();
}

const dsn = process.env.SENTRY_DSN;

if (!dsn) {
  // Not an error: Sentry is optional, and the app must run without it.
  console.warn("⚠️ SENTRY_DSN not set — backend error tracking is DISABLED");
} else {
  Sentry.init({
    dsn,
    environment: process.env.NODE_ENV || "development",

    // Performance sampling: 10% in production, everything in development.
    tracesSampleRate: process.env.NODE_ENV === "production" ? 0.1 : 1.0,

    // Never send request bodies, headers, cookies or IPs automatically.
    // This codebase handles OTPs, session tokens and Aadhaar fragments, none of
    // which may leave the server. Anything needed is attached deliberately.
    sendDefaultPii: false,

    // Defence in depth: strip credential-bearing fields even if a future
    // integration or a manual captureException attaches them.
    beforeSend(event) {
      if (event.request) {
        delete event.request.cookies;
        delete event.request.data;
        if (event.request.headers) {
          for (const h of ["authorization", "cookie", "set-cookie", "x-csrf-token", "x-hubble-secret"]) {
            delete event.request.headers[h];
          }
        }
      }
      return event;
    },

    // Noise that is not actionable.
    ignoreErrors: [
      "ECONNRESET",
      "EPIPE",
      "Client network socket disconnected",
    ],
  });

  console.log(`✅ Sentry initialised (environment: ${process.env.NODE_ENV || "development"})`);
}

export default Sentry;
