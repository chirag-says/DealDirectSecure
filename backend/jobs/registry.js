import { collectReceipts } from "../services/pushService.js";
import { rollupEvents } from "./eventsRollup.js";
import { pruneDisabledTokens } from "./pushTokenPrune.js";
import { sendVisitReminders } from "./visitReminders.js";
import { sendOwnerWeeklyDigest } from "./ownerWeeklyDigest.js";
import { publishExpiredReviews } from "./reviewPublish.js";
import { scanPriceDrops } from "./priceDropScan.js";
import { aggregateLocalities } from "./localityAggregate.js";
import { runRentalClock } from "./rentalClock.js";
import { expirePoints } from "./pointsExpiry.js";

/**
 * The job table. Cron expressions are evaluated in Asia/Kolkata.
 *
 * Adding a job is one row here plus a handler module. Nothing else registers
 * anything: `server.js` calls `startJobs(JOBS)` once, after the database is
 * connected and only outside the test environment.
 */
export const JOBS = [
  {
    name: "push-receipts",
    schedule: "*/15 * * * *",
    handler: () => collectReceipts(),
    staleAfterMs: 10 * 60 * 1000,
  },
  {
    name: "push-token-prune",
    schedule: "30 3 * * *",
    handler: pruneDisabledTokens,
  },
  {
    name: "events-rollup",
    schedule: "15 1 * * *",
    handler: rollupEvents,
  },
  {
    name: "visit-reminders",
    schedule: "5 * * * *",
    handler: sendVisitReminders,
    staleAfterMs: 20 * 60 * 1000,
  },
  {
    name: "owner-weekly-digest",
    schedule: "0 8 * * 1",
    handler: sendOwnerWeeklyDigest,
  },
  {
    name: "review-publish",
    schedule: "30 2 * * *",
    handler: publishExpiredReviews,
  },
  // Phase 1: the return spine.
  {
    name: "price-drop-scan",
    schedule: "*/15 * * * *",
    handler: scanPriceDrops,
    staleAfterMs: 20 * 60 * 1000,
  },
  // Phase 4: the data products. Nightly, after midnight IST, when the day's
  // listings are in and nobody is reading.
  {
    name: "locality-aggregate",
    schedule: "45 0 * * *",
    handler: aggregateLocalities,
    staleAfterMs: 60 * 60 * 1000,
  },
  // Phase 5: the LTV loop.
  {
    name: "rental-clock",
    schedule: "0 9 * * *",
    handler: runRentalClock,
  },
  {
    name: "points-expiry",
    schedule: "30 9 * * *",
    handler: expirePoints,
  },
];
