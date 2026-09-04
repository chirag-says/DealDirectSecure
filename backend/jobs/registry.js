import { collectReceipts } from "../services/pushService.js";
import { rollupEvents } from "./eventsRollup.js";
import { pruneDisabledTokens } from "./pushTokenPrune.js";
import { sendVisitReminders } from "./visitReminders.js";
import { sendOwnerWeeklyDigest } from "./ownerWeeklyDigest.js";
import { publishExpiredReviews } from "./reviewPublish.js";

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
];
