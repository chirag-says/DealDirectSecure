import cron from "node-cron";
import JobRun from "../models/JobRun.js";

/**
 * The scheduler (Phase 0, engine E2).
 *
 * One in-process runner. The backend is single-instance by design (Socket.IO
 * presence, rate-limit counters and the cache all live in process memory), so
 * a distributed lock would be protecting against a second instance that cannot
 * exist today. What IS protected against:
 *
 *   overlap     a tick that arrives while the previous run of the same job is
 *               still going is skipped (in-process flag, plus a JobRun row
 *               younger than `staleAfterMs` with no `finishedAt`);
 *   restarts    handlers receive the last SUCCESSFUL run's `cursor` and return
 *               a new one, so a crash mid-run resumes from the last committed
 *               point rather than from the beginning;
 *   one bad job the runner catches everything a handler throws, records it on
 *               the JobRun row, and keeps the other jobs on schedule.
 *
 * Handlers are plain async functions `({ now, cursor, log }) => ({ cursor?, ...stats })`
 * and are tested by calling them directly with a fixed `now`. The cron wiring
 * is the only part that touches the clock.
 */

const running = new Set();
const tasks = [];

export async function lastSuccessfulRun(name) {
  return JobRun.findOne({ name, ok: true }).sort({ startedAt: -1 }).lean();
}

/**
 * Execute one job now, honouring overlap protection and recording the run.
 * Exported so tests and an operator can trigger a job without the schedule.
 */
export async function runJob(job, { now = new Date() } = {}) {
  if (running.has(job.name)) return { skipped: "running" };

  const staleAfterMs = job.staleAfterMs ?? 30 * 60 * 1000;
  const inFlight = await JobRun.findOne({
    name: job.name,
    finishedAt: null,
    startedAt: { $gte: new Date(now.getTime() - staleAfterMs) },
  }).lean();
  if (inFlight) return { skipped: "in-flight" };

  running.add(job.name);
  const previous = await lastSuccessfulRun(job.name);
  const run = await JobRun.create({ name: job.name, startedAt: now });

  try {
    const result = (await job.handler({ now, cursor: previous?.cursor ?? null, log: console })) || {};
    const { cursor = null, ...stats } = result;
    await JobRun.updateOne(
      { _id: run._id },
      { $set: { finishedAt: new Date(), ok: true, cursor, stats } }
    );
    return { ok: true, stats, cursor };
  } catch (err) {
    console.error(`[jobs] ${job.name} failed:`, err.message);
    await JobRun.updateOne(
      { _id: run._id },
      { $set: { finishedAt: new Date(), ok: false, error: String(err.message).slice(0, 500) } }
    );
    return { ok: false, error: err.message };
  } finally {
    running.delete(job.name);
  }
}

/**
 * Wire every enabled job to its cron expression. Idempotent.
 *
 * @param {Array<{name: string, schedule: string, handler: Function, enabled?: boolean}>} jobs
 */
export function startJobs(jobs, { timezone = "Asia/Kolkata" } = {}) {
  if (tasks.length) return tasks.length;

  for (const job of jobs) {
    if (job.enabled === false) continue;
    if (!cron.validate(job.schedule)) {
      console.error(`[jobs] ${job.name}: invalid schedule "${job.schedule}", not started`);
      continue;
    }
    const task = cron.schedule(job.schedule, () => void runJob(job), { timezone });
    tasks.push(task);
  }

  console.log(`[jobs] ${tasks.length} scheduled job(s) started`);
  return tasks.length;
}

export function stopJobs() {
  for (const task of tasks) task.stop();
  tasks.length = 0;
}
