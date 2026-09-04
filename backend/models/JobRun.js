import mongoose from "mongoose";

/**
 * A record of one scheduled-job execution.
 *
 * The runner writes a row when a job starts and completes it when the handler
 * returns. Two things depend on these rows:
 *
 *  1. Idempotency across restarts. A handler that sends messages reads the
 *     last successful run's `cursor` (usually a timestamp) and only processes
 *     what happened after it, so a crash mid-run followed by a restart does
 *     not re-send what the first attempt already sent.
 *  2. Overlap protection. A run that has started and not finished within
 *     `staleAfterMs` is treated as crashed and superseded; a fresher one is
 *     treated as still running and the new tick is skipped.
 */
const jobRunSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, index: true },
    startedAt: { type: Date, required: true },
    finishedAt: { type: Date, default: null },
    ok: { type: Boolean, default: null },
    error: { type: String, default: null },
    cursor: { type: mongoose.Schema.Types.Mixed, default: null },
    stats: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { versionKey: false }
);

jobRunSchema.index({ name: 1, startedAt: -1 });
jobRunSchema.index({ startedAt: 1 }, { expireAfterSeconds: 60 * 24 * 3600 });

const JobRun = mongoose.model("JobRun", jobRunSchema);
export default JobRun;
