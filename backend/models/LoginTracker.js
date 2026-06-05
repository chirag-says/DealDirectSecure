/**
 * LoginTracker Model — DealDirect Loyalty
 * Tracks daily login counts per user per month for the monthly login streak.
 * Client spec: "Log in 15+ days in a month → 100 pts"
 */
import mongoose from 'mongoose';

const loginTrackerSchema = new mongoose.Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true,
            index: true,
        },
        // Format: "YYYY-MM" (e.g. "2026-03")
        month: {
            type: String,
            required: true,
            match: [/^\d{4}-\d{2}$/, 'Month must be in YYYY-MM format'],
        },
        // Set of unique login dates in the month (stored as day numbers: 1-31)
        loginDays: {
            type: [Number],
            default: [],
        },
        // Whether the streak reward was already awarded for this month
        rewardAwarded: {
            type: Boolean,
            default: false,
        },
    },
    {
        timestamps: true,
    }
);

// Compound unique index: one record per user per month
loginTrackerSchema.index({ userId: 1, month: 1 }, { unique: true });

const LoginTracker = mongoose.model('LoginTracker', loginTrackerSchema);
export default LoginTracker;
