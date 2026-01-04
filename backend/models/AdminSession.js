import mongoose from "mongoose";
import crypto from "crypto";

/**
 * AdminSession Schema
 * Server-side session management for enterprise security
 * Enables session revocation, integrity verification, and audit trails
 */
const adminSessionSchema = new mongoose.Schema(
    {
        // Reference to the admin user
        admin: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Admin",
            required: true,
            index: true,
        },
        // Unique session token (stored in HttpOnly cookie)
        sessionToken: {
            type: String,
            required: true,
            unique: true,
            index: true,
        },
        // Session fingerprint for integrity verification
        fingerprint: {
            type: String,
            required: true,
        },
        // IP address of session creation
        ipAddress: {
            type: String,
            required: true,
        },
        // User agent at session creation
        userAgent: {
            type: String,
            default: "",
        },
        // Session expiration time
        expiresAt: {
            type: Date,
            required: true,
            index: true,
        },
        // Last activity timestamp for session timeout
        lastActivity: {
            type: Date,
            default: Date.now,
        },
        // Whether MFA was verified for this session
        mfaVerified: {
            type: Boolean,
            default: false,
        },
        // Session status
        isActive: {
            type: Boolean,
            default: true,
            index: true,
        },
        // Revocation details
        revokedAt: {
            type: Date,
            default: null,
        },
        revokedReason: {
            type: String,
            default: null,
        },
        // Device/location info for security
        deviceInfo: {
            browser: String,
            os: String,
            device: String,
        },
    },
    { timestamps: true }
);

// Compound index for efficient session lookups
adminSessionSchema.index({ admin: 1, isActive: 1 });
adminSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL index

/**
 * Generate a cryptographically secure session token
 */
adminSessionSchema.statics.generateToken = function () {
    return crypto.randomBytes(64).toString("hex");
};

/**
 * Generate session fingerprint from request data
 */
adminSessionSchema.statics.generateFingerprint = function (req) {
    const data = [
        req.headers["user-agent"] || "",
        req.headers["accept-language"] || "",
        req.headers["accept-encoding"] || "",
    ].join("|");
    return crypto.createHash("sha256").update(data).digest("hex");
};

/**
 * Verify session fingerprint matches current request
 */
adminSessionSchema.methods.verifyFingerprint = function (req) {
    const currentFingerprint = this.constructor.generateFingerprint(req);
    return this.fingerprint === currentFingerprint;
};

/**
 * Extend session activity
 */
adminSessionSchema.methods.touch = async function () {
    this.lastActivity = new Date();
    return this.save();
};

/**
 * Revoke session
 */
adminSessionSchema.methods.revoke = async function (reason = "manual_logout") {
    this.isActive = false;
    this.revokedAt = new Date();
    this.revokedReason = reason;
    return this.save();
};

/**
 * Revoke all sessions for an admin (except current)
 */
adminSessionSchema.statics.revokeAllForAdmin = async function (
    adminId,
    exceptSessionId = null,
    reason = "security_action"
) {
    const query = { admin: adminId, isActive: true };
    if (exceptSessionId) {
        query._id = { $ne: exceptSessionId };
    }
    return this.updateMany(query, {
        isActive: false,
        revokedAt: new Date(),
        revokedReason: reason,
    });
};

/**
 * Clean up expired sessions
 */
adminSessionSchema.statics.cleanupExpired = async function () {
    return this.deleteMany({
        $or: [{ expiresAt: { $lt: new Date() } }, { isActive: false }],
    });
};

export default mongoose.model("AdminSession", adminSessionSchema);
