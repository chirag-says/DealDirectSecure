/**
 * User Session Model
 * Enterprise-grade server-side session management for end users
 */
import mongoose from "mongoose";
import crypto from "crypto";

const userSessionSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true,
        },
        // Secure session token (stored hashed in DB)
        sessionToken: {
            type: String,
            required: true,
            unique: true,
            index: true,
        },
        // Token hash for validation
        tokenHash: {
            type: String,
            required: true,
        },
        // Session fingerprint for integrity check
        fingerprint: {
            type: String,
            required: true,
        },
        // Device and client information
        deviceInfo: {
            userAgent: String,
            platform: String,
            browser: String,
            isMobile: Boolean,
        },
        // Network information
        ipAddress: {
            type: String,
            required: true,
        },
        // Session expiration
        expiresAt: {
            type: Date,
            required: true,
            index: { expireAfterSeconds: 0 }, // TTL index - auto-delete expired sessions
        },
        // Session state
        isActive: {
            type: Boolean,
            default: true,
        },
        // Revocation tracking
        revokedAt: {
            type: Date,
            default: null,
        },
        revokedReason: {
            type: String,
            default: null,
        },
        // Activity tracking
        lastActivity: {
            type: Date,
            default: Date.now,
        },
    },
    { timestamps: true }
);

// Indexes for efficient queries
userSessionSchema.index({ user: 1, isActive: 1 });
userSessionSchema.index({ tokenHash: 1 });
userSessionSchema.index({ expiresAt: 1 });

/**
 * Generate a cryptographically secure session token
 */
userSessionSchema.statics.generateSessionToken = function () {
    return crypto.randomBytes(48).toString("base64url");
};

/**
 * Hash a session token for storage
 */
userSessionSchema.statics.hashToken = function (token) {
    return crypto.createHash("sha256").update(token).digest("hex");
};

/**
 * Generate session fingerprint from request
 */
userSessionSchema.statics.generateFingerprint = function (req) {
    const components = [
        req.headers["user-agent"] || "",
        req.headers["accept-language"] || "",
        req.headers["accept-encoding"] || "",
    ].join("|");
    return crypto.createHash("sha256").update(components).digest("hex").substring(0, 32);
};

/**
 * Create a new session for user
 */
userSessionSchema.statics.createSession = async function (user, req, expirationHours = 168) {
    // 7 days default
    const sessionToken = this.generateSessionToken();
    const tokenHash = this.hashToken(sessionToken);
    const fingerprint = this.generateFingerprint(req);
    const expiresAt = new Date(Date.now() + expirationHours * 60 * 60 * 1000);

    // Parse user agent
    const userAgent = req.headers["user-agent"] || "";
    const isMobile = /mobile|android|iphone|ipad/i.test(userAgent);
    const platform = userAgent.includes("Windows")
        ? "Windows"
        : userAgent.includes("Mac")
            ? "macOS"
            : userAgent.includes("Linux")
                ? "Linux"
                : userAgent.includes("Android")
                    ? "Android"
                    : userAgent.includes("iPhone") || userAgent.includes("iPad")
                        ? "iOS"
                        : "Unknown";

    const session = await this.create({
        user: user._id,
        sessionToken: tokenHash, // Store hash, not raw token
        tokenHash,
        fingerprint,
        deviceInfo: {
            userAgent: userAgent.substring(0, 512), // Limit length
            platform,
            isMobile,
        },
        ipAddress: req.ip || req.connection?.remoteAddress || "unknown",
        expiresAt,
        lastActivity: new Date(),
    });

    return { session, sessionToken }; // Return raw token (for cookie) and session
};

/**
 * Validate session token and return session
 */
userSessionSchema.statics.validateSession = async function (sessionToken, req) {
    if (!sessionToken) return null;

    const tokenHash = this.hashToken(sessionToken);
    const session = await this.findOne({
        tokenHash,
        isActive: true,
        expiresAt: { $gt: new Date() },
    }).populate("user", "-password -otp -otpExpires -resetPasswordOtp -resetPasswordOtpExpires");

    if (!session) return null;

    // Verify fingerprint integrity
    const currentFingerprint = this.generateFingerprint(req);
    if (session.fingerprint !== currentFingerprint) {
        // Fingerprint mismatch - potential session hijacking
        await this.revokeSession(session._id, "fingerprint_mismatch");
        return null;
    }

    // Update last activity
    session.lastActivity = new Date();
    await session.save();

    return session;
};

/**
 * Revoke a specific session
 */
userSessionSchema.statics.revokeSession = async function (sessionId, reason = "manual_logout") {
    return this.findByIdAndUpdate(sessionId, {
        isActive: false,
        revokedAt: new Date(),
        revokedReason: reason,
    });
};

/**
 * Revoke all sessions for a user
 */
userSessionSchema.statics.revokeAllUserSessions = async function (userId, reason = "logout_all") {
    return this.updateMany(
        { user: userId, isActive: true },
        {
            isActive: false,
            revokedAt: new Date(),
            revokedReason: reason,
        }
    );
};

/**
 * Revoke all sessions except current
 */
userSessionSchema.statics.revokeOtherSessions = async function (userId, currentSessionId, reason = "security") {
    return this.updateMany(
        {
            user: userId,
            _id: { $ne: currentSessionId },
            isActive: true,
        },
        {
            isActive: false,
            revokedAt: new Date(),
            revokedReason: reason,
        }
    );
};

/**
 * Get active sessions for user
 */
userSessionSchema.statics.getActiveSessions = async function (userId) {
    return this.find({
        user: userId,
        isActive: true,
        expiresAt: { $gt: new Date() },
    })
        .select("deviceInfo ipAddress createdAt lastActivity")
        .sort({ lastActivity: -1 });
};

/**
 * Cleanup expired sessions
 */
userSessionSchema.statics.cleanupExpiredSessions = async function () {
    const result = await this.deleteMany({
        $or: [{ expiresAt: { $lt: new Date() } }, { isActive: false, updatedAt: { $lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } }],
    });
    return result.deletedCount;
};

export default mongoose.model("UserSession", userSessionSchema);
