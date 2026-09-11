/**
 * User Model - Enterprise Security Enhanced
 * Secure user schema with session tracking and security features
 */
import mongoose from "mongoose";
import crypto from "crypto";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      maxlength: [100, "Name cannot exceed 100 characters"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, "Please provide a valid email"],
    },
    password: {
      type: String,
      // Conditional: a Google account has no password and never will unless the
      // user sets one. Making this unconditionally required would make every
      // Google user unsaveable.
      //
      // Scoped to `isNew` on purpose. On a new document every path is present,
      // so `this.googleId` is trustworthy. On an existing one it usually is
      // not: googleId and password are both `select: false`, so a routine
      // `findOne().save()` sees googleId as undefined, concludes a password is
      // required, finds none selected either, and would fail validation on an
      // account that is perfectly valid. Mongoose does skip validators on
      // unselected paths, so that would not actually fire today — but making
      // the rule depend on that subtlety is how it breaks later.
      required: [
        function () {
          return this.isNew && !this.googleId;
        },
        "Password is required",
      ],
      minlength: [8, "Password must be at least 8 characters"],
      select: false, // Never return password by default
    },
    // Google's `sub` claim — stable for the life of the Google account, unlike
    // the email address, which Workspace admins can reassign to a different
    // person. Always match on this first and treat email as a fallback lookup.
    googleId: {
      type: String,
      unique: true,
      sparse: true,
      select: false,
    },
    role: {
      type: String,
      // 'user' and 'buyer' are equivalent - buyers/seekers. 'owner' = sellers
      // Both values accepted for backward compatibility
      enum: ["user", "buyer", "owner"],
      default: "buyer", // New users default to buyer role
    },

    // Profile fields
    phone: {
      type: String,
      match: [/^[6-9]\d{9}$/, "Please provide a valid 10-digit phone number"],
      unique: true,
      sparse: true,
    },
    alternatePhone: { type: String },
    address: {
      line1: { type: String },
      line2: { type: String },
      city: { type: String },
      state: { type: String },
      pincode: { type: String },
    },
    profileImage: { type: String },
    dateOfBirth: { type: Date },
    gender: { type: String, enum: ["Male", "Female", "Other", ""] },
    bio: {
      type: String,
      maxlength: [500, "Bio cannot exceed 500 characters"],
    },

    // Account Status
    isActive: {
      type: Boolean,
      default: true,
    },
    isBlocked: {
      type: Boolean,
      default: false
    },
    blockReason: {
      type: String,
      default: "",
      select: false, // Only admin should see this
    },
    blockedAt: {
      type: Date,
      select: false,
    },
    blockedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      select: false,
    },

    // Preferences
    preferences: {
      emailNotifications: { type: Boolean, default: true },
      smsNotifications: { type: Boolean, default: false },
    },

    // Account usability. Despite the historic name and the "email verification"
    // wording in authUser.requireVerified, nothing here ever proved an email:
    // registerUser sets it after a *phone* OTP, and registerUserDirect sets it
    // on creation with no proof of anything. Too many call sites read it to
    // safely change what it means, so it keeps its current meaning — "this
    // account is usable" — and the two fields below carry the real claims.
    isVerified: {
      type: Boolean,
      default: false
    },
    otp: {
      type: String,
      select: false, // Never return OTP in queries
    },
    otpExpires: {
      type: Date,
      select: false,
    },

    // ------------------------------------------------------------------
    // Auth unification: explicit identity proofs.
    //
    // `emailVerified` is set only by Google, which is the only source that
    // actually checks an inbox. Password registration still does not.
    //
    // `phoneVerified` is set only by entering an OTP sent to that number, and
    // is what every just-in-time gate reads. Nothing new reads `isVerified`.
    // ------------------------------------------------------------------
    emailVerified: { type: Boolean, default: false },
    phoneVerified: { type: Boolean, default: false },
    phoneVerifiedAt: { type: Date, default: null },

    // The in-flight phone link. Deliberately NOT stored in the `otp` field
    // above: that one field is shared by registration, the owner upgrade and
    // password reset, so two concurrent flows silently overwrite each other.
    // The pending number also has nowhere else to live, since it must not touch
    // `phone` until an OTP proves it.
    pendingPhone: {
      phone: { type: String, select: false },
      otp: { type: String, select: false },
      expires: { type: Date, select: false },
      attempts: { type: Number, default: 0, select: false },
      sends: { type: Number, default: 0, select: false },
      windowStart: { type: Date, select: false },
    },

    // Security Fields
    security: {
      // Failed login tracking
      failedLoginAttempts: {
        type: Number,
        default: 0,
        select: false,
      },
      lockoutUntil: {
        type: Date,
        default: null,
        select: false,
      },
      // Password change tracking
      passwordChangedAt: {
        type: Date,
        default: null,
      },
      // Last login tracking
      lastLoginAt: {
        type: Date,
        default: null,
      },
      lastLoginIp: {
        type: String,
        default: null,
        select: false,
      },
      // `sessionVersion` was removed here (Phase 5.6). It was written only by
      // an `invalidateSessions()` method that nothing ever called, and read by
      // nothing at all.
      //
      // What actually invalidates sessions after a password change is the
      // UserSession record being revoked — `revokeOtherSessions` on change and
      // `revokeAllUserSessions` on reset. `changedPasswordAfter` below is a
      // second line of defence, but only on the legacy no-sessionId path in
      // authMiddleware; the session path never reaches it.
    },

    // Referral System — DealDirect Rewards
    referredBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },

    // ------------------------------------------------------------------
    // Phase 3 (F17): the verification badge, set by an admin who checked
    // identity and, for owners, the property papers. Public on listings.
    // ------------------------------------------------------------------
    verification: {
      identity: { type: Boolean, default: false },
      documents: { type: Boolean, default: false },
      verifiedAt: { type: Date, default: null },
      verifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: "Admin", default: null },
    },

    // ------------------------------------------------------------------
    // Phase 3 (F15): linkage inputs for the verified-close check. Device
    // hashes are opaque installation ids the clients register; never a
    // fingerprint of the person. Both are hidden from every default read.
    // ------------------------------------------------------------------
    deviceHashes: { type: [String], default: [], select: false },
    payoutVpa: { type: String, default: null, select: false },
    referralCode: {
      type: String,
      unique: true,
      sparse: true, // Allow null (not every user has one generated yet)
      uppercase: true,
      trim: true,
    },
    // `hasCompletedFirstAction` was removed here (Phase 5.6). It was declared
    // for a referral milestone that was never built: no code read it, and no
    // code ever set it to true.

    // Deprecated fields - kept for migration compatibility
    resetPasswordOtp: {
      type: String,
      select: false,
    },
    resetPasswordOtpExpires: {
      type: Date,
      select: false,
    },
  },
  {
    timestamps: true,
    toJSON: {
      transform: function (doc, ret) {
        // Remove sensitive fields from JSON output
        delete ret.password;
        delete ret.otp;
        delete ret.otpExpires;
        delete ret.googleId;
        delete ret.pendingPhone;
        delete ret.resetPasswordOtp;
        delete ret.resetPasswordOtpExpires;
        delete ret.blockReason;
        delete ret.blockedAt;
        delete ret.blockedBy;
        delete ret.__v;
        if (ret.security) {
          delete ret.security.failedLoginAttempts;
          delete ret.security.lockoutUntil;
          delete ret.security.lastLoginIp;
        }
        return ret;
      }
    }
  }
);

// ============================================
// PRE-SAVE HOOK: Auto-generate referralCode
// ============================================

userSchema.pre("save", async function (next) {
  // Only generate if this is a new user and no referralCode exists
  if (this.isNew && !this.referralCode) {
    const generateCode = () => {
      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      let code = "DD";
      for (let i = 0; i < 4; i++) {
        code += chars.charAt(crypto.randomInt(0, chars.length));
      }
      return code;
    };

    // Try up to 5 times to generate a unique code
    for (let attempt = 0; attempt < 5; attempt++) {
      const code = generateCode();
      const exists = await mongoose.model("User").findOne({ referralCode: code }).lean();
      if (!exists) {
        this.referralCode = code;
        break;
      }
    }
  }
  next();
});

// Indexes
// email is declared `unique: true` inline, which already builds this index.
userSchema.index({ role: 1 });
userSchema.index({ isVerified: 1 });
// googleId is declared `unique: true, sparse: true` inline, which builds its
// own index. phoneVerified is indexed because the migration and any future
// re-verification sweep both filter on it across the whole collection.
userSchema.index({ phoneVerified: 1 });
userSchema.index({ isBlocked: 1 });
userSchema.index({ createdAt: -1 });
// referralCode is declared `unique: true, sparse: true` inline.
userSchema.index({ referredBy: 1 });

// Virtual for full address
userSchema.virtual("fullAddress").get(function () {
  if (!this.address) return null;
  const parts = [
    this.address.line1,
    this.address.line2,
    this.address.city,
    this.address.state,
    this.address.pincode,
  ].filter(Boolean);
  return parts.join(", ");
});

// Instance method: Check if account is locked
userSchema.methods.isLocked = function () {
  return this.security?.lockoutUntil && this.security.lockoutUntil > new Date();
};

// Instance method: Increment failed login attempts
userSchema.methods.incrementFailedLogins = async function () {
  const maxAttempts = 5;
  const lockoutMinutes = 15;

  this.security = this.security || {};
  this.security.failedLoginAttempts = (this.security.failedLoginAttempts || 0) + 1;

  if (this.security.failedLoginAttempts >= maxAttempts) {
    this.security.lockoutUntil = new Date(Date.now() + lockoutMinutes * 60 * 1000);
  }

  await this.save();
};

// Instance method: Reset failed login attempts
userSchema.methods.resetFailedLogins = async function () {
  this.security = this.security || {};
  this.security.failedLoginAttempts = 0;
  this.security.lockoutUntil = null;
  await this.save();
};

// Instance method: Update last login
userSchema.methods.updateLastLogin = async function (ip) {
  this.security = this.security || {};
  this.security.lastLoginAt = new Date();
  this.security.lastLoginIp = ip;
  await this.save();
};

// Instance method: Check if password changed after token issued
userSchema.methods.changedPasswordAfter = function (jwtTimestamp) {
  if (this.security?.passwordChangedAt) {
    const changedTimestamp = parseInt(this.security.passwordChangedAt.getTime() / 1000, 10);
    return jwtTimestamp < changedTimestamp;
  }
  return false;
};

// `invalidateSessions()` was removed here (Phase 5.6) along with the
// sessionVersion field it incremented. Nothing called it. To invalidate
// sessions, use UserSession.revokeAllUserSessions — which is what the password
// flows already do.

// Static method: Filter safe fields for API response
userSchema.statics.getSafeFields = function () {
  return "-password -otp -otpExpires -googleId -pendingPhone -resetPasswordOtp -resetPasswordOtpExpires -blockReason -blockedAt -blockedBy -security.failedLoginAttempts -security.lockoutUntil -security.lastLoginIp";
};

// Static method: Get public profile fields
userSchema.statics.getPublicFields = function () {
  return "name profileImage role bio";
};

const User = mongoose.model("User", userSchema);
export default User;
