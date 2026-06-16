const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const UserSchema = new mongoose.Schema(
    {
        // ─────────────────────────────────────────
        // BASIC INFO
        // ─────────────────────────────────────────
        name: {
            type: String,
            required: [true, "Name is required"],
            trim: true,
            minlength: [2, "Name must be at least 2 characters"],
            maxlength: [50, "Name cannot exceed 50 characters"],
        },

        email: {
            type: String,
            required: [true, "Email is required"],
            unique: true,
            lowercase: true,
            trim: true,
            match: [
                /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
                "Please enter a valid email address",
            ],
        },

        password: {
            type: String,
            required: [true, "Password is required"],
            minlength: [8, "Password must be at least 8 characters"],
            select: false, // Never return password in queries
        },

        role: {
            type: String,
            enum: ["user", "admin"],
            default: "user",
        },

        // ─────────────────────────────────────────
        // ACCOUNT STATUS
        // ─────────────────────────────────────────
        isEmailVerified: {
            type: Boolean,
            default: false,
        },

        isLocked: {
            type: Boolean,
            default: false,
        },

        lockUntil: {
            type: Date,
            default: null,
        },

        failedLoginAttempts: {
            type: Number,
            default: 0,
        },

        // ─────────────────────────────────────────
        // OTP
        // ─────────────────────────────────────────
        otp: {
            type: String,
            default: null,
            select: false,
        },

        otpExpiresAt: {
            type: Date,
            default: null,
            select: false,
        },

        // ─────────────────────────────────────────
        // TRUST & RISK SCORES
        // ─────────────────────────────────────────
        trustScore: {
            type: Number,
            default: 100,
            min: 0,
            max: 100,
        },

        riskScore: {
            type: Number,
            default: 0,
            min: 0,
            max: 100,
        },

        // ─────────────────────────────────────────
        // BEHAVIORAL BASELINE (Phase 3)
        // ─────────────────────────────────────────
        behavioralBaseline: {
            avgTypingSpeed: { type: Number, default: null },
            avgDwellTime: { type: Number, default: null },
            avgFlightTime: { type: Number, default: null },
            sampleCount: { type: Number, default: 0 },
        },

        // ─────────────────────────────────────────
        // CONTEXT BASELINE (Phase 4)
        // ─────────────────────────────────────────
        knownIPs: {
            type: [String],
            default: [],
        },

        knownDevices: {
            type: [String],
            default: [],
        },

        knownCountries: {
            type: [String],
            default: [],
        },

        lastLoginAt: {
            type: Date,
            default: null,
        },

        lastLoginIP: {
            type: String,
            default: null,
        },
    },
    {
        timestamps: true, // createdAt + updatedAt auto
    }
);

// ─────────────────────────────────────────
// PRE-SAVE HOOK — Hash password before saving
// ─────────────────────────────────────────
UserSchema.pre("save", async function () {
    // Only hash if password was modified
    if (!this.isModified("password")) return;

    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
    this.password = await bcrypt.hash(this.password, saltRounds);
});

// ─────────────────────────────────────────
// INSTANCE METHOD — Compare passwords
// ─────────────────────────────────────────
UserSchema.methods.comparePassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// ─────────────────────────────────────────
// INSTANCE METHOD — Check if account is locked
// ─────────────────────────────────────────
UserSchema.methods.isAccountLocked = function () {
    if (!this.isLocked) return false;

    // Auto-unlock if lock period has expired
    if (this.lockUntil && this.lockUntil < Date.now()) {
        return false; // Expired lock
    }

    return true;
};

// ─────────────────────────────────────────
// INSTANCE METHOD — Increment failed attempts
// ─────────────────────────────────────────
UserSchema.methods.incrementFailedAttempts = async function () {
    const maxAttempts = parseInt(process.env.MAX_FAILED_LOGINS) || 5;
    const lockMinutes = parseInt(process.env.ACCOUNT_LOCK_MINUTES) || 30;

    this.failedLoginAttempts += 1;

    if (this.failedLoginAttempts >= maxAttempts) {
        this.isLocked = true;
        this.lockUntil = new Date(Date.now() + lockMinutes * 60 * 1000);
    }

    await this.save();
};

// ─────────────────────────────────────────
// INSTANCE METHOD — Reset failed attempts on success
// ─────────────────────────────────────────
UserSchema.methods.resetFailedAttempts = async function () {
    this.failedLoginAttempts = 0;
    this.isLocked = false;
    this.lockUntil = null;
    await this.save();
};

module.exports = mongoose.model("User", UserSchema);