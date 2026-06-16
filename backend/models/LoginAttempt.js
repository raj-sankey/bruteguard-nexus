const mongoose = require("mongoose");

const LoginAttemptSchema = new mongoose.Schema(
    {
        // ─────────────────────────────────────────
        // USER REFERENCE
        // ─────────────────────────────────────────
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true,
        },

        email: {
            type: String,
            required: true,
            lowercase: true,
            trim: true,
        },

        // ─────────────────────────────────────────
        // ATTEMPT OUTCOME
        // ─────────────────────────────────────────
        success: {
            type: Boolean,
            required: true,
            default: false,
        },

        failureReason: {
            type: String,
            enum: [
                "wrong_password",
                "account_locked",
                "user_not_found",
                "otp_failed",
                "risk_blocked",
                null,
            ],
            default: null,
        },

        // ─────────────────────────────────────────
        // BEHAVIORAL BIOMETRICS
        // ─────────────────────────────────────────
        biometrics: {
            // Total time to type the password (ms)
            typingSpeed: {
                type: Number,
                default: null,
            },

            // Average time each key is held down (ms)
            avgDwellTime: {
                type: Number,
                default: null,
            },

            // Average time between key releases and next key press (ms)
            avgFlightTime: {
                type: Number,
                default: null,
            },

            // Raw keystroke events array
            // Each: { key, dwellTime, flightTime, timestamp }
            keystrokes: {
                type: [
                    {
                        key: { type: String },
                        dwellTime: { type: Number },
                        flightTime: { type: Number },
                        timestamp: { type: Number },
                    },
                ],
                default: [],
            },

            // Total keystrokes captured
            keystrokeCount: {
                type: Number,
                default: 0,
            },
        },

        // ─────────────────────────────────────────
        // CONTEXT DATA (filled in Phase 4)
        // ─────────────────────────────────────────
        context: {
            ipAddress: { type: String, default: null },
            country: { type: String, default: null },
            city: { type: String, default: null },
            region: { type: String, default: null },
            isp: { type: String, default: null },

            device: { type: String, default: null },
            browser: { type: String, default: null },
            os: { type: String, default: null },

            userAgent: { type: String, default: null },
            deviceFingerprint: { type: String, default: null },

            isKnownIP: { type: Boolean, default: false },
            isKnownDevice: { type: Boolean, default: false },
            isKnownCountry: { type: Boolean, default: false },
        },

        // ─────────────────────────────────────────
        // RISK DATA (filled in Phase 5)
        // ─────────────────────────────────────────
        riskScore: {
            type: Number,
            default: null,
            min: 0,
            max: 100,
        },

        riskLevel: {
            type: String,
            enum: ["low", "medium", "high", null],
            default: null,
        },

        riskFactors: {
            type: [String],
            default: [],
        },

        // ─────────────────────────────────────────
        // MFA
        // ─────────────────────────────────────────
        mfaTriggered: {
            type: Boolean,
            default: false,
        },

        mfaVerified: {
            type: Boolean,
            default: false,
        },

        // ─────────────────────────────────────────
        // TIMESTAMPS
        // ─────────────────────────────────────────
        attemptedAt: {
            type: Date,
            default: Date.now,
            index: true,
        },
    },
    {
        timestamps: true,
    }
);

// Index for fast queries per user + time
LoginAttemptSchema.index({ userId: 1, attemptedAt: -1 });
LoginAttemptSchema.index({ "context.ipAddress": 1, attemptedAt: -1 });
LoginAttemptSchema.index({ success: 1, attemptedAt: -1 });

module.exports = mongoose.model("LoginAttempt", LoginAttemptSchema);