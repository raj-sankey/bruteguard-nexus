const mongoose = require("mongoose");

// ─────────────────────────────────────────
// DESIGN DECISION: Dedicated TrustScoreLog model
//
// Alternative considered: derive trust history from LoginAttempt.riskScore.
// Rejected because:
//   1. LoginAttempt records don't store the score *delta* — only the raw
//      risk score at that moment.  We can't reconstruct "changed by -10"
//      without knowing the score before and after.
//   2. Not every trust-score event maps to a login attempt
//      (e.g., future admin-manual adjustments, password-change bonuses).
//   3. Pagination/filtering on a purpose-built collection is far cheaper
//      than aggregating LoginAttempt and doing arithmetic.
//
// This collection is append-only (no updates). Each document records:
//   - Which user
//   - What event caused the change (eventType)
//   - The delta (+/-)
//   - The score before and after
//   - Any linked LoginAttempt for deep linking
// ─────────────────────────────────────────

const TrustScoreLogSchema = new mongoose.Schema(
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

        // ─────────────────────────────────────────
        // EVENT CLASSIFICATION
        // Each eventType maps to a defined constant in trustScoreService.js
        // ─────────────────────────────────────────
        eventType: {
            type: String,
            required: true,
            enum: [
                "clean_login",          // Successful, low-risk login — positive delta
                "mfa_success",          // MFA triggered AND passed — small positive delta
                "wrong_password",       // Failed login — negative delta
                "high_risk_login",      // Risk score >= HIGH threshold — large negative delta
                "brute_force",          // Account was locked by brute force — large negative delta
                "credential_stuffing",  // IP flagged for credential stuffing — negative delta
                "account_locked",       // Account became locked — negative delta
                "mfa_failed",           // OTP expired or wrong OTP — negative delta
                "manual_adjustment",    // Future: admin override
            ],
            index: true,
        },

        // ─────────────────────────────────────────
        // SCORE DELTA
        // Positive = increase, Negative = decrease
        // ─────────────────────────────────────────
        delta: {
            type: Number,
            required: true,
        },

        // Snapshot of score before this event was applied
        scoreBefore: {
            type: Number,
            required: true,
            min: 0,
            max: 100,
        },

        // Score after applying delta (clamped 0–100)
        scoreAfter: {
            type: Number,
            required: true,
            min: 0,
            max: 100,
        },

        // ─────────────────────────────────────────
        // OPTIONAL CONTEXT
        // ─────────────────────────────────────────

        // Link back to the login attempt that triggered this log entry
        loginAttemptId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "LoginAttempt",
            default: null,
        },

        // Human-readable note explaining the change
        note: {
            type: String,
            default: null,
        },

        // Risk score at the time of login (0-100), if applicable
        riskScoreAtEvent: {
            type: Number,
            default: null,
        },

        // ─────────────────────────────────────────
        // TIMESTAMPS
        // ─────────────────────────────────────────
        loggedAt: {
            type: Date,
            default: Date.now,
            index: true,
        },
    },
    {
        timestamps: true,
    }
);

// Compound index for fast per-user, time-ordered history queries
TrustScoreLogSchema.index({ userId: 1, loggedAt: -1 });
// Index for admin analytics on event type distribution
TrustScoreLogSchema.index({ eventType: 1, loggedAt: -1 });

module.exports = mongoose.model("TrustScoreLog", TrustScoreLogSchema);
