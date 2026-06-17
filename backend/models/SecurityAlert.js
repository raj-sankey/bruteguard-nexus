const mongoose = require("mongoose");

const SecurityAlertSchema = new mongoose.Schema(
    {
        // ─────────────────────────────────────────
        // ALERT IDENTIFICATION
        // ─────────────────────────────────────────
        alertType: {
            type: String,
            required: true,
            enum: [
                "brute_force",
                "credential_stuffing",
                "account_locked",
                "suspicious_ip",
                "new_device",
                "new_country",
                "impossible_travel",
                "high_risk_login",
                "otp_failed",
                "otp_expired",
                "trust_score_drop",
                "manual_lock",
                "manual_unlock",
                "password_changed",
                "admin_action",
            ],
            index: true,
        },

        // ─────────────────────────────────────────
        // SEVERITY
        // ─────────────────────────────────────────
        severity: {
            type: String,
            enum: ["info", "low", "medium", "high", "critical"],
            default: "medium",
            index: true,
        },

        // ─────────────────────────────────────────
        // LINKED ENTITIES
        // ─────────────────────────────────────────
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null,
            index: true,
        },

        email: {
            type: String,
            default: null,
            lowercase: true,
        },

        loginAttemptId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "LoginAttempt",
            default: null,
        },

        // ─────────────────────────────────────────
        // ALERT CONTENT
        // ─────────────────────────────────────────
        title: {
            type: String,
            required: true,
        },

        message: {
            type: String,
            required: true,
        },

        // Extra structured data (IP, counts, etc.)
        metadata: {
            type: mongoose.Schema.Types.Mixed,
            default: {},
        },

        // ─────────────────────────────────────────
        // CONTEXT AT TIME OF ALERT
        // ─────────────────────────────────────────
        ipAddress: {
            type: String,
            default: null,
        },

        country: {
            type: String,
            default: null,
        },

        device: {
            type: String,
            default: null,
        },

        browser: {
            type: String,
            default: null,
        },

        // ─────────────────────────────────────────
        // ALERT STATUS
        // ─────────────────────────────────────────
        isRead: {
            type: Boolean,
            default: false,
            index: true,
        },

        isResolved: {
            type: Boolean,
            default: false,
            index: true,
        },

        resolvedAt: {
            type: Date,
            default: null,
        },

        resolvedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null,
        },

        resolvedNote: {
            type: String,
            default: null,
        },

        // ─────────────────────────────────────────
        // TIMESTAMPS
        // ─────────────────────────────────────────
        triggeredAt: {
            type: Date,
            default: Date.now,
            index: true,
        },
    },
    {
        timestamps: true,
    }
);

// Compound indexes for fast admin queries
SecurityAlertSchema.index({ userId: 1, triggeredAt: -1 });
SecurityAlertSchema.index({ alertType: 1, severity: 1, triggeredAt: -1 });
SecurityAlertSchema.index({ isResolved: 1, isRead: 1, triggeredAt: -1 });

module.exports = mongoose.model("SecurityAlert", SecurityAlertSchema);