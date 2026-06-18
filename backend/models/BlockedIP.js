const mongoose = require("mongoose");

const BlockedIPSchema = new mongoose.Schema(
    {
        // ─────────────────────────────────────────
        // IP IDENTIFICATION
        // ─────────────────────────────────────────
        ipAddress: {
            type: String,
            required: true,
            unique: true,
            index: true,
        },

        // ─────────────────────────────────────────
        // BLOCK DETAILS
        // ─────────────────────────────────────────
        reason: {
            type: String,
            enum: [
                "credential_stuffing",
                "brute_force",
                "manual_block",
                "suspicious_activity",
                "too_many_accounts",
            ],
            required: true,
        },

        isActive: {
            type: Boolean,
            default: true,
            index: true,
        },

        isPermanent: {
            type: Boolean,
            default: false,
        },

        blockUntil: {
            type: Date,
            default: null,
        },

        // ─────────────────────────────────────────
        // ATTACK EVIDENCE
        // ─────────────────────────────────────────
        attackStats: {
            totalAttempts: { type: Number, default: 0 },
            uniqueAccounts: { type: Number, default: 0 },
            failedAttempts: { type: Number, default: 0 },
            successfulLogins: { type: Number, default: 0 },
            firstSeenAt: { type: Date, default: Date.now },
            lastSeenAt: { type: Date, default: Date.now },
        },

        // Accounts this IP targeted
        targetedAccounts: {
            type: [String],
            default: [],
        },

        // ─────────────────────────────────────────
        // GEO INFO
        // ─────────────────────────────────────────
        country: { type: String, default: null },
        region: { type: String, default: null },
        city: { type: String, default: null },
        isp: { type: String, default: null },

        // ─────────────────────────────────────────
        // ADMIN ACTIONS
        // ─────────────────────────────────────────
        blockedBy: {
            type: String,
            enum: ["system", "admin"],
            default: "system",
        },

        blockedByAdminId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null,
        },

        unblockNote: {
            type: String,
            default: null,
        },

        unblockHistory: {
            type: [
                {
                    unblockedAt: { type: Date },
                    unblockedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
                    note: { type: String },
                },
            ],
            default: [],
        },
    },
    {
        timestamps: true,
    }
);

// Auto-deactivate expired blocks via a virtual check
BlockedIPSchema.methods.isCurrentlyBlocked = function () {
    if (!this.isActive) return false;
    if (this.isPermanent) return true;
    if (this.blockUntil && this.blockUntil < Date.now()) return false;
    return true;
};

module.exports = mongoose.model("BlockedIP", BlockedIPSchema);