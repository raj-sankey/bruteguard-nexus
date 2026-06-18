const LoginAttempt = require("../models/LoginAttempt");
const BlockedIP = require("../models/BlockedIP");
const User = require("../models/User");
const { createAlert } = require("../utils/alertHelper");

// ─────────────────────────────────────────
// THRESHOLDS — tunable via .env
// ─────────────────────────────────────────
const getThresholds = () => ({
    // How many unique accounts an IP can target
    // before being flagged
    maxUniqueAccounts: parseInt(process.env.CS_MAX_UNIQUE_ACCOUNTS) || 5,

    // Total attempts from one IP in the window
    maxTotalAttempts: parseInt(process.env.CS_MAX_TOTAL_ATTEMPTS) || 20,

    // Time window to look back (minutes)
    windowMinutes: parseInt(process.env.CS_WINDOW_MINUTES) || 60,

    // How long to block the IP (minutes)
    blockDurationMinutes: parseInt(process.env.CS_BLOCK_DURATION_MINUTES) || 1440, // 24 hours
});

// ─────────────────────────────────────────
// CHECK IF IP IS CURRENTLY BLOCKED
// Called at the start of every login attempt
// ─────────────────────────────────────────
const isIPBlocked = async (ipAddress) => {
    try {
        // Skip check for local IPs
        if (
            !ipAddress ||
            ipAddress === "::1" ||
            ipAddress === "127.0.0.1" ||
            ipAddress.startsWith("192.168") ||
            ipAddress.startsWith("10.")
        ) {
            return { blocked: false, isLocal: true };
        }

        const blockedIP = await BlockedIP.findOne({ ipAddress, isActive: true });

        if (!blockedIP) return { blocked: false };

        // Check if block has expired
        if (!blockedIP.isPermanent && blockedIP.blockUntil && blockedIP.blockUntil < Date.now()) {
            // Auto-expire the block
            blockedIP.isActive = false;
            await blockedIP.save();
            return { blocked: false, autoExpired: true };
        }

        if (blockedIP.isCurrentlyBlocked()) {
            return {
                blocked: true,
                reason: blockedIP.reason,
                blockUntil: blockedIP.blockUntil,
                isPermanent: blockedIP.isPermanent,
                message: blockedIP.isPermanent
                    ? "Your IP address has been permanently blocked due to malicious activity."
                    : `Your IP address is temporarily blocked until ${blockedIP.blockUntil?.toISOString()}.`,
            };
        }

        return { blocked: false };

    } catch (error) {
        console.error("❌ IP block check error:", error.message);
        return { blocked: false };
    }
};

// ─────────────────────────────────────────
// ANALYZE IP BEHAVIOR
// Looks at recent attempts from this IP
// Returns stuffing score + evidence
// ─────────────────────────────────────────
const analyzeIPBehavior = async (ipAddress) => {
    try {
        const { windowMinutes } = getThresholds();
        const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);

        // Get all attempts from this IP in the window
        const attempts = await LoginAttempt.find({
            "context.ipAddress": ipAddress,
            attemptedAt: { $gte: windowStart },
        }).select("email success attemptedAt failureReason userId");

        if (attempts.length === 0) {
            return {
                isSuspicious: false,
                totalAttempts: 0,
                uniqueAccounts: 0,
                failedAttempts: 0,
                evidence: [],
            };
        }

        // Count unique accounts targeted
        const uniqueEmails = [...new Set(attempts.map((a) => a.email))];
        const failedAttempts = attempts.filter((a) => !a.success).length;
        const successAttempts = attempts.filter((a) => a.success).length;

        const evidence = [];

        const thresholds = getThresholds();
        const isSuspicious =
            uniqueEmails.length >= thresholds.maxUniqueAccounts ||
            attempts.length >= thresholds.maxTotalAttempts;

        if (uniqueEmails.length >= thresholds.maxUniqueAccounts) {
            evidence.push(
                `IP targeted ${uniqueEmails.length} unique accounts in ${windowMinutes} minutes`
            );
        }

        if (attempts.length >= thresholds.maxTotalAttempts) {
            evidence.push(
                `IP made ${attempts.length} login attempts in ${windowMinutes} minutes`
            );
        }

        if (failedAttempts > attempts.length * 0.7) {
            evidence.push(
                `High failure rate: ${failedAttempts}/${attempts.length} attempts failed`
            );
        }

        return {
            isSuspicious,
            totalAttempts: attempts.length,
            uniqueAccounts: uniqueEmails.length,
            failedAttempts,
            successAttempts,
            targetedEmails: uniqueEmails,
            evidence,
            windowMinutes,
        };

    } catch (error) {
        console.error("❌ IP behavior analysis error:", error.message);
        return { isSuspicious: false, error: error.message };
    }
};

// ─────────────────────────────────────────
// BLOCK AN IP
// Called when credential stuffing detected
// ─────────────────────────────────────────
const blockIP = async ({
    ipAddress,
    reason,
    country,
    region,
    city,
    isp,
    attackStats,
    targetedAccounts,
    blockedBy = "system",
    blockedByAdminId = null,
    isPermanent = false,
    durationMinutes,
}) => {
    try {
        const { blockDurationMinutes } = getThresholds();
        const duration = durationMinutes || blockDurationMinutes;
        const blockUntil = isPermanent
            ? null
            : new Date(Date.now() + duration * 60 * 1000);

        // Upsert — update existing or create new
        const blockedIP = await BlockedIP.findOneAndUpdate(
            { ipAddress },
            {
                $set: {
                    reason,
                    isActive: true,
                    isPermanent,
                    blockUntil,
                    country: country || null,
                    region: region || null,
                    city: city || null,
                    isp: isp || null,
                    blockedBy,
                    blockedByAdminId: blockedByAdminId || null,
                    "attackStats.lastSeenAt": new Date(),
                },
                $max: {
                    "attackStats.totalAttempts": attackStats?.totalAttempts || 0,
                    "attackStats.uniqueAccounts": attackStats?.uniqueAccounts || 0,
                    "attackStats.failedAttempts": attackStats?.failedAttempts || 0,
                    "attackStats.successfulLogins": attackStats?.successfulLogins || 0,
                },
                $addToSet: {
                    targetedAccounts: { $each: targetedAccounts || [] },
                },
                $setOnInsert: {
                    "attackStats.firstSeenAt": new Date(),
                },
            },
            { upsert: true, new: true }
        );

        console.log(`🚫 IP Blocked: ${ipAddress} — Reason: ${reason} — Until: ${blockUntil}`);
        return blockedIP;

    } catch (error) {
        console.error("❌ IP block error:", error.message);
        return null;
    }
};

// ─────────────────────────────────────────
// DETECT AND HANDLE CREDENTIAL STUFFING
// Master function — called on every login
// ─────────────────────────────────────────
const detectCredentialStuffing = async ({
    ipAddress,
    email,
    country,
    region,
    city,
    isp,
    loginAttemptId,
    userId,
}) => {
    try {
        // Skip for local IPs
        if (
            !ipAddress ||
            ipAddress === "::1" ||
            ipAddress === "127.0.0.1" ||
            ipAddress.startsWith("192.168") ||
            ipAddress.startsWith("10.")
        ) {
            return { suspicious: false, blocked: false, isLocal: true };
        }

        // Analyze behavior of this IP
        const behavior = await analyzeIPBehavior(ipAddress);

        if (!behavior.isSuspicious) {
            return {
                suspicious: false,
                blocked: false,
                totalAttempts: behavior.totalAttempts,
                uniqueAccounts: behavior.uniqueAccounts,
            };
        }

        // ── SUSPICIOUS — BLOCK THE IP ──────────
        const blockedIP = await blockIP({
            ipAddress,
            reason: "credential_stuffing",
            country,
            region,
            city,
            isp,
            attackStats: {
                totalAttempts: behavior.totalAttempts,
                uniqueAccounts: behavior.uniqueAccounts,
                failedAttempts: behavior.failedAttempts,
            },
            targetedAccounts: behavior.targetedEmails || [],
        });

        // Fire credential stuffing alert
        await createAlert({
            alertType: "credential_stuffing",
            severity: "critical",
            userId: userId || null,
            email: email || null,
            loginAttemptId,
            title: "Credential Stuffing Attack Detected",
            message: `IP ${ipAddress} targeted ${behavior.uniqueAccounts} unique accounts with ${behavior.totalAttempts} attempts in ${behavior.windowMinutes} minutes. IP has been blocked.`,
            metadata: {
                ipAddress,
                totalAttempts: behavior.totalAttempts,
                uniqueAccounts: behavior.uniqueAccounts,
                failedAttempts: behavior.failedAttempts,
                targetedAccounts: behavior.targetedEmails,
                evidence: behavior.evidence,
                blockUntil: blockedIP?.blockUntil,
            },
            ipAddress,
            country,
        });

        return {
            suspicious: true,
            blocked: true,
            blockUntil: blockedIP?.blockUntil,
            totalAttempts: behavior.totalAttempts,
            uniqueAccounts: behavior.uniqueAccounts,
            failedAttempts: behavior.failedAttempts,
            evidence: behavior.evidence,
        };

    } catch (error) {
        console.error("❌ Credential stuffing detection error:", error.message);
        return { suspicious: false, blocked: false, error: error.message };
    }
};

// ─────────────────────────────────────────
// GET CREDENTIAL STUFFING STATS
// ─────────────────────────────────────────
const getCredentialStuffingStats = async () => {
    try {
        const SecurityAlert = require("../models/SecurityAlert");

        const totalBlocked = await BlockedIP.countDocuments({ isActive: true });
        const totalAlerts = await SecurityAlert.countDocuments({ alertType: "credential_stuffing" });

        const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const last24hBlocked = await BlockedIP.countDocuments({
            reason: "credential_stuffing",
            createdAt: { $gte: last24h },
        });

        // Top attacking IPs
        const topAttackers = await BlockedIP.find({ reason: "credential_stuffing" })
            .sort({ "attackStats.totalAttempts": -1 })
            .limit(10)
            .select("ipAddress country attackStats targetedAccounts blockUntil isPermanent createdAt");

        // Most targeted accounts in last 24h
        const mostTargeted = await LoginAttempt.aggregate([
            {
                $match: {
                    success: false,
                    attemptedAt: { $gte: last24h },
                },
            },
            {
                $group: {
                    _id: "$email",
                    attackCount: { $sum: 1 },
                    attackingIPs: { $addToSet: "$context.ipAddress" },
                    lastAttempt: { $max: "$attemptedAt" },
                },
            },
            { $sort: { attackCount: -1 } },
            { $limit: 10 },
        ]);

        return {
            totalBlockedIPs: totalBlocked,
            totalCSAlerts: totalAlerts,
            last24hNewBlocks: last24hBlocked,
            topAttackingIPs: topAttackers,
            mostTargetedAccounts: mostTargeted,
        };

    } catch (error) {
        console.error("❌ CS stats error:", error.message);
        return null;
    }
};

module.exports = {
    isIPBlocked,
    analyzeIPBehavior,
    blockIP,
    detectCredentialStuffing,
    getCredentialStuffingStats,
};