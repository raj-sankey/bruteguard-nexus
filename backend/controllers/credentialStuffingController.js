const BlockedIP = require("../models/BlockedIP");
const SecurityAlert = require("../models/SecurityAlert");
const LoginAttempt = require("../models/LoginAttempt");
const {
    isIPBlocked,
    analyzeIPBehavior,
    blockIP,
    getCredentialStuffingStats,
} = require("../services/credentialStuffingService");
const { extractIP } = require("../utils/getIPInfo");
const { createAlert } = require("../utils/alertHelper");

// ─────────────────────────────────────────
// CHECK MY IP STATUS
// GET /api/credstuffing/ip/check
// Protected
// ─────────────────────────────────────────
const checkMyIPStatus = async (req, res) => {
    try {
        const ipAddress = extractIP(req);
        const status = await isIPBlocked(ipAddress);
        const behavior = await analyzeIPBehavior(ipAddress);

        return res.status(200).json({
            success: true,
            data: {
                ipAddress,
                isBlocked: status.blocked,
                blockDetails: status.blocked ? {
                    reason: status.reason,
                    blockUntil: status.blockUntil,
                    isPermanent: status.isPermanent,
                } : null,
                behavior: {
                    totalAttempts: behavior.totalAttempts,
                    uniqueAccounts: behavior.uniqueAccounts,
                    failedAttempts: behavior.failedAttempts,
                    isSuspicious: behavior.isSuspicious,
                    evidence: behavior.evidence,
                },
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error checking IP status.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET STATS DASHBOARD
// GET /api/credstuffing/admin/stats
// Admin only
// ─────────────────────────────────────────
const getCSStats = async (req, res) => {
    try {
        const stats = await getCredentialStuffingStats();

        return res.status(200).json({
            success: true,
            data: stats,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching credential stuffing stats.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET ALL BLOCKED IPs
// GET /api/credstuffing/admin/blocked
// Admin only
// ─────────────────────────────────────────
const getAllBlockedIPs = async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;
        const activeOnly = req.query.active !== "false";

        const query = activeOnly ? { isActive: true } : {};

        const blockedIPs = await BlockedIP.find(query)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const total = await BlockedIP.countDocuments(query);

        // Separate active vs expired
        const now = Date.now();
        const enriched = blockedIPs.map((ip) => ({
            ...ip.toObject(),
            isCurrentlyActive: ip.isCurrentlyBlocked(),
            remainingMinutes: ip.blockUntil && ip.blockUntil > now
                ? Math.ceil((ip.blockUntil - now) / 60000)
                : 0,
        }));

        return res.status(200).json({
            success: true,
            data: {
                blockedIPs: enriched,
                pagination: {
                    total,
                    page,
                    pages: Math.ceil(total / limit),
                    limit,
                },
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching blocked IPs.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — MANUALLY BLOCK AN IP
// POST /api/credstuffing/admin/block
// Admin only
// ─────────────────────────────────────────
const manuallyBlockIP = async (req, res) => {
    try {
        const {
            ipAddress,
            reason = "manual_block",
            isPermanent = false,
            durationMinutes = 1440,
            note,
        } = req.body;

        if (!ipAddress) {
            return res.status(400).json({
                success: false,
                message: "IP address is required.",
            });
        }

        const blocked = await blockIP({
            ipAddress,
            reason,
            isPermanent,
            durationMinutes,
            blockedBy: "admin",
            blockedByAdminId: req.user.id,
        });

        await createAlert({
            alertType: "suspicious_ip",
            severity: "high",
            userId: req.user.id,
            title: "IP Manually Blocked by Admin",
            message: `IP ${ipAddress} was manually blocked by admin. Reason: ${reason}. Duration: ${isPermanent ? "Permanent" : durationMinutes + " minutes"}.`,
            metadata: { ipAddress, reason, isPermanent, durationMinutes, note, adminId: req.user.id },
            ipAddress,
        });

        return res.status(200).json({
            success: true,
            message: `IP ${ipAddress} has been blocked successfully.`,
            data: {
                ipAddress,
                reason,
                isPermanent,
                blockUntil: blocked?.blockUntil,
                blockedBy: "admin",
                blockedAt: new Date(),
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error blocking IP.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — UNBLOCK AN IP
// PUT /api/credstuffing/admin/unblock/:ipAddress
// Admin only
// ─────────────────────────────────────────
const unblockIP = async (req, res) => {
    try {
        const { ipAddress } = req.params;
        const { note } = req.body;

        const blockedIP = await BlockedIP.findOne({ ipAddress });
        if (!blockedIP) {
            return res.status(404).json({
                success: false,
                message: "IP address not found in block list.",
            });
        }

        // Add to unblock history
        blockedIP.isActive = false;
        blockedIP.unblockNote = note || null;
        blockedIP.unblockHistory.push({
            unblockedAt: new Date(),
            unblockedBy: req.user.id,
            note: note || "Unblocked by admin",
        });

        await blockedIP.save();

        await createAlert({
            alertType: "admin_action",
            severity: "info",
            userId: req.user.id,
            title: "Blocked IP Removed",
            message: `IP ${ipAddress} was unblocked by admin. Note: ${note || "None"}`,
            metadata: { ipAddress, adminId: req.user.id, note },
            ipAddress,
        });

        return res.status(200).json({
            success: true,
            message: `IP ${ipAddress} has been unblocked.`,
            data: {
                ipAddress,
                unblockNote: note,
                unblockedBy: req.user.id,
                unblockedAt: new Date(),
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error unblocking IP.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET IP ACTIVITY DETAILS
// GET /api/credstuffing/admin/ip/:ipAddress
// Admin only
// ─────────────────────────────────────────
const getIPDetails = async (req, res) => {
    try {
        const { ipAddress } = req.params;

        // Get block record
        const blockRecord = await BlockedIP.findOne({ ipAddress });

        // Get all login attempts from this IP
        const attempts = await LoginAttempt.find({
            "context.ipAddress": ipAddress,
        })
            .sort({ attemptedAt: -1 })
            .limit(50)
            .select("email success failureReason riskScore riskLevel attemptedAt context.country context.browser context.device");

        // Get alerts triggered by this IP
        const alerts = await SecurityAlert.find({ ipAddress })
            .sort({ triggeredAt: -1 })
            .limit(20)
            .select("alertType severity title message triggeredAt");

        // Unique targeted accounts
        const uniqueEmails = [...new Set(attempts.map((a) => a.email))];
        const successCount = attempts.filter((a) => a.success).length;
        const failureCount = attempts.filter((a) => !a.success).length;

        // Live behavior analysis
        const behavior = await analyzeIPBehavior(ipAddress);

        return res.status(200).json({
            success: true,
            data: {
                ipAddress,
                blockRecord: blockRecord || null,
                isBlocked: blockRecord?.isActive || false,
                behavior,
                summary: {
                    totalAttempts: attempts.length,
                    successCount,
                    failureCount,
                    uniqueAccounts: uniqueEmails.length,
                    targetedAccounts: uniqueEmails,
                },
                recentAttempts: attempts,
                relatedAlerts: alerts,
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching IP details.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET CS ALERTS
// GET /api/credstuffing/admin/alerts
// Admin only
// ─────────────────────────────────────────
const getCSAlerts = async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;

        const alerts = await SecurityAlert.find({
            alertType: "credential_stuffing",
        })
            .sort({ triggeredAt: -1 })
            .skip(skip)
            .limit(limit)
            .populate("userId", "name email");

        const total = await SecurityAlert.countDocuments({
            alertType: "credential_stuffing",
        });

        return res.status(200).json({
            success: true,
            data: {
                alerts,
                pagination: {
                    total,
                    page,
                    pages: Math.ceil(total / limit),
                    limit,
                },
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching CS alerts.",
            error: error.message,
        });
    }
};

module.exports = {
    checkMyIPStatus,
    getCSStats,
    getAllBlockedIPs,
    manuallyBlockIP,
    unblockIP,
    getIPDetails,
    getCSAlerts,
};