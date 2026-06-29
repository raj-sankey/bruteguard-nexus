const mongoose      = require("mongoose");
const User          = require("../models/User");
const LoginAttempt  = require("../models/LoginAttempt");
const SecurityAlert = require("../models/SecurityAlert");
const BlockedIP     = require("../models/BlockedIP");
const { getTrustLevel } = require("./trustScoreService");

// ─────────────────────────────────────────
// GET ALL USERS
// Supports search (name/email), role filter, isLocked filter, sortBy
// ─────────────────────────────────────────
const getAllUsers = async ({
    page     = 1,
    limit    = 20,
    search   = "",
    role     = "",
    isLocked = "",
    sortBy   = "createdAt",
} = {}) => {
    const safePage  = Math.max(parseInt(page)  || 1, 1);
    const safeLimit = Math.min(parseInt(limit) || 20, 100);
    const skip      = (safePage - 1) * safeLimit;

    // ── Build filter ──────────────────────────────────────────────
    const filter = {};

    if (search) {
        // Case-insensitive partial match on name OR email
        filter.$or = [
            { name:  { $regex: search, $options: "i" } },
            { email: { $regex: search, $options: "i" } },
        ];
    }

    if (role && ["user", "admin"].includes(role)) {
        filter.role = role;
    }

    if (isLocked !== "" && isLocked !== undefined) {
        filter.isLocked = isLocked === "true" || isLocked === true;
    }

    // ── Allowed sort fields — whitelist to prevent injection ──────
    const allowedSorts = ["createdAt", "trustScore", "riskScore", "lastLoginAt", "email", "name"];
    const sortField    = allowedSorts.includes(sortBy) ? sortBy : "createdAt";
    const sortOrder    = sortField === "trustScore" ? 1 : -1; // ascending for trustScore (lowest first)

    const [users, total] = await Promise.all([
        User.find(filter)
            .sort({ [sortField]: sortOrder })
            .skip(skip)
            .limit(safeLimit)
            .select("name email role isLocked lockUntil failedLoginAttempts trustScore riskScore lastLoginAt lastLoginIP createdAt")
            .lean(),
        User.countDocuments(filter),
    ]);

    // Attach trust level label to each user for the admin table
    const usersWithLevel = users.map((u) => ({
        ...u,
        trustLevel: getTrustLevel(u.trustScore).label,
    }));

    return {
        users: usersWithLevel,
        pagination: {
            total,
            page:  safePage,
            pages: Math.ceil(total / safeLimit),
            limit: safeLimit,
        },
    };
};

// ─────────────────────────────────────────
// GET FULL USER DETAIL BY ID
// Returns profile + recent login attempts + recent alerts
// ─────────────────────────────────────────
const getUserDetailById = async (userId) => {
    // Fetch user (no password)
    const user = await User.findById(userId).select("-password").lean();

    if (!user) return null;

    // ── Recent login attempts ─────────────────────────────────────
    const recentAttempts = await LoginAttempt.find({ userId })
        .sort({ attemptedAt: -1 })
        .limit(10)
        .select("success failureReason context riskScore riskLevel riskFactors mfaTriggered mfaVerified attemptedAt")
        .lean();

    // ── Recent security alerts ────────────────────────────────────
    const recentAlerts = await SecurityAlert.find({ userId })
        .sort({ triggeredAt: -1 })
        .limit(10)
        .select("alertType severity title message isRead isResolved triggeredAt metadata")
        .lean();

    // ── Aggregated stats ──────────────────────────────────────────
    const [totalAttempts, successCount, failCount] = await Promise.all([
        LoginAttempt.countDocuments({ userId }),
        LoginAttempt.countDocuments({ userId, success: true }),
        LoginAttempt.countDocuments({ userId, success: false }),
    ]);

    const successRate = totalAttempts > 0
        ? parseFloat(((successCount / totalAttempts) * 100).toFixed(1))
        : 0;

    return {
        user: {
            ...user,
            trustLevel: getTrustLevel(user.trustScore).label,
        },
        stats: {
            totalAttempts,
            successCount,
            failCount,
            successRate,
            totalAlerts:    recentAlerts.length,
            unreadAlerts:   recentAlerts.filter((a) => !a.isRead).length,
        },
        recentAttempts,
        recentAlerts,
    };
};

// ─────────────────────────────────────────
// GET ALL LOGIN ATTEMPTS (Admin)
// Filterable by userId, success, riskLevel, ipAddress
// ─────────────────────────────────────────
const getAllLoginAttempts = async ({
    page       = 1,
    limit      = 20,
    userId     = "",
    success    = "",
    riskLevel  = "",
    ipAddress  = "",
} = {}) => {
    const safePage  = Math.max(parseInt(page)  || 1, 1);
    const safeLimit = Math.min(parseInt(limit) || 20, 100);
    const skip      = (safePage - 1) * safeLimit;

    const filter = {};

    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
        filter.userId = new mongoose.Types.ObjectId(userId);
    }

    if (success !== "" && success !== undefined) {
        filter.success = success === "true" || success === true;
    }

    if (riskLevel && ["low", "medium", "high"].includes(riskLevel)) {
        filter.riskLevel = riskLevel;
    }

    if (ipAddress) {
        filter["context.ipAddress"] = ipAddress;
    }

    const [attempts, total] = await Promise.all([
        LoginAttempt.find(filter)
            .sort({ attemptedAt: -1 })
            .skip(skip)
            .limit(safeLimit)
            // Populate user name + email for admin view
            .populate("userId", "name email role")
            .lean(),
        LoginAttempt.countDocuments(filter),
    ]);

    return {
        attempts,
        pagination: {
            total,
            page:  safePage,
            pages: Math.ceil(total / safeLimit),
            limit: safeLimit,
        },
    };
};

// ─────────────────────────────────────────
// GET SYSTEM-WIDE STATS
// The master admin dashboard summary endpoint
// ─────────────────────────────────────────
const getSystemWideStats = async () => {
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const last7d  = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    // ── Run all aggregations in parallel ─────────────────────────
    const [
        totalUsers,
        lockedUsers,
        adminCount,

        totalLogins,
        successLogins,
        failedLogins,
        last24hLogins,

        totalAlerts,
        alertsBySeverity,
        unresolvedAlerts,

        totalBlockedIPs,
        activeBlockedIPs,

        trustRiskAgg,
    ] = await Promise.all([
        User.countDocuments({}),
        User.countDocuments({ isLocked: true }),
        User.countDocuments({ role: "admin" }),

        LoginAttempt.countDocuments({}),
        LoginAttempt.countDocuments({ success: true }),
        LoginAttempt.countDocuments({ success: false }),
        LoginAttempt.countDocuments({ attemptedAt: { $gte: last24h } }),

        SecurityAlert.countDocuments({}),
        SecurityAlert.aggregate([
            { $group: { _id: "$severity", count: { $sum: 1 } } },
        ]),
        SecurityAlert.countDocuments({ isResolved: false }),

        BlockedIP.countDocuments({}),
        BlockedIP.countDocuments({ isActive: true }),

        // Avg trust + risk scores in one aggregation pass
        User.aggregate([
            {
                $group: {
                    _id: null,
                    avgTrustScore: { $avg: "$trustScore" },
                    avgRiskScore:  { $avg: "$riskScore" },
                },
            },
        ]),
    ]);

    const successRate = totalLogins > 0
        ? parseFloat(((successLogins / totalLogins) * 100).toFixed(1))
        : 0;

    const bySeverity = alertsBySeverity.reduce((acc, { _id, count }) => {
        if (_id) acc[_id] = count;
        return acc;
    }, {});

    const avgTrust = trustRiskAgg[0]?.avgTrustScore != null
        ? parseFloat(trustRiskAgg[0].avgTrustScore.toFixed(2))
        : null;

    const avgRisk = trustRiskAgg[0]?.avgRiskScore != null
        ? parseFloat(trustRiskAgg[0].avgRiskScore.toFixed(2))
        : null;

    return {
        users: {
            total:   totalUsers,
            locked:  lockedUsers,
            admins:  adminCount,
            regular: totalUsers - adminCount,
        },
        logins: {
            total:       totalLogins,
            successful:  successLogins,
            failed:      failedLogins,
            last24h:     last24hLogins,
            successRate,
        },
        alerts: {
            total:      totalAlerts,
            unresolved: unresolvedAlerts,
            bySeverity,
        },
        blockedIPs: {
            total:  totalBlockedIPs,
            active: activeBlockedIPs,
        },
        scores: {
            avgTrustScore: avgTrust,
            avgRiskScore:  avgRisk,
        },
        generatedAt: new Date(),
    };
};

module.exports = {
    getAllUsers,
    getUserDetailById,
    getAllLoginAttempts,
    getSystemWideStats,
};
