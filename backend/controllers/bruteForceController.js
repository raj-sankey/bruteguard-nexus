const mongoose     = require("mongoose");
const User = require("../models/User");
const LoginAttempt = require("../models/LoginAttempt");
const SecurityAlert = require("../models/SecurityAlert");
const {
    checkLockStatus,
    manualUnlock,
    getBruteForceStats,
} = require("../services/bruteForceService");
const { createAlert } = require("../utils/alertHelper");

// ─────────────────────────────────────────
// GET MY LOCK STATUS
// GET /api/bruteforce/status
// Protected
// ─────────────────────────────────────────
const getMyLockStatus = async (req, res) => {
    try {
        const status = await checkLockStatus(req.user.id);

        return res.status(200).json({
            success: true,
            data: status,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching lock status.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET MY FAILED ATTEMPTS HISTORY
// GET /api/bruteforce/attempts
// Protected
// ─────────────────────────────────────────
const getMyFailedAttempts = async (req, res) => {
    try {
        const userId = req.user.id;
        const limit = parseInt(req.query.limit) || 20;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;

        const attempts = await LoginAttempt.find({
            userId,
            success: false,
        })
            .sort({ attemptedAt: -1 })
            .skip(skip)
            .limit(limit)
            .select(
                "failureReason context.ipAddress context.country context.browser context.device riskScore attemptedAt"
            );

        const total = await LoginAttempt.countDocuments({ userId, success: false });

        // Group by failure reason
        const byReason = await LoginAttempt.aggregate([
            { $match: { userId: new mongoose.Types.ObjectId(userId), success: false } },
            { $group: { _id: "$failureReason", count: { $sum: 1 } } },
        ]);

        return res.status(200).json({
            success: true,
            data: {
                attempts,
                stats: {
                    total,
                    byReason: byReason.reduce((acc, item) => {
                        if (item._id) acc[item._id] = item.count;
                        return acc;
                    }, {}),
                },
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
            message: "Error fetching failed attempts.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET BRUTE FORCE DASHBOARD
// GET /api/bruteforce/admin/stats
// Admin only
// ─────────────────────────────────────────
const getBruteForceAdminStats = async (req, res) => {
    try {
        const stats = await getBruteForceStats();

        return res.status(200).json({
            success: true,
            data: stats,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching brute force stats.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET ALL LOCKED ACCOUNTS
// GET /api/bruteforce/admin/locked
// Admin only
// ─────────────────────────────────────────
const getLockedAccounts = async (req, res) => {
    try {
        const lockedUsers = await User.find({ isLocked: true })
            .select("name email failedLoginAttempts lockUntil lastLoginAt lastLoginIP createdAt")
            .sort({ lockUntil: -1 });

        // Separate auto-expired locks vs active locks
        const now = Date.now();
        const activeLocks = lockedUsers.filter((u) => u.lockUntil && u.lockUntil > now);
        const expiredLocks = lockedUsers.filter((u) => u.lockUntil && u.lockUntil <= now);

        return res.status(200).json({
            success: true,
            data: {
                totalLocked: lockedUsers.length,
                activeLocks: activeLocks.length,
                expiredLocks: expiredLocks.length,
                accounts: lockedUsers.map((u) => ({
                    id: u._id,
                    name: u.name,
                    email: u.email,
                    failedAttempts: u.failedLoginAttempts,
                    lockUntil: u.lockUntil,
                    isExpired: u.lockUntil <= now,
                    remainingMinutes: u.lockUntil > now
                        ? Math.ceil((u.lockUntil - now) / 60000)
                        : 0,
                    lastLoginIP: u.lastLoginIP,
                    lastLoginAt: u.lastLoginAt,
                })),
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching locked accounts.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — UNLOCK A USER ACCOUNT
// PUT /api/bruteforce/admin/unlock/:userId
// Admin only
// ─────────────────────────────────────────
const unlockUserAccount = async (req, res) => {
    try {
        const { userId } = req.params;
        const adminId = req.user.id;

        const result = await manualUnlock(userId, adminId);

        if (!result.success) {
            return res.status(404).json({
                success: false,
                message: result.message,
            });
        }

        return res.status(200).json({
            success: true,
            message: result.message,
            data: {
                userId: result.userId,
                email: result.email,
                unlockedBy: adminId,
                unlockedAt: new Date(),
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error unlocking account.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — MANUALLY LOCK A USER ACCOUNT
// PUT /api/bruteforce/admin/lock/:userId
// Admin only
// ─────────────────────────────────────────
const lockUserAccount = async (req, res) => {
    try {
        const { userId } = req.params;
        const { durationMinutes = 60, reason = "Manual admin lock" } = req.body;
        const adminId = req.user.id;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        user.isLocked = true;
        user.lockUntil = new Date(Date.now() + durationMinutes * 60 * 1000);
        await user.save();

        // Create manual lock alert
        await createAlert({
            alertType: "manual_lock",
            severity: "high",
            userId: user._id,
            email: user.email,
            title: "Account Manually Locked by Admin",
            message: `Account ${user.email} was manually locked by admin for ${durationMinutes} minutes. Reason: ${reason}`,
            metadata: { adminId, durationMinutes, reason, lockUntil: user.lockUntil },
        });

        return res.status(200).json({
            success: true,
            message: `Account ${user.email} locked for ${durationMinutes} minutes.`,
            data: {
                userId: user._id,
                email: user.email,
                lockUntil: user.lockUntil,
                durationMinutes,
                reason,
                lockedBy: adminId,
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error locking account.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET BRUTE FORCE ALERTS
// GET /api/bruteforce/admin/alerts
// Admin only
// ─────────────────────────────────────────
const getBruteForceAlerts = async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;

        const alerts = await SecurityAlert.find({
            alertType: { $in: ["brute_force", "account_locked", "manual_lock"] },
        })
            .sort({ triggeredAt: -1 })
            .skip(skip)
            .limit(limit)
            .populate("userId", "name email");

        const total = await SecurityAlert.countDocuments({
            alertType: { $in: ["brute_force", "account_locked", "manual_lock"] },
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
            message: "Error fetching brute force alerts.",
            error: error.message,
        });
    }
};

module.exports = {
    getMyLockStatus,
    getMyFailedAttempts,
    getBruteForceAdminStats,
    getLockedAccounts,
    unlockUserAccount,
    lockUserAccount,
    getBruteForceAlerts,
};