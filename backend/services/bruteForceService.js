const User = require("../models/User");
const LoginAttempt = require("../models/LoginAttempt");
const {
    createBruteForceAlert,
    createAccountLockedAlert,
} = require("../utils/alertHelper");

// ─────────────────────────────────────────
// CHECK AND HANDLE BRUTE FORCE
// Called on every failed login attempt
// ─────────────────────────────────────────
const handleFailedAttempt = async ({
    userId,
    email,
    ipAddress,
    country,
    device,
    browser,
    loginAttemptId,
}) => {
    try {
        const user = await User.findById(userId);
        if (!user) return null;

        const maxAttempts = parseInt(process.env.MAX_FAILED_LOGINS) || 5;
        const lockMinutes = parseInt(process.env.ACCOUNT_LOCK_MINUTES) || 30;

        // Increment failed attempts
        user.failedLoginAttempts += 1;
        const currentAttempts = user.failedLoginAttempts;

        // ── THRESHOLD REACHED — LOCK ACCOUNT ──
        if (currentAttempts >= maxAttempts) {
            user.isLocked = true;
            user.lockUntil = new Date(Date.now() + lockMinutes * 60 * 1000);
            await user.save();

            // Fire brute force alert
            await createBruteForceAlert({
                userId,
                email,
                ipAddress,
                country,
                device,
                browser,
                attemptCount: currentAttempts,
                loginAttemptId,
            });

            // Fire account locked alert
            await createAccountLockedAlert({
                userId,
                email,
                ipAddress,
                lockUntil: user.lockUntil,
            });

            return {
                locked: true,
                attemptCount: currentAttempts,
                lockUntil: user.lockUntil,
                attemptsLeft: 0,
                alertsGenerated: ["brute_force", "account_locked"],
            };
        }

        // ── NOT LOCKED YET — SAVE AND WARN ────
        await user.save();

        const attemptsLeft = maxAttempts - currentAttempts;

        // Warn at 1 attempt remaining
        if (attemptsLeft === 1) {
            console.warn(`⚠️  User ${email} has 1 attempt left before lockout.`);
        }

        return {
            locked: false,
            attemptCount: currentAttempts,
            attemptsLeft,
            lockUntil: null,
        };

    } catch (error) {
        console.error("❌ Brute force handler error:", error.message);
        return null;
    }
};

// ─────────────────────────────────────────
// CHECK IF ACCOUNT IS LOCKED
// Returns lock status + time remaining
// ─────────────────────────────────────────
const checkLockStatus = async (userId) => {
    try {
        const user = await User.findById(userId);
        if (!user) return { exists: false };

        // Auto-unlock if lock period expired
        if (user.isLocked && user.lockUntil && user.lockUntil < Date.now()) {
            await user.resetFailedAttempts();
            return {
                exists: true,
                locked: false,
                autoUnlocked: true,
                message: "Lock period expired. Account auto-unlocked.",
            };
        }

        if (user.isLocked) {
            const remainingMs = user.lockUntil - Date.now();
            const remainingMinutes = Math.ceil(remainingMs / 60000);

            return {
                exists: true,
                locked: true,
                lockUntil: user.lockUntil,
                remainingMinutes,
                failedAttempts: user.failedLoginAttempts,
                message: `Account locked for ${remainingMinutes} more minute(s).`,
            };
        }

        return {
            exists: true,
            locked: false,
            failedAttempts: user.failedLoginAttempts,
            attemptsLeft: (parseInt(process.env.MAX_FAILED_LOGINS) || 5) - user.failedLoginAttempts,
            message: "Account is not locked.",
        };

    } catch (error) {
        console.error("❌ Lock status check error:", error.message);
        return null;
    }
};

// ─────────────────────────────────────────
// MANUAL UNLOCK (Admin action)
// ─────────────────────────────────────────
const manualUnlock = async (userId, adminId) => {
    try {
        const user = await User.findById(userId);
        if (!user) return { success: false, message: "User not found." };

        await user.resetFailedAttempts();

        const { createAlert } = require("../utils/alertHelper");
        await createAlert({
            alertType: "manual_unlock",
            severity: "info",
            userId: user._id,
            email: user.email,
            title: "Account Manually Unlocked",
            message: `Account ${user.email} was manually unlocked by admin.`,
            metadata: { adminId, unlockedAt: new Date() },
        });

        return {
            success: true,
            message: `Account ${user.email} has been unlocked successfully.`,
            userId: user._id,
            email: user.email,
        };

    } catch (error) {
        console.error("❌ Manual unlock error:", error.message);
        return { success: false, message: error.message };
    }
};

// ─────────────────────────────────────────
// GET BRUTE FORCE STATS
// Used by analytics and admin dashboard
// ─────────────────────────────────────────
const getBruteForceStats = async () => {
    try {
        const SecurityAlert = require("../models/SecurityAlert");

        // Total brute force alerts
        const totalBruteForce = await SecurityAlert.countDocuments({
            alertType: "brute_force",
        });

        // Last 24 hours
        const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const last24hCount = await SecurityAlert.countDocuments({
            alertType: "brute_force",
            triggeredAt: { $gte: last24h },
        });

        // Currently locked accounts
        const lockedAccounts = await User.find({ isLocked: true })
            .select("email failedLoginAttempts lockUntil lastLoginIP")
            .sort({ lockUntil: -1 });

        // Most targeted accounts
        const mostTargeted = await LoginAttempt.aggregate([
            { $match: { success: false } },
            {
                $group: {
                    _id: "$email",
                    failureCount: { $sum: 1 },
                    lastAttempt: { $max: "$attemptedAt" },
                    ips: { $addToSet: "$context.ipAddress" },
                },
            },
            { $sort: { failureCount: -1 } },
            { $limit: 10 },
        ]);

        // Most attacking IPs
        const attackingIPs = await LoginAttempt.aggregate([
            { $match: { success: false } },
            {
                $group: {
                    _id: "$context.ipAddress",
                    attackCount: { $sum: 1 },
                    targets: { $addToSet: "$email" },
                    lastAttempt: { $max: "$attemptedAt" },
                },
            },
            { $sort: { attackCount: -1 } },
            { $limit: 10 },
        ]);

        return {
            totalBruteForceAlerts: totalBruteForce,
            last24hAlerts: last24hCount,
            currentlyLockedCount: lockedAccounts.length,
            lockedAccounts,
            mostTargetedAccounts: mostTargeted,
            topAttackingIPs: attackingIPs,
        };

    } catch (error) {
        console.error("❌ Brute force stats error:", error.message);
        return null;
    }
};

module.exports = {
    handleFailedAttempt,
    checkLockStatus,
    manualUnlock,
    getBruteForceStats,
};